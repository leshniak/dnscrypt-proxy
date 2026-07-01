package main

import (
	"errors"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/svcb"
)

type PluginPreferIPv4 struct {
	proxy *Proxy
}

func (plugin *PluginPreferIPv4) Name() string {
	return "prefer_ipv4"
}

func (plugin *PluginPreferIPv4) Description() string {
	return "Return a synthetic response to AAAA queries if A record exists"
}

func (plugin *PluginPreferIPv4) Init(proxy *Proxy) error {
	plugin.proxy = proxy
	return nil
}

func (plugin *PluginPreferIPv4) Drop() error {
	return nil
}

func (plugin *PluginPreferIPv4) Reload() error {
	return nil
}

func (plugin *PluginPreferIPv4) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	question := msg.Question[0]
	if question.Header().Class != dns.ClassINET || dns.RRToType(question) != dns.TypeAAAA {
		return nil
	}
	msgA := dns.NewMsg(question.Header().Name, dns.TypeA)
	msgA.ID = pluginsState.questionMsg.ID
	msgA.RecursionDesired = pluginsState.questionMsg.RecursionDesired
	if err := msgA.Pack(); err != nil {
		return err
	}
	msgAPacket := msgA.Data
	if !plugin.proxy.clientsCountInc() {
		return errors.New("Too many concurrent connections to handle A subqueries")
	}
	respAPacket := plugin.proxy.processIncomingQuery(
		"trampoline",
		plugin.proxy.xTransport.mainProto,
		msgAPacket,
		nil,
		nil,
		time.Now(),
		false,
	)
	plugin.proxy.clientsCountDec()
	if len(respAPacket) == 0 {
		return errors.New("Empty response from PreferIPv4 trampoline query")
	}
	respA := dns.Msg{Data: respAPacket}
	if err := respA.Unpack(); err != nil {
		return err
	}
	if respA.Rcode != dns.RcodeSuccess {
		return nil
	}
	hasAAnswer := false
	for _, answer := range respA.Answer {
		if dns.RRToType(answer) == dns.TypeA {
			hasAAnswer = true
			break
		}
	}
	if !hasAAnswer {
		return nil
	}
	synth := EmptyResponseFromMessage(msg)
	hinfo := new(dns.HINFO)
	hinfo.Hdr = dns.Header{
		Name: question.Header().Name, Class: dns.ClassINET, TTL: 86400,
	}
	hinfo.Cpu = "AAAA queries have been locally blocked by dnscrypt-proxy"
	hinfo.Os = "Set prefer_ipv4 to false to disable this feature"
	synth.Answer = []dns.RR{hinfo}
	qName := question.Header().Name
	i := strings.Index(qName, ".")
	parentZone := "."
	if !(i < 0 || i+1 >= len(qName)) {
		parentZone = qName[i+1:]
	}
	soa := new(dns.SOA)
	soa.Mbox = "h.invalid."
	soa.Ns = "a.root-servers.net."
	soa.Serial = 1
	soa.Refresh = 10000
	soa.Minttl = 2400
	soa.Expire = 604800
	soa.Retry = 300
	soa.Hdr = dns.Header{
		Name: parentZone, Class: dns.ClassINET, TTL: 60,
	}
	synth.Ns = []dns.RR{soa}
	pluginsState.synthResponse = synth
	pluginsState.action = PluginsActionSynth
	pluginsState.returnCode = PluginsReturnCodeSynth
	return nil
}

// ---

type PluginPreferIPv4Response struct{}

func (plugin *PluginPreferIPv4Response) Name() string {
	return "prefer_ipv4_response"
}

func (plugin *PluginPreferIPv4Response) Description() string {
	return "Removes IPv6 from HTTPS queries"
}

func (plugin *PluginPreferIPv4Response) Init(proxy *Proxy) error {
	return nil
}

func (plugin *PluginPreferIPv4Response) Drop() error {
	return nil
}

func (plugin *PluginPreferIPv4Response) Reload() error {
	return nil
}

func hasIPv4Hint(value []svcb.Pair) bool {
	for _, pair := range value {
		if _, ok := pair.(*svcb.IPV4HINT); ok {
			return true
		}
	}
	return false
}

func hasIPv6Hint(value []svcb.Pair) bool {
	for _, pair := range value {
		if _, ok := pair.(*svcb.IPV6HINT); ok {
			return true
		}
	}
	return false
}

func (plugin *PluginPreferIPv4Response) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	question := msg.Question[0]
	if question.Header().Class != dns.ClassINET || dns.RRToType(question) != dns.TypeHTTPS {
		return nil
	}

	// We must only rewrite the response when there is genuinely something to
	// strip: an HTTPS record that advertises BOTH an IPv4 and an IPv6 hint.
	//
	// Why the strict guard: synthesizing goes through EmptyResponseFromMessage,
	// a shared helper we deliberately do not modify. Since the miekg/dns v2
	// migration it no longer copies the source Rcode nor the authority/additional
	// sections. Blindly synthesizing therefore masked NXDOMAIN/SERVFAIL as
	// NOERROR and dropped the SOA of NODATA answers. For names without an HTTPS
	// record (e.g. reddit.com), that turned a clean NODATA into a NOERROR reply
	// carrying a bogus HINFO, which clients like Firefox reject ("server not
	// found") on first load. When there is nothing to filter we leave the
	// upstream response completely untouched.
	if msg.Rcode != dns.RcodeSuccess {
		return nil
	}
	needsFiltering := false
	for _, answer := range msg.Answer {
		if https, ok := answer.(*dns.HTTPS); ok &&
			hasIPv4Hint(https.Value) && hasIPv6Hint(https.Value) {
			needsFiltering = true
			break
		}
	}
	if !needsFiltering {
		return nil
	}

	synth := EmptyResponseFromMessage(msg)
	// EmptyResponseFromMessage drops these; restore them so we only alter the
	// IPv6 hints and nothing else about the response.
	synth.Rcode = msg.Rcode
	synth.Ns = msg.Ns
	synth.Extra = msg.Extra
	for _, answer := range msg.Answer {
		originalAnswer, ok := answer.(*dns.HTTPS)
		if !ok || !hasIPv4Hint(originalAnswer.Value) {
			// Not an HTTPS record, or no IPv4 hint to prefer: keep as-is so a
			// host without IPv4 still receives its IPv6 hint.
			synth.Answer = append(synth.Answer, answer)
			continue
		}
		synthAnswer := new(dns.HTTPS)
		synthAnswer.Hdr = *originalAnswer.Header()
		synthAnswer.Priority = originalAnswer.Priority
		synthAnswer.Target = originalAnswer.Target
		synthAnswer.Value = make([]svcb.Pair, 0, len(originalAnswer.Value))
		for _, pair := range originalAnswer.Value {
			if _, ok := pair.(*svcb.IPV6HINT); !ok {
				synthAnswer.Value = append(synthAnswer.Value, pair)
			}
		}
		synth.Answer = append(synth.Answer, synthAnswer)
	}
	// Leave an informational marker so the user can tell that filtering
	// happened (e.g. in dig output). This is safe here because we only reach
	// this point when a real HTTPS record was actually filtered, so the
	// answer still carries valid SVCB data alongside the HINFO - unlike the
	// previous unconditional append, which injected a HINFO into NODATA/
	// NXDOMAIN replies and broke clients.
	hinfo := new(dns.HINFO)
	hinfo.Hdr = dns.Header{
		Name: question.Header().Name, Class: dns.ClassINET, TTL: 86400,
	}
	hinfo.Cpu = "HTTPS queries have been locally filtered by dnscrypt-proxy"
	hinfo.Os = "Set prefer_ipv4 to false to disable this feature"
	synth.Answer = append(synth.Answer, hinfo)
	pluginsState.synthResponse = synth
	pluginsState.action = PluginsActionSynth
	pluginsState.returnCode = PluginsReturnCodeCloak
	return nil
}
