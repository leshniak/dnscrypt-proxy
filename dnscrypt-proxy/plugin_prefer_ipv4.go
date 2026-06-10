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
		header := answer.Header()
		if dns.RRToType(header) == dns.TypeA {
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

func (plugin *PluginPreferIPv4Response) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	question := msg.Question[0]
	if question.Header().Class != dns.ClassINET || dns.RRToType(question) != dns.TypeHTTPS {
		return nil
	}
	synth := EmptyResponseFromMessage(msg)
	for _, answer := range msg.Answer {
		header := answer.Header()

		if dns.RRToType(header) == dns.TypeHTTPS {
			originalAnswer := answer.(*dns.HTTPS)

			synthAnswer := new(dns.HTTPS)
			synthAnswer.Hdr = *originalAnswer.Header()
			synthAnswer.Priority = originalAnswer.Priority
			synthAnswer.Target = originalAnswer.Target
			synthAnswer.SVCB = originalAnswer.SVCB

			hasIPv4Hint := false
			for _, pair := range originalAnswer.Value {
				if _, ok := pair.(*svcb.IPV4HINT); ok {
					hasIPv4Hint = true
					break
				}
			}

			if hasIPv4Hint {
				filtered := make([]svcb.Pair, 0, len(originalAnswer.Value))

				for _, pair := range originalAnswer.Value {
					if _, ok := pair.(*svcb.IPV6HINT); !ok {
						filtered = append(filtered, pair)
					}
				}

				synthAnswer.Value = filtered
			} else {
				synthAnswer.Value = make([]svcb.Pair, len(originalAnswer.Value))
				copy(synthAnswer.Value, originalAnswer.Value)
			}

			synth.Answer = append(synth.Answer, synthAnswer)
		} else {
			synth.Answer = append(synth.Answer, answer)
		}
	}
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
