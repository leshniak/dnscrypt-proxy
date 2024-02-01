package main

import (
	"strings"

	"github.com/miekg/dns"
)

type PluginBlockType65 struct{}

func (plugin *PluginBlockType65) Name() string {
	return "block_type65"
}

func (plugin *PluginBlockType65) Description() string {
	return "Immediately return a synthetic response to HTTPS (Type65) queries."
}

func (plugin *PluginBlockType65) Init(proxy *Proxy) error {
	return nil
}

func (plugin *PluginBlockType65) Drop() error {
	return nil
}

func (plugin *PluginBlockType65) Reload() error {
	return nil
}

func (plugin *PluginBlockType65) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	question := msg.Question[0]
	if question.Qclass != dns.ClassINET || question.Qtype != dns.TypeHTTPS {
		return nil
	}
	synth := EmptyResponseFromMessage(msg)
	hinfo := new(dns.HINFO)
	hinfo.Hdr = dns.RR_Header{
		Name: question.Name, Rrtype: dns.TypeHINFO,
		Class: dns.ClassINET, Ttl: 86400,
	}
	hinfo.Cpu = "HTTPS (Type65) queries have been locally blocked by dnscrypt-proxy"
	hinfo.Os = "Set block_type65 to false to disable that feature"
	synth.Answer = []dns.RR{hinfo}
	qName := question.Name
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
	soa.Hdr = dns.RR_Header{
		Name: parentZone, Rrtype: dns.TypeSOA,
		Class: dns.ClassINET, Ttl: 60,
	}
	synth.Ns = []dns.RR{soa}
	pluginsState.synthResponse = synth
	pluginsState.action = PluginsActionSynth
	pluginsState.returnCode = PluginsReturnCodeSynth
	return nil
}
