package dnsserver_test

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"dnsfilter/internal/dnsserver"
	"dnsfilter/internal/dnstest"
	"dnsfilter/internal/policy"
	"dnsfilter/internal/store"
	"dnsfilter/internal/upstream"
)

func TestUDPAndTCPForwardAllowedQuery(t *testing.T) {
	fake, filter, _ := fixture(t, nil, nil)
	for _, transport := range []string{"udp", "tcp"} {
		resp := ask(t, filter, transport, "example.com.")
		if resp.Rcode != dns.RcodeSuccess {
			t.Fatalf("%s rcode = %s", transport, dns.RcodeToString[resp.Rcode])
		}
		if len(resp.Question) != 1 || resp.Question[0].Name != "example.com." {
			t.Fatalf("%s question = %+v", transport, resp.Question)
		}
		if ip := firstA(resp); ip == nil || !ip.Equal(net.ParseIP("192.0.2.50")) {
			t.Fatalf("%s answer = %v", transport, resp.Answer)
		}
	}
	if fake.UDPHits.Load() < 2 {
		t.Fatalf("upstream udp hits = %d, want at least 2", fake.UDPHits.Load())
	}
}

func TestBlockedQueryDoesNotCallUpstream(t *testing.T) {
	fake, filter, _ := fixture(t, nil, []policy.FeedRule{{Name: "demo-local", Domain: "malware-demo.test"}})
	before := fake.UDPHits.Load() + fake.TCPHits.Load()
	resp := ask(t, filter, "udp", "malware-demo.test.")
	if resp.Rcode != dns.RcodeRefused {
		t.Fatalf("rcode = %s", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 0 {
		t.Fatalf("blocked answer = %v", resp.Answer)
	}
	if len(resp.Question) != 1 || resp.Question[0].Name != "malware-demo.test." {
		t.Fatalf("question = %+v", resp.Question)
	}
	if fake.UDPHits.Load()+fake.TCPHits.Load() != before {
		t.Fatal("blocked query reached upstream")
	}
	resp = ask(t, filter, "udp", "notexample.test.")
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("boundary rcode = %s", dns.RcodeToString[resp.Rcode])
	}
}

func TestSuffixAndAllowPrecedence(t *testing.T) {
	_, filter, _ := fixture(t, []policy.Rule{
		{ID: 1, Domain: "example.test", Kind: policy.KindDeny, Match: policy.MatchSuffix},
		{ID: 2, Domain: "ok.example.test", Kind: policy.KindAllow, Match: policy.MatchExact},
	}, []policy.FeedRule{{Name: "demo-local", Domain: "ok.example.test"}})

	blocked := ask(t, filter, "udp", "a.example.test.")
	if blocked.Rcode != dns.RcodeRefused {
		t.Fatalf("child rcode = %s", dns.RcodeToString[blocked.Rcode])
	}
	allowed := ask(t, filter, "tcp", "ok.example.test.")
	if allowed.Rcode != dns.RcodeSuccess {
		t.Fatalf("allow rcode = %s", dns.RcodeToString[allowed.Rcode])
	}
	boundary := ask(t, filter, "udp", "notexample.test.")
	if boundary.Rcode != dns.RcodeSuccess {
		t.Fatalf("boundary rcode = %s", dns.RcodeToString[boundary.Rcode])
	}
}

func TestUpstreamTimeoutReturnsSERVFAIL(t *testing.T) {
	fake, filter, _ := fixture(t, nil, nil)
	fake.SetDelay(400 * time.Millisecond)
	resp := ask(t, filter, "udp", "example.com.")
	if resp.Rcode != dns.RcodeServerFailure {
		t.Fatalf("rcode = %s", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 0 {
		t.Fatalf("servfail answer = %v", resp.Answer)
	}
}

func TestTruncatedUpstreamRetriesTCP(t *testing.T) {
	fake, filter, _ := fixture(t, nil, nil)
	fake.SetTruncateUDP(true)
	resp := ask(t, filter, "udp", "example.com.")
	if resp.Rcode != dns.RcodeSuccess || resp.Truncated {
		t.Fatalf("resp truncated=%v rcode=%s", resp.Truncated, dns.RcodeToString[resp.Rcode])
	}
	if ip := firstA(resp); ip == nil || !ip.Equal(net.ParseIP("192.0.2.50")) {
		t.Fatalf("answer = %v", resp.Answer)
	}
	if fake.UDPHits.Load() != 1 || fake.TCPHits.Load() != 1 {
		t.Fatalf("hits udp=%d tcp=%d", fake.UDPHits.Load(), fake.TCPHits.Load())
	}
}

func TestMalformedQueriesDoNotPanic(t *testing.T) {
	_, filter, _ := fixture(t, nil, nil)
	conn, err := net.Dial("udp", filter.UDPAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}); err != nil {
		t.Fatal(err)
	}
	resp := ask(t, filter, "udp", "example.com.")
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("server did not recover, rcode = %s", dns.RcodeToString[resp.Rcode])
	}

	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	m.Question = append(m.Question, dns.Question{Name: "second.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
	got := exchange(t, filter.UDPAddr().String(), "udp", m)
	if got.Rcode != dns.RcodeFormatError {
		t.Fatalf("multi-question rcode = %s", dns.RcodeToString[got.Rcode])
	}

	update := new(dns.Msg)
	update.SetQuestion("example.com.", dns.TypeA)
	update.Opcode = dns.OpcodeUpdate
	got = exchange(t, filter.UDPAddr().String(), "udp", update)
	if got.Rcode != dns.RcodeNotImplemented {
		t.Fatalf("update rcode = %s", dns.RcodeToString[got.Rcode])
	}
}

func TestQueryEventsArePersisted(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir + "/dnsfilter.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	_, filter, _ := fixtureWith(t, nil, []policy.FeedRule{{Name: "demo-local", Domain: "malware-demo.test"}}, func(ctx context.Context, ev dnsserver.QueryEvent) error {
		_, err := st.InsertEvent(ctx, store.Event{
			Timestamp: ev.Timestamp, ClientIP: ev.ClientIP, QName: ev.QName, QType: ev.QType,
			Transport: ev.Transport, Action: ev.Action, RCode: ev.RCode,
			UpstreamLatencyMS: ev.UpstreamLatencyMS, MatchedSource: ev.MatchedSource, MatchedDomain: ev.MatchedDomain,
		})
		return err
	})
	ask(t, filter, "udp", "example.com.")
	ask(t, filter, "tcp", "malware-demo.test.")

	events, total, err := st.ListEvents(context.Background(), store.EventFilter{Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 {
		t.Fatalf("events = %d", total)
	}
	byName := map[string]store.Event{}
	for _, ev := range events {
		byName[ev.QName] = ev
		if ev.ClientIP != "127.0.0.1" {
			t.Fatalf("client = %s", ev.ClientIP)
		}
		if ev.Timestamp.Location() != time.UTC && ev.Timestamp.UTC().IsZero() {
			t.Fatalf("timestamp = %s", ev.Timestamp)
		}
	}
	allowed := byName["example.com"]
	if allowed.Action != "ALLOWED" || allowed.RCode != "NOERROR" || allowed.Transport != "udp" || allowed.UpstreamLatencyMS == nil {
		t.Fatalf("allowed = %+v", allowed)
	}
	blocked := byName["malware-demo.test"]
	if blocked.Action != "BLOCKED" || blocked.RCode != "REFUSED" || blocked.Transport != "tcp" || blocked.MatchedSource != "demo-local" || blocked.UpstreamLatencyMS != nil {
		t.Fatalf("blocked = %+v", blocked)
	}
}

func TestRuleChangeAppliesWithoutRestart(t *testing.T) {
	fake, filter, engine := fixture(t, nil, nil)
	if ask(t, filter, "udp", "c2-demo.test.").Rcode != dns.RcodeSuccess {
		t.Fatal("expected forward before the rule exists")
	}
	snap, err := policy.NewSnapshot([]policy.Rule{{
		ID: 9, Domain: "c2-demo.test", Kind: policy.KindDeny, Match: policy.MatchExact,
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	engine.Replace(snap)
	before := fake.UDPHits.Load() + fake.TCPHits.Load()
	if ask(t, filter, "udp", "c2-demo.test.").Rcode != dns.RcodeRefused {
		t.Fatal("new deny rule was not applied")
	}
	if fake.UDPHits.Load()+fake.TCPHits.Load() != before {
		t.Fatal("blocked query reached upstream after the live update")
	}
}

func fixture(t *testing.T, rules []policy.Rule, feeds []policy.FeedRule) (*dnstest.Upstream, *dnsserver.Server, *policy.Engine) {
	t.Helper()
	var got []dnsserver.QueryEvent
	var mu sync.Mutex
	return fixtureWith(t, rules, feeds, func(_ context.Context, ev dnsserver.QueryEvent) error {
		mu.Lock()
		got = append(got, ev)
		mu.Unlock()
		return nil
	})
}

func fixtureWith(t *testing.T, rules []policy.Rule, feeds []policy.FeedRule, record dnsserver.Recorder) (*dnstest.Upstream, *dnsserver.Server, *policy.Engine) {
	t.Helper()
	fake, err := dnstest.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fake.Close() })
	snap, err := policy.NewSnapshot(rules, feeds)
	if err != nil {
		t.Fatal(err)
	}
	engine := policy.NewEngine()
	engine.Replace(snap)
	filter, err := dnsserver.Listen(dnsserver.Options{
		ListenUDP:    "127.0.0.1:0",
		ListenTCP:    "127.0.0.1:0",
		Engine:       engine,
		Upstream:     &upstream.Client{Addr: fake.Addr, Timeout: 150 * time.Millisecond},
		BlockedRCode: "REFUSED",
		Record:       record,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { filter.Close() })
	return fake, filter, engine
}

func ask(t *testing.T, filter *dnsserver.Server, transport, name string) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeA)
	m.RecursionDesired = true
	addr := filter.UDPAddr().String()
	if transport == "tcp" {
		addr = filter.TCPAddr().String()
	}
	return exchange(t, addr, transport, m)
}

func exchange(t *testing.T, addr, transport string, msg *dns.Msg) *dns.Msg {
	t.Helper()
	client := &dns.Client{Net: transport, Timeout: 2 * time.Second}
	resp, _, err := client.Exchange(msg, addr)
	if err != nil {
		t.Fatalf("%s exchange: %v", transport, err)
	}
	return resp
}

func firstA(msg *dns.Msg) net.IP {
	for _, rr := range msg.Answer {
		if a, ok := rr.(*dns.A); ok {
			return a.A
		}
	}
	return nil
}
