package upstream_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"

	"dnsfilter/internal/dnstest"
	"dnsfilter/internal/upstream"
)

func TestExchangeReturnsUpstreamAnswer(t *testing.T) {
	fake := start(t)
	client := &upstream.Client{Addr: fake.Addr, Timeout: time.Second}
	resp, _, err := client.Exchange(context.Background(), question("example.com."))
	if err != nil {
		t.Fatal(err)
	}
	if fake.UDPHits.Load() != 1 || fake.TCPHits.Load() != 0 {
		t.Fatalf("hits udp=%d tcp=%d", fake.UDPHits.Load(), fake.TCPHits.Load())
	}
	if ip := answerIP(resp); ip == nil || !ip.Equal(net.ParseIP("192.0.2.50")) {
		t.Fatalf("answer = %v", resp.Answer)
	}
}

func TestTruncatedUDPIsRetriedOverTCP(t *testing.T) {
	fake := start(t)
	fake.SetTruncateUDP(true)
	client := &upstream.Client{Addr: fake.Addr, Timeout: time.Second}
	msg := question("example.com.")
	resp, _, err := client.Exchange(context.Background(), msg)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Id == 0 {
		t.Fatal("test question lost its id")
	}
	if fake.UDPHits.Load() != 1 || fake.TCPHits.Load() != 1 {
		t.Fatalf("hits udp=%d tcp=%d", fake.UDPHits.Load(), fake.TCPHits.Load())
	}
	if resp.Truncated {
		t.Fatal("client was given the truncated UDP response")
	}
	if ip := answerIP(resp); ip == nil || !ip.Equal(net.ParseIP("192.0.2.50")) {
		t.Fatalf("tcp answer = %v", resp.Answer)
	}
}

func TestTimeout(t *testing.T) {
	fake := start(t)
	fake.SetDelay(400 * time.Millisecond)
	client := &upstream.Client{Addr: fake.Addr, Timeout: 80 * time.Millisecond}
	start := time.Now()
	_, _, err := client.Exchange(context.Background(), question("example.com."))
	if err == nil {
		t.Fatal("expected timeout")
	}
	if time.Since(start) > time.Second {
		t.Fatalf("timeout took %s", time.Since(start))
	}
}

func start(t *testing.T) *dnstest.Upstream {
	t.Helper()
	fake, err := dnstest.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fake.Close() })
	return fake
}

func question(name string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeA)
	m.RecursionDesired = true
	return m
}

func answerIP(msg *dns.Msg) net.IP {
	if msg == nil {
		return nil
	}
	for _, rr := range msg.Answer {
		if a, ok := rr.(*dns.A); ok {
			return a.A
		}
	}
	return nil
}
