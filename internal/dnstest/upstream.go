// Package dnstest provides a local DNS resolver for integration tests.
package dnstest

import (
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// Upstream is a fake resolver bound to one loopback port for UDP and TCP.
type Upstream struct {
	Addr    string
	UDPHits atomic.Int32
	TCPHits atomic.Int32
	Answer  net.IP

	delay    atomic.Int64
	truncate atomic.Bool
	udp      *dns.Server
	tcp      *dns.Server
}

// SetDelay makes every response wait. It is safe to call while the server is running.
func (u *Upstream) SetDelay(d time.Duration) { u.delay.Store(int64(d)) }

// SetTruncateUDP makes UDP responses carry TC=1 and no answer.
func (u *Upstream) SetTruncateUDP(v bool) { u.truncate.Store(v) }

// Start listens on 127.0.0.1 and answers A queries.
func Start() (*Upstream, error) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	port := conn.LocalAddr().(*net.UDPAddr).Port
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		conn.Close()
		return nil, err
	}
	u := &Upstream{Addr: fmt.Sprintf("127.0.0.1:%d", port), Answer: net.ParseIP("192.0.2.50")}
	handler := dns.HandlerFunc(u.serve)
	u.udp = &dns.Server{PacketConn: conn, Handler: handler}
	u.tcp = &dns.Server{Listener: ln, Handler: handler}
	go func() { _ = u.udp.ActivateAndServe() }()
	go func() { _ = u.tcp.ActivateAndServe() }()
	return u, nil
}

// Close stops both listeners.
func (u *Upstream) Close() error {
	var err error
	if u.udp != nil {
		err = u.udp.Shutdown()
	}
	if u.tcp != nil {
		if e := u.tcp.Shutdown(); err == nil {
			err = e
		}
	}
	return err
}

func (u *Upstream) serve(w dns.ResponseWriter, req *dns.Msg) {
	tcp := strings.HasPrefix(w.RemoteAddr().Network(), "tcp")
	if tcp {
		u.TCPHits.Add(1)
	} else {
		u.UDPHits.Add(1)
	}
	if delay := time.Duration(u.delay.Load()); delay > 0 {
		time.Sleep(delay)
	}
	resp := new(dns.Msg)
	if req != nil {
		resp.SetReply(req)
	}
	if !tcp && u.truncate.Load() {
		resp.Truncated = true
		_ = w.WriteMsg(resp)
		return
	}
	if req != nil && len(req.Question) == 1 {
		resp.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{
				Name:   req.Question[0].Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    60,
			},
			A: u.Answer,
		}}
	}
	_ = w.WriteMsg(resp)
}
