// Package dnsserver accepts DNS queries and applies the filter policy.
package dnsserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"syscall"
	"time"

	"github.com/miekg/dns"

	"dnsfilter/internal/policy"
	"dnsfilter/internal/upstream"
)

// QueryEvent is the record written for one DNS query.
type QueryEvent struct {
	Timestamp         time.Time
	ClientIP          string
	QName             string
	QType             string
	Transport         string
	Action            string
	RCode             string
	UpstreamLatencyMS *int64
	MatchedSource     string
	MatchedDomain     string
}

// Recorder persists a query event. A nil recorder skips logging.
type Recorder func(context.Context, QueryEvent) error

// Live holds the answer settings an operator can change while the filter runs.
type Live struct {
	BlockedRCode    string
	Upstream        string
	UpstreamTimeout time.Duration
}

// Options configures the UDP and TCP listeners. When Settings is set it is read for every
// query and takes the place of Upstream and BlockedRCode.
type Options struct {
	ListenUDP    string
	ListenTCP    string
	Engine       *policy.Engine
	Upstream     *upstream.Client
	BlockedRCode string
	Settings     func() Live
	Record       Recorder
	Logger       *slog.Logger
}

// Server is the DNS data plane.
type Server struct {
	udp *dns.Server
	tcp *dns.Server
}

// listenError adds the usual fix to the two bind failures an operator meets first.
func listenError(proto, addr string, err error) error {
	hint := ""
	switch {
	case errors.Is(err, syscall.EADDRINUSE):
		hint = ". Another program already uses this port: set dns.listen_udp and dns.listen_tcp in config.json to a free one"
	case errors.Is(err, syscall.EACCES):
		hint = ". Ports below 1024 need permission: run make port53 once, or start the filter with sudo"
	}
	return fmt.Errorf("dns %s listen %s: %w%s", proto, addr, err, hint)
}

// Listen binds UDP and TCP. If either bind fails, neither listener is left running.
func Listen(opt Options) (*Server, error) {
	if opt.Engine == nil {
		opt.Engine = policy.NewEngine()
	}
	if opt.Logger == nil {
		opt.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	udpConn, err := net.ListenPacket("udp", opt.ListenUDP)
	if err != nil {
		return nil, listenError("udp", opt.ListenUDP, err)
	}
	tcpLn, err := net.Listen("tcp", opt.ListenTCP)
	if err != nil {
		udpConn.Close()
		return nil, listenError("tcp", opt.ListenTCP, err)
	}
	h := &handler{
		engine:   opt.Engine,
		upstream: opt.Upstream,
		blocked:  rcodeValue(opt.BlockedRCode),
		settings: opt.Settings,
		record:   opt.Record,
		logger:   opt.Logger,
	}
	udpReady := make(chan struct{})
	tcpReady := make(chan struct{})
	errCh := make(chan error, 2)
	srv := &Server{
		udp: &dns.Server{PacketConn: udpConn, Handler: h, NotifyStartedFunc: func() { close(udpReady) }},
		tcp: &dns.Server{Listener: tcpLn, Handler: h, NotifyStartedFunc: func() { close(tcpReady) }},
	}
	go func() {
		if err := srv.udp.ActivateAndServe(); err != nil && !isStopped(err) {
			errCh <- fmt.Errorf("dns udp: %w", err)
		}
	}()
	go func() {
		if err := srv.tcp.ActivateAndServe(); err != nil && !isStopped(err) {
			errCh <- fmt.Errorf("dns tcp: %w", err)
		}
	}()
	if err := waitReady(udpReady, errCh); err != nil {
		_ = srv.Close()
		udpConn.Close()
		tcpLn.Close()
		return nil, err
	}
	if err := waitReady(tcpReady, errCh); err != nil {
		_ = srv.Close()
		return nil, err
	}
	return srv, nil
}

func waitReady(ready <-chan struct{}, errCh <-chan error) error {
	select {
	case <-ready:
		return nil
	case err := <-errCh:
		return err
	case <-time.After(3 * time.Second):
		return fmt.Errorf("dns listener did not start")
	}
}

func isStopped(err error) bool {
	if err == nil {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "closed") || strings.Contains(msg, "timeout") || strings.Contains(msg, "not started")
}

// Close stops both listeners.
func (s *Server) Close() error {
	var err error
	if s.udp != nil {
		err = s.udp.Shutdown()
	}
	if s.tcp != nil {
		if e := s.tcp.Shutdown(); err == nil {
			err = e
		}
	}
	return err
}

// UDPAddr returns the bound UDP address.
func (s *Server) UDPAddr() net.Addr { return s.udp.PacketConn.LocalAddr() }

// TCPAddr returns the bound TCP address.
func (s *Server) TCPAddr() net.Addr { return s.tcp.Listener.Addr() }

type handler struct {
	engine   *policy.Engine
	upstream *upstream.Client
	blocked  int
	settings func() Live
	record   Recorder
	logger   *slog.Logger
}

func (h *handler) current() (*upstream.Client, int) {
	if h.settings == nil {
		return h.upstream, h.blocked
	}
	live := h.settings()
	return &upstream.Client{Addr: live.Upstream, Timeout: live.UpstreamTimeout}, rcodeValue(live.BlockedRCode)
}

func (h *handler) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	defer func() {
		if rec := recover(); rec != nil {
			h.logger.Error("dns handler recovered from panic", "panic", fmt.Sprint(rec))
		}
	}()
	transport := "udp"
	clientIP := ""
	if w.RemoteAddr() != nil {
		if strings.HasPrefix(w.RemoteAddr().Network(), "tcp") {
			transport = "tcp"
		}
		clientIP = hostOnly(w.RemoteAddr().String())
	}
	resp, ev := h.handle(req, transport, clientIP)
	h.store(ev)
	if resp == nil {
		return
	}
	if transport == "udp" {
		resp = fitUDP(req, resp)
	}
	if err := w.WriteMsg(resp); err != nil {
		h.logger.Warn("dns write failed", "client", clientIP, "error", err.Error())
	}
}

func (h *handler) handle(req *dns.Msg, transport, clientIP string) (*dns.Msg, QueryEvent) {
	ev := QueryEvent{
		Timestamp: time.Now().UTC(),
		ClientIP:  clientIP,
		Transport: transport,
		Action:    policy.ActionError,
		RCode:     "FORMERR",
		QType:     "UNKNOWN",
	}
	if req == nil || len(req.Question) != 1 {
		resp := reply(req, dns.RcodeFormatError)
		if req != nil && len(req.Question) > 0 {
			ev.QName = presentation(req.Question[0].Name)
			ev.QType = typeName(req.Question[0].Qtype)
		}
		return resp, ev
	}
	q := req.Question[0]
	ev.QType = typeName(q.Qtype)
	ev.QName = presentation(q.Name)
	if req.Opcode != dns.OpcodeQuery {
		return reply(req, dns.RcodeNotImplemented), withRCode(ev, "NOTIMP")
	}
	name, err := policy.Normalize(q.Name)
	if err != nil {
		return reply(req, dns.RcodeFormatError), ev
	}
	ev.QName = name
	up, blocked := h.current()
	decision := h.engine.Decide(name)
	ev.MatchedSource = decision.MatchedSource
	ev.MatchedDomain = decision.MatchedDomain
	if decision.Invalid || !decision.Forward {
		if decision.Invalid {
			ev.MatchedSource = ""
			ev.MatchedDomain = ""
			return reply(req, dns.RcodeFormatError), ev
		}
		ev.Action = policy.ActionBlocked
		code := dns.RcodeToString[blocked]
		if code == "" {
			code = "REFUSED"
		}
		return reply(req, blocked), withRCode(ev, code)
	}
	if up == nil {
		h.logger.Error("upstream client is not configured", "qname", name)
		ev.Action = policy.ActionError
		return reply(req, dns.RcodeServerFailure), withRCode(ev, "SERVFAIL")
	}
	started := time.Now()
	resp, rtt, err := up.Exchange(context.Background(), req)
	ms := rtt.Milliseconds()
	if ms == 0 {
		ms = time.Since(started).Milliseconds()
	}
	ev.UpstreamLatencyMS = &ms
	if err != nil || resp == nil {
		h.logger.Warn("upstream query failed", "qname", name, "error", errString(err))
		ev.Action = policy.ActionError
		return reply(req, dns.RcodeServerFailure), withRCode(ev, "SERVFAIL")
	}
	ev.Action = policy.ActionAllowed
	code := dns.RcodeToString[resp.Rcode]
	if code == "" {
		code = fmt.Sprintf("RCODE%d", resp.Rcode)
	}
	return resp, withRCode(ev, code)
}

func (h *handler) store(ev QueryEvent) {
	if h.record == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := h.record(ctx, ev); err != nil {
		h.logger.Error("could not store dns event", "qname", ev.QName, "error", err.Error())
	}
}

func reply(req *dns.Msg, rcode int) *dns.Msg {
	m := new(dns.Msg)
	if req != nil {
		m.SetReply(req)
	} else {
		m.Response = true
	}
	m.Rcode = rcode
	m.RecursionAvailable = true
	return m
}

func withRCode(ev QueryEvent, code string) QueryEvent {
	ev.RCode = code
	return ev
}

func fitUDP(req, resp *dns.Msg) *dns.Msg {
	if req == nil || resp == nil {
		return resp
	}
	limit := 512
	if opt := req.IsEdns0(); opt != nil && int(opt.UDPSize()) > limit {
		limit = int(opt.UDPSize())
	}
	packed, err := resp.Pack()
	if err != nil || len(packed) <= limit {
		return resp
	}
	trimmed := resp.Copy()
	trimmed.Truncate(limit)
	return trimmed
}

func rcodeValue(name string) int {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "NXDOMAIN":
		return dns.RcodeNameError
	case "SERVFAIL":
		return dns.RcodeServerFailure
	default:
		return dns.RcodeRefused
	}
}

func typeName(qtype uint16) string {
	if name, ok := dns.TypeToString[qtype]; ok {
		return name
	}
	return fmt.Sprintf("TYPE%d", qtype)
}

func presentation(name string) string {
	name = strings.TrimSpace(name)
	name = strings.TrimSuffix(name, ".")
	return strings.ToLower(name)
}

func hostOnly(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

func errString(err error) string {
	if err == nil {
		return "empty upstream response"
	}
	return err.Error()
}
