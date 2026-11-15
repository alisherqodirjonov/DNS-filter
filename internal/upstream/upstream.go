// Package upstream forwards DNS queries and retries truncated UDP answers over TCP.
package upstream

import (
	"context"
	"fmt"
	"time"

	"github.com/miekg/dns"
)

// Client is a single configured resolver.
type Client struct {
	Addr    string
	Timeout time.Duration
}

// Exchange sends msg to the upstream resolver.
// A UDP response with TC=1 is retried over TCP. The original message is not modified.
func (c *Client) Exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, time.Duration, error) {
	if msg == nil {
		return nil, 0, fmt.Errorf("upstream: empty message")
	}
	if c.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.Timeout)
		defer cancel()
	}
	udp := &dns.Client{Net: "udp", Timeout: c.Timeout}
	resp, rtt, err := udp.ExchangeContext(ctx, msg.Copy(), c.Addr)
	if err != nil {
		return nil, rtt, err
	}
	if resp != nil && resp.Truncated {
		tcp := &dns.Client{Net: "tcp", Timeout: c.Timeout}
		tcpResp, tcpRTT, err := tcp.ExchangeContext(ctx, msg.Copy(), c.Addr)
		if err != nil {
			return nil, rtt + tcpRTT, err
		}
		return tcpResp, rtt + tcpRTT, nil
	}
	return resp, rtt, nil
}
