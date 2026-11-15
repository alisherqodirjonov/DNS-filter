package policy

import (
	"strings"
	"sync"
	"testing"
)

func TestNormalize(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "EXAMPLE.COM.", want: "example.com"},
		{in: "Example.Com", want: "example.com"},
		{in: "bücher.test", want: "xn--bcher-kva.test"},
		{in: "xn--bcher-kva.test", want: "xn--bcher-kva.test"},
		{in: "_dmarc.example.test", want: "_dmarc.example.test"},
		{in: "  malware-demo.test.  ", want: "malware-demo.test"},
		{in: "", wantErr: true},
		{in: ".", wantErr: true},
		{in: "example..test", wantErr: true},
		{in: "*.example.test", wantErr: true},
		{in: "-bad.test", wantErr: true},
		{in: "not a domain", wantErr: true},
		{in: "192.0.2.10", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := Normalize(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Normalize(%q) = %q, want error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("Normalize(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func mustSnapshot(t *testing.T, rules []Rule, feeds []FeedRule) *Snapshot {
	t.Helper()
	snap, err := NewSnapshot(rules, feeds)
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

func TestExactAndSuffixMatching(t *testing.T) {
	snap := mustSnapshot(t, []Rule{
		{ID: 1, Domain: "Example.TEST.", Kind: KindDeny, Match: MatchExact},
		{ID: 2, Domain: "example.test", Kind: KindDeny, Match: MatchSuffix},
	}, nil)

	exact := snap.Decide("example.test")
	if exact.Action != ActionBlocked || exact.MatchedSource != SourceManual || exact.MatchedDomain != "example.test" {
		t.Fatalf("exact = %+v", exact)
	}
	if other := snap.Decide("www.example.test"); other.MatchedDomain != "example.test" || other.Action != ActionBlocked {
		t.Fatalf("suffix child = %+v", other)
	}
	// The exact rule is preferred when both match the same name.
	if exact.Forward {
		t.Fatal("exact deny forwarded")
	}

	child := snap.Decide("a.example.test")
	if child.Action != ActionBlocked || child.MatchedDomain != "example.test" {
		t.Fatalf("a.example.test = %+v", child)
	}
	boundary := snap.Decide("notexample.test")
	if boundary.Action != ActionAllowed || !boundary.Forward || boundary.MatchedSource != "" {
		t.Fatalf("notexample.test = %+v", boundary)
	}
}

func TestAllowOverridesDenyAndFeed(t *testing.T) {
	snap := mustSnapshot(t, []Rule{
		{ID: 7, Domain: "malware-demo.test", Kind: KindAllow, Match: MatchExact},
		{ID: 8, Domain: "malware-demo.test", Kind: KindDeny, Match: MatchSuffix},
	}, []FeedRule{
		{Name: "demo-local", Domain: "malware-demo.test"},
		{Name: "other", Domain: "phishing-demo.test"},
	})

	allowed := snap.Decide("malware-demo.test")
	if allowed.Action != ActionAllowed || !allowed.Forward || allowed.MatchedSource != SourceManual || allowed.MatchedDomain != "malware-demo.test" {
		t.Fatalf("allow override = %+v", allowed)
	}
	blocked := snap.Decide("phishing-demo.test")
	if blocked.Action != ActionBlocked || blocked.Forward || blocked.MatchedSource != "other" || blocked.MatchedDomain != "phishing-demo.test" {
		t.Fatalf("feed block = %+v", blocked)
	}
	plain := snap.Decide("example.com")
	if plain.Action != ActionAllowed || !plain.Forward || plain.MatchedSource != "" {
		t.Fatalf("forward = %+v", plain)
	}
}

func TestManualDenyPrecedesFeedAndLongestSuffixWins(t *testing.T) {
	snap := mustSnapshot(t, []Rule{
		{ID: 3, Domain: "a.example.test", Kind: KindDeny, Match: MatchExact},
	}, []FeedRule{
		{Name: "broad", Domain: "example.test"},
		{Name: "specific", Domain: "a.example.test"},
	})
	got := snap.Decide("a.example.test")
	if got.MatchedSource != SourceManual || got.MatchedDomain != "a.example.test" {
		t.Fatalf("manual precedence = %+v", got)
	}
	child := snap.Decide("b.a.example.test")
	if child.MatchedSource != "specific" || child.MatchedDomain != "a.example.test" {
		t.Fatalf("longest feed suffix = %+v", child)
	}
}

func TestEngineReplaceIsVisibleWithoutRestart(t *testing.T) {
	engine := NewEngine()
	if d := engine.Decide("malware-demo.test"); d.Action != ActionAllowed {
		t.Fatalf("empty engine = %+v", d)
	}
	engine.Replace(mustSnapshot(t, nil, []FeedRule{{Name: "demo-local", Domain: "malware-demo.test"}}))
	if d := engine.Decide("Malware-Demo.TEST."); d.Action != ActionBlocked || d.MatchedSource != "demo-local" {
		t.Fatalf("after replace = %+v", d)
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 100; n++ {
				engine.Decide("a.malware-demo.test")
				if n%10 == 0 {
					engine.Replace(mustSnapshot(t, nil, []FeedRule{{Name: "demo-local", Domain: "malware-demo.test"}}))
				}
			}
		}()
	}
	wg.Wait()
}

func TestInvalidNameIsNotBlocked(t *testing.T) {
	snap := mustSnapshot(t, nil, []FeedRule{{Name: "demo", Domain: "example.test"}})
	got := snap.Decide("*.example.test")
	if !got.Invalid || got.Action != ActionError || got.Forward {
		t.Fatalf("invalid = %+v", got)
	}
	if strings.Contains(got.MatchedSource, "demo") {
		t.Fatal("invalid name matched a feed")
	}
}
