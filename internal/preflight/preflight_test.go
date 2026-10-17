package preflight

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// fakeDNS serves A, AAAA and CAA records from a map keyed by "type name".
func fakeDNS(t *testing.T, records map[string][]dns.RR) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		m.Answer = records[dns.TypeToString[q.Qtype]+" "+strings.ToLower(q.Name)]
		_ = w.WriteMsg(m)
	})}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })
	return pc.LocalAddr().String()
}

func rr(t *testing.T, s string) dns.RR {
	r, err := dns.NewRR(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func options(t *testing.T, server string, dialErr map[string]error) Options {
	return Options{
		CAIdentities: []string{"letsencrypt.org"},
		DNSServer:    server,
		Resolver: &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "udp", server)
		}},
		LocalAddrs: func() ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("203.0.113.10"), netip.MustParseAddr("2001:db8::10")}, nil
		},
		Dial: func(_ context.Context, _, addr string) (net.Conn, error) {
			if err := dialErr[addr]; err != nil {
				return nil, err
			}
			c1, c2 := net.Pipe()
			c2.Close()
			return c1, nil
		},
	}
}

func find(checks []Check, name string) []Check {
	var out []Check
	for _, c := range checks {
		if c.Name == name {
			out = append(out, c)
		}
	}
	return out
}

func TestDomainChecks(t *testing.T) {
	server := fakeDNS(t, map[string][]dns.RR{
		"A ok.example.com.":       {rr(t, "ok.example.com. 60 IN A 203.0.113.10")},
		"AAAA ok.example.com.":    {rr(t, "ok.example.com. 60 IN AAAA 2001:db8::10")},
		"CAA example.com.":        {rr(t, `example.com. 60 IN CAA 0 issue "letsencrypt.org"`)},
		"A internal.example.org.": {rr(t, "internal.example.org. 60 IN A 10.0.0.5")},
		"CAA example.org.":        {rr(t, `example.org. 60 IN CAA 0 issue "digicert.com"`)},
		"A other.example.net.":    {rr(t, "other.example.net. 60 IN A 198.51.100.7")},
		"CAA wild.example.net.":   {rr(t, `wild.example.net. 60 IN CAA 0 issuewild ";"`), rr(t, `wild.example.net. 60 IN CAA 0 issue "letsencrypt.org"`)},
	})

	// IPv6 port 80 broken: the classic Let's Encrypt failure.
	checks := Domain(context.Background(), "ok.example.com", options(t, server, map[string]error{
		"[2001:db8::10]:80": errors.New("connection refused"),
	}))
	if Worst(checks) != Fail {
		t.Errorf("checks = %+v", checks)
	}
	if c := find(checks, "port 80 (AAAA)"); len(c) != 1 || c[0].Severity != Fail || !strings.Contains(c[0].Detail, "prefers IPv6") {
		t.Errorf("AAAA port check = %+v", c)
	}
	if c := find(checks, "port 80 (A)"); len(c) != 1 || c[0].Severity != OK {
		t.Errorf("A port check = %+v", c)
	}
	if c := find(checks, "CAA"); c[0].Severity != OK || !strings.Contains(c[0].Detail, "CAA at example.com allows letsencrypt.org") {
		t.Errorf("CAA = %+v", c)
	}

	// Private address and a CAA record for another CA.
	checks = Domain(context.Background(), "internal.example.org", options(t, server, nil))
	if c := find(checks, "A"); c[0].Severity != Warn || !strings.Contains(c[0].Detail, "private address") {
		t.Errorf("A = %+v", c)
	}
	if c := find(checks, "CAA"); c[0].Severity != Fail || !strings.Contains(c[0].Detail, "digicert.com") {
		t.Errorf("CAA = %+v", c)
	}

	// Foreign address warns; missing name fails.
	checks = Domain(context.Background(), "other.example.net", options(t, server, nil))
	if c := find(checks, "A"); c[0].Severity != Warn || !strings.Contains(c[0].Detail, "not an address of this server") {
		t.Errorf("A = %+v", c)
	}
	checks = Domain(context.Background(), "missing.example.net", options(t, server, nil))
	if c := find(checks, "dns"); len(c) != 1 || c[0].Severity != Fail {
		t.Errorf("dns = %+v", checks)
	}

	// issuewild ";" forbids wildcards even though issue allows the CA.
	checks = Domain(context.Background(), "*.wild.example.net", options(t, server, nil))
	if c := find(checks, "CAA"); c[0].Severity != Fail {
		t.Errorf("wildcard CAA = %+v", c)
	}
	checks = Domain(context.Background(), "www.wild.example.net", options(t, server, nil))
	if c := find(checks, "CAA"); c[0].Severity != OK {
		t.Errorf("non-wildcard CAA = %+v", c)
	}
}

func TestSyntax(t *testing.T) {
	for _, ok := range []string{"example.com", "*.example.com", "a-b.example.co.uk", "xn--d1acufc.xn--p1ai"} {
		if err := Syntax(ok); err != nil {
			t.Errorf("Syntax(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{"localhost", "1.2.3.4", "-a.example.com", "a..example.com", "ex ample.com", strings.Repeat("a", 64) + ".com"} {
		if Syntax(bad) == nil {
			t.Errorf("Syntax(%q) accepted", bad)
		}
	}
}
