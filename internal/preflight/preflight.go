// Package preflight checks a domain before issuance: syntax, A and AAAA
// records (separately), private or foreign addresses, port 80 reachability
// per address family and CAA policy. Passing preflight does not prove
// control of the domain; only the ACME challenge does.
package preflight

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Severity of a check result.
type Severity int

const (
	OK Severity = iota
	Warn
	Fail
)

func (s Severity) String() string { return [...]string{"ok", "warn", "fail"}[s] }

// Check is one preflight finding.
type Check struct {
	Domain   string   `json:"domain"`
	Name     string   `json:"name"`
	Severity Severity `json:"severity"`
	Detail   string   `json:"detail"`
}

// Options configure the checks. Zero values use the system resolver.
type Options struct {
	CAIdentities []string // CAA issuer domains of the CA, e.g. "letsencrypt.org"; empty skips enforcement
	Resolver     *net.Resolver
	DNSServer    string                       // host:port for CAA queries; default from /etc/resolv.conf
	LocalAddrs   func() ([]netip.Addr, error) // addresses of this host
	Dial         func(ctx context.Context, network, addr string) (net.Conn, error)
	SkipPort     bool
}

// CAIdentities returns the CAA identities of well-known ACME directories.
func CAIdentities(directory string) []string {
	if strings.Contains(directory, "letsencrypt.org") {
		return []string{"letsencrypt.org"}
	}
	return nil
}

var labelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// Syntax validates a domain name (a leading "*." is allowed).
func Syntax(name string) error {
	n := strings.TrimPrefix(strings.ToLower(strings.TrimSuffix(name, ".")), "*.")
	if len(n) == 0 || len(n) > 253 {
		return fmt.Errorf("%q: invalid length", name)
	}
	if net.ParseIP(n) != nil {
		return fmt.Errorf("%q: IP addresses cannot be validated over HTTP-01", name)
	}
	labels := strings.Split(n, ".")
	if len(labels) < 2 {
		return fmt.Errorf("%q: not a fully qualified domain name", name)
	}
	for _, l := range labels {
		if !labelRe.MatchString(l) {
			return fmt.Errorf("%q: invalid label %q", name, l)
		}
	}
	return nil
}

// Domain runs every check for name.
func Domain(ctx context.Context, name string, o Options) []Check {
	add := func(out []Check, check string, s Severity, format string, args ...any) []Check {
		return append(out, Check{Domain: name, Name: check, Severity: s, Detail: fmt.Sprintf(format, args...)})
	}
	var out []Check
	if err := Syntax(name); err != nil {
		return add(out, "syntax", Fail, "%v", err)
	}
	wildcard := strings.HasPrefix(name, "*.")
	host := strings.TrimPrefix(name, "*.")

	res := o.Resolver
	if res == nil {
		res = net.DefaultResolver
	}
	var local []netip.Addr
	if o.LocalAddrs != nil {
		local, _ = o.LocalAddrs()
	} else {
		local, _ = localAddrs()
	}

	if !wildcard {
		resolved := 0
		for _, fam := range []struct{ network, label string }{{"ip4", "A"}, {"ip6", "AAAA"}} {
			ips, err := res.LookupNetIP(ctx, fam.network, host)
			if err != nil || len(ips) == 0 {
				out = add(out, fam.label, OK, "no %s record", fam.label)
				continue
			}
			resolved++
			seen := map[netip.Addr]bool{}
			for _, ip := range ips {
				ip = ip.Unmap()
				if seen[ip] {
					continue
				}
				seen[ip] = true
				switch {
				case ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified():
					out = add(out, fam.label, Warn, "%s is a private address: a public CA cannot reach it (internal or split-horizon DNS?)", ip)
				case len(local) > 0 && !slices.Contains(local, ip):
					out = add(out, fam.label, Warn, "%s is not an address of this server (NAT, load balancer or wrong record?)", ip)
				default:
					out = add(out, fam.label, OK, "%s", ip)
				}
				if !o.SkipPort {
					out = append(out, port80(ctx, name, ip, fam.label, o))
				}
			}
		}
		if resolved == 0 {
			out = add(out, "dns", Fail, "%s does not resolve (no A or AAAA record)", host)
		}
	}
	out = append(out, caa(ctx, name, o))
	return out
}

func port80(ctx context.Context, name string, ip netip.Addr, family string, o Options) Check {
	dial := o.Dial
	if dial == nil {
		d := &net.Dialer{Timeout: 3 * time.Second}
		dial = d.DialContext
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	c := Check{Domain: name, Name: "port 80 (" + family + ")"}
	conn, err := dial(ctx, "tcp", netip.AddrPortFrom(ip, 80).String())
	if err != nil {
		c.Severity = Fail
		c.Detail = fmt.Sprintf("cannot connect to %s port 80: %v", ip, err)
		if family == "AAAA" {
			c.Detail += " — Let's Encrypt prefers IPv6: fix or remove the AAAA record, or listen on [::]:80"
		}
		return c
	}
	conn.Close()
	c.Detail = fmt.Sprintf("%s:80 accepts connections", ip)
	return c
}

// caa walks from the name up to the TLD and evaluates the first CAA set
// found (RFC 8659).
func caa(ctx context.Context, name string, o Options) Check {
	c := Check{Domain: name, Name: "CAA"}
	server := o.DNSServer
	if server == "" {
		cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil || len(cfg.Servers) == 0 {
			c.Severity, c.Detail = Warn, "cannot read /etc/resolv.conf for CAA lookup"
			return c
		}
		server = net.JoinHostPort(cfg.Servers[0], cfg.Port)
	}
	wildcard := strings.HasPrefix(name, "*.")
	labels := dns.SplitDomainName(strings.TrimPrefix(name, "*."))
	client := &dns.Client{Timeout: 5 * time.Second}
	for i := 0; i < len(labels); i++ {
		zone := dns.Fqdn(strings.Join(labels[i:], "."))
		m := new(dns.Msg)
		m.SetQuestion(zone, dns.TypeCAA)
		m.RecursionDesired = true
		r, _, err := client.ExchangeContext(ctx, m, server)
		if err != nil {
			c.Severity, c.Detail = Warn, fmt.Sprintf("CAA lookup for %s failed: %v", zone, err)
			return c
		}
		if r.Rcode == dns.RcodeServerFailure {
			// A SERVFAIL makes CAs refuse issuance.
			c.Severity, c.Detail = Fail, fmt.Sprintf("CAA lookup for %s returned SERVFAIL; CAs will refuse to issue", zone)
			return c
		}
		var issue, issuewild []string
		for _, rr := range r.Answer {
			if rec, ok := rr.(*dns.CAA); ok {
				v, _, _ := strings.Cut(rec.Value, ";")
				v = strings.TrimSpace(strings.ToLower(v))
				switch strings.ToLower(rec.Tag) {
				case "issue":
					issue = append(issue, v)
				case "issuewild":
					issuewild = append(issuewild, v)
				}
			}
		}
		if len(issue) == 0 && len(issuewild) == 0 {
			continue
		}
		allowed := issue
		if wildcard && len(issuewild) > 0 {
			allowed = issuewild
		}
		zone = strings.TrimSuffix(zone, ".")
		if len(o.CAIdentities) == 0 {
			c.Severity, c.Detail = Warn, fmt.Sprintf("CAA at %s allows %s; make sure it includes your CA", zone, strings.Join(allowed, ", "))
			return c
		}
		for _, id := range o.CAIdentities {
			if slices.Contains(allowed, id) {
				c.Detail = fmt.Sprintf("CAA at %s allows %s", zone, id)
				return c
			}
		}
		c.Severity = Fail
		c.Detail = fmt.Sprintf("CAA at %s only allows %q; add `0 issue \"%s\"`", zone, strings.Join(allowed, ", "), o.CAIdentities[0])
		return c
	}
	c.Detail = "no CAA records (any CA may issue)"
	return c
}

func localAddrs() ([]netip.Addr, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, a := range addrs {
		if p, err := netip.ParsePrefix(a.String()); err == nil {
			out = append(out, p.Addr().Unmap())
		}
	}
	// Behind 1:1 NAT the public address is not on an interface; allow
	// declaring it explicitly.
	for _, s := range strings.Split(os.Getenv("CERTX_PUBLIC_IPS"), ",") {
		if ip, err := netip.ParseAddr(strings.TrimSpace(s)); err == nil {
			out = append(out, ip)
		}
	}
	return out, nil
}

// Worst returns the highest severity in checks.
func Worst(checks []Check) Severity {
	w := OK
	for _, c := range checks {
		w = max(w, c.Severity)
	}
	return w
}
