package acme

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/providers/dns/digitalocean"
	"github.com/go-acme/lego/v4/providers/dns/exec"
	"github.com/go-acme/lego/v4/providers/dns/hetzner"
	"github.com/go-acme/lego/v4/providers/dns/rfc2136"
)

// DNS providers for DNS-01. Credentials come from the provider's own
// environment variables (e.g. CLOUDFLARE_DNS_API_TOKEN), typically set in
// /etc/certx/env.
var dnsProviders = map[string]struct {
	env string
	new func() (challenge.Provider, error)
}{
	"cloudflare":   {"CLOUDFLARE_DNS_API_TOKEN (or CLOUDFLARE_EMAIL + CLOUDFLARE_API_KEY)", func() (challenge.Provider, error) { return cloudflare.NewDNSProvider() }},
	"digitalocean": {"DO_AUTH_TOKEN", func() (challenge.Provider, error) { return digitalocean.NewDNSProvider() }},
	"hetzner":      {"HETZNER_API_KEY", func() (challenge.Provider, error) { return hetzner.NewDNSProvider() }},
	"rfc2136":      {"RFC2136_NAMESERVER, RFC2136_TSIG_KEY, RFC2136_TSIG_SECRET (BIND, PowerDNS, Knot)", func() (challenge.Provider, error) { return rfc2136.NewDNSProvider() }},
	"exec":         {"EXEC_PATH: a script called as `script present|cleanup <fqdn> <value>`", func() (challenge.Provider, error) { return exec.NewDNSProvider() }},
}

// DNSProviders lists supported providers and their credential variables.
func DNSProviders() []string {
	var out []string
	for name, p := range dnsProviders {
		out = append(out, name+": "+p.env)
	}
	sort.Strings(out)
	return out
}

// ValidDNSProvider reports whether name is supported.
func ValidDNSProvider(name string) error {
	if _, ok := dnsProviders[name]; !ok {
		return fmt.Errorf("unknown DNS provider %q; supported:\n  %s", name, strings.Join(DNSProviders(), "\n  "))
	}
	return nil
}

// CheckDNSProvider verifies that the provider's credentials are present.
func CheckDNSProvider(name string) error {
	_, _, err := dnsProvider(name)
	return err
}

func dnsProvider(name string) (challenge.Provider, []dns01.ChallengeOption, error) {
	p, ok := dnsProviders[name]
	if !ok {
		return nil, nil, ValidDNSProvider(name)
	}
	provider, err := p.new()
	if err != nil {
		return nil, nil, fmt.Errorf("DNS provider %s: %w (needs %s)", name, err, p.env)
	}
	var opts []dns01.ChallengeOption
	// CERTX_DNS_RESOLVERS: resolvers used to check propagation (host:port,…).
	if r := os.Getenv("CERTX_DNS_RESOLVERS"); r != "" {
		opts = append(opts, dns01.AddRecursiveNameservers(strings.Split(r, ",")))
	}
	// CERTX_DNS_PROPAGATION_WAIT: wait a fixed time instead of querying the
	// authoritative servers (for split-horizon or test setups).
	if w := os.Getenv("CERTX_DNS_PROPAGATION_WAIT"); w != "" {
		d, err := time.ParseDuration(w)
		if err != nil {
			return nil, nil, fmt.Errorf("CERTX_DNS_PROPAGATION_WAIT: %w", err)
		}
		opts = append(opts, dns01.PropagationWait(d, true))
	}
	return provider, opts, nil
}
