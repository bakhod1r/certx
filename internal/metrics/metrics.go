// Package metrics renders the inventory in the Prometheus text exposition
// format, for `certx metrics` or the node_exporter textfile collector.
package metrics

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bakhod1r/certx/internal/acme"
	"github.com/bakhod1r/certx/internal/certificate"
	"github.com/bakhod1r/certx/internal/discovery"
	"github.com/bakhod1r/certx/internal/state"
)

// Write renders metrics for inv, the CertX store and the last renew run.
func Write(w io.Writer, inv *discovery.Inventory, storage string, last *state.Run, now time.Time) error {
	m := &writer{w: w}

	m.help("certx_host_certificate_expiry_timestamp_seconds", "gauge", "NotAfter of the certificate configured for a virtual host.")
	for _, h := range inv.Hosts {
		if h.Cert == nil || !h.Enabled {
			continue
		}
		m.sample("certx_host_certificate_expiry_timestamp_seconds", hostLabels(h), float64(h.Cert.NotAfter.Unix()))
	}
	m.help("certx_host_status", "gauge", "1 for the current audit status of each virtual host.")
	for _, h := range inv.Hosts {
		if !h.Enabled {
			continue
		}
		l := hostLabels(h)
		l = append(l, "status", string(h.Status))
		m.sample("certx_host_status", l, 1)
	}
	m.help("certx_host_status_critical", "gauge", "1 when the virtual host has a critical certificate problem.")
	for _, h := range inv.Hosts {
		if h.Enabled {
			m.sample("certx_host_status_critical", hostLabels(h), b2f(h.Status.Critical()))
		}
	}

	m.help("certx_managed_certificate_expiry_timestamp_seconds", "gauge", "NotAfter of certificates stored by CertX.")
	names, _ := acme.List(storage)
	sort.Strings(names)
	for _, n := range names {
		p := acme.Paths(storage, n)
		info, err := certificate.Inspect(p.Cert, "", now)
		if err != nil {
			continue
		}
		m.sample("certx_managed_certificate_expiry_timestamp_seconds", []string{"name", n}, float64(info.NotAfter.Unix()))
	}

	m.help("certx_scan_warnings", "gauge", "Configuration parser warnings in the last scan.")
	m.sample("certx_scan_warnings", nil, float64(len(inv.Warnings)))

	if last != nil {
		m.help("certx_last_renew_timestamp_seconds", "gauge", "Time the last `certx renew` finished.")
		m.sample("certx_last_renew_timestamp_seconds", nil, float64(last.Finished.Unix()))
		m.help("certx_last_renew_success", "gauge", "1 when the last `certx renew` had no failures.")
		m.sample("certx_last_renew_success", nil, b2f(last.OK()))
		m.help("certx_last_renew_certificates", "gauge", "Certificates per outcome in the last `certx renew`.")
		for _, r := range []struct {
			outcome string
			n       int
		}{{"renewed", last.Renewed}, {"skipped", last.Skipped}, {"failed", last.Failed}} {
			m.sample("certx_last_renew_certificates", []string{"outcome", r.outcome}, float64(r.n))
		}
	}
	return m.err
}

func hostLabels(h discovery.Host) []string {
	return []string{
		"server", string(h.Server), "name", firstName(h), "file", h.File, "line", strconv.Itoa(h.Line),
		"managed_by", h.ManagedBy,
	}
}

func firstName(h discovery.Host) string {
	if len(h.Names) == 0 {
		return ""
	}
	return h.Names[0]
}

type writer struct {
	w   io.Writer
	err error
}

func (m *writer) help(name, typ, help string) {
	m.printf("# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
}

func (m *writer) sample(name string, labels []string, v float64) {
	var b strings.Builder
	b.WriteString(name)
	if len(labels) > 0 {
		b.WriteByte('{')
		for i := 0; i < len(labels); i += 2 {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(labels[i] + `="` + escape(labels[i+1]) + `"`)
		}
		b.WriteByte('}')
	}
	m.printf("%s %s\n", b.String(), strconv.FormatFloat(v, 'g', -1, 64))
}

func (m *writer) printf(format string, args ...any) {
	if m.err == nil {
		_, m.err = fmt.Fprintf(m.w, format, args...)
	}
}

func escape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s)
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
