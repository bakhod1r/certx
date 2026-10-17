package tui

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/bakhod1r/certx/internal/certificate"
	"github.com/bakhod1r/certx/internal/discovery"
)

func (m model) View() string {
	if m.width == 0 {
		return ""
	}
	switch m.view {
	case viewDetail:
		h := m.inv.Hosts[m.detailIdx]
		return m.pager(firstName(h), "esc back · ↑/↓ scroll · n/p next/prev · t live TLS check")
	case viewText:
		return m.pager(m.textTitle, "esc back · ↑/↓ scroll")
	}
	return m.listView()
}

func (m model) pager(title, keys string) string {
	head := titleStyle.Render("CertX") + mutedStyle.Render(" › ") + lipgloss.NewStyle().Bold(true).Render(title)
	pct := mutedStyle.Render(fmt.Sprintf("%3.0f%%", m.vp.ScrollPercent()*100))
	return lipgloss.JoinVertical(lipgloss.Left,
		head,
		mutedStyle.Render(strings.Repeat("─", m.width)),
		m.vp.View(),
		mutedStyle.Render(strings.Repeat("─", m.width)),
		mutedStyle.Render(keys)+"  "+pct,
	)
}

func (m model) listView() string {
	var b strings.Builder
	b.WriteString(m.header() + "\n")
	b.WriteString(m.summary() + "\n")
	b.WriteString(m.tabsLine() + "\n")

	if m.inv == nil {
		body := m.spin.View() + " " + m.busy
		b.WriteString(lipgloss.Place(m.width, m.listHeight()+1, lipgloss.Center, lipgloss.Center, body))
		b.WriteString("\n" + m.footer())
		return b.String()
	}

	cols := m.columns()
	b.WriteString(headerStyle.Render(m.row(cols, "", "SERVER", "STATUS", "DAYS", "PORTS", "DOMAINS", "CONFIG")) + "\n")

	h := m.listHeight()
	if len(m.rows) == 0 {
		msg := "No virtual hosts found."
		if m.filter.Value() != "" || m.tab != 0 {
			msg = "No virtual hosts match the current filter."
		}
		b.WriteString(lipgloss.Place(m.width, h, lipgloss.Center, lipgloss.Center, mutedStyle.Render(msg)))
	} else {
		end := min(len(m.rows), m.offset+h)
		for i := m.offset; i < end; i++ {
			b.WriteString(m.hostRow(cols, i) + "\n")
		}
		b.WriteString(strings.Repeat("\n", h-(end-m.offset)))
	}
	b.WriteString(m.footer())
	return b.String()
}

func (m model) header() string {
	left := titleStyle.Render("CertX") + mutedStyle.Render("  certificate inventory")
	var badges []string
	if m.inv != nil {
		for _, s := range m.inv.Servers {
			label := string(s.Kind)
			if !s.Found {
				badges = append(badges, mutedStyle.Render(label+" —"))
				continue
			}
			if s.Version != "" {
				label += " " + s.Version
			}
			if s.Binary == "" {
				label += " (config only)"
			}
			badges = append(badges, okStyle.Render("● ")+label)
		}
	}
	right := strings.Join(badges, "   ")
	gap := max(1, m.width-lipgloss.Width(left)-lipgloss.Width(right))
	return left + strings.Repeat(" ", gap) + right
}

func (m model) summary() string {
	if m.inv == nil {
		return mutedStyle.Render("…")
	}
	counts := map[discovery.Status]int{}
	for _, h := range m.inv.Hosts {
		counts[h.Status]++
	}
	parts := []string{fmt.Sprintf("%d hosts", len(m.inv.Hosts))}
	for _, s := range []discovery.Status{
		discovery.StatusOK, discovery.StatusExpiring, discovery.StatusExpired, discovery.StatusMismatch,
		discovery.StatusKeyMismatch, discovery.StatusBadChain, discovery.StatusSelfSigned,
		discovery.StatusNotYetValid, discovery.StatusError, discovery.StatusNoTLS,
	} {
		if counts[s] > 0 {
			parts = append(parts, statusStyle(s).Render(fmt.Sprintf("%d %s", counts[s], strings.ToLower(string(s)))))
		}
	}
	if n := len(m.inv.Warnings); n > 0 {
		parts = append(parts, warnStyle.Render(fmt.Sprintf("%d warnings (w)", n)))
	}
	return strings.Join(parts, mutedStyle.Render(" · "))
}

func (m model) tabsLine() string {
	var parts []string
	for i, t := range tabs {
		if i == m.tab {
			parts = append(parts, tabActive.Render(t))
		} else {
			parts = append(parts, tabInactive.Render(t))
		}
	}
	line := strings.Join(parts, " ") + mutedStyle.Render("   sort: "+sortNames[m.sortBy])
	if m.filtering {
		line += "   " + m.filter.View()
	} else if v := m.filter.Value(); v != "" {
		line += mutedStyle.Render("   filter: ") + v
	}
	return line
}

func (m model) footer() string {
	if m.busy != "" && m.inv != nil {
		return m.spin.View() + " " + m.busy
	}
	if m.help {
		return mutedStyle.Render("↑/↓ j/k move · pgup/pgdn page · g/G top/bottom · enter details · tab/shift+tab server\n" +
			"/ filter · esc clear · s sort · r rescan · v nginx -t / apachectl -t · e export JSON · w warnings · q quit")
	}
	if m.flash != "" {
		return m.flash
	}
	pos := ""
	if len(m.rows) > 0 {
		pos = fmt.Sprintf("%d/%d  ", m.cursor+1, len(m.rows))
	}
	return mutedStyle.Render(pos + "enter details · tab server · / filter · s sort · r rescan · v validate · e export · ? help · q quit")
}

type columns struct{ server, status, days, ports, domains, config int }

func (m model) columns() columns {
	c := columns{server: 7, status: 15, days: 6, ports: 9}
	rest := m.width - 2 - c.server - c.status - c.days - c.ports - 6
	c.domains = max(12, rest*55/100)
	c.config = max(8, rest-c.domains)
	return c
}

func (m model) row(c columns, mark, server, status, days, ports, domains, config string) string {
	return cell(mark, 2) + cell(server, c.server) + " " + cell(status, c.status) + " " + rcell(days, c.days) + " " +
		cell(ports, c.ports) + " " + cell(domains, c.domains) + " " + cell(config, c.config)
}

func (m model) hostRow(c columns, i int) string {
	h := m.inv.Hosts[m.rows[i]]
	days := "-"
	if h.Cert != nil {
		days = strconv.Itoa(h.Cert.DaysLeft)
	}
	names := strings.Join(h.Names, " ")
	if names == "" {
		names = "(no server_name)"
	}
	cfg := h.Location()
	if !h.Enabled {
		cfg = "[disabled] " + cfg
	}
	if i == m.cursor {
		return selStyle.Render(m.row(c, "▸", string(h.Server), statusLabel(h.Status), days, h.Ports(), names, cfg))
	}
	row := cell("", 2) + cell(string(h.Server), c.server) + " " +
		statusStyle(h.Status).Render(cell(statusLabel(h.Status), c.status)) + " " +
		rcell(days, c.days) + " " + cell(h.Ports(), c.ports) + " " + cell(names, c.domains) + " " +
		mutedStyle.Render(cell(cfg, c.config))
	if !h.Enabled {
		return mutedStyle.Render(row)
	}
	return row
}

// ---------------------------------------------------------------- detail

func kv(label, value string) string {
	return labelStyle.Render(label) + value + "\n"
}

func (m model) detail(idx int) string {
	h := m.inv.Hosts[idx]
	var b strings.Builder

	b.WriteString(statusStyle(h.Status).Bold(true).Render(statusLabel(h.Status)) + "\n\n")
	b.WriteString(kv("Names", orDash(strings.Join(h.Names, ", "))))
	state := "enabled"
	if !h.Enabled {
		state = "disabled (not included by main config)"
	}
	b.WriteString(kv("Server", fmt.Sprintf("%s · %s", h.Server, state)))
	b.WriteString(kv("Config", h.Location()))
	var listens []string
	for _, l := range h.Listen {
		s := strconv.Itoa(l.Port)
		if l.Addr != "" {
			s = l.Addr + ":" + s
		}
		if l.TLS {
			s += " (tls)"
		}
		listens = append(listens, s)
	}
	b.WriteString(kv("Listen", strings.Join(listens, ", ")))
	b.WriteString(kv("Webroot", orDash(h.Webroot)))
	b.WriteString(kv("Redirect", yesNo(h.RedirectsToHTTPS, "→ https", "no")))
	b.WriteString(kv("Managed by", orDash(h.ManagedBy)))

	if h.CertFile != "" {
		b.WriteString(sectionStyle.Render("Certificate") + "\n")
		b.WriteString(kv("File", h.CertFile))
		key := orDash(h.KeyFile)
		if c := h.Cert; c != nil {
			switch {
			case c.KeyError != "":
				key += errStyle.Render("  ✖ " + c.KeyError)
			case c.KeyMatch != nil && *c.KeyMatch:
				key += okStyle.Render("  ✔ matches")
			case c.KeyMatch != nil:
				key += errStyle.Render("  ✖ does not match")
			}
		}
		b.WriteString(kv("Key", key))
		if h.ChainFile != "" {
			b.WriteString(kv("Chain file", h.ChainFile))
		}
		if h.Cert != nil {
			b.WriteString(certBlock(h.Cert))
		}
	}

	b.WriteString(sectionStyle.Render("Issues") + "\n")
	if len(h.Issues) == 0 {
		b.WriteString(okStyle.Render("  none") + "\n")
	}
	for _, is := range h.Issues {
		b.WriteString("  • " + is + "\n")
	}

	b.WriteString(sectionStyle.Render("Live TLS endpoint") + "\n")
	switch r, ok := m.remote[idx]; {
	case m.probing[idx]:
		b.WriteString(mutedStyle.Render("  connecting…") + "\n")
	case !ok:
		b.WriteString(mutedStyle.Render("  press t to fetch the certificate served by "+orDash(discovery.ProbeName(h))) + "\n")
	case r.err != nil:
		b.WriteString(errStyle.Render("  ✖ "+r.err.Error()) + "\n")
	default:
		b.WriteString(kv("Endpoint", r.info.Source+" · "+r.info.TLSVersion))
		b.WriteString(certBlock(r.info))
		if h.Cert != nil {
			if h.Cert.FingerprintSHA256 == r.info.FingerprintSHA256 {
				b.WriteString(okStyle.Render("✔ served certificate matches the local file") + "\n")
			} else {
				b.WriteString(warnStyle.Render("⚠ served certificate differs from the local file (reload pending or another server answers)") + "\n")
			}
		}
	}
	return lipgloss.NewStyle().Padding(0, 1).Width(max(20, m.width)).Render(b.String())
}

func certBlock(c *certificate.Info) string {
	var b strings.Builder
	b.WriteString(kv("Subject", c.Subject))
	b.WriteString(kv("Issuer", c.Issuer))
	b.WriteString(kv("SANs", orDash(strings.Join(c.DNSNames, ", "))))
	days := fmt.Sprintf("%d days left", c.DaysLeft)
	switch {
	case c.DaysLeft < 0:
		days = errStyle.Render(fmt.Sprintf("expired %d days ago", -c.DaysLeft))
	case c.DaysLeft <= 30:
		days = warnStyle.Render(days)
	default:
		days = okStyle.Render(days)
	}
	b.WriteString(kv("Valid", c.NotBefore.Format(time.DateOnly)+" → "+c.NotAfter.Format(time.DateOnly)+"  "+days))
	b.WriteString(kv("Serial", c.Serial))
	b.WriteString(kv("SHA-256", c.FingerprintSHA256))
	chain := fmt.Sprintf("%d certificate(s)", c.ChainLength)
	switch {
	case c.SelfSigned:
		chain += warnStyle.Render("  ◐ self-signed")
	case c.ChainError != "":
		chain += errStyle.Render("  ✖ " + c.ChainError)
	default:
		chain += okStyle.Render("  ✔ trusted")
	}
	b.WriteString(kv("Chain", chain))
	return b.String()
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func yesNo(v bool, yes, no string) string {
	if v {
		return yes
	}
	return no
}
