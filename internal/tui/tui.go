// Package tui implements the interactive terminal interface of CertX.
package tui

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/bakhod1r/certx/internal/certificate"
	"github.com/bakhod1r/certx/internal/discovery"
	"github.com/bakhod1r/certx/internal/webserver"
)

// Run starts the interactive interface.
func Run(opts discovery.Options) error {
	_, err := tea.NewProgram(newModel(opts), tea.WithAltScreen()).Run()
	return err
}

type view int

const (
	viewList view = iota
	viewDetail
	viewText
)

var (
	tabs      = []string{"All", "Nginx", "Apache"}
	sortNames = []string{"severity", "expiry", "domain", "file"}
)

type (
	scanDoneMsg struct {
		inv *discovery.Inventory
		err error
	}
	validateDoneMsg struct{ out string }
	exportDoneMsg   struct {
		path string
		err  error
	}
	remoteDoneMsg struct {
		idx  int
		info *certificate.Info
		err  error
	}
)

type remoteResult struct {
	name string
	info *certificate.Info
	err  error
}

type model struct {
	opts discovery.Options
	inv  *discovery.Inventory

	rows   []int // indices into inv.Hosts after filtering and sorting
	cursor int
	offset int
	tab    int
	sortBy int

	filter    textinput.Model
	filtering bool

	view      view
	textTitle string
	detailIdx int
	vp        viewport.Model

	spin    spinner.Model
	busy    string
	flash   string
	remote  map[int]remoteResult
	probing map[int]bool

	width, height int
	help          bool
}

func newModel(opts discovery.Options) model {
	ti := textinput.New()
	ti.Prompt = "/ "
	ti.Placeholder = "filter by domain or file"
	ti.CharLimit = 128

	sp := spinner.New()
	sp.Spinner = spinner.Dot
	sp.Style = titleStyle

	return model{
		opts:    opts,
		filter:  ti,
		spin:    sp,
		busy:    "Scanning web server configuration…",
		remote:  map[int]remoteResult{},
		probing: map[int]bool{},
	}
}

func (m model) Init() tea.Cmd {
	return tea.Batch(m.spin.Tick, scanCmd(m.opts))
}

func scanCmd(opts discovery.Options) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		inv, err := discovery.Scan(ctx, opts)
		return scanDoneMsg{inv: inv, err: err}
	}
}

func validateCmd(opts discovery.Options, inv *discovery.Inventory) tea.Cmd {
	return func() tea.Msg {
		return validateDoneMsg{out: discovery.Validate(context.Background(), opts, inv)}
	}
}

func exportCmd(inv *discovery.Inventory) tea.Cmd {
	return func() tea.Msg {
		path := fmt.Sprintf("certx-inventory-%s.json", time.Now().Format("20060102-150405"))
		data, err := json.MarshalIndent(inv, "", "  ")
		if err == nil {
			err = os.WriteFile(path, append(data, '\n'), 0o644)
		}
		return exportDoneMsg{path: path, err: err}
	}
}

func remoteCmd(idx int, h discovery.Host) tea.Cmd {
	name := discovery.ProbeName(h)
	port := 443
	for _, l := range h.Listen {
		if l.TLS {
			port = l.Port
			break
		}
	}
	return func() tea.Msg {
		info, err := certificate.Remote(context.Background(), name, port, name, time.Now())
		return remoteDoneMsg{idx: idx, info: info, err: err}
	}
}

// ---------------------------------------------------------------- update

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.vp.Width = msg.Width
		m.vp.Height = max(1, msg.Height-4)
		m.clamp()
		return m, nil

	case spinner.TickMsg:
		if m.busy == "" {
			return m, nil
		}
		var cmd tea.Cmd
		m.spin, cmd = m.spin.Update(msg)
		return m, cmd

	case scanDoneMsg:
		m.busy = ""
		if msg.err != nil {
			m.flash = errStyle.Render("Scan failed: " + msg.err.Error())
			return m, nil
		}
		m.inv = msg.inv
		m.remote = map[int]remoteResult{}
		m.applyFilter()
		m.flash = fmt.Sprintf("Scanned %d virtual hosts", len(m.inv.Hosts))
		return m, nil

	case validateDoneMsg:
		m.busy = ""
		m.openText("Configuration test", msg.out)
		return m, nil

	case exportDoneMsg:
		m.busy = ""
		if msg.err != nil {
			m.flash = errStyle.Render("Export failed: " + msg.err.Error())
		} else {
			m.flash = okStyle.Render("Inventory written to " + msg.path)
		}
		return m, nil

	case remoteDoneMsg:
		delete(m.probing, msg.idx)
		m.remote[msg.idx] = remoteResult{name: discovery.ProbeName(m.inv.Hosts[msg.idx]), info: msg.info, err: msg.err}
		if m.view == viewDetail && m.detailIdx == msg.idx {
			m.vp.SetContent(m.detail(msg.idx))
		}
		return m, nil

	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
		switch m.view {
		case viewDetail, viewText:
			return m.updatePager(msg)
		}
		if m.filtering {
			return m.updateFilter(msg)
		}
		return m.updateList(msg)
	}
	return m, nil
}

func (m model) updateFilter(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.filter.SetValue("")
		fallthrough
	case "enter":
		m.filtering = false
		m.filter.Blur()
		m.applyFilter()
		return m, nil
	}
	var cmd tea.Cmd
	m.filter, cmd = m.filter.Update(msg)
	m.applyFilter()
	return m, cmd
}

func (m model) updateList(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	m.flash = ""
	switch msg.String() {
	case "q":
		return m, tea.Quit
	case "up", "k":
		m.cursor--
	case "down", "j":
		m.cursor++
	case "pgup", "ctrl+u":
		m.cursor -= m.listHeight()
	case "pgdown", "ctrl+d":
		m.cursor += m.listHeight()
	case "home", "g":
		m.cursor = 0
	case "end", "G":
		m.cursor = len(m.rows) - 1
	case "tab":
		m.tab = (m.tab + 1) % len(tabs)
		m.applyFilter()
	case "shift+tab":
		m.tab = (m.tab + len(tabs) - 1) % len(tabs)
		m.applyFilter()
	case "s":
		m.sortBy = (m.sortBy + 1) % len(sortNames)
		m.applyFilter()
	case "/":
		m.filtering = true
		return m, m.filter.Focus()
	case "esc":
		m.filter.SetValue("")
		m.applyFilter()
	case "?":
		m.help = !m.help
	case "enter":
		if len(m.rows) > 0 {
			m.detailIdx = m.rows[m.cursor]
			m.view = viewDetail
			m.vp.SetContent(m.detail(m.detailIdx))
			m.vp.GotoTop()
		}
	case "r":
		if m.busy == "" {
			m.busy = "Rescanning…"
			return m, tea.Batch(m.spin.Tick, scanCmd(m.opts))
		}
	case "v":
		if m.busy == "" && m.inv != nil {
			m.busy = "Running configuration test…"
			return m, tea.Batch(m.spin.Tick, validateCmd(m.opts, m.inv))
		}
	case "e":
		if m.busy == "" && m.inv != nil {
			m.busy = "Exporting…"
			return m, tea.Batch(m.spin.Tick, exportCmd(m.inv))
		}
	case "w":
		if m.inv != nil {
			text := "No warnings."
			if len(m.inv.Warnings) > 0 {
				text = "• " + strings.Join(m.inv.Warnings, "\n• ")
			}
			m.openText("Warnings", text)
		}
	}
	m.clamp()
	return m, nil
}

func (m model) updatePager(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q", "backspace":
		m.view = viewList
		return m, nil
	case "t":
		if m.view == viewDetail && !m.probing[m.detailIdx] {
			h := m.inv.Hosts[m.detailIdx]
			if discovery.ProbeName(h) == "" {
				m.remote[m.detailIdx] = remoteResult{err: fmt.Errorf("no public server name to probe")}
				m.vp.SetContent(m.detail(m.detailIdx))
				return m, nil
			}
			m.probing[m.detailIdx] = true
			m.vp.SetContent(m.detail(m.detailIdx))
			return m, remoteCmd(m.detailIdx, h)
		}
	case "n", "p":
		if m.view == viewDetail && len(m.rows) > 0 {
			pos := indexOf(m.rows, m.detailIdx)
			if msg.String() == "n" {
				pos = min(pos+1, len(m.rows)-1)
			} else {
				pos = max(pos-1, 0)
			}
			m.cursor = pos
			m.detailIdx = m.rows[pos]
			m.vp.SetContent(m.detail(m.detailIdx))
			m.vp.GotoTop()
			m.clamp()
			return m, nil
		}
	}
	var cmd tea.Cmd
	m.vp, cmd = m.vp.Update(msg)
	return m, cmd
}

func (m *model) openText(title, body string) {
	m.view = viewText
	m.textTitle = title
	m.vp.SetContent(lipgloss.NewStyle().Width(max(20, m.width-2)).Render(body))
	m.vp.GotoTop()
}

func (m *model) applyFilter() {
	m.rows = m.rows[:0]
	if m.inv == nil {
		return
	}
	q := strings.ToLower(strings.TrimSpace(m.filter.Value()))
	for i, h := range m.inv.Hosts {
		if m.tab == 1 && h.Server != webserver.KindNginx || m.tab == 2 && h.Server != webserver.KindApache {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(strings.Join(h.Names, " ")+" "+h.File), q) {
			continue
		}
		m.rows = append(m.rows, i)
	}
	hosts := m.inv.Hosts
	sort.SliceStable(m.rows, func(a, b int) bool {
		x, y := hosts[m.rows[a]], hosts[m.rows[b]]
		switch m.sortBy {
		case 0:
			return x.Status.Severity() > y.Status.Severity()
		case 1:
			return daysLeft(x) < daysLeft(y)
		case 2:
			return firstName(x) < firstName(y)
		default:
			return x.Location() < y.Location()
		}
	})
	m.clamp()
}

func (m *model) clamp() {
	m.cursor = min(m.cursor, len(m.rows)-1)
	m.cursor = max(m.cursor, 0)
	h := m.listHeight()
	if m.cursor < m.offset {
		m.offset = m.cursor
	}
	if m.cursor >= m.offset+h {
		m.offset = m.cursor - h + 1
	}
	m.offset = max(0, min(m.offset, len(m.rows)-h))
}

// listHeight is the number of table rows that fit between header and footer.
func (m model) listHeight() int {
	return max(1, m.height-7)
}

func daysLeft(h discovery.Host) int {
	if h.Cert == nil {
		return 1 << 30
	}
	return h.Cert.DaysLeft
}

func firstName(h discovery.Host) string {
	if len(h.Names) == 0 {
		return "~"
	}
	return strings.ToLower(h.Names[0])
}

func indexOf(xs []int, v int) int {
	for i, x := range xs {
		if x == v {
			return i
		}
	}
	return 0
}
