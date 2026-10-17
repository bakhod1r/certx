// Package scheduler installs `certx renew` as a systemd timer or a cron job.
package scheduler

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/bakhod1r/certx/internal/execx"
)

// Kind is the scheduling backend.
type Kind string

const (
	Systemd Kind = "systemd"
	Cron    Kind = "cron"
)

const (
	unitName  = "certx-renew"
	cronName  = "certx"
	marker    = "# Installed by CertX — remove with: certx scheduler uninstall"
	onCalAt   = "*-*-* 03,15:%02d:00"
	cronSched = "%d 3,15 * * *"
)

// Scheduler manages the renewal job. Paths and the command runner are
// configurable for tests.
type Scheduler struct {
	SystemdDir string // /etc/systemd/system
	CronDir    string // /etc/cron.d
	RunDir     string // /run/systemd/system, present when systemd is PID 1
	Run        func(ctx context.Context, name string, args ...string) (string, error)
}

// Default returns a Scheduler for the real system.
func Default() *Scheduler {
	return &Scheduler{SystemdDir: "/etc/systemd/system", CronDir: "/etc/cron.d", RunDir: "/run/systemd/system", Run: execx.Run}
}

// Detect picks systemd when it is running, cron otherwise.
func (s *Scheduler) Detect() Kind {
	if fi, err := os.Stat(s.RunDir); err == nil && fi.IsDir() {
		return Systemd
	}
	return Cron
}

// File is a file the scheduler writes.
type File struct {
	Path    string
	Content string
}

// Files returns what Install would write for command (absolute binary path
// followed by arguments).
func (s *Scheduler) Files(kind Kind, command []string) ([]File, error) {
	if len(command) == 0 || !filepath.IsAbs(command[0]) {
		return nil, errors.New("scheduler: command must start with an absolute path")
	}
	for _, a := range command {
		// "%" is special in both cron (newline) and systemd (specifiers).
		if strings.ContainsAny(a, "%\n") {
			return nil, fmt.Errorf("scheduler: unsupported character in argument %q", a)
		}
	}
	// Spread hosts over the hour instead of every server hitting the CA at :00.
	minute := spread()
	cmd := quoteCommand(command)
	switch kind {
	case Systemd:
		service := fmt.Sprintf(`%s
[Unit]
Description=CertX certificate renewal
Documentation=https://github.com/bakhod1r/certx
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=%s
TimeoutStartSec=30min
PrivateTmp=true
NoNewPrivileges=true
`, marker, cmd)
		timer := fmt.Sprintf(`%s
[Unit]
Description=Run CertX certificate renewal twice a day

[Timer]
OnCalendar=`+onCalAt+`
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
`, marker, minute)
		return []File{
			{filepath.Join(s.SystemdDir, unitName+".service"), service},
			{filepath.Join(s.SystemdDir, unitName+".timer"), timer},
		}, nil
	case Cron:
		line := fmt.Sprintf(cronSched+" root %s --quiet >/dev/null 2>&1\n", minute, cmd)
		return []File{{filepath.Join(s.CronDir, cronName), marker + "\nSHELL=/bin/sh\nPATH=/usr/sbin:/usr/bin:/sbin:/bin\n" + line}}, nil
	}
	return nil, fmt.Errorf("unknown scheduler %q", kind)
}

// Install writes the job and, for systemd, enables the timer.
func (s *Scheduler) Install(ctx context.Context, kind Kind, command []string) ([]File, error) {
	files, err := s.Files(kind, command)
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		if err := guard(f.Path); err != nil {
			return nil, err
		}
		if err := os.WriteFile(f.Path, []byte(f.Content), 0o644); err != nil {
			return nil, err
		}
	}
	if kind == Systemd {
		if out, err := s.Run(ctx, "systemctl", "daemon-reload"); err != nil {
			return files, fmt.Errorf("systemctl daemon-reload: %v\n%s", err, out)
		}
		if out, err := s.Run(ctx, "systemctl", "enable", "--now", unitName+".timer"); err != nil {
			return files, fmt.Errorf("systemctl enable: %v\n%s", err, out)
		}
	}
	return files, nil
}

// Uninstall removes every CertX scheduling file it finds.
func (s *Scheduler) Uninstall(ctx context.Context) ([]string, error) {
	var removed []string
	if s.installed(Systemd) {
		_, _ = s.Run(ctx, "systemctl", "disable", "--now", unitName+".timer")
	}
	for _, p := range s.paths() {
		if err := guard(p); err != nil {
			continue
		}
		if err := os.Remove(p); err == nil {
			removed = append(removed, p)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return removed, err
		}
	}
	if len(removed) > 0 && s.Detect() == Systemd {
		_, _ = s.Run(ctx, "systemctl", "daemon-reload")
	}
	return removed, nil
}

// Status describes the installed job.
type Status struct {
	Kind      Kind     `json:"kind,omitempty"`
	Files     []string `json:"files,omitempty"`
	NextRun   string   `json:"next_run,omitempty"`
	Conflicts []string `json:"conflicts,omitempty"`
}

// Status reports what is installed and other renewal jobs on the host.
func (s *Scheduler) Status(ctx context.Context) Status {
	var st Status
	for _, k := range []Kind{Systemd, Cron} {
		if s.installed(k) {
			st.Kind = k
		}
	}
	for _, p := range s.paths() {
		if _, err := os.Stat(p); err == nil {
			st.Files = append(st.Files, p)
		}
	}
	switch st.Kind {
	case Systemd:
		if out, err := s.Run(ctx, "systemctl", "show", unitName+".timer", "--property=NextElapseUSecRealtime", "--value"); err == nil && out != "" {
			st.NextRun = out
		}
	case Cron:
		st.NextRun = "daily at 03:xx and 15:xx (see " + filepath.Join(s.CronDir, cronName) + ")"
	}
	for _, p := range []string{
		filepath.Join(s.SystemdDir, "timers.target.wants", "certbot.timer"),
		"/lib/systemd/system/certbot.timer",
		filepath.Join(s.CronDir, "certbot"),
	} {
		if _, err := os.Stat(p); err == nil {
			st.Conflicts = append(st.Conflicts, p+" (Certbot renews its own certificates; CertX leaves them alone)")
		}
	}
	return st
}

func (s *Scheduler) paths() []string {
	return []string{
		filepath.Join(s.SystemdDir, unitName+".service"),
		filepath.Join(s.SystemdDir, unitName+".timer"),
		filepath.Join(s.CronDir, cronName),
	}
}

func (s *Scheduler) installed(k Kind) bool {
	p := filepath.Join(s.CronDir, cronName)
	if k == Systemd {
		p = filepath.Join(s.SystemdDir, unitName+".timer")
	}
	_, err := os.Stat(p)
	return err == nil
}

// guard refuses to overwrite or delete files that CertX did not create.
func guard(path string) error {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !strings.HasPrefix(string(data), marker) {
		return fmt.Errorf("%s exists and was not created by CertX; refusing to touch it", path)
	}
	return nil
}

func spread() int {
	host, _ := os.Hostname()
	h := fnv.New32a()
	h.Write([]byte(host))
	return int(h.Sum32() % 60)
}

// quoteCommand renders argv for systemd ExecStart and /bin/sh.
func quoteCommand(argv []string) string {
	out := make([]string, len(argv))
	for i, a := range argv {
		if a != "" && !strings.ContainsAny(a, " \t\"'\\$`;&|<>(){}*?#~") {
			out[i] = a
			continue
		}
		out[i] = `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, `$`, `\$`, "`", "\\`").Replace(a) + `"`
	}
	return strings.Join(out, " ")
}
