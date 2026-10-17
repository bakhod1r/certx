package scheduler

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fake(t *testing.T) (*Scheduler, *[]string) {
	t.Helper()
	root := t.TempDir()
	var calls []string
	s := &Scheduler{
		SystemdDir: filepath.Join(root, "systemd"), CronDir: filepath.Join(root, "cron.d"), RunDir: filepath.Join(root, "run"),
		Run: func(_ context.Context, name string, args ...string) (string, error) {
			calls = append(calls, name+" "+strings.Join(args, " "))
			return "Sat 2026-10-18 03:41:00 UTC", nil
		},
	}
	for _, d := range []string{s.SystemdDir, s.CronDir} {
		os.MkdirAll(d, 0o755)
	}
	return s, &calls
}

func TestSystemdInstallStatusUninstall(t *testing.T) {
	s, calls := fake(t)
	os.MkdirAll(s.RunDir, 0o755)
	if s.Detect() != Systemd {
		t.Fatal("systemd not detected")
	}
	cmd := []string{"/usr/local/bin/certx", "renew", "--yes", "--nginx-conf=/etc/my nginx/nginx.conf"}
	files, err := s.Install(context.Background(), Systemd, cmd)
	if err != nil {
		t.Fatal(err)
	}
	service := files[0].Content
	if !strings.Contains(service, `ExecStart=/usr/local/bin/certx renew --yes "--nginx-conf=/etc/my nginx/nginx.conf"`) {
		t.Errorf("service:\n%s", service)
	}
	if !strings.Contains(files[1].Content, "Persistent=true") || !strings.Contains(files[1].Content, "RandomizedDelaySec=1h") {
		t.Errorf("timer:\n%s", files[1].Content)
	}
	if strings.Join(*calls, ";") != "systemctl daemon-reload;systemctl enable --now certx-renew.timer" {
		t.Errorf("calls = %v", *calls)
	}
	st := s.Status(context.Background())
	if st.Kind != Systemd || len(st.Files) != 2 || st.NextRun == "" {
		t.Errorf("status = %+v", st)
	}
	removed, err := s.Uninstall(context.Background())
	if err != nil || len(removed) != 2 {
		t.Fatalf("removed %v, %v", removed, err)
	}
	if st := s.Status(context.Background()); st.Kind != "" {
		t.Errorf("still installed: %+v", st)
	}
}

func TestCronAndGuards(t *testing.T) {
	s, _ := fake(t)
	if s.Detect() != Cron {
		t.Fatal("expected cron without systemd")
	}
	files, err := s.Install(context.Background(), Cron, []string{"/usr/bin/certx", "renew", "--yes"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(files[0].Content, " 3,15 * * * root /usr/bin/certx renew --yes --quiet") {
		t.Errorf("cron:\n%s", files[0].Content)
	}

	// Never overwrite or delete a foreign file with the same name.
	foreign := filepath.Join(s.CronDir, "certx")
	os.WriteFile(foreign, []byte("# hand-written\n"), 0o644)
	if _, err := s.Install(context.Background(), Cron, []string{"/usr/bin/certx", "renew"}); err == nil {
		t.Error("overwrote a foreign cron file")
	}
	if _, err := s.Uninstall(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Error("deleted a foreign cron file")
	}

	for _, bad := range [][]string{{"certx", "renew"}, {"/usr/bin/certx", "--log-file=/var/log/%h.log"}} {
		if _, err := s.Files(Cron, bad); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
}
