package deployment

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bakhod1r/certx/internal/webserver"
)

type fakeAdapter struct {
	webserver.Adapter
	validateErr         error
	validated, reloaded int
}

func (f *fakeAdapter) Validate(context.Context, webserver.Installation) (string, error) {
	f.validated++
	return "syntax is ok", f.validateErr
}

func (f *fakeAdapter) Reload(context.Context, webserver.Installation) (string, error) {
	f.reloaded++
	return "", nil
}

func setup(t *testing.T) (dir string, cs *webserver.ChangeSet, fa *fakeAdapter, targets map[webserver.Kind]Target) {
	t.Helper()
	dir = t.TempDir()
	conf := filepath.Join(dir, "site.conf")
	if err := os.WriteFile(conf, []byte("old\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	cs = &webserver.ChangeSet{
		Label:   "test",
		Servers: []webserver.Kind{webserver.KindNginx},
		Edits: []webserver.FileEdit{
			{Path: conf, Existed: true, Before: []byte("old\n"), After: []byte("new\n"), Mode: 0o640},
			{Path: filepath.Join(dir, "extra.conf"), After: []byte("extra\n"), Mode: 0o644},
			{Path: filepath.Join(dir, "link.conf"), Symlink: "extra.conf"},
		},
	}
	fa = &fakeAdapter{}
	targets = map[webserver.Kind]Target{webserver.KindNginx: {Adapter: fa, Inst: webserver.Installation{Binary: "/usr/sbin/nginx"}}}
	return
}

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		return "<missing>"
	}
	return string(b)
}

func TestApplyAndRollback(t *testing.T) {
	dir, cs, fa, targets := setup(t)
	backups := filepath.Join(dir, "backups")
	m, err := Apply(context.Background(), cs, targets, backups)
	if err != nil {
		t.Fatal(err)
	}
	if read(t, filepath.Join(dir, "site.conf")) != "new\n" || read(t, filepath.Join(dir, "link.conf")) != "extra\n" {
		t.Fatal("changes not written")
	}
	if fi, _ := os.Stat(filepath.Join(dir, "site.conf")); fi.Mode().Perm() != 0o640 {
		t.Errorf("mode = %v", fi.Mode())
	}
	if fa.validated != 1 || fa.reloaded != 1 {
		t.Errorf("validated=%d reloaded=%d", fa.validated, fa.reloaded)
	}

	list, err := List(backups)
	if err != nil || len(list) != 1 || list[0].ID != m.ID {
		t.Fatalf("list = %v, %v", list, err)
	}
	if _, err := Rollback(context.Background(), backups, m.ID, targets); err != nil {
		t.Fatal(err)
	}
	if read(t, filepath.Join(dir, "site.conf")) != "old\n" {
		t.Error("not restored")
	}
	for _, f := range []string{"extra.conf", "link.conf"} {
		if _, err := os.Lstat(filepath.Join(dir, f)); err == nil {
			t.Errorf("%s not removed", f)
		}
	}
	if m, _ := Load(backups, m.ID); !m.RolledBack {
		t.Error("manifest not marked rolled back")
	}
	if _, err := Rollback(context.Background(), backups, m.ID, targets); err == nil {
		t.Error("second rollback of the same backup must be refused")
	}
}

func TestRollbackRefusesLaterEdits(t *testing.T) {
	dir, cs, _, targets := setup(t)
	backups := filepath.Join(dir, "backups")
	m, err := Apply(context.Background(), cs, targets, backups)
	if err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(dir, "site.conf")
	if err := os.WriteFile(conf, []byte("new\nhand edit\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := Rollback(context.Background(), backups, m.ID, targets); err == nil || !strings.Contains(err.Error(), "modified after") {
		t.Fatalf("err = %v", err)
	}
	if read(t, conf) != "new\nhand edit\n" {
		t.Error("later edit was overwritten")
	}
}

func TestApplyRollsBackOnValidationFailure(t *testing.T) {
	dir, cs, fa, targets := setup(t)
	fa.validateErr = errors.New("exit status 1")
	_, err := Apply(context.Background(), cs, targets, filepath.Join(dir, "backups"))
	if err == nil || !strings.Contains(err.Error(), "configuration test failed") {
		t.Fatalf("err = %v", err)
	}
	if read(t, filepath.Join(dir, "site.conf")) != "old\n" {
		t.Error("file not restored")
	}
	if _, err := os.Lstat(filepath.Join(dir, "extra.conf")); err == nil {
		t.Error("new file not removed")
	}
	if fa.reloaded != 0 {
		t.Error("must not reload an invalid configuration")
	}
}

func TestApplyDetectsDrift(t *testing.T) {
	dir, cs, _, targets := setup(t)
	if err := os.WriteFile(filepath.Join(dir, "site.conf"), []byte("edited by hand\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(context.Background(), cs, targets, filepath.Join(dir, "backups")); err == nil || !strings.Contains(err.Error(), "changed since") {
		t.Fatalf("err = %v", err)
	}
	if read(t, filepath.Join(dir, "site.conf")) != "edited by hand\n" {
		t.Error("hand edit overwritten")
	}
}

func TestApplyRequiresBinary(t *testing.T) {
	dir, cs, _, targets := setup(t)
	targets[webserver.KindNginx] = Target{Adapter: &fakeAdapter{}}
	if _, err := Apply(context.Background(), cs, targets, filepath.Join(dir, "backups")); err == nil {
		t.Fatal("expected refusal without a binary to validate with")
	}
}

func TestLoadRejectsTraversal(t *testing.T) {
	for _, id := range []string{"", "..", "../x", "a/b"} {
		if _, err := Load(t.TempDir(), id); err == nil {
			t.Errorf("Load(%q) succeeded", id)
		}
	}
}

func TestDiff(t *testing.T) {
	cs := &webserver.ChangeSet{Edits: []webserver.FileEdit{{
		Path: "/etc/x.conf", Existed: true,
		Before: []byte("a\nb\nc\nd\ne\nf\ng\nh\n"),
		After:  []byte("a\nb\nc\nd\nE\nf\ng\nh\n"),
	}}}
	want := "--- /etc/x.conf\n+++ /etc/x.conf\n@@ -2,7 +2,7 @@\n b\n c\n d\n-e\n+E\n f\n g\n h\n"
	if got := Diff(cs); got != want {
		t.Errorf("got:\n%s", got)
	}
}
