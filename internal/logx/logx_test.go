package logx

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "certx.log")
	r := &Rotating{Path: path, MaxBytes: 10, Keep: 2}
	for _, s := range []string{"aaaaaaaa\n", "bbbbbbbb\n", "cccccccc\n", "dddddddd\n"} {
		if _, err := r.Write([]byte(s)); err != nil {
			t.Fatal(err)
		}
	}
	r.Close()
	read := func(p string) string { b, _ := os.ReadFile(p); return string(b) }
	if read(path) != "dddddddd\n" || read(path+".1") != "cccccccc\n" || read(path+".2") != "bbbbbbbb\n" {
		t.Errorf("files: %q %q %q", read(path), read(path+".1"), read(path+".2"))
	}
	if _, err := os.Stat(path + ".3"); err == nil {
		t.Error("kept more backups than configured")
	}
}

func TestAudit(t *testing.T) {
	dir := t.TempDir()
	if err := Audit(dir, Event{Action: "deploy", Domains: []string{"a.example"}, Result: "ok", Backup: "id1"}); err != nil {
		t.Fatal(err)
	}
	if err := Audit(dir, Event{Action: "renew", Result: "failed", Detail: "boom"}); err != nil {
		t.Fatal(err)
	}
	f, _ := os.Open(filepath.Join(dir, "audit.log"))
	defer f.Close()
	var events []Event
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatal(err)
		}
		events = append(events, e)
	}
	if len(events) != 2 || events[0].Backup != "id1" || events[1].Result != "failed" || events[0].Time.IsZero() {
		t.Errorf("events = %+v", events)
	}
	if fi, _ := os.Stat(filepath.Join(dir, "audit.log")); !strings.HasSuffix(fi.Mode().Perm().String(), "r-----") {
		t.Errorf("audit log mode = %v", fi.Mode())
	}
}
