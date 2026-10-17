// Package deployment applies ChangeSets safely: drift check, backup, atomic
// writes, configuration test, graceful reload and automatic rollback.
package deployment

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/bakhod1r/certx/internal/webserver"
)

// Target is a web server that can be validated and reloaded.
type Target struct {
	Adapter webserver.Adapter
	Inst    webserver.Installation
}

// Entry records one file touched by a deployment.
type Entry struct {
	Path    string      `json:"path"`
	Existed bool        `json:"existed"`
	Backup  string      `json:"backup,omitempty"`
	Mode    fs.FileMode `json:"mode"`
	Symlink string      `json:"symlink,omitempty"`
	After   string      `json:"after_sha256,omitempty"` // content CertX wrote
}

// Manifest describes a backup that can be rolled back.
type Manifest struct {
	ID         string           `json:"id"`
	Label      string           `json:"label"`
	Created    time.Time        `json:"created"`
	Servers    []webserver.Kind `json:"servers"`
	Entries    []Entry          `json:"entries"`
	RolledBack bool             `json:"rolled_back"`
}

// Apply writes cs after backing up every touched file, then validates and
// reloads each affected server. Any failure restores the backup.
func Apply(ctx context.Context, cs *webserver.ChangeSet, targets map[webserver.Kind]Target, backupDir string) (*Manifest, error) {
	if cs.Empty() {
		return nil, errors.New("nothing to apply")
	}
	for _, k := range cs.Servers {
		if t, ok := targets[k]; !ok || t.Inst.Binary == "" {
			return nil, fmt.Errorf("%s binary not found: cannot validate the configuration, refusing to apply", k)
		}
	}
	if err := checkDrift(cs); err != nil {
		return nil, err
	}
	m, err := backup(cs, backupDir)
	if err != nil {
		return nil, fmt.Errorf("backup: %w", err)
	}
	if err := write(cs); err != nil {
		return m, restoreWith(m, backupDir, fmt.Errorf("write: %w", err))
	}
	for _, k := range cs.Servers {
		t := targets[k]
		if out, err := t.Adapter.Validate(ctx, t.Inst); err != nil {
			return m, restoreWith(m, backupDir, fmt.Errorf("%s configuration test failed, changes rolled back:\n%s", k, out))
		}
	}
	for _, k := range cs.Servers {
		t := targets[k]
		if out, err := t.Adapter.Reload(ctx, t.Inst); err != nil {
			rerr := restoreWith(m, backupDir, fmt.Errorf("%s reload failed, changes rolled back: %v\n%s", k, err, out))
			_, _ = t.Adapter.Reload(ctx, t.Inst)
			return m, rerr
		}
	}
	return m, nil
}

// Rollback restores backup id, validates and reloads the affected servers.
// It refuses when a file was changed after CertX wrote it.
func Rollback(ctx context.Context, backupDir, id string, targets map[webserver.Kind]Target) (*Manifest, error) {
	m, err := Load(backupDir, id)
	if err != nil {
		return nil, err
	}
	if m.RolledBack {
		return m, fmt.Errorf("backup %s was already rolled back", id)
	}
	for _, e := range m.Entries {
		if e.Symlink != "" {
			continue
		}
		cur, err := os.ReadFile(e.Path)
		if err != nil {
			return m, fmt.Errorf("%s: %w", e.Path, err)
		}
		if e.After != "" && sha(cur) != e.After {
			return m, fmt.Errorf("%s was modified after backup %s was applied; restore it manually from %s",
				e.Path, id, filepath.Join(backupDir, id))
		}
	}
	if err := restore(m, backupDir); err != nil {
		return m, err
	}
	for _, k := range m.Servers {
		t, ok := targets[k]
		if !ok || t.Inst.Binary == "" {
			continue
		}
		if out, err := t.Adapter.Validate(ctx, t.Inst); err != nil {
			return m, fmt.Errorf("%s configuration test failed after rollback:\n%s", k, out)
		}
		if out, err := t.Adapter.Reload(ctx, t.Inst); err != nil {
			return m, fmt.Errorf("%s reload failed after rollback: %v\n%s", k, err, out)
		}
	}
	m.RolledBack = true
	return m, saveManifest(m, backupDir)
}

// List returns all manifests, newest first.
func List(backupDir string) ([]*Manifest, error) {
	dirs, err := os.ReadDir(backupDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []*Manifest
	for _, d := range dirs {
		if m, err := Load(backupDir, d.Name()); err == nil {
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out, nil
}

// Load reads the manifest of backup id.
func Load(backupDir, id string) (*Manifest, error) {
	if id == "" || strings.ContainsAny(id, `/\`) || id == "." || id == ".." {
		return nil, fmt.Errorf("invalid backup id %q", id)
	}
	data, err := os.ReadFile(filepath.Join(backupDir, id, "manifest.json"))
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func checkDrift(cs *webserver.ChangeSet) error {
	for _, e := range cs.Edits {
		if err := checkPath(e.Path); err != nil {
			return err
		}
		if !e.Existed {
			if _, err := os.Lstat(e.Path); err == nil {
				return fmt.Errorf("%s already exists; re-run plan", e.Path)
			}
			continue
		}
		cur, err := os.ReadFile(e.Path)
		if err != nil {
			return err
		}
		if !bytes.Equal(cur, e.Before) {
			return fmt.Errorf("%s changed since the plan was computed; re-run plan", e.Path)
		}
	}
	return nil
}

func checkPath(p string) error {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p || strings.ContainsRune(p, 0) {
		return fmt.Errorf("refusing unsafe path %q", p)
	}
	return nil
}

func backup(cs *webserver.ChangeSet, backupDir string) (*Manifest, error) {
	id := time.Now().UTC().Format("20060102T150405.000Z")
	dir := filepath.Join(backupDir, id)
	if err := os.MkdirAll(filepath.Join(dir, "files"), 0o700); err != nil {
		return nil, err
	}
	m := &Manifest{ID: id, Label: cs.Label, Created: time.Now().UTC(), Servers: cs.Servers}
	for i, e := range cs.Edits {
		en := Entry{Path: e.Path, Existed: e.Existed, Mode: e.Mode, Symlink: e.Symlink}
		if e.Symlink == "" {
			en.After = sha(e.After)
		}
		if e.Existed {
			en.Backup = fmt.Sprintf("files/%03d-%s", i, filepath.Base(e.Path))
			if err := os.WriteFile(filepath.Join(dir, en.Backup), e.Before, 0o600); err != nil {
				return nil, err
			}
		}
		m.Entries = append(m.Entries, en)
	}
	return m, saveManifest(m, backupDir)
}

func saveManifest(m *Manifest, backupDir string) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return AtomicWrite(filepath.Join(backupDir, m.ID, "manifest.json"), append(data, '\n'), 0o600)
}

func write(cs *webserver.ChangeSet) error {
	for _, e := range cs.Edits {
		if e.Symlink != "" {
			if err := os.Symlink(e.Symlink, e.Path); err != nil {
				return err
			}
			continue
		}
		mode := e.Mode
		if mode == 0 {
			mode = 0o644
		}
		if err := AtomicWrite(e.Path, e.After, mode); err != nil {
			return err
		}
	}
	return nil
}

func restore(m *Manifest, backupDir string) error {
	var errs []error
	for i := len(m.Entries) - 1; i >= 0; i-- {
		e := m.Entries[i]
		if !e.Existed {
			if err := os.Remove(e.Path); err != nil && !errors.Is(err, fs.ErrNotExist) {
				errs = append(errs, err)
			}
			continue
		}
		data, err := os.ReadFile(filepath.Join(backupDir, m.ID, e.Backup))
		if err == nil {
			err = AtomicWrite(e.Path, data, e.Mode)
		}
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func restoreWith(m *Manifest, backupDir string, cause error) error {
	if err := restore(m, backupDir); err != nil {
		return fmt.Errorf("%w\nROLLBACK FAILED (backup %s): %v", cause, m.ID, err)
	}
	m.RolledBack = true
	_ = saveManifest(m, backupDir)
	return cause
}

func sha(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// AtomicWrite writes data to a temporary file in the same directory and
// renames it over path.
func AtomicWrite(path string, data []byte, mode fs.FileMode) error {
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("refusing to replace symlink %s", path)
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".certx-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(mode.Perm()); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
