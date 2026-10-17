// Package logx provides a size-rotated log file and the audit trail.
package logx

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Rotating is an io.Writer that rotates path when it exceeds MaxBytes,
// keeping Keep old files (path.1 … path.N).
type Rotating struct {
	Path     string
	MaxBytes int64
	Keep     int

	mu   sync.Mutex
	f    *os.File
	size int64
}

// Open returns a Rotating writer with 10 MiB files and 5 backups.
func Open(path string) (*Rotating, error) {
	r := &Rotating{Path: path, MaxBytes: 10 << 20, Keep: 5}
	return r, r.open()
}

func (r *Rotating) open() error {
	if err := os.MkdirAll(filepath.Dir(r.Path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(r.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	r.f, r.size = f, fi.Size()
	return nil
}

func (r *Rotating) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		if err := r.open(); err != nil {
			return 0, err
		}
	}
	if r.MaxBytes > 0 && r.size+int64(len(p)) > r.MaxBytes && r.size > 0 {
		if err := r.rotate(); err != nil {
			return 0, err
		}
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}

func (r *Rotating) rotate() error {
	r.f.Close()
	r.f = nil
	for i := r.Keep - 1; i >= 1; i-- {
		_ = os.Rename(fmt.Sprintf("%s.%d", r.Path, i), fmt.Sprintf("%s.%d", r.Path, i+1))
	}
	if r.Keep > 0 {
		if err := os.Rename(r.Path, r.Path+".1"); err != nil {
			return err
		}
	} else if err := os.Remove(r.Path); err != nil {
		return err
	}
	return r.open()
}

// Close closes the current file.
func (r *Rotating) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return nil
	}
	err := r.f.Close()
	r.f = nil
	return err
}

// Event is one audit-trail record.
type Event struct {
	Time    time.Time `json:"time"`
	Action  string    `json:"action"` // issue, renew, deploy, rollback
	Domains []string  `json:"domains,omitempty"`
	Result  string    `json:"result"` // ok, failed, skipped
	Detail  string    `json:"detail,omitempty"`
	Backup  string    `json:"backup,omitempty"`
	User    string    `json:"user,omitempty"`
}

// Audit appends e to <storage>/audit.log as one JSON line.
func Audit(storage string, e Event) error {
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	if e.User == "" {
		e.User = os.Getenv("SUDO_USER")
	}
	r, err := Open(filepath.Join(storage, "audit.log"))
	if err != nil {
		return err
	}
	defer r.Close()
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	_, err = r.Write(append(line, '\n'))
	return err
}
