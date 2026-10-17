// Package state persists the outcome of the last renewal run.
package state

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/bakhod1r/certx/internal/deployment"
)

// Run summarises one `certx renew` execution.
type Run struct {
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished"`
	Renewed  int       `json:"renewed"`
	Skipped  int       `json:"skipped"`
	Failed   int       `json:"failed"`
	Results  any       `json:"results,omitempty"`
}

// OK reports whether the run had no failures.
func (r *Run) OK() bool { return r.Failed == 0 }

type file struct {
	LastRun *Run `json:"last_run"`
}

func path(storage string) string { return filepath.Join(storage, "state.json") }

// SaveRun records r as the last run.
func SaveRun(storage string, r *Run) error {
	if err := os.MkdirAll(storage, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(file{LastRun: r}, "", "  ")
	if err != nil {
		return err
	}
	return deployment.AtomicWrite(path(storage), append(data, '\n'), 0o644)
}

// LastRun returns the last recorded run, or nil when none exists.
func LastRun(storage string) (*Run, error) {
	data, err := os.ReadFile(path(storage))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var f file
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	return f.LastRun, nil
}
