// Package execx runs external commands without shell interpolation.
package execx

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

// DefaultTimeout bounds every command started through Run.
const DefaultTimeout = 30 * time.Second

// Run executes name with args and returns the trimmed combined output.
func Run(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, DefaultTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}
