// Package config loads CertX settings from /etc/certx/env, a KEY=VALUE
// file shared by interactive runs, cron and systemd. Variables already set
// in the environment take precedence.
package config

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
)

// DefaultEnvFile is read when CERTX_ENV_FILE is not set.
const DefaultEnvFile = "/etc/certx/env"

// LoadEnvFile applies the variables in path. A missing file is not an
// error. The returned warning is non-empty when the file is readable by
// group or others, since it may hold API tokens.
func LoadEnvFile(path string) (warning string, err error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	defer f.Close()
	if fi, err := f.Stat(); err == nil && fi.Mode().Perm()&0o077 != 0 {
		warning = fmt.Sprintf("%s is readable by group or others; run: chmod 600 %s", path, path)
	}
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		key, val, ok := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		if !ok || key == "" || strings.ContainsAny(key, " \t") {
			return warning, fmt.Errorf("%s:%d: expected KEY=VALUE", path, n)
		}
		val = strings.TrimSpace(val)
		if len(val) >= 2 && (val[0] == '"' || val[0] == '\'') && val[len(val)-1] == val[0] {
			val = val[1 : len(val)-1]
		}
		if _, set := os.LookupEnv(key); !set {
			os.Setenv(key, val)
		}
	}
	return warning, sc.Err()
}
