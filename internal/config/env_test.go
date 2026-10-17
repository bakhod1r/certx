package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadEnvFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "env")
	content := "# comment\nCERTX_T_A=1\nexport CERTX_T_B=\"two words\"\nCERTX_T_C='x=y'\n\nCERTX_T_KEEP=file\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CERTX_T_KEEP", "env")
	for _, k := range []string{"CERTX_T_A", "CERTX_T_B", "CERTX_T_C"} {
		os.Unsetenv(k)
		t.Cleanup(func() { os.Unsetenv(k) })
	}
	warn, err := LoadEnvFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(warn, "chmod 600") {
		t.Errorf("expected permission warning, got %q", warn)
	}
	for k, want := range map[string]string{"CERTX_T_A": "1", "CERTX_T_B": "two words", "CERTX_T_C": "x=y", "CERTX_T_KEEP": "env"} {
		if got := os.Getenv(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}

	if warn, err := LoadEnvFile(filepath.Join(t.TempDir(), "missing")); err != nil || warn != "" {
		t.Errorf("missing file: %q %v", warn, err)
	}
	bad := filepath.Join(t.TempDir(), "bad")
	os.WriteFile(bad, []byte("NOT A PAIR\n"), 0o600)
	if _, err := LoadEnvFile(bad); err == nil {
		t.Error("expected parse error")
	}
}
