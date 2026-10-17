package acme

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// settle bounds how long SelfTest waits for a reload to take effect.
var settle = 8 * time.Second

// SelfTest checks that every domain serves a token placed under webroot
// when requested through the local web server, before the CA is contacted.
// Redirects (e.g. HTTP to HTTPS) are followed like the CA would.
func SelfTest(ctx context.Context, webroot string, domains []string, localIP string) error {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return err
	}
	token := "certx-selftest-" + hex.EncodeToString(buf)
	dir := filepath.Join(webroot, ".well-known", "acme-challenge")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(dir, token)
	if err := os.WriteFile(path, []byte(token), 0o644); err != nil {
		return err
	}
	defer os.Remove(path)

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy: nil,
			// Always talk to the local web server, whatever DNS says.
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				_, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				return dialer.DialContext(ctx, network, net.JoinHostPort(localIP, port))
			},
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // only fetching our own token
		},
	}
	for _, d := range domains {
		url := "http://" + d + "/.well-known/acme-challenge/" + token
		// A graceful reload is asynchronous: old workers may answer for a
		// moment, so retry briefly before reporting a failure.
		deadline := time.Now().Add(settle)
		for {
			err := fetch(ctx, client, url, token, webroot)
			if err == nil {
				break
			}
			if time.Now().After(deadline) {
				return err
			}
			select {
			case <-ctx.Done():
				return err
			case <-time.After(250 * time.Millisecond):
			}
		}
	}
	return nil
}

func fetch(ctx context.Context, client *http.Client, url, token, webroot string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("self-check %s: %w", url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode == http.StatusOK && strings.TrimSpace(string(body)) == token {
		return nil
	}
	hint := "the virtual host does not serve the challenge directory"
	if resp.StatusCode == http.StatusForbidden {
		hint = fmt.Sprintf("the web server user cannot read %s; every parent directory needs o+x", webroot)
	}
	return fmt.Errorf("self-check %s returned HTTP %d: %s", url, resp.StatusCode, hint)
}
