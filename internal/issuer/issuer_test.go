package issuer

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bakhod1r/certx/internal/acme"
)

func TestTransient(t *testing.T) {
	for msg, want := range map[string]bool{
		"dial tcp: i/o timeout":                       true,
		"acme: error: 503 :: service unavailable":     true,
		"read: connection reset by peer":              true,
		"urn:ietf:params:acme:error:rateLimited":      false,
		"acme: error: 403 :: unauthorized :: Invalid": false,
		"urn:ietf:params:acme:error:caa :: forbidden": false,
		"something unexpected":                        false,
	} {
		if got := Transient(errors.New(msg)); got != want {
			t.Errorf("Transient(%q) = %v", msg, got)
		}
	}
}

func TestObtainRetriesTransientOnly(t *testing.T) {
	defer func() { obtainFn = acme.Obtain }()
	calls := 0
	obtainFn = func(acme.Request) (*acme.Bundle, error) {
		calls++
		if calls < 3 {
			return nil, errors.New("connection refused")
		}
		return &acme.Bundle{}, nil
	}
	req := Request{Retry: Retry{Attempts: 3, Delay: time.Millisecond}}
	if _, err := obtain(context.Background(), req, "/w", func(string) {}); err != nil || calls != 3 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}

	calls = 0
	obtainFn = func(acme.Request) (*acme.Bundle, error) { calls++; return nil, errors.New("rateLimited") }
	if _, err := obtain(context.Background(), req, "/w", func(string) {}); err == nil || calls != 1 {
		t.Fatalf("rate limit retried: err=%v calls=%d", err, calls)
	}
}

func TestObtainHonoursContext(t *testing.T) {
	defer func() { obtainFn = acme.Obtain }()
	obtainFn = func(acme.Request) (*acme.Bundle, error) { time.Sleep(time.Second); return &acme.Bundle{}, nil }
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := obtainCtx(ctx, acme.Request{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
}
