package main

import (
	"testing"
)

func TestLockReentrantAndReleasable(t *testing.T) {
	g := &globals{storage: t.TempDir()}
	release, err := g.lock()
	if err != nil {
		t.Fatal(err)
	}
	inner, err := g.lock() // nested call (issue --deploy) must not deadlock
	if err != nil {
		t.Fatal(err)
	}
	inner()
	release()
	if g.locked {
		t.Error("lock still marked as held")
	}
	again, err := g.lock()
	if err != nil {
		t.Fatalf("lock not released: %v", err)
	}
	again()
}
