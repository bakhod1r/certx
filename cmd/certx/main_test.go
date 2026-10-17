package main

import (
	"flag"
	"io"
	"reflect"
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

func TestParseInterspersed(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	yes := fs.Bool("yes", false, "")
	server := fs.String("server", "", "")
	pos, err := parseInterspersed(fs, []string{"install", "--server", "nginx", "extra", "--yes", "--", "--literal"})
	if err != nil {
		t.Fatal(err)
	}
	if !*yes || *server != "nginx" || !reflect.DeepEqual(pos, []string{"install", "extra", "--literal"}) {
		t.Errorf("yes=%v server=%q pos=%v", *yes, *server, pos)
	}
}
