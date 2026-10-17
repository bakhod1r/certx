package state

import (
	"testing"
	"time"
)

func TestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if r, err := LastRun(dir); r != nil || err != nil {
		t.Fatalf("empty: %v %v", r, err)
	}
	in := &Run{Started: time.Now().UTC().Truncate(time.Second), Finished: time.Now().UTC().Truncate(time.Second), Renewed: 1, Failed: 1}
	if err := SaveRun(dir, in); err != nil {
		t.Fatal(err)
	}
	out, err := LastRun(dir)
	if err != nil || out.Renewed != 1 || out.OK() || !out.Finished.Equal(in.Finished) {
		t.Errorf("out = %+v, %v", out, err)
	}
}
