package metrics

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bakhod1r/certx/internal/certificate/certtest"
	"github.com/bakhod1r/certx/internal/discovery"
	"github.com/bakhod1r/certx/internal/state"
	"github.com/bakhod1r/certx/internal/webserver"
)

func TestWrite(t *testing.T) {
	dir := t.TempDir()
	cert, key := certtest.WritePair(t, dir, "a", []string{"a.example.com"}, time.Now(), 10*24*time.Hour)
	conf := filepath.Join(dir, "nginx.conf")
	os.WriteFile(conf, []byte("events {}\nhttp { server { listen 443 ssl; server_name a.example.com; ssl_certificate "+cert+"; ssl_certificate_key "+key+"; } }\n"), 0o644)
	inv, err := discovery.Scan(context.Background(), discovery.Options{Servers: []webserver.Kind{webserver.KindNginx}, NginxConfig: conf})
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	last := &state.Run{Finished: time.Unix(1700000000, 0), Renewed: 2, Failed: 1}
	if err := Write(&b, inv, t.TempDir(), last, time.Now()); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"# TYPE certx_host_certificate_expiry_timestamp_seconds gauge",
		`certx_host_status{server="nginx",name="a.example.com",file="` + conf + `",line="2",managed_by="manual",status="EXPIRING"} 1`,
		"certx_last_renew_success 0",
		`certx_last_renew_certificates{outcome="renewed"} 2`,
		"certx_last_renew_timestamp_seconds 1.7e+09",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}
