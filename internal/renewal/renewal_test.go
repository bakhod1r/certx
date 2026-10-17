package renewal

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bakhod1r/certx/internal/acme"
	"github.com/bakhod1r/certx/internal/certificate"
	"github.com/bakhod1r/certx/internal/certificate/certtest"
	"github.com/bakhod1r/certx/internal/deployment"
	"github.com/bakhod1r/certx/internal/discovery"
	"github.com/bakhod1r/certx/internal/issuer"
	"github.com/bakhod1r/certx/internal/webserver"
)

type fakeServer struct {
	webserver.Adapter
	validated, reloaded int
}

func (f *fakeServer) Validate(context.Context, webserver.Installation) (string, error) {
	f.validated++
	return "", nil
}

func (f *fakeServer) Reload(context.Context, webserver.Installation) (string, error) {
	f.reloaded++
	return "", nil
}

// store writes a certificate for domain valid for ttl into storage.
func store(t *testing.T, storage, domain string, ttl time.Duration) {
	t.Helper()
	paths := acme.Paths(storage, domain)
	dir := filepath.Dir(paths.Cert)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	cert, key := certtest.WritePair(t, t.TempDir(), "c", []string{domain}, time.Now(), ttl)
	for src, dst := range map[string]string{cert: paths.Cert, key: paths.Key} {
		data, _ := os.ReadFile(src)
		if err := os.WriteFile(dst, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	data := fmt.Sprintf(`{"domains":[%q],"directory":"https://ca.example/dir"}`, domain)
	if err := os.WriteFile(filepath.Join(dir, "meta.json"), []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

func inventory(t *testing.T, storage string, plain []string, domains ...string) *discovery.Inventory {
	t.Helper()
	dir := t.TempDir()
	conf := "events {}\nhttp {\n"
	for _, d := range plain {
		conf += fmt.Sprintf("server { listen 80; server_name %s; }\n", d)
	}
	for _, d := range domains {
		p := acme.Paths(storage, d)
		conf += fmt.Sprintf("server { listen 443 ssl; server_name %s; ssl_certificate %s; ssl_certificate_key %s; }\n", d, p.Cert, p.Key)
	}
	conf += "}\n"
	path := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(path, []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	inv, err := discovery.Scan(context.Background(), discovery.Options{Servers: []webserver.Kind{webserver.KindNginx}, NginxConfig: path})
	if err != nil {
		t.Fatal(err)
	}
	return inv
}

func TestRunDecisions(t *testing.T) {
	storage := t.TempDir()
	store(t, storage, "fresh.example.com", 80*24*time.Hour)
	store(t, storage, "soon.example.com", 10*24*time.Hour)
	store(t, storage, "broken.example.com", 10*24*time.Hour)
	store(t, storage, "plain.example.com", 5*24*time.Hour)  // served over HTTP, cert not deployed
	store(t, storage, "orphan.example.com", 5*24*time.Hour) // no virtual host at all
	inv := inventory(t, storage, []string{"plain.example.com"}, "fresh.example.com", "soon.example.com", "broken.example.com")

	var executed []string
	executeFn = func(_ context.Context, req issuer.Request, p *issuer.Plan) (*certificate.Info, error) {
		executed = append(executed, req.Domains[0])
		if req.Directory != "https://ca.example/dir" {
			t.Errorf("renewal must reuse the issuing CA, got %s", req.Directory)
		}
		if req.Domains[0] == "broken.example.com" {
			return nil, errors.New("acme: error: 403 :: unauthorized")
		}
		store(t, storage, req.Domains[0], 90*24*time.Hour)
		return certificate.Inspect(p.Paths.Cert, "", time.Now())
	}
	verifyFn = func(context.Context, string, time.Time) (*certificate.Info, error) { return nil, errors.New("offline") }
	verifyWait = 0
	fa := &fakeServer{}
	targetsFn = func(*discovery.Inventory) map[webserver.Kind]deployment.Target {
		return map[webserver.Kind]deployment.Target{webserver.KindNginx: {Adapter: fa, Inst: webserver.Installation{Binary: "/fake/nginx"}}}
	}
	t.Cleanup(func() { executeFn, targetsFn = issuer.Execute, issuer.Targets })

	// Dry run decides without executing.
	res, err := Run(context.Background(), Options{Inv: inv, Storage: storage, WindowDays: 30, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Action{}
	for _, r := range res {
		got[r.Name] = r.Action
	}
	want := map[string]Action{"broken.example.com": WouldRenew, "fresh.example.com": Skipped, "orphan.example.com": WouldRenew, "plain.example.com": WouldRenew, "soon.example.com": WouldRenew}
	if fmt.Sprint(got) != fmt.Sprint(want) || len(executed) != 0 {
		t.Fatalf("dry run = %v, executed %v", got, executed)
	}

	// Real run: reloads need a server binary; there is none in tests, so
	// hosts using a renewed certificate report the missing binary.
	res, _ = Run(context.Background(), Options{Inv: inv, Storage: storage, WindowDays: 30})
	got = map[string]Action{}
	errs := map[string]string{}
	for _, r := range res {
		got[r.Name], errs[r.Name] = r.Action, r.Error
	}
	if got["fresh.example.com"] != Skipped || got["broken.example.com"] != Failed ||
		got["plain.example.com"] != NotDeployed || got["soon.example.com"] != Renewed || got["orphan.example.com"] != Failed {
		t.Errorf("run = %v", got)
	}
	if !strings.Contains(errs["orphan.example.com"], "no enabled virtual host") {
		t.Errorf("errors = %v", errs)
	}
	if fa.validated != 1 || fa.reloaded != 1 {
		t.Errorf("validated=%d reloaded=%d, want one reload for soon.example.com", fa.validated, fa.reloaded)
	}
	if len(executed) != 3 {
		t.Errorf("executed = %v", executed)
	}

	// Idempotent: a second run skips everything that was renewed.
	executed = nil
	res, _ = Run(context.Background(), Options{Inv: inv, Storage: storage, WindowDays: 30, Domains: []string{"plain.example.com", "soon.example.com"}})
	for _, r := range res {
		if r.Action != Skipped {
			t.Errorf("%s: %s", r.Name, r.Action)
		}
	}
	if len(executed) != 0 {
		t.Errorf("re-run issued again: %v", executed)
	}
}
