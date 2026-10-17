// Command certx discovers Nginx and Apache virtual hosts, audits their TLS
// certificates and issues, deploys and rolls back Let's Encrypt certificates.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/bakhod1r/certx/internal/acme"
	"github.com/bakhod1r/certx/internal/discovery"
	"github.com/bakhod1r/certx/internal/lockfile"
	"github.com/bakhod1r/certx/internal/tui"
	"github.com/bakhod1r/certx/internal/webserver"
)

var version = "dev"

// errCritical signals that at least one host has a critical status.
var errCritical = errors.New("critical certificate problems found")

const usage = `CertX — SSL/TLS certificate automation for Nginx and Apache

Usage:
  certx [command] [flags]

Commands:
  tui        Interactive terminal UI (default)
  scan       Discover virtual hosts and audit certificates
  plan       Preview certificates to issue and configuration changes
  issue      Obtain a certificate over ACME HTTP-01 (staging by default)
  deploy     Point virtual hosts at a CertX certificate (backup, test, reload)
  rollback   List backups or restore one
  validate   Run nginx -t / apachectl -t
  version    Print version

Examples:
  certx plan
  certx issue  --domain example.com --domain www.example.com --email ops@example.com
  certx issue  --domain example.com --acme production --deploy --redirect
  certx deploy --domain example.com --dry-run
  certx rollback --list

Flags:
`

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			*s = append(*s, strings.ToLower(p))
		}
	}
	return nil
}

type globals struct {
	scan     discovery.Options
	storage  string
	domains  stringList
	email    string
	acme     string
	webroot  string
	json     bool
	dryRun   bool
	yes      bool
	force    bool
	redirect bool
	deploy   bool
	list     bool

	locked bool // the run lock is already held by this process
}

func (g *globals) backupDir() string { return filepath.Join(g.storage, "backups") }
func (g *globals) lockPath() string  { return filepath.Join(g.storage, "certx.lock") }

// lock takes the run lock unless this process already holds it.
func (g *globals) lock() (func(), error) {
	if g.locked {
		return func() {}, nil
	}
	unlock, err := lockfile.Acquire(g.lockPath())
	if err != nil {
		return nil, err
	}
	g.locked = true
	return func() { unlock(); g.locked = false }, nil
}

func main() {
	err := run(os.Args[1:])
	switch {
	case err == nil:
	case errors.Is(err, flag.ErrHelp):
	case errors.Is(err, errCritical):
		os.Exit(2)
	default:
		fmt.Fprintln(os.Stderr, "certx:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	cmd := "tui"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}

	fs := flag.NewFlagSet("certx", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), usage)
		fs.PrintDefaults()
	}
	var g globals
	server := fs.String("server", envOr("CERTX_SERVER", "auto"), "web server to manage: auto, nginx or apache")
	fs.StringVar(&g.scan.NginxConfig, "nginx-conf", os.Getenv("CERTX_NGINX_CONF"), "path to nginx.conf")
	fs.StringVar(&g.scan.ApacheConfig, "apache-conf", os.Getenv("CERTX_APACHE_CONF"), "path to apache2.conf / httpd.conf")
	fs.StringVar(&g.scan.ApacheRoot, "apache-root", os.Getenv("CERTX_APACHE_ROOT"), "Apache ServerRoot (default: derived from config path)")
	fs.IntVar(&g.scan.WarnDays, "warn-days", envInt("CERTX_WARN_DAYS", 30), "days before expiry to report EXPIRING")
	fs.StringVar(&g.storage, "storage", envOr("CERTX_STORAGE", acme.DefaultStorage), "CertX state directory (certificates, accounts, backups)")
	fs.Var(&g.domains, "domain", "domain to act on (repeatable or comma-separated)")
	fs.StringVar(&g.email, "email", os.Getenv("CERTX_EMAIL"), "ACME account email")
	fs.StringVar(&g.acme, "acme", envOr("CERTX_ACME", "staging"), "ACME directory: staging, production or an https URL")
	fs.StringVar(&g.webroot, "webroot", "", "serve HTTP-01 challenges from this existing webroot instead of a temporary snippet")
	fs.BoolVar(&g.json, "json", false, "machine-readable output (scan, plan)")
	fs.BoolVar(&g.dryRun, "dry-run", false, "show what would change without changing anything")
	fs.BoolVar(&g.yes, "yes", false, "do not ask for confirmation")
	fs.BoolVar(&g.force, "force", false, "manage hosts whose certificates belong to another client (e.g. Certbot)")
	fs.BoolVar(&g.redirect, "redirect", false, "add an HTTP to HTTPS redirect when deploying")
	fs.BoolVar(&g.deploy, "deploy", false, "deploy the certificate after issuing it")
	fs.BoolVar(&g.list, "list", false, "list backups (rollback)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	switch *server {
	case "auto", "":
	case "nginx", "apache":
		g.scan.Servers = []webserver.Kind{webserver.Kind(*server)}
	default:
		return fmt.Errorf("unknown --server %q (want auto, nginx or apache)", *server)
	}

	switch cmd {
	case "tui":
		return tui.Run(tui.Options{Scan: g.scan, Storage: g.storage})
	case "scan":
		return cmdScan(&g)
	case "plan":
		return cmdPlan(&g)
	case "issue":
		return cmdIssue(&g)
	case "deploy":
		return cmdDeploy(&g)
	case "rollback":
		return cmdRollback(&g, fs.Args())
	case "validate":
		return cmdValidate(&g)
	case "version":
		fmt.Println("certx", version)
		return nil
	case "help":
		fs.Usage()
		return nil
	default:
		fs.Usage()
		return fmt.Errorf("unknown command %q", cmd)
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(key)); err == nil {
		return v
	}
	return def
}
