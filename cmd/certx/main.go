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
	"time"

	"github.com/bakhod1r/certx/internal/acme"
	"github.com/bakhod1r/certx/internal/config"
	"github.com/bakhod1r/certx/internal/discovery"
	"github.com/bakhod1r/certx/internal/lockfile"
	"github.com/bakhod1r/certx/internal/plan"
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
  renew      Renew CertX certificates inside the renewal window (for timers)
  revoke     Revoke a CertX certificate (it is re-issued by the next renew)
  doctor     Diagnose the environment: servers, ports, DNS, CAA, CA, storage
  metrics    Print Prometheus metrics (or write them with --metrics-file)
  scheduler  install | status | uninstall the twice-daily renewal job
  notify     Send a test notification to the configured channels
  validate   Run nginx -t / apachectl -t
  version    Print version

Examples:
  certx plan
  certx issue  --domain example.com --domain www.example.com --email ops@example.com
  certx issue  --domain example.com --acme production --deploy --redirect
  certx issue  --domain '*.example.com' --domain example.com --dns cloudflare --deploy
  certx deploy --domain example.com --dry-run
  certx rollback --list
  certx renew --dry-run
  certx scheduler install

Settings and secrets (CERTX_WEBHOOK_URL, CERTX_TELEGRAM_TOKEN, CERTX_TELEGRAM_CHAT_ID,
CERTX_SMTP_ADDR, CERTX_EMAIL_TO, ...) can live in /etc/certx/env (KEY=VALUE, chmod 600).

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

	windowDays int
	alertDays  int
	timeout    time.Duration
	quiet      bool
	logFile    string
	scheduler  string
	dns        string
	reason     string
	metrics    string
	filter     plan.Filter
	setFlags   []string // flags given explicitly, forwarded to the scheduled job

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
	case errors.Is(err, errRenewFailed):
		os.Exit(1)
	default:
		fmt.Fprintln(os.Stderr, "certx:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	envFile := envOr("CERTX_ENV_FILE", config.DefaultEnvFile)
	if warn, err := config.LoadEnvFile(envFile); err != nil {
		return err
	} else if warn != "" {
		fmt.Fprintln(os.Stderr, "warning:", warn)
	}

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
	fs.IntVar(&g.windowDays, "window-days", envInt("CERTX_RENEW_DAYS", 30), "renew certificates expiring within this many days")
	fs.IntVar(&g.alertDays, "alert-days", envInt("CERTX_ALERT_DAYS", 14), "notify about certificates expiring within this many days")
	fs.DurationVar(&g.timeout, "timeout", 30*time.Minute, "overall time limit for issue and renew")
	fs.BoolVar(&g.quiet, "quiet", false, "only print renewals, failures and alerts (renew)")
	fs.StringVar(&g.logFile, "log-file", envOr("CERTX_LOG_FILE", "/var/log/certx/certx.log"), "renew log file (rotated); empty disables")
	fs.StringVar(&g.scheduler, "scheduler", "auto", "scheduler backend: auto, systemd or cron")
	fs.StringVar(&g.dns, "dns", os.Getenv("CERTX_DNS"), "DNS-01 provider (required for wildcards): "+strings.Join(dnsNames(), ", "))
	fs.StringVar(&g.reason, "reason", "unspecified", "revocation reason: unspecified, keyCompromise, superseded, cessationOfOperation")
	fs.StringVar(&g.metrics, "metrics-file", os.Getenv("CERTX_METRICS_FILE"), "write Prometheus metrics here (node_exporter textfile collector)")
	exclude := stringList(splitEnv("CERTX_EXCLUDE"))
	allow := stringList(splitEnv("CERTX_ALLOW"))
	fs.Var(&exclude, "exclude", "never manage domains matching these patterns, e.g. '*.internal,staging.*'")
	fs.Var(&allow, "allow", "only manage domains matching these patterns")
	positional, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	g.filter = plan.Filter{Allow: allow, Exclude: exclude}
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "server", "nginx-conf", "apache-conf", "apache-root", "storage", "acme", "email",
			"window-days", "alert-days", "warn-days", "log-file", "timeout", "exclude", "allow", "metrics-file":
			g.setFlags = append(g.setFlags, "--"+f.Name+"="+f.Value.String())
		}
	})
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
		return cmdRollback(&g, positional)
	case "renew":
		return cmdRenew(&g)
	case "scheduler":
		return cmdScheduler(&g, positional)
	case "notify":
		return cmdNotify(&g)
	case "revoke":
		return cmdRevoke(&g)
	case "doctor":
		return cmdDoctor(&g)
	case "metrics":
		return cmdMetrics(&g)
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

// parseInterspersed parses flags that appear before, between or after
// positional arguments ("scheduler install --yes", "rollback ID --yes").
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return positional, nil
		}
		if rest[0] == "--" {
			return append(positional, rest[1:]...), nil
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
}

func splitEnv(key string) []string {
	var out []string
	for _, p := range strings.Split(os.Getenv(key), ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, strings.ToLower(p))
		}
	}
	return out
}

func dnsNames() []string {
	var out []string
	for _, p := range acme.DNSProviders() {
		name, _, _ := strings.Cut(p, ":")
		out = append(out, name)
	}
	return out
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
