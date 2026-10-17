// Command certx discovers Nginx and Apache virtual hosts and audits their
// TLS certificates.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/bakhod1r/certx/internal/discovery"
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
  tui       Interactive terminal UI (default)
  scan      Discover virtual hosts and audit certificates
  validate  Run nginx -t / apachectl -t
  version   Print version

Flags:
`

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
	var opts discovery.Options
	server := fs.String("server", envOr("CERTX_SERVER", "auto"), "web server to inspect: auto, nginx or apache")
	fs.StringVar(&opts.NginxConfig, "nginx-conf", os.Getenv("CERTX_NGINX_CONF"), "path to nginx.conf")
	fs.StringVar(&opts.ApacheConfig, "apache-conf", os.Getenv("CERTX_APACHE_CONF"), "path to apache2.conf / httpd.conf")
	fs.StringVar(&opts.ApacheRoot, "apache-root", os.Getenv("CERTX_APACHE_ROOT"), "Apache ServerRoot (default: derived from config path)")
	fs.IntVar(&opts.WarnDays, "warn-days", envInt("CERTX_WARN_DAYS", 30), "days before expiry to report EXPIRING")
	jsonOut := fs.Bool("json", false, "machine-readable output (scan)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	switch *server {
	case "auto", "":
	case "nginx", "apache":
		opts.Servers = []webserver.Kind{webserver.Kind(*server)}
	default:
		return fmt.Errorf("unknown --server %q (want auto, nginx or apache)", *server)
	}

	switch cmd {
	case "tui":
		return tui.Run(opts)
	case "scan":
		return scan(opts, *jsonOut)
	case "validate":
		inv, err := discovery.Scan(context.Background(), opts)
		if err != nil {
			return err
		}
		fmt.Println(discovery.Validate(context.Background(), opts, inv))
		return nil
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

func scan(opts discovery.Options, asJSON bool) error {
	inv, err := discovery.Scan(context.Background(), opts)
	if err != nil {
		return err
	}
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(inv); err != nil {
			return err
		}
	} else {
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "SERVER\tSTATUS\tDAYS\tPORTS\tDOMAINS\tCONFIG")
		for _, h := range inv.Hosts {
			days := "-"
			if h.Cert != nil {
				days = strconv.Itoa(h.Cert.DaysLeft)
			}
			loc := h.Location()
			if !h.Enabled {
				loc += " (disabled)"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", h.Server, h.Status, days, h.Ports(), strings.Join(h.Names, " "), loc)
		}
		tw.Flush()
		for _, w := range inv.Warnings {
			fmt.Fprintln(os.Stderr, "warning:", w)
		}
	}
	for _, h := range inv.Hosts {
		if h.Enabled && h.Status.Critical() {
			return errCritical
		}
	}
	return nil
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
