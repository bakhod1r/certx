package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/bakhod1r/certx/internal/acme"
	"github.com/bakhod1r/certx/internal/certificate"
	"github.com/bakhod1r/certx/internal/deployment"
	"github.com/bakhod1r/certx/internal/discovery"
	"github.com/bakhod1r/certx/internal/issuer"
	"github.com/bakhod1r/certx/internal/logx"
	"github.com/bakhod1r/certx/internal/plan"
	"github.com/bakhod1r/certx/internal/webserver"
)

func scan(g *globals) (*discovery.Inventory, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	return discovery.Scan(ctx, g.scan)
}

func cmdScan(g *globals) error {
	inv, err := scan(g)
	if err != nil {
		return err
	}
	if g.json {
		if err := printJSON(inv); err != nil {
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
		printWarnings(inv)
	}
	for _, h := range inv.Hosts {
		if h.Enabled && h.Status.Critical() {
			return errCritical
		}
	}
	return nil
}

func cmdValidate(g *globals) error {
	inv, err := scan(g)
	if err != nil {
		return err
	}
	fmt.Println(discovery.Validate(context.Background(), inv))
	return nil
}

// ---------------------------------------------------------------- plan

func cmdPlan(g *globals) error {
	inv, err := scan(g)
	if err != nil {
		return err
	}
	actions := plan.Actions(inv, plan.Options{Domains: g.domains, Force: g.force})

	type jsonAction struct {
		Server   webserver.Kind `json:"server"`
		Location string         `json:"location"`
		Names    []string       `json:"names"`
		Status   string         `json:"status"`
		NeedCert bool           `json:"need_cert"`
		Reason   string         `json:"reason"`
		Skip     string         `json:"skip,omitempty"`
		Command  string         `json:"command,omitempty"`
		Diff     string         `json:"diff,omitempty"`
		Notes    []string       `json:"notes,omitempty"`
	}
	var out []jsonAction
	for _, a := range actions {
		ja := jsonAction{
			Server: a.Host.Server, Location: a.Host.Location(), Names: a.Names,
			Status: string(a.Host.Status), NeedCert: a.NeedCert, Reason: a.Reason, Skip: a.Skip,
		}
		if a.NeedCert && a.Skip == "" {
			ja.Command = issueCommand(a.Names)
			name, err := acme.CertName(a.Names[0])
			if err != nil {
				return err
			}
			cs, err := plan.Changes(inv, "deploy", []discovery.Host{a.Host},
				plan.TLS(acme.Paths(g.storage, name), webserver.TLSOptions{Redirect: g.redirect}))
			if err != nil {
				ja.Skip = err.Error()
			} else if !cs.Empty() {
				ja.Diff = deployment.Diff(cs)
				ja.Notes = cs.Notes
			}
		}
		out = append(out, ja)
	}
	if g.json {
		return printJSON(out)
	}
	if len(out) == 0 {
		fmt.Println("No enabled virtual hosts with public names found.")
		printWarnings(inv)
		return nil
	}
	pending := 0
	for _, a := range out {
		mark := "✔"
		switch {
		case a.Skip != "":
			mark = "–"
		case a.NeedCert:
			mark = "→"
			pending++
		}
		fmt.Printf("%s %s  [%s %s]\n", mark, strings.Join(a.Names, ", "), a.Server, a.Location)
		fmt.Printf("    status: %s — %s\n", a.Status, a.Reason)
		if a.Skip != "" {
			fmt.Printf("    skipped: %s\n", a.Skip)
			continue
		}
		if a.Command != "" {
			fmt.Printf("    run: %s\n", a.Command)
		}
		if a.Diff != "" {
			fmt.Println("    configuration change on deploy:")
			fmt.Println(indent(a.Diff, "      "))
		}
		for _, n := range a.Notes {
			fmt.Println("    note:", n)
		}
	}
	fmt.Printf("\n%d of %d sites need a certificate. Nothing was changed.\n", pending, len(out))
	printWarnings(inv)
	return nil
}

func issueCommand(names []string) string {
	var b strings.Builder
	b.WriteString("certx issue")
	for _, n := range names {
		b.WriteString(" --domain " + n)
	}
	b.WriteString(" --deploy")
	return b.String()
}

// ---------------------------------------------------------------- issue

func cmdIssue(g *globals) error {
	if len(g.domains) == 0 {
		return errors.New("--domain is required")
	}
	dir, err := acme.DirectoryURL(g.acme)
	if err != nil {
		return err
	}
	inv, err := scan(g)
	if err != nil {
		return err
	}
	preflight(g.domains)

	req := issuer.Request{
		Inv: inv, Storage: g.storage, Directory: dir, Email: g.email, Domains: g.domains,
		Webroot: g.webroot, Retry: issuer.Retry{Attempts: 2, Delay: 10 * time.Second}, Out: os.Stdout,
	}
	p, err := issuer.Prepare(req)
	if err != nil {
		return err
	}
	fmt.Printf("Certificate:  %s\n", strings.Join(g.domains, ", "))
	fmt.Printf("CA:           %s\n", dir)
	fmt.Printf("Storage:      %s\n", filepath.Dir(p.Paths.Cert))
	fmt.Printf("Challenge:    HTTP-01 from %s\n", p.Webroot)
	if dir == acme.LetsEncryptStaging {
		fmt.Println("Note:         staging certificates are not trusted by browsers; use --acme production when ready")
	}
	if !p.Challenge.Empty() {
		fmt.Println("\nTemporary configuration for the challenge (removed afterwards):")
		fmt.Println(indent(deployment.Diff(p.Challenge), "  "))
	}
	if g.dryRun {
		fmt.Println("Dry run: nothing was changed.")
		return nil
	}
	if !confirm(g.yes, "Request the certificate?") {
		return errors.New("aborted")
	}
	release, err := g.lock()
	if err != nil {
		return err
	}
	defer release()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()
	acme.SetLogOutput(io.Discard)
	if f, lerr := logx.Open(g.logFile); g.logFile != "" && lerr == nil {
		defer f.Close()
		acme.SetLogOutput(f)
	}
	info, err := issuer.Execute(ctx, req, p)
	audit(g, "issue", g.domains, err, "")
	if err != nil {
		return err
	}
	fmt.Printf("✔ Certificate saved to %s (expires %s)\n", p.Paths.Cert, info.NotAfter.Format(time.DateOnly))

	if !g.deploy {
		fmt.Printf("Next: certx deploy --domain %s\n", g.domains[0])
		return nil
	}
	g.yes = true // already confirmed
	return cmdDeploy(g)
}

// preflight prints DNS warnings; ownership is proven by the ACME challenge.
func preflight(domains []string) {
	for _, d := range domains {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, d)
		cancel()
		switch {
		case err != nil:
			fmt.Fprintf(os.Stderr, "warning: %s does not resolve: %v\n", d, err)
		case len(ips) > 0:
			var s []string
			for _, ip := range ips {
				s = append(s, ip.String())
			}
			fmt.Printf("DNS:          %s → %s\n", d, strings.Join(s, ", "))
		}
	}
}

// ---------------------------------------------------------------- deploy

func cmdDeploy(g *globals) error {
	if len(g.domains) == 0 {
		return errors.New("--domain is required")
	}
	name, err := acme.CertName(g.domains[0])
	if err != nil {
		return err
	}
	paths := acme.Paths(g.storage, name)
	local, err := certificate.Inspect(paths.Cert, paths.Key, time.Now())
	if err != nil {
		return fmt.Errorf("no usable CertX certificate for %s (run certx issue first): %w", g.domains[0], err)
	}
	if local.KeyMatch == nil || !*local.KeyMatch {
		return fmt.Errorf("%s: certificate and key do not match", paths.Cert)
	}
	for _, d := range g.domains {
		if !local.Covers(d) {
			return fmt.Errorf("%s does not cover %s", paths.Cert, d)
		}
	}

	inv, err := scan(g)
	if err != nil {
		return err
	}
	var hosts []discovery.Host
	for _, a := range plan.Actions(inv, plan.Options{Domains: g.domains, Force: g.force}) {
		if a.Host.ManagedBy == "certbot" && !g.force {
			fmt.Printf("– skipping %s: %s\n", a.Host.Location(), "certificate is managed by Certbot (use --force)")
			continue
		}
		hosts = append(hosts, a.Host)
	}
	if len(hosts) == 0 {
		return fmt.Errorf("no enabled virtual host to deploy %s to", strings.Join(g.domains, ", "))
	}
	cs, err := plan.Changes(inv, "deploy "+name, hosts, plan.TLS(paths, webserver.TLSOptions{Redirect: g.redirect}))
	if err != nil {
		return err
	}
	if cs.Empty() {
		fmt.Println("✔ Configuration already uses this certificate.")
		return nil
	}
	fmt.Println(deployment.Diff(cs))
	for _, n := range cs.Notes {
		fmt.Println("note:", n)
	}
	if g.dryRun {
		fmt.Println("Dry run: nothing was changed.")
		return nil
	}
	if !confirm(g.yes, "Apply these changes?") {
		return errors.New("aborted")
	}
	release, err := g.lock()
	if err != nil {
		return err
	}
	defer release()

	step("Backing up, testing configuration and reloading")
	m, err := deployment.Apply(context.Background(), cs, issuer.Targets(inv), g.backupDir())
	backupID := ""
	if m != nil {
		backupID = m.ID
	}
	audit(g, "deploy", g.domains, err, backupID)
	if err != nil {
		return err
	}
	fmt.Printf("✔ Deployed (backup %s; undo with: certx rollback %s)\n", m.ID, m.ID)

	for _, d := range g.domains {
		verifyServed(d, local.FingerprintSHA256)
	}
	return nil
}

// verifyServed checks that the domain now serves the certificate with the
// given fingerprint. A graceful reload is asynchronous, so it retries for a
// few seconds before warning. Problems are reported, not returned: the
// configuration is already valid and live.
func verifyServed(domain, fingerprint string) {
	var (
		remote *certificate.Info
		err    error
	)
	for deadline := time.Now().Add(8 * time.Second); ; {
		remote, err = certificate.Remote(context.Background(), domain, 443, domain, time.Now())
		if (err == nil && remote.FingerprintSHA256 == fingerprint) || time.Now().After(deadline) {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	switch {
	case err != nil:
		fmt.Fprintf(os.Stderr, "warning: could not verify https://%s: %v\n", domain, err)
	case remote.FingerprintSHA256 != fingerprint:
		fmt.Fprintf(os.Stderr, "warning: https://%s still serves a different certificate (serial %s)\n", domain, remote.Serial)
	default:
		fmt.Printf("✔ https://%s serves the new certificate\n", domain)
	}
}

// ---------------------------------------------------------------- rollback

func cmdRollback(g *globals, args []string) error {
	if g.list || len(args) == 0 {
		ms, err := deployment.List(g.backupDir())
		if err != nil {
			return err
		}
		if len(ms) == 0 {
			fmt.Println("No backups.")
			return nil
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tCREATED\tLABEL\tFILES\tSTATE")
		for _, m := range ms {
			state := "applied"
			if m.RolledBack {
				state = "rolled back"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\n", m.ID, m.Created.Local().Format(time.DateTime), m.Label, len(m.Entries), state)
		}
		return tw.Flush()
	}
	id := args[0]
	m, err := deployment.Load(g.backupDir(), id)
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("backup %s not found", id)
	}
	if err != nil {
		return err
	}
	for _, e := range m.Entries {
		action := "restore"
		if !e.Existed {
			action = "remove"
		}
		fmt.Printf("  %s %s\n", action, e.Path)
	}
	if g.dryRun {
		fmt.Println("Dry run: nothing was changed.")
		return nil
	}
	if !confirm(g.yes, "Roll back "+m.Label+"?") {
		return errors.New("aborted")
	}
	release, err := g.lock()
	if err != nil {
		return err
	}
	defer release()
	inv, err := scan(g)
	if err != nil {
		return err
	}
	_, err = deployment.Rollback(context.Background(), g.backupDir(), id, issuer.Targets(inv))
	audit(g, "rollback", nil, err, id)
	if err != nil {
		return err
	}
	fmt.Println("✔ Rolled back", id)
	return nil
}

// ---------------------------------------------------------------- helpers

// audit records an action in the audit trail; failures only warn.
func audit(g *globals, action string, domains []string, err error, backup string) {
	e := logx.Event{Action: action, Domains: domains, Result: "ok", Backup: backup}
	if err != nil {
		e.Result, e.Detail = "failed", err.Error()
	}
	if aerr := logx.Audit(g.storage, e); aerr != nil {
		fmt.Fprintln(os.Stderr, "warning: audit log:", aerr)
	}
}

func confirm(yes bool, prompt string) bool {
	if yes {
		return true
	}
	fmt.Fprintf(os.Stderr, "%s [y/N]: ", prompt)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	}
	return false
}

func step(s string) { fmt.Println("…", s) }

func indent(s, prefix string) string {
	s = strings.TrimRight(s, "\n")
	return prefix + strings.ReplaceAll(s, "\n", "\n"+prefix)
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func printWarnings(inv *discovery.Inventory) {
	for _, w := range inv.Warnings {
		fmt.Fprintln(os.Stderr, "warning:", w)
	}
}
