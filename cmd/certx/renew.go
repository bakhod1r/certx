package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/bakhod1r/certx/internal/acme"
	"github.com/bakhod1r/certx/internal/discovery"
	"github.com/bakhod1r/certx/internal/issuer"
	"github.com/bakhod1r/certx/internal/logx"
	"github.com/bakhod1r/certx/internal/notify"
	"github.com/bakhod1r/certx/internal/renewal"
	"github.com/bakhod1r/certx/internal/scheduler"
	"github.com/bakhod1r/certx/internal/state"
)

// errRenewFailed makes `certx renew` exit non-zero for timers and CI.
var errRenewFailed = errors.New("one or more renewals failed")

func cmdRenew(g *globals) error {
	dir, err := acme.DirectoryURL(g.acme)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	acme.SetLogOutput(io.Discard)
	if g.logFile != "" && !g.dryRun {
		if f, err := logx.Open(g.logFile); err != nil {
			fmt.Fprintln(os.Stderr, "warning: log file:", err)
		} else {
			defer f.Close()
			log = slog.New(slog.NewTextHandler(f, nil))
			acme.SetLogOutput(f) // ACME protocol details go to the file, not the terminal
		}
	}

	if !g.dryRun {
		release, err := g.lock()
		if err != nil {
			return err
		}
		defer release()
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()

	run := &state.Run{Started: time.Now().UTC()}
	log.Info("renew started", "window_days", g.windowDays, "dry_run", g.dryRun)
	inv, err := discovery.Scan(ctx, g.scan)
	if err != nil {
		return err
	}
	var progress io.Writer = os.Stdout
	if g.quiet {
		progress = io.Discard
	}
	results, err := renewal.Run(ctx, renewal.Options{
		Inv: inv, Storage: g.storage, DefaultDirectory: dir, DefaultEmail: g.email,
		WindowDays: g.windowDays, Force: g.force, DryRun: g.dryRun, Domains: g.domains,
		Retry: issuer.DefaultRetry, Out: progress,
	})
	if err != nil {
		return err
	}

	if len(results) == 0 && !g.quiet {
		fmt.Println("No CertX certificates found (issue one with: certx issue --domain ...).")
	}
	var renewed, failed, alerts []string
	for _, r := range results {
		names := strings.Join(r.Domains, ", ")
		if names == "" {
			names = r.Name
		}
		switch r.Action {
		case renewal.Skipped:
			run.Skipped++
			if !g.quiet {
				fmt.Printf("– %s: %s\n", names, r.Reason)
			}
		case renewal.WouldRenew:
			fmt.Printf("→ %s: would renew (%s)\n", names, r.Reason)
		case renewal.Renewed, renewal.NotDeployed:
			run.Renewed++
			line := fmt.Sprintf("%s renewed, valid until %s", names, r.NotAfter.Format(time.DateOnly))
			if r.Action == renewal.NotDeployed || r.Reason != "" && !strings.HasPrefix(r.Reason, "expires") && r.Reason != "forced" {
				line += " — " + r.Reason
			}
			renewed = append(renewed, line)
			fmt.Println("✔", line)
		case renewal.Failed:
			run.Failed++
			line := fmt.Sprintf("%s: %s", names, firstLine(r.Error))
			if r.DaysLeft < 0 {
				line += " — CERTIFICATE IS EXPIRED"
			} else if !r.NotAfter.IsZero() {
				line += fmt.Sprintf(" — current certificate expires in %d days", r.DaysLeft)
			}
			failed = append(failed, line)
			fmt.Fprintln(os.Stderr, "✖", line)
			fmt.Fprintln(os.Stderr, indent(r.Error, "    "))
		}
		log.Info("certificate", "name", r.Name, "action", string(r.Action), "reason", r.Reason, "days_left", r.DaysLeft, "error", r.Error)
		if r.Action != renewal.Skipped && r.Action != renewal.WouldRenew {
			var err error
			if r.Error != "" {
				err = errors.New(r.Error)
			}
			audit(g, "renew", r.Domains, err, "")
		}
	}

	// Monitoring: other certificates on this server (Certbot, manual) that
	// are about to expire or already have.
	for _, h := range inv.Hosts {
		if !h.Enabled || h.Cert == nil || h.ManagedBy == "certx" {
			continue
		}
		if h.Cert.DaysLeft <= g.alertDays {
			alerts = append(alerts, fmt.Sprintf("%s (%s, %s) expires in %d days", strings.Join(h.Names, ", "), h.ManagedBy, h.Location(), h.Cert.DaysLeft))
		}
	}
	for _, a := range alerts {
		fmt.Fprintln(os.Stderr, "⚠", a)
	}

	run.Finished = time.Now().UTC()
	run.Results = results
	log.Info("renew finished", "renewed", run.Renewed, "skipped", run.Skipped, "failed", run.Failed, "alerts", len(alerts))
	if g.dryRun {
		return nil
	}
	if err := state.SaveRun(g.storage, run); err != nil {
		fmt.Fprintln(os.Stderr, "warning: state:", err)
	}

	if msg, ok := renewMessage(renewed, failed, alerts); ok {
		if ns := notify.FromEnv(); len(ns) > 0 {
			nctx, ncancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer ncancel()
			if err := notify.SendAll(nctx, ns, msg); err != nil {
				fmt.Fprintln(os.Stderr, "warning: notification:", err)
				log.Warn("notification failed", "error", err.Error())
			}
		}
	}
	if run.Failed > 0 {
		return errRenewFailed
	}
	return nil
}

// renewMessage builds the notification; ok is false when there is nothing
// worth telling anyone (every certificate was simply skipped).
func renewMessage(renewed, failed, alerts []string) (notify.Message, bool) {
	m := notify.Message{Level: notify.Info}
	switch {
	case len(failed) > 0:
		m.Level, m.Title = notify.Error, fmt.Sprintf("%d certificate renewal(s) failed", len(failed))
	case len(alerts) > 0:
		m.Level, m.Title = notify.Warning, fmt.Sprintf("%d certificate(s) expiring soon", len(alerts))
	case len(renewed) > 0:
		m.Title = fmt.Sprintf("%d certificate(s) renewed", len(renewed))
	default:
		return m, false
	}
	for _, f := range failed {
		m.Lines = append(m.Lines, "FAILED: "+f)
	}
	for _, a := range alerts {
		m.Lines = append(m.Lines, "EXPIRING: "+a)
	}
	for _, r := range renewed {
		m.Lines = append(m.Lines, "renewed: "+r)
	}
	return m, true
}

func cmdNotify(g *globals) error {
	ns := notify.FromEnv()
	if len(ns) == 0 {
		return errors.New("no notification channel configured (set CERTX_WEBHOOK_URL, CERTX_TELEGRAM_TOKEN + CERTX_TELEGRAM_CHAT_ID or CERTX_SMTP_ADDR + CERTX_EMAIL_TO)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	msg := notify.Message{Level: notify.Info, Title: "test notification", Lines: []string{"If you can read this, CertX alerts work."}}
	var failed bool
	for _, n := range ns {
		if err := n.Send(ctx, msg); err != nil {
			failed = true
			fmt.Fprintf(os.Stderr, "✖ %s: %v\n", n.Name(), err)
		} else {
			fmt.Printf("✔ %s\n", n.Name())
		}
	}
	if failed {
		return errors.New("some notifications failed")
	}
	return nil
}

// ---------------------------------------------------------------- scheduler

func cmdScheduler(g *globals, args []string) error {
	action := "status"
	if len(args) > 0 {
		action = args[0]
	}
	s := scheduler.Default()
	ctx := context.Background()
	switch action {
	case "install":
		kind := scheduler.Kind(g.scheduler)
		if g.scheduler == "auto" || g.scheduler == "" {
			kind = s.Detect()
		}
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		command := append([]string{exe, "renew", "--yes"}, g.setFlags...)
		files, err := s.Files(kind, command)
		if err != nil {
			return err
		}
		for _, f := range files {
			fmt.Printf("--- %s\n%s\n", f.Path, f.Content)
		}
		if g.dryRun {
			fmt.Println("Dry run: nothing was changed.")
			return nil
		}
		if !confirm(g.yes, fmt.Sprintf("Install the %s renewal job?", kind)) {
			return errors.New("aborted")
		}
		if _, err := s.Install(ctx, kind, command); err != nil {
			return err
		}
		fmt.Printf("✔ Installed %s job: certx renew runs twice a day\n", kind)
		printConflicts(s.Status(ctx))
		return nil
	case "uninstall":
		if !confirm(g.yes, "Remove the CertX renewal job?") {
			return errors.New("aborted")
		}
		removed, err := s.Uninstall(ctx)
		for _, p := range removed {
			fmt.Println("removed", p)
		}
		if err == nil && len(removed) == 0 {
			fmt.Println("No CertX renewal job installed.")
		}
		return err
	case "status":
		st := s.Status(ctx)
		if g.json {
			last, _ := state.LastRun(g.storage)
			return printJSON(map[string]any{"scheduler": st, "last_run": last})
		}
		if st.Kind == "" {
			fmt.Println("Scheduler:  not installed (run: certx scheduler install)")
		} else {
			fmt.Printf("Scheduler:  %s\n", st.Kind)
			for _, f := range st.Files {
				fmt.Printf("            %s\n", f)
			}
			if st.NextRun != "" {
				fmt.Printf("Next run:   %s\n", st.NextRun)
			}
		}
		last, err := state.LastRun(g.storage)
		switch {
		case err != nil:
			fmt.Println("Last run:   unreadable:", err)
		case last == nil:
			fmt.Println("Last run:   never")
		default:
			mark := "✔"
			if !last.OK() {
				mark = "✖"
			}
			fmt.Printf("Last run:   %s %s (%s ago) — %d renewed, %d skipped, %d failed\n",
				mark, last.Finished.Local().Format(time.DateTime), time.Since(last.Finished).Round(time.Second),
				last.Renewed, last.Skipped, last.Failed)
		}
		printConflicts(st)
		return nil
	}
	return fmt.Errorf("unknown scheduler action %q (want install, status or uninstall)", action)
}

func printConflicts(st scheduler.Status) {
	for _, c := range st.Conflicts {
		fmt.Println("note:", c)
	}
}

func firstLine(s string) string {
	l, _, _ := strings.Cut(s, "\n")
	return l
}
