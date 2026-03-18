package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ebpf-detect/aura/internal/alerts"
	"github.com/ebpf-detect/aura/internal/engine"
	"github.com/ebpf-detect/aura/internal/loader"
)

const version = "4.0.16"

func main() {
	jsonMode := flag.Bool("json", false, "output alerts as JSON (for SIEM / jq)")
	minLevel := flag.String("level", "INFO", "minimum severity to display: INFO | MEDIUM | HIGH | CRITICAL")
	logFile := flag.String("log", "", "path to log file (JSON, appended)")
	showVer := flag.Bool("version", false, "print version and exit")

	// v2
	wall := flag.Bool("wall", false, "broadcast CRITICAL alerts to all terminals via wall")
	webhookURL := flag.String("webhook", "", "webhook URL for alert HTTP POST")
	emailTo := flag.String("email-to", "", "email address for alerts (requires -email-smtp)")
	emailSMTP := flag.String("email-smtp", "localhost:25", "SMTP server for email alerts")
	emailFrom := flag.String("email-from", "aura@localhost", "from address for email alerts")
	mitigateFlag := flag.Bool("mitigate", false, "auto-kill processes on CRITICAL REVERSE_SHELL events")
	whitelistComms := flag.String("whitelist", "sshd,sudo,systemd,cron", "comma-separated process names to whitelist")

	// v3
	daemonFlag := flag.Bool("daemon", false, "run in background (daemonize, write PID to /var/run/aura.pid)")
	_ = flag.Bool("daemonized", false, "")
	datadogKey := flag.String("datadog-api-key", "", "Datadog API key for event forwarding")
	datadogSite := flag.String("datadog-site", "datadoghq.com", "Datadog site (e.g. datadoghq.eu)")

	// v4
	noCorrelate := flag.Bool("no-correlate", false, "disable kill chain correlation engine")

	flag.Parse()

	if *showVer {
		fmt.Printf("aura v%s\n", version)
		os.Exit(0)
	}

	if *daemonFlag {
		if err := daemonize(); err != nil {
			fmt.Fprintf(os.Stderr, "daemonize: %v\n", err)
			os.Exit(1)
		}
		*jsonMode = true
		if *logFile == "" {
			defaultLog := "/var/log/aura/events.json"
			logFile = &defaultLog
		}
	}

	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "error: must run as root (requires CAP_BPF + CAP_SYS_ADMIN)")
		os.Exit(1)
	}

	level := alerts.Severity(strings.ToUpper(*minLevel))
	switch level {
	case alerts.SevInfo, alerts.SevMedium, alerts.SevHigh, alerts.SevCritical:
	default:
		fmt.Fprintf(os.Stderr, "error: invalid -level %q. use INFO | MEDIUM | HIGH | CRITICAL\n", *minLevel)
		os.Exit(1)
	}

	cfg := alerts.Config{
		JSONMode: *jsonMode,
		MinLevel: level,
		LogFile:  *logFile,
	}

	wl := alerts.NewWhitelist(strings.Split(*whitelistComms, ","))

	det, err := loader.New(cfg, wl, *mitigateFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	printer := det.Printer()

	if *wall {
		n := alerts.NewDedupNotifier(alerts.NewWallNotifier(alerts.SevCritical), 60*time.Second)
		printer.AddNotifier(n)
	}

	if *webhookURL != "" {
		n := alerts.NewDedupNotifier(alerts.NewWebhookNotifier(*webhookURL, alerts.SevHigh), 30*time.Second)
		printer.AddNotifier(n)
	}

	if *emailTo != "" {
		n := alerts.NewDedupNotifier(
			alerts.NewEmailNotifier(*emailSMTP, *emailFrom, []string{*emailTo}, alerts.SevCritical),
			5*time.Minute,
		)
		printer.AddNotifier(n)
	}

	if *datadogKey != "" {
		n := alerts.NewDedupNotifier(
			alerts.NewDatadogNotifier(*datadogKey, alerts.SevHigh, *datadogSite),
			30*time.Second,
		)
		printer.AddNotifier(n)
	}

	stop := make(chan struct{})

	var corr *engine.Correlator
	if !*noCorrelate {
		corr = engine.NewCorrelator(printer, 5*time.Minute)
		printer.AddNotifier(corr)
		go corr.Run(stop)
	}
	_ = corr

	fmt.Printf("aura v%s — loading probes...\n", version)
	if err := det.Load(); err != nil {
		fmt.Fprintf(os.Stderr, "error loading probes: %v\n", err)
		os.Exit(1)
	}
	defer det.Close()

	fmt.Printf("running  pid=%-6d  level=%-8s", os.Getpid(), level)
	if *logFile != "" {
		fmt.Printf("  log=%s", *logFile)
	}
	if *mitigateFlag {
		fmt.Printf("  mitigate=on")
	}
	if !*noCorrelate {
		fmt.Printf("  correlator=on")
	}
	fmt.Println()
	fmt.Println("probes   privesc | memory | bpf_load | net_connect | reverse_shell | module_load | exec | cred_access")
	fmt.Println("+ hidden_proc (userspace goroutine, 5s scan)")
	if !*noCorrelate {
		fmt.Println("+ kill_chain correlator (5m window, 60s decay)")
	}
	fmt.Println("─────────────────────────────────────────────────────────────────")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sig
		fmt.Println()
		det.PrintStats()
		close(stop)
	}()

	if err := det.Run(stop); err != nil {
		fmt.Fprintf(os.Stderr, "runtime error: %v\n", err)
		os.Exit(1)
	}
}
