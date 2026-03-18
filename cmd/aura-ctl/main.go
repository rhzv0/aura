package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const version = "4.0.16"

const (
	colorCritical  = "\033[1;31m"
	colorHigh      = "\033[31m"
	colorMedium    = "\033[33m"
	colorInfo      = "\033[36m"
	colorKillChain = "\033[1;35m"
	colorRiskScore = "\033[35m"
	colorReset     = "\033[0m"
	colorBold      = "\033[1m"
	colorDim       = "\033[2m"
)

func sevColor(sev string) string {
	switch sev {
	case "CRITICAL":
		return colorCritical
	case "HIGH":
		return colorHigh
	case "MEDIUM":
		return colorMedium
	case "INFO":
		return colorInfo
	default:
		return colorReset
	}
}

func typeColor(typ string) string {
	switch typ {
	case "KILL_CHAIN":
		return colorKillChain
	case "RISK_SCORE":
		return colorRiskScore
	default:
		return ""
	}
}

var sevRank = map[string]int{
	"INFO": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4,
}

type event struct {
	Timestamp   time.Time      `json:"timestamp"`
	Severity    string         `json:"severity"`
	Type        string         `json:"type"`
	PID         uint32         `json:"pid"`
	UID         uint32         `json:"uid"`
	Comm        string         `json:"comm"`
	Description string         `json:"description"`
	Details     map[string]any `json:"details,omitempty"`
	Technique   string         `json:"technique,omitempty"`
	Tactic      string         `json:"tactic,omitempty"`
	Score       int            `json:"score,omitempty"`
}

const pidFile = "/var/run/aura.pid"

func main() {
	logFile := flag.String("log", "/var/log/aura/events.json", "aura log file")
	minSev := flag.String("level", "HIGH", "minimum severity: INFO|MEDIUM|HIGH|CRITICAL")
	tailMode := flag.Bool("tail", false, "follow log in real time")
	last := flag.Int("last", 20, "show last N events (non-tail mode)")
	showVer := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVer {
		fmt.Printf("aura-ctl v%s\n", version)
		os.Exit(0)
	}

	args := flag.Args()
	if len(args) > 0 {
		switch args[0] {
		case "status":
			showStatus(*logFile)
			return
		case "stop":
			stopDaemon()
			return
		case "start":
			startDaemon()
			return
		case "restart":
			stopDaemon()
			time.Sleep(1 * time.Second)
			startDaemon()
			return
		case "risks":
			showRisks(*logFile)
			return
		case "chains":
			showChains(*logFile)
			return
		}
	}

	if *tailMode {
		tailLog(*logFile, *minSev)
	} else {
		showLast(*logFile, *minSev, *last)
	}
}

func stopDaemon() {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		fmt.Println("aura not running (no pid file)")
		os.Exit(1)
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(data)))
	proc, err := os.FindProcess(pid)
	if err != nil {
		fmt.Printf("aura not running (pid %d)\n", pid)
		os.Exit(1)
	}
	if proc.Signal(syscall.Signal(0)) != nil {
		fmt.Printf("aura not running (pid %d stale)\n", pid)
		os.Remove(pidFile)
		os.Exit(1)
	}
	proc.Signal(syscall.SIGTERM)
	fmt.Printf("aura stopped (pid %d)\n", pid)
}

func startDaemon() {
	binPaths := []string{
		"/opt/aura/bin/aura-current",
		"/opt/aura/bin/aura-v4",
		"/opt/aura/bin/aura-v3",
	}
	var auraBin string
	for _, p := range binPaths {
		if _, err := os.Stat(p); err == nil {
			auraBin = p
			break
		}
	}
	if auraBin == "" {
		p, err := exec.LookPath("aura")
		if err != nil {
			fmt.Fprintln(os.Stderr, "error: cannot find aura binary")
			os.Exit(1)
		}
		auraBin = p
	}

	cmd := exec.Command(auraBin, "-daemon", "-json", "-log", "/var/log/aura/events.json")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "error starting aura: %v\n", err)
		os.Exit(1)
	}
}

func readEvents(logFile string) ([]event, error) {
	f, err := os.Open(logFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var events []event
	scanner := bufio.NewScanner(f)
	buf := make([]byte, 0, 1024*1024)
	scanner.Buffer(buf, 1024*1024)
	for scanner.Scan() {
		var e event
		if json.Unmarshal(scanner.Bytes(), &e) != nil {
			continue
		}
		events = append(events, e)
	}
	return events, nil
}

func showStatus(logFile string) {
	events, err := readEvents(logFile)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "no log file found at %s\n", logFile)
			fmt.Fprintln(os.Stderr, "hint: start aura with -log flag or use -log to specify the correct path")
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	bySev := make(map[string]int)
	byType := make(map[string]int)
	total := 0
	var firstTS, lastTS time.Time

	for _, e := range events {
		bySev[e.Severity]++
		byType[e.Type]++
		total++
		if firstTS.IsZero() || e.Timestamp.Before(firstTS) {
			firstTS = e.Timestamp
		}
		if lastTS.IsZero() || e.Timestamp.After(lastTS) {
			lastTS = e.Timestamp
		}
	}

	pidStatus := "STOPPED"
	pidNum := 0
	if data, err := os.ReadFile(pidFile); err == nil {
		pid, _ := strconv.Atoi(strings.TrimSpace(string(data)))
		proc, err := os.FindProcess(pid)
		if err == nil && proc.Signal(syscall.Signal(0)) == nil {
			pidStatus = "RUNNING"
			pidNum = pid
		} else {
			pidStatus = "STALE PID"
			pidNum = pid
		}
	}

	uptime := ""
	if !firstTS.IsZero() && !lastTS.IsZero() {
		d := lastTS.Sub(firstTS)
		if d < time.Minute {
			uptime = fmt.Sprintf("%ds", int(d.Seconds()))
		} else if d < time.Hour {
			uptime = fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
		} else {
			uptime = fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
		}
	}

	killChains := byType["KILL_CHAIN"]
	riskAlerts := byType["RISK_SCORE"]
	lastEvent := ""
	if !lastTS.IsZero() {
		lastEvent = lastTS.Format("15:04:05")
	}

	w := 64
	fmt.Printf("%s%s Aura v%s %s%s\n", colorBold, "\u250c\u2500", version, strings.Repeat("\u2500", w-len(version)-14), "\u2510")

	pidStr := ""
	if pidNum > 0 {
		pidStr = fmt.Sprintf("  \u2502  PID: %d", pidNum)
	}
	uptimeStr := ""
	if uptime != "" {
		uptimeStr = fmt.Sprintf("  \u2502  Uptime: %s", uptime)
	}
	statusColor := colorCritical
	if pidStatus == "RUNNING" {
		statusColor = "\033[32m"
	}
	line := fmt.Sprintf("\u2502 Status: %s%s%s%s%s", statusColor, pidStatus, colorReset+colorBold, pidStr, uptimeStr)
	pad := w + 1 - visLen(line)
	if pad < 1 {
		pad = 1
	}
	fmt.Printf("%s%s%s\u2502%s\n", colorBold, line, strings.Repeat(" ", pad), colorReset)

	fmt.Printf("%s\u251c%s\u2524%s\n", colorBold, strings.Repeat("\u2500", w), colorReset)
	fmt.Printf("%s\u2502 %-28s\u2502  %-30s\u2502%s\n", colorBold, "Events by Severity", "Events by Type", colorReset)

	sevOrder := []string{"CRITICAL", "HIGH", "MEDIUM", "INFO"}
	typeOrder := []string{
		"KILL_CHAIN", "REVERSE_SHELL", "NET_CONNECT", "EXEC",
		"CRED_ACCESS", "PRIVESC", "MEMORY_ANOMALY", "MODULE_LOAD",
		"BPF_LOAD", "HIDDEN_PROCESS", "RISK_SCORE",
	}

	maxRows := len(typeOrder)
	if len(sevOrder)+1 > maxRows {
		maxRows = len(sevOrder) + 1
	}

	for i := 0; i < maxRows; i++ {
		leftPart := ""
		if i < len(sevOrder) {
			s := sevOrder[i]
			n := bySev[s]
			c := sevColor(s)
			leftPart = fmt.Sprintf("  %s%-10s%s %d", c, s, colorReset, n)
		} else if i == len(sevOrder) {
			leftPart = fmt.Sprintf("  %-10s %d", "TOTAL", total)
		}

		rightPart := ""
		if i < len(typeOrder) {
			t := typeOrder[i]
			n := byType[t]
			tc := typeColor(t)
			if tc != "" {
				rightPart = fmt.Sprintf("  %s%-18s%s %d", tc, t, colorReset, n)
			} else {
				rightPart = fmt.Sprintf("  %-18s %d", t, n)
			}
		}

		lpad := 29 - visLen(leftPart)
		if lpad < 0 {
			lpad = 0
		}
		rpad := 31 - visLen(rightPart)
		if rpad < 0 {
			rpad = 0
		}
		fmt.Printf("%s\u2502%s%s\u2502%s%s\u2502%s\n", colorBold, colorReset+leftPart, strings.Repeat(" ", lpad), colorReset+rightPart, strings.Repeat(" ", rpad), colorReset)
	}

	fmt.Printf("%s\u251c%s\u2524%s\n", colorBold, strings.Repeat("\u2500", w), colorReset)

	footerLine := fmt.Sprintf("\u2502 Kill Chains: %d  \u2502  Risk Alerts: %d  \u2502  Last event: %s", killChains, riskAlerts, lastEvent)
	fpad := w + 1 - visLen(footerLine)
	if fpad < 1 {
		fpad = 1
	}
	fmt.Printf("%s%s%s\u2502%s\n", colorBold, footerLine, strings.Repeat(" ", fpad), colorReset)
	fmt.Printf("%s\u2514%s\u2518%s\n", colorBold, strings.Repeat("\u2500", w), colorReset)
}

// visLen retorna o comprimento visível da string ignorando sequências ANSI.
func visLen(s string) int {
	n := 0
	inEsc := false
	for _, r := range s {
		if r == '\033' {
			inEsc = true
			continue
		}
		if inEsc {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
				inEsc = false
			}
			continue
		}
		n++
	}
	return n
}

func showLast(logFile, minSev string, n int) {
	events, err := readEvents(logFile)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "no log file found at %s\n", logFile)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	minRank := sevRank[strings.ToUpper(minSev)]

	var filtered []event
	for _, e := range events {
		if sevRank[e.Severity] >= minRank {
			filtered = append(filtered, e)
		}
	}

	start := 0
	if len(filtered) > n {
		start = len(filtered) - n
	}
	for _, e := range filtered[start:] {
		printEvent(e)
	}
	fmt.Printf("\n--- showing last %d of %d matching events (>= %s) ---\n", len(filtered)-start, len(filtered), minSev)
}

func tailLog(logFile, minSev string) {
	f, err := os.Open(logFile)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "no log file found at %s\nhint: start aura first, or specify -log path\n", logFile)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	minRank := sevRank[strings.ToUpper(minSev)]

	f.Seek(0, io.SeekEnd)

	fmt.Printf("[aura-ctl] tailing %s (>= %s) — Ctrl+C to stop\n", logFile, minSev)

	reader := bufio.NewReader(f)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var e event
		if json.Unmarshal([]byte(line), &e) != nil {
			continue
		}
		if sevRank[e.Severity] >= minRank {
			printEvent(e)
		}
	}
}

func printEvent(e event) {
	c := sevColor(e.Severity)
	if tc := typeColor(e.Type); tc != "" {
		c = tc
	}
	ts := e.Timestamp.Format("15:04:05")

	fmt.Printf("%s[%s] %-8s  %-18s (%-15s) pid=%-6d uid=%-4d%s\n",
		c, ts, e.Severity, e.Type, e.Comm,
		e.PID, e.UID, colorReset,
	)

	if e.Technique != "" || e.Tactic != "" {
		tacticStr := e.Tactic
		techStr := e.Technique
		if tacticStr == "" {
			tacticStr = "-"
		}
		if techStr == "" {
			techStr = "-"
		}
		fmt.Printf("%s           Tactic: %s  ATT&CK: %s%s\n", colorDim, tacticStr, techStr, colorReset)
	}

	fmt.Printf("           %s\n", e.Description)

	if e.Type == "KILL_CHAIN" || e.Type == "RISK_SCORE" {
		for k, v := range e.Details {
			fmt.Printf("           %s: %v\n", k, v)
		}
	}
}

func showRisks(logFile string) {
	events, err := readEvents(logFile)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "no log file found at %s\n", logFile)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	type riskEntry struct {
		Comm     string
		PID      uint32
		Score    int
		LastTime time.Time
		LastSev  string
	}

	risks := make(map[uint32]*riskEntry)
	for _, e := range events {
		if e.Type != "RISK_SCORE" {
			continue
		}
		score := 0
		if s, ok := e.Details["score"]; ok {
			switch v := s.(type) {
			case float64:
				score = int(v)
			case int:
				score = v
			}
		}
		if existing, ok := risks[e.PID]; ok {
			if score > existing.Score {
				existing.Score = score
			}
			if e.Timestamp.After(existing.LastTime) {
				existing.LastTime = e.Timestamp
				existing.LastSev = e.Severity
			}
		} else {
			risks[e.PID] = &riskEntry{
				Comm:     e.Comm,
				PID:      e.PID,
				Score:    score,
				LastTime: e.Timestamp,
				LastSev:  e.Severity,
			}
		}
	}

	if len(risks) == 0 {
		fmt.Println("no risk score alerts found")
		return
	}

	var sorted []*riskEntry
	for _, r := range risks {
		sorted = append(sorted, r)
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Score > sorted[j].Score
	})

	w := 61
	fmt.Printf("%s\u250c\u2500 Risk Scores %s\u2510%s\n", colorBold, strings.Repeat("\u2500", w-15), colorReset)
	fmt.Printf("%s\u2502  %-18s %-8s %-8s %-24s\u2502%s\n", colorBold, "Process", "PID", "Score", "Last Alert", colorReset)
	for _, r := range sorted {
		c := sevColor(r.LastSev)
		ts := r.LastTime.Format("15:04:05")
		line := fmt.Sprintf("  %-18s %-8d %s%-8d%s %s (%s)", r.Comm, r.PID, c, r.Score, colorReset, ts, r.LastSev)
		vl := visLen(line)
		pad := w - vl - 1
		if pad < 0 {
			pad = 0
		}
		fmt.Printf("%s\u2502%s%s%s\u2502%s\n", colorBold, colorReset+line, strings.Repeat(" ", pad), colorBold, colorReset)
	}
	fmt.Printf("%s\u2514%s\u2518%s\n", colorBold, strings.Repeat("\u2500", w), colorReset)
}

func showChains(logFile string) {
	events, err := readEvents(logFile)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "no log file found at %s\n", logFile)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	var chains []event
	for _, e := range events {
		if e.Type == "KILL_CHAIN" {
			chains = append(chains, e)
		}
	}

	if len(chains) == 0 {
		fmt.Println("no kill chain events found")
		return
	}

	w := 61
	fmt.Printf("%s\u250c\u2500 Kill Chains Detected %s\u2510%s\n", colorBold, strings.Repeat("\u2500", w-24), colorReset)
	for _, e := range chains {
		ts := e.Timestamp.Format("15:04:05")
		c := sevColor(e.Severity)

		line1 := fmt.Sprintf("  %s[%s] %s %s pid=%d%s", c, ts, e.Severity, e.Comm, e.PID, colorReset)
		l1pad := w - visLen(line1) - 1
		if l1pad < 0 {
			l1pad = 0
		}
		fmt.Printf("%s\u2502%s%s%s\u2502%s\n", colorBold, colorReset+line1, strings.Repeat(" ", l1pad), colorBold, colorReset)

		line2 := fmt.Sprintf("  %s", e.Description)
		l2pad := w - visLen(line2) - 1
		if l2pad < 0 {
			l2pad = 0
		}
		fmt.Printf("%s\u2502%s%s%s\u2502%s\n", colorBold, colorReset+line2, strings.Repeat(" ", l2pad), colorBold, colorReset)

		evtCount := 0
		pattern := ""
		if e.Details != nil {
			if v, ok := e.Details["events"]; ok {
				switch n := v.(type) {
				case float64:
					evtCount = int(n)
				case int:
					evtCount = n
				}
			}
			if v, ok := e.Details["pattern"]; ok {
				pattern = fmt.Sprintf("%v", v)
			}
		}
		line3 := fmt.Sprintf("  Events: %d  Pattern: %s", evtCount, pattern)
		l3pad := w - visLen(line3) - 1
		if l3pad < 0 {
			l3pad = 0
		}
		fmt.Printf("%s\u2502%s%s%s\u2502%s\n", colorBold, colorReset+line3, strings.Repeat(" ", l3pad), colorBold, colorReset)
	}
	fmt.Printf("%s\u2514%s\u2518%s\n", colorBold, strings.Repeat("\u2500", w), colorReset)
}
