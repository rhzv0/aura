package alerts

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

type Severity string

const (
	SevInfo     Severity = "INFO"
	SevMedium   Severity = "MEDIUM"
	SevHigh     Severity = "HIGH"
	SevCritical Severity = "CRITICAL"
)

var severityRank = map[Severity]int{
	SevInfo:     1,
	SevMedium:   2,
	SevHigh:     3,
	SevCritical: 4,
}

type Alert struct {
	Timestamp   time.Time      `json:"timestamp"`
	Severity    Severity       `json:"severity"`
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

var severityScore = map[Severity]int{
	SevInfo:     1,
	SevMedium:   5,
	SevHigh:     15,
	SevCritical: 30,
}

func (a Alert) SeverityScore() int {
	return severityScore[a.Severity]
}

type Stats struct {
	mu     sync.Mutex
	ByType map[string]int
	BySev  map[Severity]int
	Total  int
}

func newStats() *Stats {
	return &Stats{
		ByType: make(map[string]int),
		BySev:  make(map[Severity]int),
	}
}

func (s *Stats) record(a Alert) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ByType[a.Type]++
	s.BySev[a.Severity]++
	s.Total++
}

type Notifier interface {
	Notify(a Alert) error
	MinSeverity() Severity
}

func SeverityRank(s Severity) int {
	return severityRank[s]
}

type Printer struct {
	jsonMode  bool
	minSev    int
	logFile   *os.File
	stats     *Stats
	notifiers []Notifier
	mu        sync.Mutex
}

type Config struct {
	JSONMode bool
	MinLevel Severity
	LogFile  string
}

func NewPrinter(cfg Config) (*Printer, error) {
	minSev := severityRank[SevInfo]
	if cfg.MinLevel != "" {
		if r, ok := severityRank[cfg.MinLevel]; ok {
			minSev = r
		}
	}

	p := &Printer{
		jsonMode: cfg.JSONMode,
		minSev:   minSev,
		stats:    newStats(),
	}

	if cfg.LogFile != "" {
		f, err := os.OpenFile(cfg.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
		if err != nil {
			return nil, fmt.Errorf("log file: %w", err)
		}
		p.logFile = f
	}

	return p, nil
}

func (p *Printer) AddNotifier(n Notifier) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.notifiers = append(p.notifiers, n)
}

func (p *Printer) Emit(a Alert) {
	if severityRank[a.Severity] < p.minSev {
		return
	}

	p.stats.record(a)

	b, _ := json.Marshal(a)

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.logFile != nil {
		fmt.Fprintln(p.logFile, string(b))
	}

	if p.jsonMode {
		fmt.Println(string(b))
	} else {
		color := severityColor(a.Severity)
		reset := "\033[0m"
		ts := a.Timestamp.Format("2006-01-02 15:04:05.000")

		fmt.Fprintf(os.Stdout,
			"%s[%s] [%-8s] %-14s (%-15s) pid=%-6d uid=%-4d %s%s\n",
			color, ts, a.Severity, a.Type, a.Comm,
			a.PID, a.UID, a.Description, reset,
		)
		for k, v := range a.Details {
			fmt.Fprintf(os.Stdout, "                                  %s  %s: %v%s\n", color, k, v, reset)
		}
	}

	for _, n := range p.notifiers {
		if SeverityRank(a.Severity) >= SeverityRank(n.MinSeverity()) {
			go n.Notify(a)
		}
	}
}

func (p *Printer) PrintStats() {
	s := p.stats
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.Total == 0 {
		fmt.Println("no events detected.")
		return
	}

	fmt.Printf("\n─── session summary ─────────────────────────────\n")
	fmt.Printf("  total events : %d\n", s.Total)
	fmt.Println()

	for _, sev := range []Severity{SevCritical, SevHigh, SevMedium, SevInfo} {
		if n := s.BySev[sev]; n > 0 {
			fmt.Printf("  %s%-8s%s : %d\n", severityColor(sev), sev, "\033[0m", n)
		}
	}
	fmt.Println()

	for t, n := range s.ByType {
		fmt.Printf("  %-16s : %d\n", t, n)
	}
	fmt.Println("─────────────────────────────────────────────────")

	if p.logFile != nil {
		fmt.Printf("  log saved to : %s\n", p.logFile.Name())
	}
}

func (p *Printer) Close() {
	if p.logFile != nil {
		p.logFile.Close()
	}
}

func severityColor(s Severity) string {
	switch s {
	case SevCritical:
		return "\033[1;31m"
	case SevHigh:
		return "\033[0;31m"
	case SevMedium:
		return "\033[0;33m"
	default:
		return "\033[0;36m"
	}
}
