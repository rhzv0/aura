package engine

import (
	"fmt"
	"sync"
	"time"

	"github.com/ebpf-detect/aura/internal/alerts"
)

// Correlator rastreia eventos por árvore de processo e detecta kill chains.
// Implementa alerts.Notifier — é adicionado diretamente ao Printer.
type Correlator struct {
	mu      sync.Mutex
	window  time.Duration
	events  map[uint32][]alerts.Alert
	ppids   map[uint32]uint32
	scores  map[uint32]int
	scored  map[uint32]time.Time
	chains  map[string]time.Time  // key: "PATTERN_NAME:rootPID" → dedup 60s
	riskDup map[uint32]time.Time
	printer *alerts.Printer
}

func NewCorrelator(printer *alerts.Printer, window time.Duration) *Correlator {
	return &Correlator{
		window:  window,
		events:  make(map[uint32][]alerts.Alert),
		ppids:   make(map[uint32]uint32),
		scores:  make(map[uint32]int),
		scored:  make(map[uint32]time.Time),
		chains:  make(map[string]time.Time),
		riskDup: make(map[uint32]time.Time),
		printer: printer,
	}
}

func (c *Correlator) Notify(a alerts.Alert) error {
	// Evitar loop de feedback: KILL_CHAIN e RISK_SCORE são sintéticos
	if a.Type == "KILL_CHAIN" || a.Type == "RISK_SCORE" {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if a.Type == "EXEC" && a.Details != nil {
		if ppidVal, ok := a.Details["ppid"]; ok {
			switch v := ppidVal.(type) {
			case uint32:
				c.ppids[a.PID] = v
			case float64:
				c.ppids[a.PID] = uint32(v)
			}
		}
	}

	root := c.rootPID(a.PID)

	c.events[root] = append(c.events[root], a)

	score := a.SeverityScore()
	if _, ok := c.scored[root]; !ok {
		c.scored[root] = time.Now()
	}
	c.scores[root] += score

	c.checkPatterns(root)
	c.checkRiskScore(root, a.Comm)

	return nil
}

func (c *Correlator) MinSeverity() alerts.Severity {
	return alerts.SevInfo
}

func (c *Correlator) Run(stop <-chan struct{}) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			c.decay()
		}
	}
}

func (c *Correlator) decay() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-c.window)

	// Decai 20% por tick — score cai naturalmente se não houver atividade
	for pid, score := range c.scores {
		newScore := int(float64(score) * 0.8)
		if newScore <= 0 {
			delete(c.scores, pid)
			delete(c.scored, pid)
		} else {
			c.scores[pid] = newScore
			c.scored[pid] = now
		}
	}

	for pid, evts := range c.events {
		var fresh []alerts.Alert
		for _, e := range evts {
			if e.Timestamp.After(cutoff) {
				fresh = append(fresh, e)
			}
		}
		if len(fresh) == 0 {
			delete(c.events, pid)
		} else {
			c.events[pid] = fresh
		}
	}

	for key, t := range c.chains {
		if now.Sub(t) > 60*time.Second {
			delete(c.chains, key)
		}
	}

	for pid, t := range c.riskDup {
		if now.Sub(t) > 2*time.Minute {
			delete(c.riskDup, pid)
		}
	}
}

func (c *Correlator) rootPID(pid uint32) uint32 {
	visited := make(map[uint32]bool)
	cur := pid
	for {
		if cur <= 1 {
			return pid
		}
		parent, ok := c.ppids[cur]
		if !ok || parent == cur || parent <= 1 {
			return cur
		}
		if visited[cur] {
			return cur // evita loop em caso de ciclo no mapa
		}
		visited[cur] = true
		cur = parent
	}
}

func (c *Correlator) hasType(root uint32, typ string, critOnly bool) bool {
	for _, e := range c.events[root] {
		if e.Type == typ {
			if critOnly && e.Severity != alerts.SevCritical {
				continue
			}
			return true
		}
	}
	return false
}

func (c *Correlator) checkPatterns(root uint32) {
	now := time.Now()

	type pattern struct {
		name    string
		sev     alerts.Severity
		msg     string
		matched bool
	}

	patterns := []pattern{
		{
			name:    "KILL_CHAIN_LATERAL",
			sev:     alerts.SevCritical,
			msg:     "Kill chain: C2 callback -> execution -> credential access",
			matched: c.hasType(root, "NET_CONNECT", true) && c.hasType(root, "EXEC", false) && c.hasType(root, "CRED_ACCESS", false),
		},
		{
			name:    "KILL_CHAIN_PRIVESC_PERSIST",
			sev:     alerts.SevCritical,
			msg:     "Kill chain: privilege escalation -> persistence attempt",
			matched: c.hasType(root, "PRIVESC", false) && (c.hasType(root, "MODULE_LOAD", false) || c.hasType(root, "EXEC", false)),
		},
		{
			name:    "KILL_CHAIN_FILELESS",
			sev:     alerts.SevHigh,
			msg:     "Kill chain: in-memory payload -> execution",
			matched: c.hasType(root, "MEMORY_ANOMALY", false) && c.hasType(root, "EXEC", false),
		},
		{
			name:    "KILL_CHAIN_EBPF_ROOTKIT",
			sev:     alerts.SevCritical,
			msg:     "Kill chain: eBPF rootkit loaded with C2 callback",
			matched: c.hasType(root, "BPF_LOAD", false) && c.hasType(root, "NET_CONNECT", false),
		},
		{
			name:    "KILL_CHAIN_SHELL_ESCALATE",
			sev:     alerts.SevCritical,
			msg:     "Kill chain: reverse shell established -> escalation",
			matched: c.hasType(root, "REVERSE_SHELL", false) && (c.hasType(root, "PRIVESC", false) || c.hasType(root, "CRED_ACCESS", false)),
		},
	}

	for _, p := range patterns {
		if !p.matched {
			continue
		}
		key := fmt.Sprintf("%s:%d", p.name, root)
		if last, ok := c.chains[key]; ok && now.Sub(last) < 60*time.Second {
			continue
		}
		c.chains[key] = now

		comm := ""
		for _, e := range c.events[root] {
			comm = e.Comm
			break
		}

		a := alerts.Alert{
			Timestamp:   now,
			Type:        "KILL_CHAIN",
			Severity:    p.sev,
			Comm:        comm,
			PID:         root,
			Description: p.msg,
			Technique:   "Multiple",
			Tactic:      "Multiple",
			Details:     map[string]any{"events": len(c.events[root]), "pattern": p.name},
		}
		c.printer.Emit(a)
	}
}

func (c *Correlator) checkRiskScore(root uint32, comm string) {
	score := c.scores[root]
	now := time.Now()

	var sev alerts.Severity
	switch {
	case score >= 200:
		sev = alerts.SevCritical
	case score >= 100:
		sev = alerts.SevHigh
	case score >= 50:
		sev = alerts.SevMedium
	default:
		return
	}

	if last, ok := c.riskDup[root]; ok && now.Sub(last) < 2*time.Minute {
		return
	}
	c.riskDup[root] = now

	a := alerts.Alert{
		Timestamp:   now,
		Type:        "RISK_SCORE",
		Severity:    sev,
		Comm:        comm,
		PID:         root,
		Description: fmt.Sprintf("process risk score: %d", score),
		Details:     map[string]any{"score": score},
	}
	c.printer.Emit(a)
}
