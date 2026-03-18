package loader

import (
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ebpf-detect/aura/internal/alerts"
)

// HiddenProcDetector detecta processos que existem no kernel mas sumiram do /proc.
// Rootkits que hookam getdents64 escondem processos assim — eles aparecem via
// execve no eBPF mas não aparecem no ReadDir do /proc.
type HiddenProcDetector struct {
	mu      sync.Mutex
	tracked map[uint32]string
	printer *alerts.Printer
}

func NewHiddenProcDetector(printer *alerts.Printer) *HiddenProcDetector {
	return &HiddenProcDetector{
		tracked: make(map[uint32]string),
		printer: printer,
	}
}

func (h *HiddenProcDetector) Track(pid uint32, comm string) {
	h.mu.Lock()
	h.tracked[pid] = comm
	h.mu.Unlock()
}

func (h *HiddenProcDetector) Untrack(pid uint32) {
	h.mu.Lock()
	delete(h.tracked, pid)
	h.mu.Unlock()
}

func (h *HiddenProcDetector) Run(stop <-chan struct{}) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			h.scan()
		}
	}
}

func (h *HiddenProcDetector) scan() {
	visible := make(map[uint32]struct{})
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.ParseUint(e.Name(), 10, 32)
		if err == nil {
			visible[uint32(pid)] = struct{}{}
		}
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	for pid, comm := range h.tracked {
		if _, ok := visible[pid]; !ok {
			statusFile := "/proc/" + strconv.Itoa(int(pid)) + "/status"
			if _, err := os.Stat(statusFile); os.IsNotExist(err) {
				// processo saiu normalmente
				delete(h.tracked, pid)
				continue
			}
			// /proc/<pid>/status existe mas não aparece no ReadDir:
			// assinatura de rootkit hookando getdents64
			if !strings.Contains(comm, "aura") {
				a := alerts.Alert{
					Timestamp:   time.Now(),
					Type:        "HIDDEN_PROCESS",
					Severity:    alerts.SevCritical,
					PID:         pid,
					Comm:        comm,
					Description: "process hidden from /proc (possible rootkit)",
					Details:     map[string]any{"pid": pid, "comm": comm},
				}
				h.printer.Emit(a)
			}
		}
	}
}
