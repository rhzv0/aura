package alerts

import (
	"sync"
	"time"
)

// DedupNotifier suprime alertas repetidos do mesmo (Type + Comm) dentro do cooldown.
type DedupNotifier struct {
	inner    Notifier
	cooldown time.Duration
	mu       sync.Mutex
	last     map[string]time.Time
}

func NewDedupNotifier(inner Notifier, cooldown time.Duration) *DedupNotifier {
	return &DedupNotifier{
		inner:    inner,
		cooldown: cooldown,
		last:     make(map[string]time.Time),
	}
}

func (d *DedupNotifier) MinSeverity() Severity { return d.inner.MinSeverity() }

func (d *DedupNotifier) Notify(a Alert) error {
	key := string(a.Type) + ":" + a.Comm
	d.mu.Lock()
	if t, ok := d.last[key]; ok && time.Since(t) < d.cooldown {
		d.mu.Unlock()
		return nil
	}
	d.last[key] = time.Now()
	d.mu.Unlock()
	return d.inner.Notify(a)
}
