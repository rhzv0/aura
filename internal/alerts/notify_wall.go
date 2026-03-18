package alerts

import (
	"fmt"
	"os/exec"
)

type WallNotifier struct {
	minSev Severity
}

func NewWallNotifier(minSev Severity) *WallNotifier {
	return &WallNotifier{minSev: minSev}
}

func (w *WallNotifier) MinSeverity() Severity { return w.minSev }

func (w *WallNotifier) Notify(a Alert) error {
	msg := fmt.Sprintf(
		"\n  AURA ALERT [%s] %s\n   process: %s (pid %d, uid %d)\n   %s\n",
		a.Severity, a.Type, a.Comm, a.PID, a.UID, a.Description,
	)
	cmd := exec.Command("wall", "-n", msg)
	return cmd.Run()
}
