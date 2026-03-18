package mitigate

import (
	"fmt"
	"syscall"
)

func KillProcess(pid uint32) error {
	if pid == 0 {
		return fmt.Errorf("invalid pid 0")
	}
	return syscall.Kill(int(pid), syscall.SIGKILL)
}
