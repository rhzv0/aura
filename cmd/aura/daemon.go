package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"
)

const pidFile = "/var/run/aura.pid"

func daemonize() error {
	for _, arg := range os.Args {
		if arg == "-daemonized" || arg == "--daemonized" {
			return setupDaemonChild()
		}
	}

	args := append(os.Args[1:], "-daemonized")

	devNull, err := os.OpenFile("/dev/null", os.O_RDWR, 0)
	if err != nil {
		return err
	}

	cmd := exec.Command(os.Args[0], args...)
	cmd.Stdin = devNull
	cmd.Stdout = devNull
	cmd.Stderr = devNull
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true, // nova sessão, desanexa do terminal
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start daemon: %w", err)
	}

	os.MkdirAll("/var/run", 0755)
	os.WriteFile(pidFile, []byte(strconv.Itoa(cmd.Process.Pid)), 0644)

	fmt.Printf("[aura] daemon started (pid %d)\n", cmd.Process.Pid)
	os.Exit(0)
	return nil // unreachable
}

func setupDaemonChild() error {
	devNull, err := os.OpenFile("/dev/null", os.O_RDWR, 0)
	if err != nil {
		return err
	}
	os.Stdin = devNull
	os.MkdirAll("/var/log/aura", 0755)
	return nil
}
