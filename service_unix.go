//go:build !windows

package main

import (
	"context"
	"os/exec"
	"syscall"
	"time"
)

// daemonProcAttr detaches the child from the controlling terminal and its
// process group, so it survives the parent shell exiting.
func daemonProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}

func isAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	return syscall.Kill(pid, 0) == nil
}

func stopProcess(pid int) error {
	return syscall.Kill(pid, syscall.SIGTERM)
}

func forceKill(pid int) error {
	return syscall.Kill(pid, syscall.SIGKILL)
}

// execCommandContext builds a command that can be killed as a whole
// process group. Plain CommandContext only kills the direct child, so
// `sh -c "sleep N"` would leak the grandchild (which keeps holding the
// output pipe and blocks Wait forever).
func execCommandContext(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) // negative pid = whole group
		}
		return nil
	}
	// Safety net: even if some fd holder survives, unblock Wait.
	cmd.WaitDelay = 2 * time.Second
	return cmd
}
