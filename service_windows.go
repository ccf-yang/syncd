//go:build windows

package main

import (
	"context"
	"os/exec"
	"strconv"
	"syscall"
	"time"
)

const detachProcessFlags = 0x00000008 // DETACHED_PROCESS

func daemonProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{CreationFlags: detachProcessFlags}
}

var kernel32 = syscall.NewLazyDLL("kernel32.dll")

func isAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	open, err := syscall.OpenProcess(0x00100000 /*SYNCHRONIZE*/, false, uint32(pid))
	if err != nil {
		return false
	}
	defer syscall.CloseHandle(open)
	const waitTimeout = 0x00000102
	wait := kernel32.NewProc("WaitForSingleObject")
	r, _, _ := wait.Call(uintptr(open), 0)
	return r == waitTimeout // WAIT_OBJECT_0 (0) means the process has exited
}

func stopProcess(pid int) error {
	// taskkill /F is immediate; state files are written atomically and
	// downloads resume from .part files, so this is safe.
	return exec.Command("taskkill", "/PID", strconv.Itoa(pid), "/F").Run()
}

func forceKill(pid int) error {
	return stopProcess(pid)
}

// execCommandContext builds a command that is killed together with its
// whole process tree on cancellation (taskkill /T), since plain
// CommandContext only kills the direct child.
func execCommandContext(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			_ = exec.Command("taskkill", "/PID", strconv.Itoa(cmd.Process.Pid), "/T", "/F").Run()
		}
		return nil
	}
	cmd.WaitDelay = 2 * time.Second
	return cmd
}
