package handler

// me_agent tool: code_run — sandboxed Python execution.
//
// Layered sandbox (no docker daemon, ~30ms per call):
//
//   prlimit  — kernel-enforced resource caps:
//                --as=512M --cpu=30 --nproc=64 --fsize=10M
//   setpriv  — privilege drops applied before exec:
//                --reuid 65534 --regid 65534 --clear-groups
//                --no-new-privs       (can't gain caps via setuid)
//                --inh-caps -all      (empty inheritable cap set)
//                --bounding-set -all  (empty bounding cap set)
//   env      — only PATH/HOME/LANG/PYTHON* set; everything else cleared
//   python3 -c <code>
//
// Trade-off vs full namespace sandbox: no network namespace — the
// sandboxed process can reach the same hosts identity can. Identity
// is single-tenant + operator-trusted, so residual risk is bounded
// by identity's own egress reachability. Mem/cpu/uid/cap isolation
// is intact, which covers the OOM + runaway-loop + privilege-creep
// risks that matter most for AI-generated code.
//
// Wall-clock timeout enforced via context.WithTimeout + cmd.Cancel;
// if python3 doesn't exit cleanly it gets SIGKILL on the whole pgid.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

const (
	codeRunDefaultTimeout = 30 // seconds; capped at 60
	codeRunMaxCode        = 32 * 1024
	codeRunMaxOutput      = 16 * 1024 // per stream (stdout/stderr)
)

// codeRunAvailable checks whether the sandbox tools are wired up.
// prlimit + setpriv (from util-linux) and python3 are required.
// Probed lazily so the rest of identity boots fine even on hosts
// where the Dockerfile bits weren't applied yet.
func codeRunAvailable() error {
	for _, bin := range []string{"prlimit", "setpriv", "python3"} {
		if _, err := exec.LookPath(bin); err != nil {
			return fmt.Errorf("missing %s in PATH", bin)
		}
	}
	return nil
}

// toolCodeRun executes one snippet under prlimit + setpriv.
// Returns {stdout, stderr, exit_code, timed_out, duration_ms}.
func toolCodeRun(code string, timeoutSec int) (map[string]any, bool) {
	code = strings.TrimSpace(code)
	if code == "" {
		return map[string]any{"error": "code required"}, false
	}
	if len(code) > codeRunMaxCode {
		return map[string]any{"error": fmt.Sprintf("code too long (max %d bytes)", codeRunMaxCode)}, false
	}
	if err := codeRunAvailable(); err != nil {
		return map[string]any{"error": "sandbox not available: " + err.Error() +
			". Ensure the identity container has util-linux-misc + python3 installed (see deploy/Dockerfile)."}, false
	}
	if timeoutSec <= 0 {
		timeoutSec = codeRunDefaultTimeout
	}
	if timeoutSec > 60 {
		timeoutSec = 60
	}

	started := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec+5)*time.Second)
	defer cancel()

	// prlimit → setpriv → python3. Each layer applies before the next
	// exec, so by the time python3 runs we have: rlimits set, uid=65534,
	// gids cleared, no-new-privs set, inheritable + bounding cap sets
	// emptied. Order matters — setpriv can't open the python3 binary
	// after its uid switch if the binary's perms don't include "others
	// read+exec" (python3 in alpine does).
	args := []string{
		"--as=536870912",   // 512 MB virtual address space
		"--cpu=30",         // 30 s CPU time
		"--fsize=10485760", // 10 MB max file write
		// NOTE: skip --nproc here. prlimit applies that limit to the
		// effective UID (initially root inside the container), and
		// root already owns dozens of process slots — the next fork
		// (`setpriv → env → python3`) trips EAGAIN. The fork-bomb risk
		// is bounded by the parent container's PIDs cgroup anyway.
		"--",
		"setpriv",
		"--reuid", "65534",
		"--regid", "65534",
		"--clear-groups",
		"--no-new-privs",
		"--inh-caps", "-all",
		"--bounding-set", "-all",
		"--",
		"python3", "-c", code,
	}

	cmd := exec.CommandContext(ctx, "prlimit", args...)
	// Clean environment passed to the child — setpriv inherits this,
	// python3 sees only what we whitelist.
	cmd.Env = []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=/tmp",
		"LANG=C.UTF-8",
		"PYTHONIOENCODING=utf-8",
		"PYTHONUNBUFFERED=1",
	}
	// Run in /tmp so any relative-path writes go to a world-writable
	// dir (and stay capped by RLIMIT_FSIZE).
	cmd.Dir = "/tmp"
	// New process group so we can SIGKILL the whole tree on timeout.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		return os.ErrProcessDone
	}
	cmd.WaitDelay = 3 * time.Second

	var stdout, stderr bytes.Buffer
	cmd.Stdout = capWriter{buf: &stdout, cap: codeRunMaxOutput}
	cmd.Stderr = capWriter{buf: &stderr, cap: codeRunMaxOutput}

	err := cmd.Run()
	timedOut := errors.Is(ctx.Err(), context.DeadlineExceeded)

	exitCode := 0
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			exitCode = ee.ExitCode()
		} else {
			exitCode = -1
		}
	}

	dur := time.Since(started).Milliseconds()
	out := map[string]any{
		"stdout":      truncStr(stdout.String(), codeRunMaxOutput),
		"stderr":      truncStr(stderr.String(), codeRunMaxOutput),
		"exit_code":   exitCode,
		"timed_out":   timedOut,
		"duration_ms": dur,
	}
	return out, !timedOut && exitCode == 0
}

// capWriter wraps a bytes.Buffer with a hard cap — extra bytes are
// silently dropped. Cheaper than wrapping io.Writer twice and lets us
// stop accumulating once we hit cap.
type capWriter struct {
	buf *bytes.Buffer
	cap int
}

func (w capWriter) Write(p []byte) (int, error) {
	if w.buf.Len() >= w.cap {
		return len(p), nil // pretend success, swallow the rest
	}
	room := w.cap - w.buf.Len()
	if len(p) > room {
		w.buf.Write(p[:room])
		return len(p), nil
	}
	w.buf.Write(p)
	return len(p), nil
}
