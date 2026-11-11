// Copyright 2026 OpenKeychain contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build linux && !android

package tailagent

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"tailscale.com/logpolicy"
)

// Exercise the real upstream directory selection in an isolated process so its
// Android-like environment and process-wide TS_LOGS_DIR cannot affect other tests.
func TestTailscaleLogDirAndroidSandbox(t *testing.T) {
	if os.Getenv("TAILAGENT_LOGDIR_TEST_CHILD") == "1" {
		testTailscaleLogDirAndroidSandbox(t)
		return
	}
	dir, err := os.MkdirTemp("", "tailagent-logdir-test-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if os.Geteuid() == 0 {
		// The child drops root to prevent Linux's system directory fallback from
		// hiding the Android failure. Only this disposable fixture changes owner.
		if err := os.Chown(dir, 65534, 65534); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestTailscaleLogDirAndroidSandbox$", "-test.v")
	cmd.Dir = "/"
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		switch name {
		case "HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "STATE_DIRECTORY", "TS_LOGS_DIR", "TMPDIR":
			continue
		}
		cmd.Env = append(cmd.Env, entry)
	}
	cmd.Env = append(cmd.Env, "TAILAGENT_LOGDIR_TEST_CHILD=1", "TAILAGENT_LOGDIR_TEST_DIR="+dir,
		"TMPDIR="+filepath.Join(dir, "not-a-directory"), "XDG_DATA_HOME="+filepath.Join(dir, "not-a-directory"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("sandbox regression: %v\n%s", err, out)
	}
}

func testTailscaleLogDirAndroidSandbox(t *testing.T) {
	if os.Geteuid() == 0 {
		for _, drop := range []func() error{
			func() error { return syscall.Setgroups(nil) },
			func() error { return syscall.Setgid(65534) },
			func() error { return syscall.Setuid(65534) },
		} {
			if err := drop(); err != nil {
				t.Fatal(err)
			}
		}
	}
	dir := os.Getenv("TAILAGENT_LOGDIR_TEST_DIR")
	if err := os.WriteFile(filepath.Join(dir, "not-a-directory"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	// No HOME/cache, cwd=/, no writable temp/system directory: the same fallback
	// chain used by the Android backend must reproduce the uploaded log's panic.
	var panicValue any
	func() {
		defer func() { panicValue = recover() }()
		logpolicy.LogsDir(t.Logf)
	}()
	if panicValue != "no safe place found to store log state" {
		t.Fatalf("upstream failure did not reproduce: %v", panicValue)
	}

	stateDir := filepath.Join(dir, "tailnet-agent")
	first, err := NewNode(stateDir, "openkeychain", "", "", 9476, "")
	if err != nil {
		t.Fatal(err)
	}
	state := []byte("existing Tailscale identity state\n")
	statePath := filepath.Join(stateDir, "tailscaled.state")
	if err := os.WriteFile(statePath, state, 0600); err != nil {
		t.Fatal(err)
	}
	logDir := filepath.Join(stateDir, "logs")
	if err := os.WriteFile(logDir, []byte("blocked"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := first.Start(); err == nil || !strings.Contains(err.Error(), "create Tailscale internal log directory:") {
		t.Fatalf("blocked log directory did not return a useful error: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(logDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(logDir, 0755); err != nil {
		t.Fatal(err)
	}
	// A fresh node must be able to retry, protecting an existing log directory
	// and preserving the identity file. Invoke only its pre-start setup here;
	// the regression requires no engine, network access, or tailnet credentials.
	second, err := NewNode(stateDir, "openkeychain", "", "", 9476, "")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	tailscaleStartupMu.Lock()
	prepared, err := prepareTailscaleLogDir(second.server.Dir)
	tailscaleStartupMu.Unlock()
	if err != nil || prepared != logDir {
		t.Fatalf("prepare log directory: %q, %v", prepared, err)
	}
	if got := logpolicy.LogsDir(t.Logf); got != logDir {
		t.Fatalf("backend logger chose %q, want app-private %q", got, logDir)
	}
	info, err := os.Stat(logDir)
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatalf("log directory is not private: %v, %v", info, err)
	}
	gotState, err := os.ReadFile(statePath)
	if err != nil || !bytes.Equal(gotState, state) {
		t.Fatalf("existing node state changed: %q, %v", gotState, err)
	}
	if _, set := os.LookupEnv("HOME"); set {
		t.Fatal("log setup unexpectedly set HOME")
	}
}
