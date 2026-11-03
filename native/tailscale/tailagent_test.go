// Copyright 2026 OpenKeychain contributors
// SPDX-License-Identifier: GPL-3.0-or-later
package tailagent

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNodeValidation(t *testing.T) {
	for _, tc := range []struct {
		dir, control string
		port         int32
	}{
		{"relative", "", 9476}, {t.TempDir(), "http://headscale.example", 9476},
		{t.TempDir(), "https://user:pass@headscale.example", 9476}, {t.TempDir(), "", 80},
	} {
		if n, err := NewNode(tc.dir, "openkeychain", tc.control, "", tc.port, ""); err == nil {
			n.Close()
			t.Errorf("accepted invalid config: %+v", tc)
		}
	}
	n, err := NewNode(filepath.Join(t.TempDir(), "state"), "openkeychain", "", "", 9476, "n123, n456")
	if err != nil {
		t.Fatal(err)
	}
	if !n.allowed["n123"] || n.allowed[""] {
		t.Fatal("incorrect peer authorization map")
	}
	if err := n.Close(); err != nil {
		t.Fatal(err)
	}
	if err := n.Start(); err == nil {
		t.Fatal("closed node restarted")
	}
	if err := n.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestPeerPolicyBlankAllowsAllAuthenticatedNodes(t *testing.T) {
	for _, allowed := range []string{"", " ", " , , "} {
		n, err := NewNode(t.TempDir(), "openkeychain", "", "", 9476, allowed)
		if err != nil {
			t.Fatal(err)
		}
		if !n.allowAll || !n.allowsPeer("n123") || !n.allowsPeer("any-other-tailnet-node") {
			t.Fatal("blank node filter did not allow all authenticated nodes")
		}
		if n.allowsPeer("") {
			t.Fatal("blank authenticated identity accepted")
		}
		if err := n.Close(); err != nil {
			t.Fatal(err)
		}
	}
	n, err := NewNode(t.TempDir(), "openkeychain", "", "", 9476, "n123, n456")
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	if n.allowAll || !n.allowsPeer("n123") || !n.allowsPeer("n456") || n.allowsPeer("n789") || n.allowsPeer("") {
		t.Fatal("explicit node filter was not enforced")
	}
}

func TestStartErrorsPreserveStageAndCause(t *testing.T) {
	n, err := NewNode(t.TempDir(), "openkeychain", "", "", 9476, "")
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	// Force a local, deterministic failure before tsnet creates an engine or
	// contacts the network. The blank peer filter is unrelated to this failure.
	badDirectory := filepath.Join(t.TempDir(), "regular-file")
	if err := os.WriteFile(badDirectory, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	n.server.Dir = badDirectory
	err = n.Start()
	if err == nil || !strings.Contains(err.Error(), "start embedded Tailscale:") {
		t.Fatalf("startup error lost stage: %v", err)
	}
	var cause *os.PathError
	if !errors.As(err, &cause) {
		t.Fatalf("startup error lost original cause: %v", err)
	}
	if repeated := n.Start(); repeated != err {
		t.Fatal("repeated Start lost original failure")
	}
	logs, logErr := n.DrainLogsJSON()
	if logErr != nil || !strings.Contains(logs, "start embedded Tailscale:") {
		t.Fatal("startup failure absent from diagnostics")
	}
}

func TestStartCachesRecoveredPanic(t *testing.T) {
	n, err := NewNode(t.TempDir(), "openkeychain", "", "", 9476, "")
	if err != nil {
		t.Fatal(err)
	}
	server := n.server
	// Panic before touching the filesystem, engine, or network. An upstream
	// initialization panic must remain a failure on every subsequent Start.
	n.server = nil
	err = n.Start()
	n.server = server
	defer n.Close()
	if err == nil || !strings.Contains(err.Error(), "native Tailscale operation failed:") {
		t.Fatalf("panic was not returned as an error: %v", err)
	}
	if repeated := n.Start(); repeated != err {
		t.Fatalf("repeated Start lost recovered error: first %v, repeated %v", err, repeated)
	}
	logs, logErr := n.DrainLogsJSON()
	if logErr != nil || !strings.Contains(logs, "native Tailscale operation failed:") {
		t.Fatal("recovered startup panic absent from diagnostics")
	}
}

func TestBinaryConnectionAndEOF(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	right, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	left, err := listener.Accept()
	if err != nil {
		right.Close()
		t.Fatal(err)
	}
	c := &Connection{conn: left}
	defer c.Close()
	payload := []byte{0, '\n', '%', 0xff, '\r'}
	go func() { defer right.Close(); right.Write(payload) }()
	actual, err := c.ReadBytes(1024)
	if err != nil || !bytes.Equal(actual, payload) {
		t.Fatalf("read %v: %v", actual, err)
	}
	actual, err = c.ReadBytes(1024)
	if err != nil || len(actual) != 0 {
		t.Fatalf("EOF = %v, %v", actual, err)
	}
}

func TestConnectionWritesAndCloseInterruptsRead(t *testing.T) {
	left, right := net.Pipe()
	c := &Connection{conn: left}
	defer right.Close()
	received := make(chan []byte, 1)
	go func() { b := make([]byte, 4); io.ReadFull(right, b); received <- b }()
	count, err := c.WriteBytes([]byte("test"))
	if err != nil || count != 4 || string(<-received) != "test" {
		t.Fatalf("write = %d, %v", count, err)
	}
	done := make(chan error, 1)
	go func() { _, e := c.ReadBytes(1024); done <- e }()
	c.Close()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("closed read succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("close did not interrupt read")
	}
}

func TestConnectionBounds(t *testing.T) {
	left, right := net.Pipe()
	c := &Connection{conn: left}
	defer c.Close()
	defer right.Close()
	if _, err := c.ReadBytes(0); err == nil {
		t.Fatal("zero read accepted")
	}
	if _, err := c.ReadBytes(65537); err == nil {
		t.Fatal("oversized read accepted")
	}
	if _, err := c.WriteBytes(make([]byte, 65537)); err == nil {
		t.Fatal("oversized write accepted")
	}
}

func TestNodeShutdownInterruptsAllSessions(t *testing.T) {
	n, err := NewNode(t.TempDir(), "openkeychain", "", "", 9476, "n123")
	if err != nil {
		t.Fatal(err)
	}
	if err := n.NetworkChanged("wlan0", "192.0.2.1"); err == nil {
		t.Fatal("network callback accepted before start")
	}
	done := make(chan error, maxConnections)
	for range maxConnections {
		left, right := net.Pipe()
		defer right.Close()
		c := &Connection{conn: left, node: n}
		n.conns[c] = struct{}{}
		go func() { _, err := c.ReadBytes(1); done <- err }()
	}
	if err := n.Close(); err != nil {
		t.Fatal(err)
	}
	for range maxConnections {
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("closed session read succeeded")
			}
		case <-time.After(time.Second):
			t.Fatal("shutdown did not interrupt all sessions")
		}
	}
	if len(n.conns) != 0 {
		t.Fatal("closed sessions retained by node")
	}
	if err := n.NetworkChanged("", ""); err == nil {
		t.Fatal("network callback accepted after shutdown")
	}
}
