// Copyright 2026 OpenKeychain contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package tailagent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// This fixture is compiled only into Go test executables. The integration script
// supplies a disposable RSA or Ed25519 GnuPG home and the exact fingerprint it generated.
// Production Android listeners always obtain peer identity through Tailscale.
type bridgeInteropBackend struct {
	home        string
	fingerprint string
	control     string
	publicKeys  string
}

func (b *bridgeInteropBackend) InfoJSON() (string, error) {
	value := map[string]any{
		"keys": []map[string]any{{
			"primary": b.fingerprint, "fingerprint": b.fingerprint,
			"uid":     "OpenKeychain bridge fixture <bridge@example.invalid>",
			"expires": 0, "hardware": false,
		}},
		"public_keys": b.publicKeys,
	}
	data, err := json.Marshal(value)
	return string(data), err
}

func (b *bridgeInteropBackend) Sign(fingerprint string, data []byte, peerID, peerName string) (string, error) {
	if fingerprint != b.fingerprint || peerID != "fixture-node" || peerName != "fixture.local" {
		return "", errors.New("fixture rejected unauthorized key or peer")
	}
	if control, _ := os.ReadFile(b.control); strings.TrimSpace(string(control)) == "deny" {
		return "", errors.New("fixture local approval denied")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "gpg", "--homedir", b.home, "--batch", "--yes",
		"--no-tty", "--pinentry-mode", "loopback", "--passphrase", "", "--armor",
		"--digest-algo", "SHA256", "--local-user", b.fingerprint+"!", "--status-fd", "2", "--detach-sign")
	command.Stdin = bytes.NewReader(data)
	var status bytes.Buffer
	command.Stderr = &status
	signature, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("fixture GnuPG failed: %w", err)
	}
	if !bytes.HasPrefix(signature, []byte("-----BEGIN PGP SIGNATURE-----")) ||
		!strings.Contains(status.String(), "[GNUPG:] SIG_CREATED ") {
		return "", errors.New("fixture GnuPG returned an invalid detached signature")
	}
	response, err := json.Marshal(map[string]string{"signature": string(signature), "status": status.String()})
	return string(response), err
}

func TestBridgeInteropServer(t *testing.T) {
	home := os.Getenv("GPG_BRIDGE_INTEROP_HOME")
	if home == "" {
		t.Skip("invoked only by tools/gpg-bridge-integration/integration_test.py")
	}
	fingerprint := os.Getenv("GPG_BRIDGE_INTEROP_FINGERPRINT")
	ticketPath := os.Getenv("GPG_BRIDGE_INTEROP_TICKET")
	stopPath := os.Getenv("GPG_BRIDGE_INTEROP_STOP")
	controlPath := os.Getenv("GPG_BRIDGE_INTEROP_CONTROL")
	if fingerprint == "" || ticketPath == "" || stopPath == "" || controlPath == "" {
		t.Fatal("incomplete disposable integration fixture configuration")
	}
	publicKeys, err := exec.Command("gpg", "--homedir", home, "--batch", "--armor", "--export", fingerprint).Output()
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	backend := &bridgeInteropBackend{home: home, fingerprint: fingerprint,
		control: controlPath, publicKeys: string(publicKeys)}
	bridge, err := newBridgeServer(backend, "http://"+listener.Addr().String(), 300)
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.close()
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peer := bridgePeer{id: "fixture-node", name: "fixture.local"}
		bridge.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), bridgePeerContextKey{}, peer)))
	}), ReadHeaderTimeout: 5 * time.Second}
	defer server.Close()
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	ticket, err := bridge.ticketString()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ticketPath, []byte(ticket+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	deadline := time.NewTimer(5 * time.Minute)
	defer deadline.Stop()
	poll := time.NewTicker(50 * time.Millisecond)
	defer poll.Stop()
	for {
		select {
		case <-poll.C:
			if _, err := os.Stat(stopPath); err == nil {
				return
			}
		case err := <-done:
			if err != http.ErrServerClosed {
				t.Fatal(err)
			}
			return
		case <-deadline.C:
			t.Fatal("integration fixture timed out")
		}
	}
}
