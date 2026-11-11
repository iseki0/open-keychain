// Copyright 2026 OpenKeychain contributors
// SPDX-License-Identifier: GPL-3.0-or-later
package tailagent

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"
)

func TestDiagnosticsRedactsCredentialsBeforeQueueing(t *testing.T) {
	n := &Node{}
	secrets := []string{"login-token-value", "headscale-secret", "authkey-secret", "private-key-value", "node-key-value", "machine-key-value", "disco-key-value", "bearer-secret", "psk-secret", "password-secret", "ticket-secret"}
	n.logf("Login https://login.tailscale.com/a/login-token-value; custom https://headscale.example/register/headscale-secret; tskey-auth-authkey-secret privkey:private-key-value nodekey:node-key-value mkey:machine-key-value disco:disco-key-value")
	n.logf("Authorization: Bearer bearer-secret")
	n.logf(`{"psk":"psk-secret","password":"password-secret"} gpgbridge:v1:ticket-secret`)
	queued := strings.Join(n.logs, "\n")
	result, err := n.DrainLogsJSON()
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range secrets {
		if strings.Contains(queued, secret) || strings.Contains(result, secret) {
			t.Fatalf("secret retained in diagnostics: %s", secret)
		}
	}
	if !strings.Contains(result, "login.tailscale.com") || !strings.Contains(result, "redacted") {
		t.Fatal("useful redacted diagnostics missing")
	}
	if empty, err := n.DrainLogsJSON(); err != nil || empty != "[]" {
		t.Fatalf("drain did not clear diagnostics: %q, %v", empty, err)
	}
}

func TestDiagnosticsBoundsAndConcurrentDraining(t *testing.T) {
	n := &Node{}
	for i := range maxDiagnosticEntries + 30 {
		n.logf("event %d %s", i, strings.Repeat("界", 2000))
	}
	if len(n.logs) != maxDiagnosticEntries {
		t.Fatal("diagnostic entry bound ignored")
	}
	for _, entry := range n.logs {
		if len(entry) > maxDiagnosticBytes || !utf8.ValidString(entry) {
			t.Fatal("diagnostic size or UTF8 bound ignored")
		}
	}
	var workers sync.WaitGroup
	for range 4 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for range 100 {
				n.logf("concurrent event")
			}
		}()
	}
	workers.Add(1)
	go func() {
		defer workers.Done()
		for range 100 {
			value, err := n.DrainLogsJSON()
			var entries []string
			if err != nil || json.Unmarshal([]byte(value), &entries) != nil || len(entries) > maxDiagnosticEntries {
				t.Error("invalid concurrent log drain")
			}
		}
	}()
	workers.Wait()
}
