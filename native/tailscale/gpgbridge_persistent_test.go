// Copyright 2026 OpenKeychain contributors
// SPDX-License-Identifier: GPL-3.0-or-later
package tailagent

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestBridgeDerivedPublicKeyMatchesNoiseKeypair(t *testing.T) {
	pair, err := bridgeSuite.GenerateKeypair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	psk := bytes.Repeat([]byte{7}, 32)
	s, err := newBridgeServerWithMaterial(&bridgeTestBackend{}, "http://127.0.0.1:17389", pair.Private, psk,
		bridgeEncoding.EncodeToString(bytes.Repeat([]byte{1}, 16)), time.Now().Unix()+60)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	if !bytes.Equal(s.public, pair.Public) {
		t.Fatal("derived X25519 public key differs from the Noise keypair")
	}
}

func TestPersistentBridgeRestoresTheSameConnectionString(t *testing.T) {
	backend := &bridgeTestBackend{}
	first, err := newPersistentBridgeServer(backend, "http://100.64.0.1:17389")
	if err != nil {
		t.Fatal(err)
	}
	if first.ticket.Expires != bridgePersistentExpires {
		t.Fatalf("persistent expiry %d", first.ticket.Expires)
	}
	state, err := first.stateString()
	if err != nil {
		t.Fatal(err)
	}
	public, psk, session := bytes.Clone(first.public), bytes.Clone(first.psk), first.ticket.Session
	firstTicket, _ := first.ticketString()
	first.close()

	restored, err := restoreBridgeServer(backend, "http://100.64.0.1:17389", state)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.close()
	if !bytes.Equal(restored.public, public) || !bytes.Equal(restored.psk, psk) || restored.ticket.Session != session {
		t.Fatal("restored bridge uses different credentials")
	}
	restoredTicket, err := restored.ticketString()
	if err != nil || restoredTicket != firstTicket {
		t.Fatal("restored connection string differs")
	}
	w, response := bridgeRequest(t, restored, bridgeClient(t, restored, "node"), map[string]string{
		"op": "sign", "fingerprint": bridgeTestFingerprint,
		"data": bridgeEncoding.EncodeToString(bridgeCommit("After restart"))}, "node")
	if w.Code != http.StatusOK || string(response["result"]) != `"signed"` {
		t.Fatalf("sign after restore: HTTP %d %v", w.Code, response)
	}
	moved, err := restoreBridgeServer(backend, "http://100.64.0.2:17389", state)
	if err != nil {
		t.Fatal(err)
	}
	defer moved.close()
	if moved.ticket.Endpoint != "http://100.64.0.2:17389" || moved.ticket.Session != session {
		t.Fatal("restored bridge must advertise the current endpoint with the same session")
	}
}

func TestPersistentBridgeStateIsValidated(t *testing.T) {
	backend := &bridgeTestBackend{}
	valid, err := newPersistentBridgeServer(backend, "http://100.64.0.1:17389")
	if err != nil {
		t.Fatal(err)
	}
	state, _ := valid.stateString()
	valid.close()
	var parsed bridgeState
	if err := json.Unmarshal([]byte(state), &parsed); err != nil {
		t.Fatal(err)
	}
	mutate := func(change func(*bridgeState)) string {
		next := parsed
		change(&next)
		data, _ := json.Marshal(next)
		return string(data)
	}
	for name, bad := range map[string]string{
		"empty object":  "{}",
		"trailing data": state + "{}",
		"unknown field": strings.Replace(state, `{"version"`, `{"extra":1,"version"`, 1),
		"version":       mutate(func(s *bridgeState) { s.Version = 2 }),
		"short key":     mutate(func(s *bridgeState) { s.Private = bridgeEncoding.EncodeToString(make([]byte, 16)) }),
		"short psk":     mutate(func(s *bridgeState) { s.PSK = bridgeEncoding.EncodeToString(make([]byte, 31)) }),
		"bad session":   mutate(func(s *bridgeState) { s.Session = "x" }),
		"expired":       mutate(func(s *bridgeState) { s.Expires = time.Now().Unix() - 1 }),
		"too far":       mutate(func(s *bridgeState) { s.Expires = bridgePersistentExpires + 1 }),
		"oversized":     strings.Repeat(" ", 5000),
	} {
		if s, err := restoreBridgeServer(backend, "http://100.64.0.1:17389", bad); err == nil {
			s.close()
			t.Errorf("%s: invalid state accepted", name)
		}
	}
}

func TestClosedPersistentBridgeDoesNotExportState(t *testing.T) {
	s, err := newPersistentBridgeServer(&bridgeTestBackend{}, "http://100.64.0.1:17389")
	if err != nil {
		t.Fatal(err)
	}
	s.close()
	if _, err := s.stateString(); err == nil {
		t.Fatal("closed bridge exported its state")
	}
}
