// Copyright 2026 OpenKeychain contributors
// SPDX-License-Identifier: GPL-3.0-or-later
package tailagent

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/flynn/noise"
)

const bridgeTestFingerprint = "0123456789ABCDEF0123456789ABCDEF01234567"

type bridgeTestBackend struct {
	calls   atomic.Int32
	block   chan struct{}
	entered chan struct{}
	info    string
}

func (b *bridgeTestBackend) InfoJSON() (string, error) {
	if b.info != "" {
		return b.info, nil
	}
	data, _ := json.Marshal(bridgeInfo{Keys: []bridgeSigningKey{{Primary: bridgeTestFingerprint,
		Fingerprint: bridgeTestFingerprint, UID: "Test key", Expires: 0}},
		PublicKeys: "-----BEGIN PGP PUBLIC KEY BLOCK-----\ntest\n-----END PGP PUBLIC KEY BLOCK-----"})
	return string(data), nil
}

func (b *bridgeTestBackend) Sign(fingerprint string, data []byte, peerID, peerName string) (string, error) {
	b.calls.Add(1)
	if b.entered != nil {
		close(b.entered)
	}
	if b.block != nil {
		<-b.block
	}
	answer, _ := json.Marshal(bridgeSigned{Signature: "-----BEGIN PGP SIGNATURE-----\ntest\n-----END PGP SIGNATURE-----",
		Status: "[GNUPG:] SIG_CREATED D 1 8 00 1700000000 " + fingerprint + "\n"})
	return string(answer), nil
}

func bridgeTestServer(t *testing.T) (*bridgeServer, *bridgeTestBackend) {
	t.Helper()
	backend := &bridgeTestBackend{}
	s, err := newBridgeServer(backend, "http://127.0.0.1:17389", 3600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.close)
	return s, backend
}

func bridgePost(s *bridgeServer, path string, body []byte, peer string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	if peer != "" {
		r = r.WithContext(context.WithValue(r.Context(), bridgePeerContextKey{}, bridgePeer{id: peer, name: peer + ".test"}))
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

type bridgeTestClient struct {
	id          string
	write, read *noise.CipherState
}

func bridgeClient(t *testing.T, s *bridgeServer, peer string) bridgeTestClient {
	t.Helper()
	hs, err := noise.NewHandshakeState(noise.Config{CipherSuite: bridgeSuite, Pattern: noise.HandshakeNK,
		Initiator: true, Prologue: []byte("gpg-bridge rpc v1"), PeerStatic: s.public,
		PresharedKey: s.psk, PresharedKeyPlacement: 0})
	if err != nil {
		t.Fatal(err)
	}
	message, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"session": s.ticket.Session, "message": bridgeEncoding.EncodeToString(message)})
	w := bridgePost(s, "/v1/handshake", body, peer)
	if w.Code != http.StatusOK {
		t.Fatalf("handshake HTTP %d: %s", w.Code, w.Body.String())
	}
	var welcome struct {
		ID      string `json:"id"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &welcome); err != nil {
		t.Fatal(err)
	}
	reply, _ := bridgeEncoding.DecodeString(welcome.Message)
	_, write, read, err := hs.ReadMessage(nil, reply)
	if err != nil || write == nil || read == nil {
		t.Fatalf("client handshake: %v", err)
	}
	return bridgeTestClient{id: welcome.ID, write: write, read: read}
}

func bridgeRequest(t *testing.T, s *bridgeServer, client bridgeTestClient, request any, peer string) (*httptest.ResponseRecorder, map[string]json.RawMessage) {
	t.Helper()
	plain, _ := json.Marshal(request)
	wire, err := bridgeSeal(client.write, plain)
	if err != nil {
		t.Fatal(err)
	}
	w := bridgePost(s, "/v1/rpc/"+client.id, wire, peer)
	var response map[string]json.RawMessage
	if w.Code == http.StatusOK {
		data, err := bridgeOpen(client.read, w.Body.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(data, &response); err != nil {
			t.Fatal(err)
		}
	}
	return w, response
}

func bridgeCommit(message string) []byte {
	return []byte("tree " + strings.Repeat("a", 40) + "\nauthor Test <t@example.invalid> 1700000000 +0000\ncommitter Test <t@example.invalid> 1700000000 +0000\n\n" + message + "\n")
}

func TestBridgeInfoTicketAndSigning(t *testing.T) {
	s, backend := bridgeTestServer(t)
	ticket, err := s.ticketString()
	if err != nil || !strings.HasPrefix(ticket, "gpgbridge:v1:") {
		t.Fatalf("ticket: %v", err)
	}
	ticketJSON, _ := bridgeEncoding.DecodeString(strings.TrimPrefix(ticket, "gpgbridge:v1:"))
	var parsed bridgeTicket
	if json.Unmarshal(ticketJSON, &parsed) != nil || parsed.Version != 1 || parsed.Session == "" || parsed.Expires != s.ticket.Expires {
		t.Fatal("invalid ticket")
	}
	public, _ := bridgeEncoding.DecodeString(parsed.ServerPublic)
	psk, _ := bridgeEncoding.DecodeString(parsed.PSK)
	if len(public) != 32 || len(psk) != 32 {
		t.Fatal("invalid key lengths")
	}
	w, response := bridgeRequest(t, s, bridgeClient(t, s, "node"), map[string]string{"op": "info"}, "node")
	if w.Code != 200 || string(response["result"]) != `"info"` || string(response["session"]) != `"`+s.ticket.Session+`"` || len(response["public_keys"]) == 0 {
		t.Fatal("invalid info response")
	}
	w, response = bridgeRequest(t, s, bridgeClient(t, s, "node"), map[string]string{"op": "sign", "fingerprint": bridgeTestFingerprint, "data": bridgeEncoding.EncodeToString(bridgeCommit("Test commit"))}, "node")
	if w.Code != 200 || string(response["result"]) != `"signed"` || backend.calls.Load() != 1 {
		t.Fatalf("sign response: %v", response)
	}
}

func TestBridgeInfoAllowsMoreThan128SelectedKeysWithinWireBounds(t *testing.T) {
	s, backend := bridgeTestServer(t)
	info := bridgeInfo{PublicKeys: "-----BEGIN PGP PUBLIC KEY BLOCK-----\ntest\n-----END PGP PUBLIC KEY BLOCK-----"}
	for index := range 129 {
		info.Keys = append(info.Keys, bridgeSigningKey{
			Primary: bridgeTestFingerprint, Fingerprint: fmt.Sprintf("%040X", index+1), UID: "Test key",
		})
	}
	encoded, err := json.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	backend.info = string(encoded)
	w, response := bridgeRequest(t, s, bridgeClient(t, s, "node"), map[string]string{"op": "info"}, "node")
	var returned []bridgeSigningKey
	if w.Code != http.StatusOK || string(response["result"]) != `"info"` ||
		json.Unmarshal(response["keys"], &returned) != nil || len(returned) != 129 {
		t.Fatal("valid selected keys were restricted by an artificial count limit")
	}
}

func TestBridgeAuthenticationAndIdentity(t *testing.T) {
	s, backend := bridgeTestServer(t)
	if bridgePost(s, "/v1/handshake", nil, "").Code != http.StatusUnauthorized {
		t.Fatal("unauthenticated transport accepted")
	}
	for _, wrongIdentity := range []bool{false, true} {
		psk := bytes.Clone(s.psk)
		public := bytes.Clone(s.public)
		if wrongIdentity {
			pair, _ := bridgeSuite.GenerateKeypair(nil)
			public = pair.Public
		} else {
			psk[0] ^= 1
		}
		hs, err := noise.NewHandshakeState(noise.Config{CipherSuite: bridgeSuite, Pattern: noise.HandshakeNK, Initiator: true, Prologue: []byte("gpg-bridge rpc v1"), PeerStatic: public, PresharedKey: psk, PresharedKeyPlacement: 0})
		if err != nil {
			t.Fatal(err)
		}
		message, _, _, err := hs.WriteMessage(nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(map[string]string{"session": s.ticket.Session, "message": bridgeEncoding.EncodeToString(message)})
		if bridgePost(s, "/v1/handshake", body, "node").Code != http.StatusUnauthorized {
			t.Fatal("wrong key accepted")
		}
	}
	if backend.calls.Load() != 0 {
		t.Fatal("handshake executed signing")
	}
}

func TestBridgePeerBindingAndReplay(t *testing.T) {
	s, _ := bridgeTestServer(t)
	client := bridgeClient(t, s, "node")
	wire, _ := bridgeSeal(client.write, []byte(`{"op":"info"}`))
	if bridgePost(s, "/v1/rpc/"+client.id, wire, "other-node").Code != 401 {
		t.Fatal("cross-peer request accepted")
	}
	if bridgePost(s, "/v1/rpc/"+client.id, wire, "node").Code != 200 {
		t.Fatal("owner request denied")
	}
	if bridgePost(s, "/v1/rpc/"+client.id, wire, "node").Code != 401 {
		t.Fatal("replayed request accepted")
	}
}

func TestBridgeTamperAndTruncationNeverSign(t *testing.T) {
	for _, mode := range []string{"tamper", "truncated-frame", "truncated-suffix", "appended-frame"} {
		t.Run(mode, func(t *testing.T) {
			s, backend := bridgeTestServer(t)
			client := bridgeClient(t, s, "node")
			plain, _ := json.Marshal(map[string]string{"op": "sign", "fingerprint": bridgeTestFingerprint, "data": bridgeEncoding.EncodeToString(bridgeCommit(strings.Repeat("x", 100000)))})
			wire, _ := bridgeSeal(client.write, plain)
			switch mode {
			case "tamper":
				wire[20] ^= 1
			case "truncated-frame":
				wire = wire[:len(wire)-1]
			case "truncated-suffix":
				wire = wire[:4+int(binary.BigEndian.Uint32(wire[:4]))]
			case "appended-frame":
				wire = append(wire, 0, 0, 0, 0)
			}
			if bridgePost(s, "/v1/rpc/"+client.id, wire, "node").Code != 401 {
				t.Fatal("invalid frame accepted")
			}
			if backend.calls.Load() != 0 {
				t.Fatal("invalid frame caused signing")
			}
			if bridgePost(s, "/v1/rpc/"+client.id, wire, "node").Code != 401 {
				t.Fatal("failed request state reused")
			}
		})
	}
}

func TestBridgeRejectsDataKeyAndExtraFields(t *testing.T) {
	s, backend := bridgeTestServer(t)
	requests := []map[string]string{
		{"op": "sign", "fingerprint": strings.Repeat("F", 40), "data": bridgeEncoding.EncodeToString(bridgeCommit("x"))},
		{"op": "sign", "fingerprint": bridgeTestFingerprint, "data": bridgeEncoding.EncodeToString([]byte("arbitrary data"))},
		{"op": "sign", "fingerprint": bridgeTestFingerprint, "data": bridgeEncoding.EncodeToString(bridgeCommit("x")), "path": "/tmp/file"},
		{"op": "info", "fingerprint": bridgeTestFingerprint},
		{"op": "decrypt"},
	}
	for _, request := range requests {
		w, response := bridgeRequest(t, s, bridgeClient(t, s, "node"), request, "node")
		if w.Code != 200 || string(response["result"]) != `"error"` {
			t.Fatal("unsupported request accepted")
		}
	}
	if backend.calls.Load() != 0 {
		t.Fatal("unsupported request caused signing")
	}
}

func TestBridgeExpirationAndPendingBounds(t *testing.T) {
	s, _ := bridgeTestServer(t)
	client := bridgeClient(t, s, "node")
	s.mu.Lock()
	s.pending[client.id].created = time.Now().Add(-31 * time.Second)
	s.mu.Unlock()
	w, _ := bridgeRequest(t, s, client, map[string]string{"op": "info"}, "node")
	if w.Code != 410 {
		t.Fatal("expired pending state accepted")
	}
	s.mu.Lock()
	s.ticket.Expires = time.Now().Unix() - 1
	s.mu.Unlock()
	if _, err := s.ticketString(); err == nil {
		t.Fatal("expired ticket available")
	}
	if bridgePost(s, "/v1/handshake", nil, "node").Code != 410 {
		t.Fatal("expired session accepted")
	}
	s2, _ := bridgeTestServer(t)
	for i := range 64 {
		s2.pending[string(rune(i+1))] = &bridgePending{created: time.Now(), peerID: "node"}
	}
	hs, _ := noise.NewHandshakeState(noise.Config{CipherSuite: bridgeSuite, Pattern: noise.HandshakeNK, Initiator: true, Prologue: []byte("gpg-bridge rpc v1"), PeerStatic: s2.public, PresharedKey: s2.psk, PresharedKeyPlacement: 0})
	message, _, _, _ := hs.WriteMessage(nil, nil)
	body, _ := json.Marshal(map[string]string{"session": s2.ticket.Session, "message": bridgeEncoding.EncodeToString(message)})
	if bridgePost(s2, "/v1/handshake", body, "node").Code != 429 {
		t.Fatal("pending limit ignored")
	}
}

func TestBridgeSigningIsSerialized(t *testing.T) {
	s, backend := bridgeTestServer(t)
	backend.entered = make(chan struct{})
	backend.block = make(chan struct{})
	first, second := bridgeClient(t, s, "node"), bridgeClient(t, s, "node")
	request := map[string]string{"op": "sign", "fingerprint": bridgeTestFingerprint, "data": bridgeEncoding.EncodeToString(bridgeCommit("x"))}
	plain, _ := json.Marshal(request)
	wire, _ := bridgeSeal(first.write, plain)
	done := make(chan int, 1)
	go func() { done <- bridgePost(s, "/v1/rpc/"+first.id, wire, "node").Code }()
	select {
	case <-backend.entered:
	case <-time.After(time.Second):
		t.Fatal("first signing did not start")
	}
	w, response := bridgeRequest(t, s, second, request, "node")
	if w.Code != 200 || string(response["result"]) != `"error"` || backend.calls.Load() != 1 {
		t.Fatal("concurrent signing was allowed")
	}
	close(backend.block)
	select {
	case code := <-done:
		if code != 200 {
			t.Fatal("first request failed")
		}
	case <-time.After(time.Second):
		t.Fatal("signing remained blocked")
	}
}

func TestBridgeRevocationDuringSigningDiscardsResult(t *testing.T) {
	for _, mode := range []string{"close", "expire"} {
		t.Run(mode, func(t *testing.T) {
			s, backend := bridgeTestServer(t)
			backend.entered = make(chan struct{})
			backend.block = make(chan struct{})
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(backend.block) }) }
			defer release()
			client := bridgeClient(t, s, "node")
			plain, _ := json.Marshal(map[string]string{
				"op": "sign", "fingerprint": bridgeTestFingerprint,
				"data": bridgeEncoding.EncodeToString(bridgeCommit("Signing while the ticket is revoked")),
			})
			wire, err := bridgeSeal(client.write, plain)
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() { done <- bridgePost(s, "/v1/rpc/"+client.id, wire, "node") }()
			select {
			case <-backend.entered:
			case <-time.After(time.Second):
				t.Fatal("backend signing did not start")
			}
			revoked := make(chan struct{})
			go func() {
				if mode == "close" {
					s.close()
				} else {
					s.mu.Lock()
					s.ticket.Expires = time.Now().Unix() - 1
					s.mu.Unlock()
				}
				close(revoked)
			}()
			select {
			case <-revoked:
			case <-time.After(time.Second):
				t.Fatal("ticket revocation waited for the blocked backend")
			}
			if _, err := s.ticketString(); err == nil {
				t.Fatal("revoked ticket remains available")
			}
			if bridgePost(s, "/v1/handshake", nil, "node").Code != http.StatusGone {
				t.Fatal("new handshake accepted after ticket revocation")
			}
			release()
			select {
			case response := <-done:
				if response.Code != http.StatusGone || strings.Contains(response.Body.String(), "PGP SIGNATURE") {
					t.Fatal("signature result returned after ticket revocation")
				}
			case <-time.After(time.Second):
				t.Fatal("request did not finish after backend release")
			}
			if backend.calls.Load() != 1 {
				t.Fatal("unexpected additional signature operation")
			}
		})
	}
}

func TestBridgeGitDataShape(t *testing.T) {
	if !bridgeGitData(bridgeCommit("x")) {
		t.Fatal("commit rejected")
	}
	tag := []byte("object " + strings.Repeat("a", 64) + "\ntype commit\ntag v1\ntagger Test <x@y> 1 +0000\n\nTag message\n")
	if !bridgeGitData(tag) {
		t.Fatal("tag rejected")
	}
	for _, data := range [][]byte{[]byte("arbitrary"), []byte("tree " + strings.Repeat("a", 40) + "\n\nmessage"), {0xff, 0xfe}} {
		if bridgeGitData(data) {
			t.Fatal("invalid Git input accepted")
		}
	}
}

type bridgeSlowWriter struct {
	header           http.Header
	entered, release chan struct{}
	once             sync.Once
}

func (w *bridgeSlowWriter) Header() http.Header { return w.header }
func (*bridgeSlowWriter) WriteHeader(int)       {}
func (w *bridgeSlowWriter) Write(data []byte) (int, error) {
	w.once.Do(func() { close(w.entered) })
	<-w.release
	return len(data), nil
}

func TestBridgeSlowHandshakeReaderCannotDelayRevocation(t *testing.T) {
	s, _ := bridgeTestServer(t)
	hs, _ := noise.NewHandshakeState(noise.Config{CipherSuite: bridgeSuite, Pattern: noise.HandshakeNK,
		Initiator: true, Prologue: []byte("gpg-bridge rpc v1"), PeerStatic: s.public,
		PresharedKey: s.psk, PresharedKeyPlacement: 0})
	message, _, _, _ := hs.WriteMessage(nil, nil)
	body, _ := json.Marshal(map[string]string{"session": s.ticket.Session, "message": bridgeEncoding.EncodeToString(message)})
	r := httptest.NewRequest(http.MethodPost, "/v1/handshake", bytes.NewReader(body))
	r = r.WithContext(context.WithValue(r.Context(), bridgePeerContextKey{}, bridgePeer{id: "node", name: "node.test"}))
	w := &bridgeSlowWriter{header: make(http.Header), entered: make(chan struct{}), release: make(chan struct{})}
	done := make(chan struct{})
	go func() { s.ServeHTTP(w, r); close(done) }()
	defer func() { close(w.release); <-done }()
	select {
	case <-w.entered:
	case <-time.After(time.Second):
		t.Fatal("handshake did not write response")
	}
	closed := make(chan struct{})
	go func() { s.close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("slow receiver delayed ticket revocation")
	}
	if _, err := s.ticketString(); err == nil {
		t.Fatal("revoked ticket remains available")
	}
}
