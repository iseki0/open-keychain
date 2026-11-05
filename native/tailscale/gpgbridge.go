// Copyright 2026 OpenKeychain contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package tailagent

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/flynn/noise"
)

const bridgePort = 17389
const bridgeMaxData = 1024 * 1024
const bridgeMaxWire = 2 * 1024 * 1024
const bridgeMaxPlain = bridgeMaxWire - 4096
const bridgeChunk = 60000

var bridgeEncoding = base64.RawURLEncoding.Strict()
var bridgeSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)

// BridgeBackend supplies the selected public keys and performs locally approved
// OpenPGP signing. Passwords never cross this interface. Implementations must
// recheck key validity, selection, session expiry, and approval before signing.
type BridgeBackend interface {
	// InfoJSON returns {"keys":[{"primary","fingerprint","uid","expires","hardware"}],"public_keys":armor}.
	InfoJSON() (string, error)
	// Sign returns {"signature":armoredDetachedSignature,"status":GnuPGStatus}.
	Sign(fingerprint string, data []byte, peerID string, peerName string) (string, error)
}

type bridgeTicket struct {
	Version      int    `json:"version"`
	Endpoint     string `json:"endpoint"`
	ServerPublic string `json:"server_public"`
	PSK          string `json:"psk"`
	Session      string `json:"session"`
	Expires      int64  `json:"expires"`
}

type bridgeSigningKey struct {
	Primary     string `json:"primary"`
	Fingerprint string `json:"fingerprint"`
	UID         string `json:"uid"`
	Expires     int64  `json:"expires"`
	Hardware    bool   `json:"hardware"`
}

type bridgeInfo struct {
	Keys       []bridgeSigningKey `json:"keys"`
	PublicKeys string             `json:"public_keys"`
}

type bridgeSigned struct {
	Signature string `json:"signature"`
	Status    string `json:"status"`
}

type bridgePeer struct{ id, name string }
type bridgePeerContextKey struct{}

type bridgePending struct {
	created time.Time
	peerID  string
	read    *noise.CipherState
	write   *noise.CipherState
}

type bridgeWelcome struct {
	ID      string `json:"id"`
	Message string `json:"message"`
}

type bridgeServer struct {
	mu        sync.Mutex
	backend   BridgeBackend
	ticket    bridgeTicket
	private   []byte
	public    []byte
	psk       []byte
	pending   map[string]*bridgePending
	closed    bool
	closeOnce sync.Once
	timer     *time.Timer
	http      *http.Server
	listener  net.Listener
	requests  chan struct{}
	signing   chan struct{}
	rateStart time.Time
	rateCount int
}

// StartBridge opens a separate HTTP endpoint inside the embedded tailnet. The
// returned gpgbridge:v1 ticket is a temporary credential; never log or persist it.
// The node must already be logged in. Every accepted peer also passes the same
// WhoIs identity check and optional NodeID filter as the Assuan listener.
// Call this on a worker thread.
func (n *Node) StartBridge(backend BridgeBackend, ttlSeconds int64) (ticket string, err error) {
	defer recoverError(&err)
	n.bridgeMu.Lock()
	defer n.bridgeMu.Unlock()
	if backend == nil {
		return "", errors.New("signing backend is required")
	}
	if n.bridge != nil {
		if existing, e := n.bridge.ticketString(); e == nil {
			return existing, nil
		}
		n.bridge.close()
		n.bridge = nil
	}
	n.mu.Lock()
	client, ctx, closed, started, startErr := n.client, n.ctx, n.closed, n.started, n.startErr
	n.mu.Unlock()
	if closed {
		return "", net.ErrClosed
	}
	if !started || startErr != nil || client == nil {
		return "", errors.New("connect to Tailscale before starting gpg-bridge")
	}
	statusCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	status, err := client.StatusWithoutPeers(statusCtx)
	if err != nil || status == nil || status.BackendState != "Running" || len(status.TailscaleIPs) == 0 {
		return "", errors.New("sign in to Tailscale before starting gpg-bridge")
	}
	endpoint := "http://" + net.JoinHostPort(status.TailscaleIPs[0].String(), "17389")
	s, err := newBridgeServer(backend, endpoint, ttlSeconds)
	if err != nil {
		return "", err
	}
	if _, err := s.info(); err != nil {
		s.close()
		return "", errors.New("choose at least one available signing key before starting gpg-bridge")
	}
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		s.close()
		return "", net.ErrClosed
	}
	listener, err := n.server.Listen("tcp", ":17389")
	n.mu.Unlock()
	if err != nil {
		s.close()
		return "", err
	}
	s.listener = &bridgeAuthorizedListener{Listener: listener, node: n}
	s.http = &http.Server{
		Handler: s, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 130 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192,
		ErrorLog: log.New(io.Discard, "", 0),
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if authorized, ok := c.(*bridgeAuthorizedConn); ok {
				return context.WithValue(ctx, bridgePeerContextKey{}, authorized.peer)
			}
			return ctx
		},
	}
	n.bridge = s
	s.mu.Lock()
	s.timer = time.AfterFunc(time.Until(time.Unix(s.ticket.Expires, 0)), s.close)
	s.mu.Unlock()
	go func() { _ = s.http.Serve(s.listener) }()
	return s.ticketString()
}

// BridgeTicket returns the active temporary ticket, or an error after expiry.
func (n *Node) BridgeTicket() (ticket string, err error) {
	defer recoverError(&err)
	n.bridgeMu.Lock()
	defer n.bridgeMu.Unlock()
	if n.bridge == nil {
		return "", errors.New("gpg-bridge is not running")
	}
	return n.bridge.ticketString()
}

// StopBridge revokes the ticket and closes only the gpg-bridge endpoint. The
// Assuan agent and Tailscale node remain available. Call from a worker thread.
func (n *Node) StopBridge() (err error) {
	defer recoverError(&err)
	n.bridgeMu.Lock()
	defer n.bridgeMu.Unlock()
	if n.bridge != nil {
		n.bridge.close()
		n.bridge = nil
	}
	return nil
}

func newBridgeServer(backend BridgeBackend, endpoint string, ttlSeconds int64) (*bridgeServer, error) {
	if backend == nil || ttlSeconds < 1 || ttlSeconds > 24*60*60 {
		return nil, errors.New("gpg-bridge lifetime must be between 1 second and 24 hours")
	}
	pair, err := bridgeSuite.GenerateKeypair(rand.Reader)
	if err != nil {
		return nil, err
	}
	psk, session := make([]byte, 32), make([]byte, 16)
	if _, err = io.ReadFull(rand.Reader, psk); err != nil {
		return nil, err
	}
	if _, err = io.ReadFull(rand.Reader, session); err != nil {
		return nil, err
	}
	return &bridgeServer{
		backend: backend, private: pair.Private, public: pair.Public, psk: psk,
		ticket: bridgeTicket{Version: 1, Endpoint: endpoint,
			ServerPublic: bridgeEncoding.EncodeToString(pair.Public), PSK: bridgeEncoding.EncodeToString(psk),
			Session: bridgeEncoding.EncodeToString(session), Expires: time.Now().Unix() + ttlSeconds},
		pending: make(map[string]*bridgePending), requests: make(chan struct{}, 32), signing: make(chan struct{}, 1),
		rateStart: time.Now(),
	}, nil
}

func (s *bridgeServer) ticketString() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || time.Now().Unix() >= s.ticket.Expires {
		return "", errors.New("gpg-bridge session expired")
	}
	data, err := json.Marshal(s.ticket)
	if err != nil {
		return "", err
	}
	return "gpgbridge:v1:" + bridgeEncoding.EncodeToString(data), nil
}

func (s *bridgeServer) close() {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		clear(s.pending)
		clear(s.private)
		clear(s.psk)
		s.ticket.PSK = ""
		timer, server, listener := s.timer, s.http, s.listener
		s.mu.Unlock()
		if timer != nil {
			timer.Stop()
		}
		if server != nil {
			_ = server.Close()
		} else if listener != nil {
			_ = listener.Close()
		}
	})
}

func (s *bridgeServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if recover() != nil {
			http.Error(w, "Signing service failed", http.StatusInternalServerError)
		}
	}()
	peer, authorized := r.Context().Value(bridgePeerContextKey{}).(bridgePeer)
	if !authorized || peer.id == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	select {
	case s.requests <- struct{}{}:
		defer func() { <-s.requests }()
	default:
		http.Error(w, "Service busy", http.StatusTooManyRequests)
		return
	}
	s.mu.Lock()
	expired := s.closed || time.Now().Unix() >= s.ticket.Expires
	s.mu.Unlock()
	if expired {
		http.Error(w, "Session expired", http.StatusGone)
		return
	}
	if r.Method != http.MethodPost || r.URL.RawQuery != "" {
		http.Error(w, "Unsupported request", http.StatusNotFound)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	switch {
	case r.URL.Path == "/v1/handshake":
		s.handshake(w, r, peer)
	case strings.HasPrefix(r.URL.Path, "/v1/rpc/"):
		s.rpc(w, r, peer, strings.TrimPrefix(r.URL.Path, "/v1/rpc/"))
	default:
		http.Error(w, "Unsupported request", http.StatusNotFound)
	}
}

func (s *bridgeServer) handshake(w http.ResponseWriter, r *http.Request, peer bridgePeer) {
	s.mu.Lock()
	now := time.Now()
	if now.Sub(s.rateStart) >= time.Second {
		s.rateStart, s.rateCount = now, 0
	}
	s.rateCount++
	if s.rateCount > 20 {
		s.mu.Unlock()
		http.Error(w, "Service busy", http.StatusTooManyRequests)
		return
	}
	s.mu.Unlock()
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
	var hello struct {
		Session string `json:"session"`
		Message string `json:"message"`
	}
	if err != nil || bridgeDecodeJSON(body, &hello) != nil {
		http.Error(w, "Invalid handshake", http.StatusBadRequest)
		return
	}
	message, err := bridgeEncoding.DecodeString(hello.Message)
	if err != nil {
		http.Error(w, "Invalid handshake", http.StatusBadRequest)
		return
	}
	welcome, status := s.completeHandshake(hello.Session, message, peer.id)
	if status != http.StatusOK {
		http.Error(w, "Handshake denied", status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(welcome)
}

// Keep network writes outside the session mutex so a slow receiver cannot
// postpone local ticket revocation or expiration.
func (s *bridgeServer) completeHandshake(session string, message []byte, peerID string) (bridgeWelcome, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || time.Now().Unix() >= s.ticket.Expires {
		return bridgeWelcome{}, http.StatusGone
	}
	if session != s.ticket.Session {
		return bridgeWelcome{}, http.StatusUnauthorized
	}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: bridgeSuite, Pattern: noise.HandshakeNK, Prologue: []byte("gpg-bridge rpc v1"),
		PresharedKey: s.psk, PresharedKeyPlacement: 0,
		StaticKeypair: noise.DHKey{Private: s.private, Public: s.public},
	})
	if err != nil {
		return bridgeWelcome{}, http.StatusInternalServerError
	}
	if _, _, _, err = hs.ReadMessage(nil, message); err != nil {
		return bridgeWelcome{}, http.StatusUnauthorized
	}
	reply, read, write, err := hs.WriteMessage(nil, nil)
	if err != nil || read == nil || write == nil {
		return bridgeWelcome{}, http.StatusInternalServerError
	}
	for id, p := range s.pending {
		if time.Since(p.created) >= 30*time.Second {
			delete(s.pending, id)
		}
	}
	if len(s.pending) >= 64 {
		return bridgeWelcome{}, http.StatusTooManyRequests
	}
	idBytes := make([]byte, 16)
	if _, err = io.ReadFull(rand.Reader, idBytes); err != nil {
		return bridgeWelcome{}, http.StatusInternalServerError
	}
	id := bridgeEncoding.EncodeToString(idBytes)
	s.pending[id] = &bridgePending{created: time.Now(), peerID: peerID, read: read, write: write}
	return bridgeWelcome{id, bridgeEncoding.EncodeToString(reply)}, http.StatusOK
}

func (s *bridgeServer) rpc(w http.ResponseWriter, r *http.Request, peer bridgePeer, id string) {
	if len(id) == 0 || len(id) > 128 || strings.ContainsAny(id, "/\\") {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	s.mu.Lock()
	p := s.pending[id]
	if p != nil && p.peerID == peer.id {
		delete(s.pending, id)
	} else {
		p = nil
	}
	s.mu.Unlock()
	if p == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if time.Since(p.created) >= 30*time.Second {
		http.Error(w, "Request expired", http.StatusGone)
		return
	}
	wire, err := io.ReadAll(http.MaxBytesReader(w, r.Body, bridgeMaxWire))
	if err != nil {
		http.Error(w, "Request too large", http.StatusRequestEntityTooLarge)
		return
	}
	plain, err := bridgeOpen(p.read, wire)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	defer clear(plain)
	var request map[string]json.RawMessage
	if bridgeDecodeJSON(plain, &request) != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	var op string
	if json.Unmarshal(request["op"], &op) != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	response := s.handle(r.Context(), peer, op, request)
	if r.Context().Err() != nil {
		return
	}
	s.mu.Lock()
	expired := s.closed || time.Now().Unix() >= s.ticket.Expires
	s.mu.Unlock()
	if expired {
		http.Error(w, "Session expired", http.StatusGone)
		return
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		http.Error(w, "Signing failed", http.StatusInternalServerError)
		return
	}
	sealed, err := bridgeSeal(p.write, encoded)
	if err != nil {
		http.Error(w, "Signing failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(sealed)
}

func (s *bridgeServer) handle(ctx context.Context, peer bridgePeer, op string, request map[string]json.RawMessage) any {
	failure := map[string]string{"result": "error", "message": "Signing was denied, expired, busy, or failed"}
	info, err := s.info()
	if err != nil {
		return failure
	}
	if op == "info" && len(request) == 1 {
		return struct {
			Result  string `json:"result"`
			Session string `json:"session"`
			Expires int64  `json:"expires"`
			bridgeInfo
		}{"info", s.ticket.Session, s.ticket.Expires, info}
	}
	if op != "sign" || len(request) != 3 {
		return failure
	}
	var fingerprint, data64 string
	if json.Unmarshal(request["fingerprint"], &fingerprint) != nil || json.Unmarshal(request["data"], &data64) != nil {
		return failure
	}
	found := false
	for _, key := range info.Keys {
		if key.Fingerprint == fingerprint && (key.Expires == 0 || key.Expires > time.Now().Unix()) {
			found = true
		}
	}
	if !found || len(data64) > (bridgeMaxData+2)/3*4 {
		return failure
	}
	data, err := bridgeEncoding.DecodeString(data64)
	defer clear(data)
	if err != nil || len(data) == 0 || len(data) > bridgeMaxData || !bridgeGitData(data) {
		return failure
	}
	select {
	case s.signing <- struct{}{}:
		defer func() { <-s.signing }()
	default:
		return failure
	}
	if ctx.Err() != nil {
		return failure
	}
	s.mu.Lock()
	expired := s.closed || time.Now().Unix() >= s.ticket.Expires
	s.mu.Unlock()
	if expired {
		return failure
	}
	answer, err := s.backend.Sign(fingerprint, data, peer.id, peer.name)
	if err != nil || len(answer) > bridgeMaxPlain {
		return failure
	}
	var signed bridgeSigned
	if bridgeDecodeJSON([]byte(answer), &signed) != nil || !strings.HasPrefix(signed.Signature, "-----BEGIN PGP SIGNATURE-----") {
		return failure
	}
	statusOK := false
	for _, line := range strings.Split(signed.Status, "\n") {
		if strings.HasPrefix(line, "[GNUPG:] SIG_CREATED ") && strings.HasSuffix(line, " "+fingerprint) {
			statusOK = true
		}
	}
	if !statusOK {
		return failure
	}
	return struct {
		Result string `json:"result"`
		bridgeSigned
	}{"signed", signed}
}

func (s *bridgeServer) info() (bridgeInfo, error) {
	var info bridgeInfo
	value, err := s.backend.InfoJSON()
	if err != nil || len(value) > bridgeMaxPlain {
		return info, errors.New("public keys unavailable")
	}
	if bridgeDecodeJSON([]byte(value), &info) != nil || len(info.Keys) == 0 ||
		len(info.PublicKeys) > bridgeMaxData || !strings.HasPrefix(info.PublicKeys, "-----BEGIN PGP PUBLIC KEY BLOCK-----") {
		return info, errors.New("public keys unavailable")
	}
	for _, key := range info.Keys {
		if !bridgeFingerprint(key.Primary) || !bridgeFingerprint(key.Fingerprint) || key.Expires < 0 {
			return info, errors.New("invalid signing key")
		}
	}
	return info, nil
}

func bridgeDecodeJSON(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("trailing JSON data")
	}
	return nil
}

func bridgeFingerprint(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for _, c := range []byte(value) {
		if !(c >= '0' && c <= '9' || c >= 'A' && c <= 'F' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// Match gpg-bridge's default basic Git commit/tag shape check. This is only an
// input restriction and display aid; it does not prove repository ownership.
func bridgeGitData(data []byte) bool {
	if !utf8.Valid(data) {
		return false
	}
	headers, _, found := strings.Cut(string(data), "\n\n")
	if !found {
		return false
	}
	fields := make(map[string]string)
	for _, line := range strings.Split(headers, "\n") {
		name, value, present := strings.Cut(strings.TrimSuffix(line, "\r"), " ")
		if present {
			if _, duplicate := fields[name]; !duplicate {
				fields[name] = value
			}
		}
	}
	_, author := fields["author"]
	_, committer := fields["committer"]
	if bridgeFingerprint(fields["tree"]) && author && committer {
		return true
	}
	_, tag := fields["tag"]
	_, tagger := fields["tagger"]
	typeOK := fields["type"] == "commit" || fields["type"] == "tree" || fields["type"] == "blob" || fields["type"] == "tag"
	return bridgeFingerprint(fields["object"]) && typeOK && tag && tagger
}

func bridgeSeal(state *noise.CipherState, plain []byte) ([]byte, error) {
	if len(plain) == 0 || len(plain) > bridgeMaxPlain {
		return nil, errors.New("message size exceeds limit")
	}
	payload := make([]byte, 8+len(plain))
	binary.BigEndian.PutUint64(payload, uint64(len(plain)))
	copy(payload[8:], plain)
	defer clear(payload)
	wire := make([]byte, 0, len(payload)+1024)
	for len(payload) > 0 {
		count := min(len(payload), bridgeChunk)
		encrypted, err := state.Encrypt(nil, nil, payload[:count])
		if err != nil {
			return nil, err
		}
		wire = binary.BigEndian.AppendUint32(wire, uint32(len(encrypted)))
		wire = append(wire, encrypted...)
		payload = payload[count:]
	}
	if len(wire) > bridgeMaxWire {
		return nil, errors.New("message size exceeds limit")
	}
	return wire, nil
}

func bridgeOpen(state *noise.CipherState, wire []byte) ([]byte, error) {
	if len(wire) == 0 || len(wire) > bridgeMaxWire {
		return nil, errors.New("message size exceeds limit")
	}
	plain := make([]byte, 0, len(wire))
	for len(wire) > 0 {
		if len(wire) < 4 {
			return nil, errors.New("truncated frame")
		}
		length := int(binary.BigEndian.Uint32(wire[:4]))
		wire = wire[4:]
		if length < 16 || length > 65535 || length > len(wire) {
			return nil, errors.New("invalid frame length")
		}
		var err error
		plain, err = state.Decrypt(plain, nil, wire[:length])
		if err != nil {
			clear(plain)
			return nil, err
		}
		wire = wire[length:]
	}
	if len(plain) < 8 || binary.BigEndian.Uint64(plain[:8]) != uint64(len(plain)-8) {
		clear(plain)
		return nil, errors.New("truncated or appended message")
	}
	return plain[8:], nil
}

type bridgeAuthorizedListener struct {
	net.Listener
	node *Node
}

type bridgeAuthorizedConn struct {
	net.Conn
	tracked *Connection
	peer    bridgePeer
}

func (c *bridgeAuthorizedConn) Close() error { return c.tracked.Close() }

func (l *bridgeAuthorizedListener) Accept() (net.Conn, error) {
	n := l.node
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		n.mu.Lock()
		client, ctx, closed := n.client, n.ctx, n.closed
		n.mu.Unlock()
		if closed || client == nil {
			_ = conn.Close()
			return nil, net.ErrClosed
		}
		lookupCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		identity, err := client.WhoIs(lookupCtx, conn.RemoteAddr().String())
		cancel()
		if err != nil || identity == nil || identity.Node == nil {
			_ = conn.Close()
			continue
		}
		id := string(identity.Node.StableID)
		n.mu.Lock()
		if n.closed || !n.allowsPeer(id) || len(n.conns) >= maxConnections {
			n.mu.Unlock()
			_ = conn.Close()
			continue
		}
		tracked := &Connection{conn: conn, node: n, peerID: id, peerName: identity.Node.Name}
		n.conns[tracked] = struct{}{}
		n.mu.Unlock()
		return &bridgeAuthorizedConn{Conn: conn, tracked: tracked, peer: bridgePeer{id: id, name: identity.Node.Name}}, nil
	}
}
