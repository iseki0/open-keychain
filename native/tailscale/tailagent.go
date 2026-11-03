// Copyright 2026 OpenKeychain contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// Package tailagent embeds a userspace-only Tailscale listener for OpenKeychain.
// It never creates a TUN device, a system VPN, or an operating-system TCP listener.
package tailagent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/tsnet"
)

const idleTimeout = 2 * time.Minute
const maxConnections = 4

// TS_LOGS_DIR is process-wide. Keep its configuration and backend initialization
// together even if two callers attempt to start nodes at the same time. Android's
// service runs one node; retain the setting for any later internal log writers.
var tailscaleStartupMu sync.Mutex

// Node owns an independent Tailscale identity. Close it when the Android service stops.
// All exported operations return errors rather than allowing a panic across JNI.
type Node struct {
	bridgeMu sync.Mutex
	bridge   *bridgeServer
	mu       sync.Mutex
	server   *tsnet.Server
	listener net.Listener
	client   *local.Client
	allowed  map[string]bool
	allowAll bool
	logMu    sync.Mutex
	logs     []string
	conns    map[*Connection]struct{}
	ctx      context.Context
	cancel   context.CancelFunc
	port     int32
	started  bool
	closed   bool
	startErr error
}

// NewNode creates a node without starting network activity. allowedPeerIdsCsv is
// a comma-separated list of stable Tailscale node IDs, not names or IP addresses.
// An empty list allows every authenticated tailnet node, subject to tailnet ACLs.
// authKey may be empty to use Tailscale's browser login. The key is never logged.
func NewNode(stateDir, hostname, controlURL, authKey string, port int32, allowedPeerIdsCsv string) (node *Node, err error) {
	defer recoverError(&err)
	if stateDir == "" || !filepath.IsAbs(stateDir) {
		return nil, errors.New("state directory must be absolute")
	}
	if hostname == "" || len(hostname) > 63 || strings.ContainsAny(hostname, "\r\n/\\") {
		return nil, errors.New("invalid hostname")
	}
	if port < 1024 || port > 65535 {
		return nil, errors.New("port must be between 1024 and 65535")
	}
	if controlURL != "" {
		u, e := url.Parse(controlURL)
		if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
			return nil, errors.New("control URL must be an HTTPS URL without credentials")
		}
	}
	allowed := make(map[string]bool)
	for _, id := range strings.Split(allowedPeerIdsCsv, ",") {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if len(id) > 128 || strings.ContainsAny(id, " \t\r\n/") {
			return nil, errors.New("invalid peer node ID")
		}
		allowed[id] = true
	}
	if e := os.MkdirAll(stateDir, 0700); e != nil {
		return nil, fmt.Errorf("create Tailscale state directory: %w", e)
	}
	if e := os.Chmod(stateDir, 0700); e != nil {
		return nil, fmt.Errorf("protect Tailscale state directory: %w", e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	n := &Node{allowed: allowed, allowAll: len(allowed) == 0,
		conns: make(map[*Connection]struct{}), ctx: ctx, cancel: cancel, port: port}
	n.server = &tsnet.Server{Dir: stateDir, Hostname: hostname, ControlURL: controlURL,
		AuthKey: authKey, Logf: n.logf, UserLogf: n.logf}
	if n.allowAll {
		n.logf("Peer access policy: all authenticated tailnet nodes")
	} else {
		n.logf("Peer access policy: %d selected stable node IDs", len(allowed))
	}
	return n, nil
}

// allowsPeer is shared by both network protocols. WhoIs must have established
// this nonempty stable identity before applying the optional app-level filter.
func (n *Node) allowsPeer(id string) bool {
	return id != "" && (n.allowAll || n.allowed[id])
}

// Start initializes the listener and returns before interactive login completes.
// Repeated Start calls return the original result. Close may race any operation.
func (n *Node) Start() (err error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return net.ErrClosed
	}
	if n.started {
		return n.startErr
	}
	n.started = true
	// Recover before caching the result and releasing mu. A backend panic must
	// not make a later Start report success on a partly initialized server.
	defer func() {
		n.startErr = err
		if err != nil {
			n.logf("%v", err)
		}
	}()
	defer recoverError(&err)
	n.logf("Starting embedded Tailscale")
	if err = n.startServer(); err != nil {
		return fmt.Errorf("start embedded Tailscale: %w", err)
	}
	n.logf("Tailscale backend initialized; creating local API client")
	n.client, err = n.server.LocalClient()
	if err != nil {
		return fmt.Errorf("create Tailscale local API client: %w", err)
	}
	n.logf("Creating tailnet Assuan listener on port %d", n.port)
	n.listener, err = n.server.Listen("tcp", ":"+strconv.Itoa(int(n.port)))
	if err != nil {
		return fmt.Errorf("create tailnet Assuan listener: %w", err)
	}
	n.logf("Embedded Tailscale initialized; waiting for login or incoming connections")
	return nil
}

func (n *Node) startServer() error {
	tailscaleStartupMu.Lock()
	defer tailscaleStartupMu.Unlock()
	logDir, err := prepareTailscaleLogDir(n.server.Dir)
	if err != nil {
		return err
	}
	n.logf("Tailscale internal log directory: %s", logDir)
	return n.server.Start()
}

// StatusJSON returns Tailscale's status, including BackendState, AuthURL,
// TailscaleIPs, and peer stable IDs. It is safe to call from a background poller.
func (n *Node) StatusJSON() (result string, err error) {
	defer recoverError(&err)
	n.mu.Lock()
	client, ctx, closed := n.client, n.ctx, n.closed
	n.mu.Unlock()
	if closed {
		return "", net.ErrClosed
	}
	if client == nil {
		return "", errors.New("node has not started")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	status, err := client.Status(ctx)
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(status)
	return string(data), err
}

// NetworkChanged refreshes the Android route cache and wakes Tailscale's
// network monitor after a ConnectivityManager callback. Android otherwise polls
// infrequently, delaying recovery after Wi-Fi/cellular transitions.
func (n *Node) NetworkChanged(interfaceName, gateway string) (err error) {
	defer recoverError(&err)
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return net.ErrClosed
	}
	if !n.started || n.startErr != nil {
		n.mu.Unlock()
		return errors.New("node has not started")
	}
	monitor := n.server.Sys().NetMon.Get()
	n.mu.Unlock()
	updatePlatformNetwork(interfaceName, gateway)
	monitor.InjectEvent()
	return nil
}

// Accept blocks until an authenticated peer allowed by the optional node filter connects.
// Peers outside a nonempty filter are closed before their bytes reach the agent.
// The tailnet's ACLs also apply. A maximum of four active connections is allowed.
func (n *Node) Accept() (connection *Connection, err error) {
	defer recoverError(&err)
	n.mu.Lock()
	listener, client, ctx, closed := n.listener, n.client, n.ctx, n.closed
	n.mu.Unlock()
	if closed {
		return nil, net.ErrClosed
	}
	if listener == nil {
		return nil, errors.New("node has not started")
	}
	for {
		conn, e := listener.Accept()
		if e != nil {
			return nil, e
		}
		lookupCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		peer, e := client.WhoIs(lookupCtx, conn.RemoteAddr().String())
		cancel()
		if e != nil || peer == nil || peer.Node == nil {
			conn.Close()
			continue
		}
		id := string(peer.Node.StableID)
		n.mu.Lock()
		if n.closed {
			n.mu.Unlock()
			conn.Close()
			return nil, net.ErrClosed
		}
		if !n.allowsPeer(id) || len(n.conns) >= maxConnections {
			n.mu.Unlock()
			conn.Close()
			continue
		}
		c := &Connection{conn: conn, node: n, peerID: id, peerName: peer.Node.Name}
		n.conns[c] = struct{}{}
		n.mu.Unlock()
		return c, nil
	}
}

// Close shuts down the listener, interrupts reads and identity lookups, and
// releases all Tailscale resources. Call it on a worker, not the Android UI thread.
func (n *Node) Close() (err error) {
	defer recoverError(&err)
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return nil
	}
	n.closed = true
	n.cancel()
	listener := n.listener
	conns := make([]*Connection, 0, len(n.conns))
	for c := range n.conns {
		conns = append(conns, c)
	}
	started := n.started
	n.mu.Unlock()
	n.StopBridge()
	if listener != nil {
		listener.Close()
	}
	for _, c := range conns {
		c.Close()
	}
	if started {
		return n.server.Close()
	}
	return nil
}

// Connection is an authorized, binary-safe duplex stream. One reader and one
// writer may run concurrently. EOF is returned as an empty byte array, not an error.
type Connection struct {
	conn     net.Conn
	node     *Node
	peerID   string
	peerName string
	once     sync.Once
	readMu   sync.Mutex
	writeMu  sync.Mutex
}

func (c *Connection) GetPeerId() string   { return c.peerID }
func (c *Connection) GetPeerName() string { return c.peerName }

// ReadBytes reads up to maxBytes (1 through 65536). Each operation has a two
// minute idle timeout; closing either the connection or node interrupts the read.
func (c *Connection) ReadBytes(maxBytes int32) (data []byte, err error) {
	defer recoverError(&err)
	if maxBytes < 1 || maxBytes > 65536 {
		return nil, errors.New("read size must be between 1 and 65536")
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if err = c.conn.SetReadDeadline(time.Now().Add(idleTimeout)); err != nil {
		return nil, err
	}
	data = make([]byte, maxBytes)
	count, e := c.conn.Read(data)
	if count > 0 {
		return data[:count], nil
	}
	if errors.Is(e, io.EOF) {
		return []byte{}, nil
	}
	return data[:count], e
}

// WriteBytes writes every byte unless the stream errors or its idle timeout
// expires. The returned byte count is suitable for Java OutputStream adapters.
func (c *Connection) WriteBytes(data []byte) (count int32, err error) {
	defer recoverError(&err)
	if len(data) > 65536 {
		return 0, errors.New("write size exceeds 65536")
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err = c.conn.SetWriteDeadline(time.Now().Add(idleTimeout)); err != nil {
		return 0, err
	}
	for len(data) > 0 {
		written, e := c.conn.Write(data)
		count += int32(written)
		data = data[written:]
		if e != nil {
			return count, e
		}
		if written == 0 {
			return count, io.ErrShortWrite
		}
	}
	return count, nil
}

func (c *Connection) Close() (err error) {
	defer recoverError(&err)
	c.once.Do(func() {
		err = c.conn.Close()
		if c.node != nil {
			c.node.mu.Lock()
			delete(c.node.conns, c)
			c.node.mu.Unlock()
		}
	})
	return err
}

func recoverError(err *error) {
	if recovered := recover(); recovered != nil {
		*err = fmt.Errorf("native Tailscale operation failed: %v", recovered)
	}
}
