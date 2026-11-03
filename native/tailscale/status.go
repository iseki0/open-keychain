// Copyright 2026 OpenKeychain contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package tailagent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"tailscale.com/ipn/ipnstate"
)

const (
	maxStatusJSONBytes   = 16 * 1024
	maxStatusAuthBytes   = 4096
	maxStatusStateBytes  = 128
	maxStatusIPs         = 8
	maxStatusHealth      = 4
	maxStatusHealthBytes = 512
)

// statusSummary is an allowlist. Never pass upstream status directly through
// JNI: it can contain a whole tailnet, endpoints, keys, and other large fields.
type statusSummary struct {
	BackendState string
	AuthURL      string
	TailscaleIPs []string
	Health       []string
}

// StatusJSON retains the old binding name with the same bounded summary as
// StatusSummaryJSON. Full peer status is never returned by either entry point.
func (n *Node) StatusJSON() (string, error) {
	return n.StatusSummaryJSON()
}

// StatusSummaryJSON returns only BackendState, AuthURL, TailscaleIPs, and Health,
// with a 16 KiB maximum. Call from a worker thread; it can wait up to five seconds
// for the local API, and closing the node cancels an outstanding request.
// AuthURL is a login credential for the dedicated sign-in UI; never log it.
func (n *Node) StatusSummaryJSON() (result string, err error) {
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
	// This also avoids generating and decoding a peer graph inside the local
	// API, before the fixed-size projection protects the Java/UI boundary.
	status, err := client.StatusWithoutPeers(ctx)
	if err != nil {
		return "", err
	}
	return marshalStatusSummary(status)
}

func marshalStatusSummary(status *ipnstate.Status) (string, error) {
	if status == nil {
		return "", errors.New("Tailscale returned an empty status")
	}
	summary := statusSummary{
		BackendState: boundedStatusText(status.BackendState, maxStatusStateBytes),
		TailscaleIPs: make([]string, 0, maxStatusIPs),
		Health:       make([]string, 0, maxStatusHealth),
	}
	// Never clip a login URL into another, invalid credential. Oversized or
	// malformed URLs are omitted; they cannot enable the sign-in button.
	if len(status.AuthURL) <= maxStatusAuthBytes && utf8.ValidString(status.AuthURL) {
		if u, err := url.Parse(status.AuthURL); err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil {
			summary.AuthURL = status.AuthURL
		}
	}
	for _, ip := range status.TailscaleIPs[:min(len(status.TailscaleIPs), maxStatusIPs)] {
		if ip.IsValid() {
			// Tailnet addresses need no zone. Excluding a zone also prevents an
			// arbitrary zone string from bypassing the fixed address-size bound.
			summary.TailscaleIPs = append(summary.TailscaleIPs, ip.WithZone("").String())
		}
	}
	for _, message := range status.Health {
		// Bound the input before redaction too, so a large health message never
		// triggers an unbounded scan/allocation in the polling path.
		message = sanitizeDiagnostic(boundedStatusText(message, maxStatusHealthBytes))
		summary.Health = append(summary.Health, boundedStatusText(message, maxStatusHealthBytes))
		if len(summary.Health) == maxStatusHealth {
			break
		}
	}
	// This is consumed as JSON, never HTML. Avoid expanding each '&' in a
	// legitimate login URL into six bytes while retaining normal JSON escaping.
	var data bytes.Buffer
	encoder := json.NewEncoder(&data)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(summary); err != nil {
		return "", err
	}
	if data.Len() > maxStatusJSONBytes {
		return "", errors.New("Tailscale status summary exceeds size limit")
	}
	return strings.TrimSuffix(data.String(), "\n"), nil
}

func boundedStatusText(value string, limit int) string {
	if len(value) > limit {
		value = value[:limit]
	}
	return strings.ToValidUTF8(value, "?")
}
