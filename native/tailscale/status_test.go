// Copyright 2026 OpenKeychain contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package tailagent

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"go4.org/mem"
	"tailscale.com/client/local"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/key"
)

func TestStatusSummaryExcludesLargePeerGraph(t *testing.T) {
	status := &ipnstate.Status{
		BackendState: "Running",
		TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.1")},
	}
	want, err := marshalStatusSummary(status)
	if err != nil {
		t.Fatal(err)
	}
	large := strings.Repeat("unneeded-endpoint-or-profile-data", 32000)
	peer := &ipnstate.PeerStatus{HostName: large, DNSName: large, Addrs: []string{large}}
	status.Self = peer
	status.Peer = make(map[key.NodePublic]*ipnstate.PeerStatus, 10000)
	for i := range 10000 {
		var raw [32]byte
		binary.LittleEndian.PutUint64(raw[:], uint64(i))
		status.Peer[key.NodePublicFromRaw32(mem.B(raw[:]))] = peer
	}
	status.MagicDNSSuffix = large
	status.CertDomains = []string{large}
	got, err := marshalStatusSummary(status)
	if err != nil {
		t.Fatal(err)
	}
	if got != want || len(got) > 256 {
		t.Fatalf("large peer graph changed compact summary: got %d bytes, want %d", len(got), len(want))
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(got), &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 4 || fields["BackendState"] == nil || fields["AuthURL"] == nil || fields["TailscaleIPs"] == nil || fields["Health"] == nil {
		t.Fatal("summary returned fields outside the fixed allowlist")
	}
}

func TestStatusSummaryCapsBeforeEncoding(t *testing.T) {
	status := &ipnstate.Status{
		BackendState: strings.Repeat("\x00", 100000),
		AuthURL:      "https://login.tailscale.com/" + strings.Repeat("&", maxStatusAuthBytes-len("https://login.tailscale.com/")),
		TailscaleIPs: make([]netip.Addr, 100000),
		Health:       make([]string, 10000),
	}
	zonedIP := netip.MustParseAddr("fd7a:115c:a1e0::1").WithZone(strings.Repeat("unused-zone", 10000))
	for i := range status.TailscaleIPs {
		status.TailscaleIPs[i] = zonedIP
	}
	largeHealth := strings.Repeat("<>&\"\\\x00", 10000)
	for i := range status.Health {
		status.Health[i] = largeHealth
	}
	encoded, err := marshalStatusSummary(status)
	if err != nil {
		t.Fatal(err)
	}
	var summary statusSummary
	if err := json.Unmarshal([]byte(encoded), &summary); err != nil {
		t.Fatal(err)
	}
	if len(encoded) > maxStatusJSONBytes || len(summary.BackendState) != maxStatusStateBytes || len(summary.TailscaleIPs) != maxStatusIPs || len(summary.Health) != maxStatusHealth {
		t.Fatal("summary exceeded its fixed bounds")
	}
	if summary.AuthURL != status.AuthURL {
		t.Fatal("valid bounded login URL was altered")
	}
	for _, health := range summary.Health {
		if len(health) > maxStatusHealthBytes {
			t.Fatal("health message exceeded its byte bound")
		}
	}
	for _, ip := range summary.TailscaleIPs {
		if len(ip) > 39 || strings.Contains(ip, "%") {
			t.Fatal("IP address retained an unbounded zone")
		}
	}
	status.AuthURL += "oversized"
	encoded, err = marshalStatusSummary(status)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(encoded), &summary); err != nil || summary.AuthURL != "" {
		t.Fatal("oversized login credential was clipped instead of omitted")
	}
	if _, err := marshalStatusSummary(nil); err == nil {
		t.Fatal("empty upstream status accepted")
	}
	if text := boundedStatusText(strings.Repeat("界", 1000), 512); len(text) > 512 || !utf8.ValidString(text) {
		t.Fatal("UTF-8 clipping produced invalid text")
	}
}

type statusRoundTripper func(*http.Request) (*http.Response, error)

func (f statusRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestStatusEntryPointsRequestWithoutPeers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	n := &Node{ctx: ctx, cancel: cancel, client: &local.Client{
		OmitAuth: true,
		Transport: statusRoundTripper(func(r *http.Request) (*http.Response, error) {
			calls++
			if r.URL.Path != "/localapi/v0/status" || r.URL.RawQuery != "peers=false" {
				t.Fatalf("status requested a full peer graph: %s", r.URL.RequestURI())
			}
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header),
				Body: io.NopCloser(strings.NewReader(`{"BackendState":"Running","TailscaleIPs":["100.64.0.1"],"Self":{"HostName":"excluded"},"Peer":{}}`))}, nil
		}),
	}}
	for _, entry := range []func() (string, error){n.StatusJSON, n.StatusSummaryJSON} {
		encoded, err := entry()
		if err != nil || strings.Contains(encoded, "excluded") || strings.Contains(encoded, "Peer") {
			t.Fatalf("status did not use the compact projection: %q, %v", encoded, err)
		}
	}
	if calls != 2 {
		t.Fatalf("expected two local status requests, got %d", calls)
	}
}

func TestCloseCancelsOutstandingStatus(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered := make(chan struct{})
	n := &Node{ctx: ctx, cancel: cancel, client: &local.Client{
		OmitAuth: true,
		Transport: statusRoundTripper(func(r *http.Request) (*http.Response, error) {
			close(entered)
			<-r.Context().Done()
			return nil, r.Context().Err()
		}),
	}}
	done := make(chan error, 1)
	go func() {
		_, err := n.StatusSummaryJSON()
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("status request never reached the local API")
	}
	if err := n.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("close did not cancel status request: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("close left status blocked in the local API")
	}
	if _, err := n.StatusSummaryJSON(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed node accepted a new status poll: %v", err)
	}
}
