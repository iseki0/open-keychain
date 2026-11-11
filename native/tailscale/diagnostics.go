// Copyright 2026 OpenKeychain contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package tailagent

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const maxDiagnosticEntries = 200
const maxDiagnosticBytes = 1500

var diagnosticURLs = regexp.MustCompile(`(?i)https?://[^\s<>"']+`)
var diagnosticTickets = regexp.MustCompile(`gpgbridge:v1:[^\s<>"']+`)
var diagnosticTSKeys = regexp.MustCompile(`(?i)tskey-[a-z0-9_-]+`)
var diagnosticTypedKeys = regexp.MustCompile(`(?i)\b(?:privkey|nodekey|mkey|discokey|disco):[^\s,;"'\]\)]+`)
var diagnosticAuthorization = regexp.MustCompile(`(?i)\b(?:proxy-authorization|authorization)\s*[:=]\s*[^\r\n]+`)
var diagnosticSecrets = regexp.MustCompile(`(?i)\b(authkey|auth_key|psk|password|passphrase|secret|token|private[_ -]?key)\b["']?\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s,;]+)`)

func sanitizeDiagnostic(value string) string {
	value = strings.ToValidUTF8(value, "?")
	value = diagnosticTickets.ReplaceAllString(value, "gpgbridge:v1:[redacted]")
	value = diagnosticAuthorization.ReplaceAllString(value, "Authorization: [redacted]")
	value = diagnosticTSKeys.ReplaceAllString(value, "tskey-[redacted]")
	value = diagnosticTypedKeys.ReplaceAllString(value, "key:[redacted]")
	value = diagnosticSecrets.ReplaceAllString(value, "$1=[redacted]")
	value = diagnosticURLs.ReplaceAllStringFunc(value, func(raw string) string {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Host == "" {
			return "[URL redacted]"
		}
		// Keep a destination useful for TLS/DNS diagnosis, but never URL userinfo,
		// paths, queries, fragments, device-login tokens, or a full AuthURL.
		return "[URL " + parsed.Scheme + "://" + parsed.Host + " redacted]"
	})
	value = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return ' '
		}
		return r
	}, value)
	if len(value) > maxDiagnosticBytes {
		value = value[:maxDiagnosticBytes-3]
		for !utf8.ValidString(value) {
			value = value[:len(value)-1]
		}
		value += "..."
	}
	return value
}

// logf sanitizes before queuing: neither native storage nor Java receives the
// original credential-bearing text. The logger has its own lock because tsnet
// may call it while Node.Start holds the node lifecycle mutex.
func (n *Node) logf(format string, values ...any) {
	line := sanitizeDiagnostic(time.Now().UTC().Format(time.RFC3339) + " " + fmt.Sprintf(format, values...))
	n.logMu.Lock()
	defer n.logMu.Unlock()
	if len(n.logs) == maxDiagnosticEntries {
		copy(n.logs, n.logs[1:])
		n.logs[len(n.logs)-1] = line
	} else {
		n.logs = append(n.logs, line)
	}
}

// DrainLogsJSON returns and removes up to 200 redacted diagnostic strings.
// It remains usable after Close so startup and shutdown failures can be read.
// Login URLs and temporary gpg-bridge tickets belong in the dedicated UI only.
func (n *Node) DrainLogsJSON() (result string, err error) {
	defer recoverError(&err)
	n.logMu.Lock()
	defer n.logMu.Unlock()
	entries := n.logs
	if entries == nil {
		entries = []string{}
	}
	data, err := json.Marshal(entries)
	if err != nil {
		return "", err
	}
	n.logs = nil
	return string(data), nil
}
