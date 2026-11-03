// Copyright 2026 OpenKeychain contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package tailagent

import (
	"fmt"
	"os"
	"path/filepath"
)

// prepareTailscaleLogDir supplies the supported logpolicy override for internal
// backend loggers, which do not inherit tsnet.Server.Dir. Android apps generally
// have no HOME or writable working/temp directory, so its fallback can panic.
// Call under tailscaleStartupMu, before starting the backend. Do not restore the
// environment setting while background Tailscale components may still use it.
func prepareTailscaleLogDir(stateDir string) (string, error) {
	dir := filepath.Join(stateDir, "logs")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("create Tailscale internal log directory: %w", err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return "", fmt.Errorf("protect Tailscale internal log directory: %w", err)
	}
	if err := os.Setenv("TS_LOGS_DIR", dir); err != nil {
		return "", fmt.Errorf("configure Tailscale internal log directory: %w", err)
	}
	return dir, nil
}
