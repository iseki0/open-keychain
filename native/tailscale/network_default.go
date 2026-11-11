// Copyright 2026 OpenKeychain contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !android || !cgo

package tailagent

func updatePlatformNetwork(interfaceName, gateway string) {}
