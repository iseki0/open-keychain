// Copyright 2026 OpenKeychain contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build android && cgo

package tailagent

/*
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>

static void *tailagent_addr_bytes(struct sockaddr *addr) {
 if (addr->sa_family == AF_INET) return &((struct sockaddr_in *)addr)->sin_addr;
 if (addr->sa_family == AF_INET6) return &((struct sockaddr_in6 *)addr)->sin6_addr;
 return NULL;
}
*/
import "C"

import (
	"fmt"
	"net"
	"unsafe"

	"tailscale.com/net/netmon"
)

// Android's untrusted_app sandbox blocks Go's netlink-based net.Interfaces.
// Bionic getifaddrs uses the app-permitted interface discovery path. Supplying
// AltAddrs is essential: net.Interface.Addrs would otherwise hit netlink again.
// This is deliberately local code, not a dependency on an unmerged upstream PR.
func init() { netmon.RegisterInterfaceGetter(androidInterfaces) }

func androidInterfaces() ([]netmon.Interface, error) {
	var head *C.struct_ifaddrs
	result, errno := C.getifaddrs(&head)
	if result != 0 {
		return nil, fmt.Errorf("getifaddrs: %w", errno)
	}
	defer C.freeifaddrs(head)
	var interfaces []netmon.Interface
	indices := make(map[string]int)
	for entry := head; entry != nil; entry = entry.ifa_next {
		if entry.ifa_name == nil {
			continue
		}
		name := C.GoString(entry.ifa_name)
		position, exists := indices[name]
		if !exists {
			flags := net.Flags(0)
			if entry.ifa_flags&C.IFF_UP != 0 {
				flags |= net.FlagUp
			}
			if entry.ifa_flags&C.IFF_BROADCAST != 0 {
				flags |= net.FlagBroadcast
			}
			if entry.ifa_flags&C.IFF_LOOPBACK != 0 {
				flags |= net.FlagLoopback
			}
			if entry.ifa_flags&C.IFF_POINTOPOINT != 0 {
				flags |= net.FlagPointToPoint
			}
			if entry.ifa_flags&C.IFF_MULTICAST != 0 {
				flags |= net.FlagMulticast
			}
			if entry.ifa_flags&C.IFF_RUNNING != 0 {
				flags |= net.FlagRunning
			}
			position = len(interfaces)
			indices[name] = position
			interfaces = append(interfaces, netmon.Interface{
				Interface: &net.Interface{Index: int(C.if_nametoindex(entry.ifa_name)), Name: name, MTU: 1500, Flags: flags},
				AltAddrs:  make([]net.Addr, 0),
			})
		}
		if entry.ifa_addr == nil || entry.ifa_netmask == nil || entry.ifa_addr.sa_family != entry.ifa_netmask.sa_family {
			continue
		}
		size := C.int(0)
		switch entry.ifa_addr.sa_family {
		case C.AF_INET:
			size = net.IPv4len
		case C.AF_INET6:
			size = net.IPv6len
		default:
			continue
		}
		ip := net.IP(C.GoBytes(unsafe.Pointer(C.tailagent_addr_bytes(entry.ifa_addr)), size))
		mask := net.IPMask(C.GoBytes(unsafe.Pointer(C.tailagent_addr_bytes(entry.ifa_netmask)), size))
		interfaces[position].AltAddrs = append(interfaces[position].AltAddrs, &net.IPNet{IP: ip, Mask: mask})
	}
	return interfaces, nil
}

func updatePlatformNetwork(interfaceName, gateway string) {
	netmon.UpdateLastKnownDefaultRouteInterface(interfaceName)
	netmon.UpdateLastKnownDefaultGateway(gateway)
}
