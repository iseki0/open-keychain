# Embedded Tailscale transport

This module builds the `tailagent` Java package used by OpenKeychain's remote
agent service. `tsnet.Server` runs its TCP/IP stack inside the app process. Only
`Server.Listen` is used; there is no Android `VpnService`, TUN device, LAN TCP
listener, or Tailscale Funnel listener. The app has its own tailnet identity and
does not depend on the separately installed Tailscale Android client.

Requirements: Go 1.27.3 or later, JDK 17, Android SDK, and NDK 28.2.13676358. Set
`ANDROID_HOME`, optionally `ANDROID_NDK_HOME`, and run `native/build-android.sh`
from the repository. Go Mobile is pinned to
`v0.0.0-20261011034528-197770444867`, Tailscale to `v1.104.4`. The script builds
arm64-v8a, armeabi-v7a, and x86_64 for Android API 24+. The generated
`native/tailscale/tailagent.aar`, sources JAR, and local build tools are ignored.
Run `go test -race ./...` from this directory to check the transport adapters.

`Tailagent.newNode(stateDir, hostname, controlURL, authKey, port, allowedPeerIdsCsv)`
creates a node. Call `start()` once and poll `statusJSON()` in a background task.
Tailscale's `AuthURL` is the interactive browser-login link. The auth key may be
empty, and is never logged by this wrapper. State belongs in the Android app's
private files directory; the wrapper sets its mode to 0700. Do not store auth keys
in project files or CI. Changing settings requires closing and recreating a node.

`accept()` first authenticates the connection with Tailscale `WhoIs`. A blank
stable-node-ID filter allows all authenticated tailnet nodes. A nonempty list
restricts access to those exact stable IDs; both Assuan and gpg-bridge use the
same policy. Names and IP addresses are display data, not authorization identities. Tailnet
ACLs should additionally restrict the chosen TCP port to the remote workspace.
Up to four accepted streams are active at once. Each connection exposes
`getPeerId()`, `getPeerName()`, `readBytes(int)`, `writeBytes(byte[])`, and `close()`.
Reads return an empty byte array at EOF. Reads and writes have two-minute idle
timeouts. Closing a node interrupts existing streams and pending identity lookups.
All potentially blocking calls, including shutdown, belong off the Android UI
thread. Forward ConnectivityManager changes to
`node.networkChanged(interfaceName, gateway)` so Tailscale updates its default
route and reconnects after Wi-Fi/cellular transitions. The Assuan protocol, key policy, and per-signature confirmation are owned
by the Android service, outside this transport module.

`drainLogsJSON()` returns a JSON array of up to 200 diagnostic strings and clears
the native buffer. Each entry is limited to 1500 UTF-8 bytes. Startup errors keep
their failing stage and original cause across JNI. Login URL paths, tickets,
authorization values, auth keys, typed key material, and password/PSK values are
redacted before entering the buffer. The Android log viewer applies its own
redaction as well. A Java `proxyerror` class is a generic Go-mobile error wrapper,
not evidence of an HTTP proxy configuration issue; inspect its message and these
diagnostics for the actual cause.

## Android device validation

Go's standard network-interface enumeration hits Android's netlink restrictions
in the app sandbox. `interfaces_android.go` registers our own getter with
Tailscale before any node starts. It uses bionic `getifaddrs` and supplies
`AltAddrs` so the stack does not fall back to Go's blocked `Interface.Addrs` path.
This follows the workaround discussed in upstream
[issue 17311](https://github.com/tailscale/tailscale/issues/17311) and
[PR 19455](https://github.com/tailscale/tailscale/pull/19455), with a local
implementation rather than depending on the unmerged PR.

Host tests and cross-compilation cannot verify an Android device's SELinux,
background-execution, or network policy. Before treating a build as ready for
regular use, install it on a physical Android device, log in to a tailnet, test
Wi-Fi/cellular transitions, direct UDP and DERP connectivity, confirm denied peers
cannot reach the signing agent, and exercise signing, rejection, timeout, and
service shutdown from the cloud workspace. No physical-device or live-tailnet
verification is implied by an AAR build.
