# Tailscale remote signing

This fork adds a separate Tailscale node inside OpenKeychain and a signing-only
GnuPG agent endpoint. Android does not use `VpnService`, create a TUN device, or
reserve the phone's system VPN slot. The listener exists inside the embedded
Tailscale userspace network, on TCP port **17373**; it is not bound to Wi-Fi,
cellular, localhost, or a public interface.

The optional [gpg-bridge v1](https://github.com/iseki0/gpg-bridge) endpoint listens
on tailnet TCP **17389** and supports the existing, unmodified `gpg-bridge`
client. It uses HTTP plus `Noise_NKpsk0_25519_ChaChaPoly_BLAKE2s` encryption,
server authentication and a temporary pre-shared credential. The phone keeps its
own Tailscale identity; no Android system VPN or separately installed Tailscale
app is required for either protocol.

This fork supports **Android 7.0 / API 24 or later** and local software **RSA,
Ed25519, ECDSA and DSA signing keys** through gpg-bridge. Assuan supports RSA and
Ed25519 with SHA-256, SHA-384 and SHA-512. Existing OpenKeychain keys
remain in the phone's key storage. By default each signature requires an explicit
approval on the phone, including when the key has no passphrase. Key passphrases can
be prefilled for the current connection or saved encrypted on the device. gpg-bridge
Git commit and tag signatures can optionally be approved automatically (see
[Unattended signing](#unattended-signing)); Assuan requests always need a tap.
Hardware-token keys, decryption, private-key export and SSH agent forwarding are
outside this version's scope.

## Download the APK

Open the [GitHub preview releases](https://github.com/iseki0/open-keychain/releases)
and download `OpenKeychain-remote-signing-preview.apk` from Assets. Each preview
also includes `SHA256SUMS`. After a successful build on the feature branch, CI
publishes a preview tied to the source commit. These are debug previews; start
with a test key while physical-device and live-tailnet validation is pending.

The workflow also uploads an APK artifact to its Actions run; downloading an
Actions artifact requires GitHub sign-in. A cloud workspace path such as
`/workspace/.../OpenKeychain-debug.apk` is an internal file location and is not
a public download URL.

## Build

Initialize the existing submodules and install JDK 17, the Android SDK, NDK
28.2.13676358, and Go 1.27.3+. Use the exact dependency versions recorded in
`native/tailscale/go.mod` and `native/build-android.sh`.

```sh
git submodule update --init --recursive
export ANDROID_HOME=/path/to/android-sdk
sdkmanager 'platforms;android-34' 'build-tools;34.0.0' 'ndk;28.2.13676358'
bash native/build-android.sh
./gradlew :OpenKeychain:assembleDebug
```

The native build script creates `native/tailscale/tailagent.aar` from source. The native
bridge also supplies an Android interface enumeration adapter, since ordinary
Go netlink enumeration is restricted in Android application sandboxes.
Generated AARs, Tailscale state, and credentials must not be committed.

The debug APK installs alongside the upstream app with its own private storage
(`org.sufficientlysecure.keychain.debug`). It cannot read keys from the upstream
app's sandbox. Import your key locally into this fork on the phone, or create a
new key there; only export the public part to the cloud machine.

Some unavailable legacy JCenter artifacts are restored using the original
upstream sources and licenses under `extern/html-textview` and
`extern/flexible-adapter*`. The per-module READMEs record the exact source tags
and commits. Nordpol and ChipsLayoutManager use their upstream JitPack builds.

## Pair the phone and the cloud node

1. Import or create a local signing key in this fork of OpenKeychain. Export its **public key**
   to the cloud machine. Never send a secret-key export or passphrase there.
2. In OpenKeychain Settings, open **Tailscale remote signing**. Set a hostname and, if
   needed, an HTTPS Headscale control URL. Leave the control URL empty for
   Tailscale's hosted service. Select individual signing keys or enable **Select
   all signing keys**. The latter includes valid software signing keys imported
   later, until you disable the option. Key rows show the algorithm; ECDSA and
   DSA use gpg-bridge rather than the Assuan endpoint.
3. Connect and use the displayed login link to enroll the embedded node. It has
   its own node identity, independent of any Tailscale Android app installed on
   the phone. Note the phone's Tailscale IP from the status display.
4. Enable **Allow all Tailscale nodes**, or leave the node box blank, to accept
   all authenticated tailnet nodes permitted by your tailnet policy. To restrict
   access, enter the authorized cloud node's **stable NodeID** instead. This
   is the `ID` value from `tailscale status --json` (`Self.ID` when run on the
   cloud node), not its hostname, Tailscale IP, machine key, or user ID. For a
   managed cloud environment, obtain the sidecar node's ID from the environment
   operator/Tailscale administration. A nonempty list restricts access to those IDs.
   Reconnect after changing peers or key selections.
5. Grant that cloud node access to the phone's TCP port 17373 for Assuan or
   17389 for gpg-bridge in the tailnet
   policy. Also allow the phone's login flow and normal Tailscale connectivity.
   Broader pre-existing allow-all rules must be removed if you intend the
   network policy itself to restrict this port. A configured application NodeID
   list applies independently; the app cannot override a restrictive tailnet ACL.
6. Allow OpenKeychain notifications. Keep its foreground notification enabled
   while signing. If the phone suspends connectivity, check its battery-saving
   restrictions for OpenKeychain. Start and stop remote signing explicitly; it
   does not automatically start after boot.

An example Tailscale grant (replace the tag assignments with your own) is:

```json
{
  "tagOwners": {
    "tag:codex-signer": ["autogroup:admin"],
    "tag:openkeychain": ["autogroup:admin"]
  },
  "grants": [
    {
      "src": ["tag:codex-signer"],
      "dst": ["tag:openkeychain"],
      "ip": ["tcp:17373", "tcp:17389"]
    }
  ]
}
```

Assign the source tag only to authorized cloud nodes. App-level authentication
uses Tailscale `WhoIs` on each accepted connection. Blank/all-node mode accepts
every authenticated tailnet node; otherwise the stable NodeID must match the
configured list. gpg-bridge additionally requires its temporary Noise credential.
Every signature still requires local approval in both modes.

The embedded Tailscale node state is stored under the application's private
`files/tailnet-agent` directory and survives a normal disconnect. Reinstalling
or clearing application data creates a new identity; revoke the old node in
Tailscale administration as appropriate. OpenKeychain's existing application
backup restriction also covers this state.

## Use the gpg-bridge client

After enrolling the phone and selecting its signing keys and allowed cloud
node policy, tap **Create or view gpg-bridge connection string** in the remote
signing screen. The node must be signed in and connected. Copy the generated
`gpgbridge:v1:...` string to the intended cloud task. It stays valid until you
revoke it: its Noise key, PSK and session are saved encrypted with an Android
Keystore key, and the bridge resumes with the same string whenever the service
connects again, including after a reboot. (The string carries a nominal expiry of
2100-01-01 because gpg-bridge clients require a timestamp.) If the phone's tailnet
address changes, create the string again. **Revoke gpg-bridge connection string**
invalidates it immediately and deletes the saved credentials; disconnecting only
pauses it. Revocation leaves the separate Assuan endpoint available while the
Tailscale node remains connected.

Install your existing [gpg-bridge Linux client](https://github.com/iseki0/gpg-bridge)
at a fixed path and run it inside the target repository:

```sh
/path/to/gpg-bridge connect
# Paste the phone's connection string when prompted.
/path/to/gpg-bridge status
git commit -m 'Signed using the phone'
git verify-commit HEAD
git tag -s v1.0 -m 'Signed release'
git verify-tag v1.0
/path/to/gpg-bridge disconnect
```

Open each signing notification on the phone and approve the displayed key,
SHA-256 digest and Git object preview. The protocol signs the original bytes
and returns an armored detached OpenPGP signature plus `SIG_CREATED` status.
The preview escapes control characters and truncates long objects; the
signature covers all original bytes. Git commit/tag formatting is checked, but
the phone cannot verify the referenced tree, files or repository ownership.
Arbitrary-data and unattended signing are not enabled.

The ticket's endpoint is `http://<phone-tailnet-IP>:17389`. Noise encrypts and
authenticates the payload within HTTP; it does not hide connection metadata.
The cloud must have a supported route to that tailnet address. In managed
CodexCloud, configure Tailscale VPN and permit this HTTP destination through the
supported environment settings, preserving inherited proxy variables. The
gpg-bridge client honors standard HTTP proxy settings. It does not use the
Assuan helper's `--http-connect` argument. The selected all-node or explicit
NodeID policy still applies in addition to the connection-string credential.

The compatibility implementation was tested against the unmodified client from
commit `60454d9354d02ae7f0288df110026d2aa1de8b59`. See
[the interoperability harness](../tools/gpg-bridge-integration/README.md) for
repeatable checks with temporary keys. Physical Android and live-tailnet
validation remain outstanding.

## Use Assuan from CodexCloud

The Python helper needs Python 3.9+, GnuPG 2.2+, and the phone's literal
Tailscale IPv4 or IPv6 address. It creates a fresh private `GNUPGHOME` for one
command, imports the supplied public key, and connects that home's GnuPG agent
socket to the phone. It neither starts a local agent nor kills or replaces an
existing one. All keys for that command must be in the supplied public-key file.
The helper currently accepts the standard Tailscale address ranges only; custom
Headscale address ranges are not supported.

For an ordinary machine with an existing Tailscale route:

```sh
python3 tools/remote-gpg-agent/remote_agent.py \
  --host 100.101.102.103 --public-key /path/to/phone-public.asc \
  -- gpg --armor --detach-sign --local-user YOUR_SIGNING_FINGERPRINT file.txt
```

For **managed CodexCloud**, Tailscale normally runs in the environment's
sidecar. The executor itself has no VPN interface or direct tailnet route.
The environment must have its supported VPN configuration enabled **and** an
explicit TCP grant for the phone's IP (for example its exact `/32` IPv4 CIDR).
Then use the approved raw TCP CONNECT listener:

```sh
python3 tools/remote-gpg-agent/remote_agent.py \
  --host 100.101.102.103 --public-key /path/to/phone-public.asc \
  --http-connect proxy:8088 \
  -- gpg --armor --detach-sign --local-user YOUR_SIGNING_FINGERPRINT file.txt
```

Check `/etc/codex/network-policy.json` and the environment's supported readiness
status before diagnosing this path. A missing VPN configuration, empty TCP
grants, a 403 CONNECT response, or a `vpn_not_ready` response requires the
environment configuration/operator workflow. HTTP destination permissions and
the ordinary HTTP proxy at port 8080 do not grant raw TCP access. Preserve the
inherited proxies; do not install a second Tailscale daemon in a managed
executor to work around the policy. The current development environment has
not been used to make a real tailnet connection to a phone.

Git signing works in the same session:

```sh
python3 tools/remote-gpg-agent/remote_agent.py \
  --host 100.101.102.103 --public-key /path/to/phone-public.asc \
  --http-connect proxy:8088 \
  -- git -c gpg.format=openpgp -c gpg.program=gpg \
         -c user.signingkey=YOUR_SIGNING_FINGERPRINT commit -S -m 'Signed change'
```

Replace the example address and fingerprint. Use the exact selected RSA or Ed25519
signing-key/subkey fingerprint; a `!` suffix can force a particular subkey in
GnuPG when necessary. The disposable home disappears when the command ends,
so this helper does not retain trustdb changes, imported keys, or agent sockets.
For several operations in one session, run `-- bash` and execute commands from
that shell.

## Optional userspace Tailscale on a self-managed Linux host

This alternative is for a host you administer, not a replacement for a managed
cloud environment's supported sidecar setup. If you do not want a system VPN
on that host, use Tailscale's userspace SOCKS5 proxy:

```sh
install -d -m 700 "$HOME/.local/state/openkeychain-tailnet"
tailscaled --tun=userspace-networking \
  --state="$HOME/.local/state/openkeychain-tailnet/tailscaled.state" \
  --socket="$HOME/.local/state/openkeychain-tailnet/tailscaled.sock" \
  --socks5-server=127.0.0.1:1055
```

Keep that process running, and enroll it from a second terminal:

```sh
tailscale --socket="$HOME/.local/state/openkeychain-tailnet/tailscaled.sock" \
  up --hostname=codex-signing
tailscale --socket="$HOME/.local/state/openkeychain-tailnet/tailscaled.sock" \
  status --json
python3 tools/remote-gpg-agent/remote_agent.py \
  --host 100.101.102.103 --public-key /path/to/phone-public.asc \
  --socks5 127.0.0.1:1055 \
  -- gpg --armor --detach-sign --local-user YOUR_SIGNING_FINGERPRINT file.txt
```

The SOCKS5 proxy must bind to loopback. Treat its state directory as a
credential. Reenrolling an ephemeral cloud node can change its stable NodeID;
update the phone's allowlist and revoke old nodes.

## Unattended signing

All three options are off by default and are set in the remote-signing screen.

* **Save key passphrase on this device** stores a passphrase encrypted with a
  non-exportable AES-256-GCM Android Keystore key (no user-authentication
  requirement, so it works while the phone is locked). The passphrase is checked
  against the key before it is saved. Saved passphrases fill in approval screens,
  survive restarts and are deleted when the app data is cleared or with **Delete
  all saved passphrases**. A connection prefill, if present, takes precedence.
* **Automatically approve gpg-bridge Git commit and tag signatures** signs
  gpg-bridge requests without a tap when a saved or prefilled passphrase exists
  (or the key has no passphrase). The native bridge has already restricted the
  payload to a Git commit or tag object. Each automatic signature posts a
  notification with the commit subject, peer, key and digest prefix, and is
  recorded in the diagnostic log. A wrong saved passphrase falls back to a normal
  approval. Assuan requests are never approved automatically because they only
  carry a digest. While enabled, anyone holding the connection string who can
  reach the phone through an allowed tailnet node can sign Git objects in your
  name, so restrict the node policy and revoke the string if it leaks.
* **Start remote signing after the phone boots** starts the foreground service
  after boot and after app updates (notifications must be allowed). The service
  is sticky, so Android restarts it if the process is killed; **Disconnect**
  stops it until the next manual start or boot.

## Approval and limits

Open the signing-request notification on the phone. The approval screen shows
the authenticated peer, selected key, hash algorithm, and digest. Enter or edit
the passphrase there, then tap **Approve this signature**. To avoid retyping it,
connect first, then use **Prefill key passphrase** in the remote-signing settings
and select an enabled signing key. Repeat for keys with different passphrases.
The prefill belongs to that exact signing-key fingerprint and works for both
Assuan and gpg-bridge. It never approves a request automatically.

Prefills stay only in the phone's memory for the current connection; disconnecting,
stopping the service, or process exit clears them. **Clear all prefilled passphrases**
clears the cache immediately; the per-key editor also offers a clear button,
and saving a blank value removes that key's prefill. Passphrases are never written
to settings, saved screen state, logs, connection strings, or the cloud.

Rejecting, timing out, stopping the service, or
changing the enabled key selection fails the request. Passphrases are not sent
to the cloud. Editing a passphrase for one approval does not change its prefill.

GnuPG agent signing transports a **digest**, so the phone cannot independently
show the original document, Git diff, or commit message. Remote-provided
descriptions are not proof of content. Grant access only to cloud nodes you
intend to authorize and check the displayed peer/key/digest before approval.

The transport limits simultaneous connections and idle waits. If a connection
expires while waiting, retry the command and approve the new request. The
implementation fails closed for unsupported keys and agent commands. Public
key metadata for the phone-selected keys can be read by an authorized peer;
private key export and decryption are unavailable.

## Technical diagnostics and Android 17

The main screen displays a small status summary rather than raw status JSON.
The service fetches Tailscale status without the peer graph, projects only
backend state, login URL, local tailnet IPs and health warnings, and bounds the
native JSON to 16 KiB. Java rejects oversized or excessively nested input before
parsing it on the service worker. The UI reads an immutable snapshot, limits
status text to 1536 characters and 12 lines, and redraws only changed values.
No JSON parsing or native status call runs on the UI thread. IP and health lists
are capped; overlong display fields are marked with an ellipsis. Oversized login
URLs are discarded rather than cut into a different credential.

Diagnostic controls are at the top of the screen. Opening the log records the
current bounded status summary on demand; the full peer JSON is neither rendered
nor retained in the polling path. Detailed startup and error events remain in
the existing bounded log viewer.

Tap **View diagnostic log** to use OpenKeychain's existing operation log viewer.
It includes startup phases, the original native error/cause chain and stack
frames, Android release/API/build/model, default interface/gateway changes,
Tailscale state and bounded native logs, key inventory and selection reasons,
and signature/session outcomes. The existing viewer supports its usual log
inspection and user-initiated sharing. **Clear diagnostic log** clears the
memory-only buffer; it is not written to disk by this feature. Connection
strings, passwords, authorization values, private-key material and login URLs
are redacted before storage.

`Connection failed: proxyerror` in the earlier preview showed only gomobile's
generic Java error wrapper. It does not identify an HTTP proxy failure, and an
empty node box does not affect Tailscale startup. The updated screen shows the
native error text, and the log identifies which startup operation failed. If
the node fails before obtaining an AuthURL, the Tailscale sign-in button remains
disabled. A log from Android 17 build `CP3A.260905.009` identified a concrete
failure: `no safe place found to store log state`. The internal LocalBackend
asks Tailscale's log policy for a directory separately from `tsnet.Server.Dir`;
Android's missing desktop home/cache and writable temporary-directory defaults
can make that lookup panic even after the network engine has initialized.

Before starting Tailscale, this fork now creates a private `logs` subdirectory
under its existing `files/tailnet-agent` state directory with mode 0700 and sets
the supported `TS_LOGS_DIR` configuration to that path. It preserves existing
node state and key storage. A recovered startup panic is cached as a failure,
so a repeated start cannot falsely report success. The regression reproduces
the upstream directory-selection panic in an isolated environment and checks
the configured path; complete connectivity still requires a device retest.

If the key list is empty, check the log's package ID and local public/secret-key
inventory. The debug preview has separate private storage from upstream
OpenKeychain. Encryption-only keys cannot sign; revoked/expired keys, missing
private material and hardware-token-only records are identified in the inventory
rather than treated as available software signers.

## APK signing and packages

CI builds two APKs:

* `OpenKeychain-tailscale-release.apk`: non-debuggable release build, package
  `org.sufficientlysecure.keychain.tailscale`. Use this for daily signing.
* `OpenKeychain-remote-signing-preview.apk`: debuggable development build,
  package `org.sufficientlysecure.keychain.debug`.

Both install alongside upstream OpenKeychain and have separate private storage.
Stable certificates come from these repository secrets (Settings → Secrets and
variables → Actions):

| Secret | Value |
| --- | --- |
| `RELEASE_KEYSTORE_BASE64` | `base64 -w0 release.p12` |
| `RELEASE_KEYSTORE_PASSWORD` | keystore and key password |
| `RELEASE_KEY_ALIAS` | key alias |
| `DEBUG_KEYSTORE_BASE64` | `base64 -w0 debug.p12` |
| `DEBUG_KEYSTORE_PASSWORD` | keystore and key password |
| `DEBUG_KEY_ALIAS` | key alias |

Without the release secrets the release APK is unsigned and not published;
without the debug secrets the debug APK uses the runner's temporary key, as
earlier previews did. The workflow prints each APK's certificate digest. Locally,
set `RELEASE_KEYSTORE_FILE` (or the `signingStoreLocation` Gradle properties) to
sign a release build. Losing the release keystore ends in-place upgrades.

Earlier previews were signed with temporary keys and cannot be upgraded in place.
Export a protected key backup in the old app, install the new APK, import and test
the key, and only then uninstall the old app. The new app enrolls as a new
Tailscale node; revoke the old node and create a new gpg-bridge string.

## Verification

Run the Python transport/isolation tests without a phone:

```sh
cd tools/remote-gpg-agent
python3 -m unittest -v test_remote_agent.py
```

The tests cover binary relay and half-closes, private socket permissions,
existing-agent preservation, SOCKS5, HTTP CONNECT, GnuPG socket interoperability,
and rejection of secret-key input. The GnuPG tests generate a disposable key and
stop only the reference agent belonging to that disposable test home. JVM
protocol tests live in `remote-agent-protocol/test.sh`; native tests live in
`native/tailscale`. A passing local test suite does not establish Android
device, login, notification, or live tailnet interoperability.

To exercise real detached signatures and signed Git commits through both the
Python client and Java Assuan protocol, run `python3 integration_test.py` from
the helper directory. This uses a local test CONNECT proxy and a disposable
reference key, without contacting a phone or an external network.
