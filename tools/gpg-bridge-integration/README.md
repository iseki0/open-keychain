# Upstream gpg-bridge interoperability

This harness runs the unmodified Rust client from
[iseki0/gpg-bridge](https://github.com/iseki0/gpg-bridge), pinned for validation to
commit `60454d9354d02ae7f0288df110026d2aa1de8b59`, against the same Go HTTP/Noise
handler used by OpenKeychain. The localhost listener and GnuPG signing backend
exist only in `native/tailscale/gpgbridge_interop_test.go`, which is excluded from
the Android AAR. The fixture creates disposable RSA and Ed25519 keys and never reads an
existing user's keys.

Build the upstream client with its locked dependencies, then run:

```sh
cargo build --release --locked --manifest-path /path/to/gpg-bridge/Cargo.toml
python3 tools/gpg-bridge-integration/integration_test.py \
  --binary /path/to/gpg-bridge/target/release/gpg-bridge
```

Use Go 1.27.3+; pass `--go /path/to/go` when it is not on `PATH`.
Both key algorithms run by default. Use `--key-type rsa` or `--key-type ed25519`
to investigate one algorithm independently.

The test exercises actual `connect`, `status`, signed Git commit/tag and their
verification, unauthorized-key rejection, local backend denial, offline
verification, credential cleanup, and restoration of the previous repository
Git configuration. It also checks that the client has no private-key files.
The large Unicode commit message crosses multiple Noise transport frames.
Noise framing, authentication, tampering, replay, size, and expiration checks
are covered by the Go protocol tests.

This establishes wire compatibility with the upstream client. It does not
establish physical Android, notification approval, or real tailnet behavior.
