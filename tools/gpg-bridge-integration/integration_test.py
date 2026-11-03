#!/usr/bin/env python3
"""Exercise the unmodified Rust gpg-bridge client against OpenKeychain's Go handler.

Uses disposable GnuPG keys and a localhost-only test fixture; no phone, real
Tailscale connection, or existing user key is accessed. Pass the actual upstream
client binary with --binary (built from the commit documented in README.md).
"""

import argparse
import contextlib
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import time


ROOT = Path(__file__).resolve().parents[2]
GO_MODULE = ROOT / "native/tailscale"


def run(arguments, *, env=None, cwd=None, check=True, timeout=45):
    result = subprocess.run([str(value) for value in arguments], env=env, cwd=cwd,
                            capture_output=True, text=True, timeout=timeout)
    if check and result.returncode:
        # Arguments contain paths/fingerprints, never the pairing ticket itself.
        raise RuntimeError("command failed: " + " ".join(map(str, arguments))
                           + "\n" + result.stderr[-6000:])
    return result


def exercise_client(binary, fixture_binary, key_type):
    with tempfile.TemporaryDirectory(prefix=f"openkeychain-gpgbridge-{key_type}-") as temporary:
        workspace = Path(temporary)
        reference = workspace / "reference"
        client_home = workspace / "client-home"
        reference.mkdir(mode=0o700)
        client_home.mkdir(mode=0o700)
        environment = dict(os.environ, GNUPGHOME=str(client_home))
        reference_environment = dict(os.environ, GNUPGHOME=str(reference))
        ticket = workspace / "ticket"
        stop = workspace / "stop"
        control = workspace / "control"
        fixture = None
        repository = workspace / "repository"
        log_path = workspace / "fixture.log"
        try:
            algorithm = {"rsa": "rsa2048", "ed25519": "ed25519"}[key_type]
            run(["gpg", "--batch", "--no-tty", "--pinentry-mode", "loopback", "--passphrase", "",
                 "--quick-generate-key", "OpenKeychain bridge fixture <bridge@example.invalid>",
                 algorithm, "sign", "0"], env=reference_environment)
            listing = run(["gpg", "--with-colons", "--list-keys"],
                          env=reference_environment).stdout
            fingerprint = next(line.split(":")[9] for line in listing.splitlines()
                               if line.startswith("fpr:"))
            fixture_environment = dict(os.environ,
                GPG_BRIDGE_INTEROP_HOME=str(reference),
                GPG_BRIDGE_INTEROP_FINGERPRINT=fingerprint,
                GPG_BRIDGE_INTEROP_TICKET=str(ticket), GPG_BRIDGE_INTEROP_STOP=str(stop),
                GPG_BRIDGE_INTEROP_CONTROL=str(control))
            with log_path.open("wb") as log:
                fixture = subprocess.Popen([str(fixture_binary),
                    "-test.run=^TestBridgeInteropServer$", "-test.v"],
                    cwd=GO_MODULE, env=fixture_environment, stdout=log, stderr=subprocess.STDOUT)
                started = time.monotonic()
                while not ticket.exists():
                    if fixture.poll() is not None:
                        raise RuntimeError("Go HTTP/Noise fixture exited before becoming ready")
                    if time.monotonic() - started > 30:
                        raise RuntimeError("Go HTTP/Noise fixture did not become ready")
                    time.sleep(0.05)

                run(["git", "init", "-q", repository])
                def git(*arguments, check=True):
                    return run(["git", "-C", repository, *arguments],
                               env=environment, check=check)
                def client(*arguments, check=True):
                    return run([binary, *arguments], cwd=repository,
                               env=environment, check=check)
                git("config", "user.name", "OpenKeychain bridge fixture")
                git("config", "user.email", "bridge@example.invalid")
                previous = {"user.signingkey": "original-signing-key", "gpg.program": "/bin/false",
                            "commit.gpgsign": "false", "tag.gpgSign": "false", "gpg.format": "ssh"}
                for key, value in previous.items():
                    git("config", "--local", key, value)
                client("connect", "--ticket-file", ticket)
                client("status")
                config_path = repository / ".git/gpg-bridge-client.json"
                assert stat.S_IMODE(config_path.stat().st_mode) == 0o600
                assert git("config", "--get", "user.signingkey").stdout.strip() == fingerprint + "!"

                (repository / "message.txt").write_text("Actual Rust client signs through Go Noise handler.\n")
                git("add", "message.txt")
                git("commit", "-q", "-m", "Rust-to-Go remote signed commit")
                git("verify-commit", "HEAD")
                large_message = workspace / "large-message.txt"
                large_message.write_text("Chunked Unicode signature\n\n" + "远端签名协议互操作。\n" * 6000,
                                         encoding="utf-8")
                git("commit", "--allow-empty", "-q", "-F", large_message)
                git("verify-commit", "HEAD")
                git("tag", "-s", "interop-v1", "-m", "Rust-to-Go remote signed tag")
                git("verify-tag", "interop-v1")
                head = git("rev-parse", "HEAD").stdout.strip()

                git("config", "user.signingkey", "0" * 40 + "!")
                denied_key = git("commit", "--allow-empty", "-q", "-S", "-m", "Unauthorized key", check=False)
                assert denied_key.returncode != 0, "unauthorized signing fingerprint was accepted"
                assert git("rev-parse", "HEAD").stdout.strip() == head
                git("config", "user.signingkey", fingerprint + "!")
                control.write_text("deny\n")
                denied = git("commit", "--allow-empty", "-q", "-S", "-m", "Locally denied", check=False)
                assert denied.returncode != 0, "local backend denial was ignored"
                assert git("rev-parse", "HEAD").stdout.strip() == head
                control.unlink()

                # The client must retain local verification when the signer is offline.
                stop.touch()
                fixture.wait(timeout=10)
                if fixture.returncode:
                    raise RuntimeError("Go HTTP/Noise fixture failed")
                git("verify-commit", "HEAD")
                git("verify-tag", "interop-v1")
                assert client("status", check=False).returncode != 0
                for home in (client_home, repository / ".git/gpg-bridge-gnupg"):
                    assert not any((home / "private-keys-v1.d").glob("*")), "private key leaked to client"
                client("disconnect")
                assert not config_path.exists()
                assert not (repository / ".git/gpg-bridge-gnupg").exists()
                assert not (repository / ".git/gpg-bridge-wrapper.sh").exists()
                for key, value in previous.items():
                    assert git("config", "--local", "--get", key).stdout.strip() == value
        except BaseException:
            if log_path.exists():
                # The fixture never logs pairing tickets, data, or credentials.
                print(log_path.read_text(errors="replace")[-6000:])
            raise
        finally:
            stop.touch()
            if fixture is not None and fixture.poll() is None:
                try:
                    fixture.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    fixture.terminate()
                    try:
                        fixture.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        fixture.kill()
                        fixture.wait()
            # Stop only agents belonging to homes created by this disposable test.
            for home in (reference, client_home, repository / ".git/gpg-bridge-gnupg"):
                with contextlib.suppress(OSError, subprocess.SubprocessError):
                    run(["gpgconf", "--homedir", home, "--kill", "gpg-agent"], check=False)
    print(f"gpg-bridge {key_type} interoperability passed: unmodified Rust client, Noise HTTP RPC, "
          "Git commit/tag and chunked Unicode signing, key denial, local denial, offline verification, "
          "no client private keys, configuration restoration")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default=os.environ.get("GPG_BRIDGE_BIN"), type=Path,
                        help="unmodified upstream gpg-bridge client binary")
    parser.add_argument("--go", default=shutil.which("go"), help="Go 1.27.3+ executable")
    parser.add_argument("--key-type", choices=("both", "rsa", "ed25519"), default="both",
                        help="disposable signing keys to exercise (default: both RSA and Ed25519)")
    args = parser.parse_args()
    if args.binary is None:
        parser.error("supply --binary or GPG_BRIDGE_BIN with the actual upstream client")
    binary = args.binary.resolve(strict=True)
    if not args.go:
        parser.error("Go 1.27.3+ is required; pass --go")
    go = Path(args.go).resolve(strict=True)
    run([binary, "--version"])
    with tempfile.TemporaryDirectory(prefix="openkeychain-gpgbridge-build-") as temporary:
        fixture_binary = Path(temporary) / "bridge-fixture.test"
        run([go, "test", "-c", "-o", fixture_binary, "."], cwd=GO_MODULE, timeout=300)
        key_types = ("rsa", "ed25519") if args.key_type == "both" else (args.key_type,)
        for key_type in key_types:
            exercise_client(binary, fixture_binary, key_type)


if __name__ == "__main__":
    main()
