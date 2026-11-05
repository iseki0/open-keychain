#!/usr/bin/env python3
"""Run GnuPG/Git using the signing agent in OpenKeychain over Tailscale.

Only public keys enter this disposable GNUPGHOME. No local gpg-agent is started.
Requires Python 3.9+, GnuPG 2.2+, and a route (or local SOCKS5 proxy) to Tailscale.
"""

import argparse
import contextlib
import ipaddress
import os
from pathlib import Path
import re
import selectors
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time


TAILNETS = (ipaddress.ip_network("100.64.0.0/10"),
            ipaddress.ip_network("fd7a:115c:a1e0::/48"))
MAX_CONNECTIONS = 4
IDLE_SECONDS = 300


def tailnet_address(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("use the phone's literal Tailscale IP address") from error
    if not any(address.version == network.version and address in network for network in TAILNETS):
        raise argparse.ArgumentTypeError("target must be a Tailscale IPv4 or IPv6 address")
    return str(address)


def port_number(value):
    try:
        port = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("port must be a number") from error
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def socks_address(value):
    host, separator, port = value.rpartition(":")
    host = host.removeprefix("[").removesuffix("]")
    try:
        address = ipaddress.ip_address(host)
    except ValueError as error:
        raise argparse.ArgumentTypeError("SOCKS5 proxy must use a literal loopback IP") from error
    if not separator or not address.is_loopback:
        raise argparse.ArgumentTypeError("SOCKS5 proxy must run on loopback")
    return str(address), port_number(port)


def connect_proxy_address(value):
    host, separator, port = value.rpartition(":")
    host = host.removeprefix("[").removesuffix("]")
    if not separator or not host or not re.fullmatch(r"[A-Za-z0-9.:-]+", host):
        raise argparse.ArgumentTypeError("HTTP CONNECT proxy must be host:port, without credentials or a URL scheme")
    return host, port_number(port)


def receive_exact(stream, count):
    chunks = bytearray()
    while len(chunks) < count:
        chunk = stream.recv(count - len(chunks))
        if not chunk:
            raise OSError("SOCKS5 proxy closed the connection")
        chunks.extend(chunk)
    return bytes(chunks)


def connect_remote(host, port, socks5=None, http_connect=None):
    if socks5 and http_connect:
        raise ValueError("choose either SOCKS5 or HTTP CONNECT")
    stream = socket.create_connection(socks5 or http_connect or (host, port), timeout=10)
    try:
        if http_connect:
            authority = "[%s]:%d" % (host, port) if ":" in host else "%s:%d" % (host, port)
            stream.sendall(("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n" %
                            (authority, authority)).encode("ascii"))
            headers = bytearray()
            while not headers.endswith(b"\r\n\r\n"):
                if len(headers) >= 16384:
                    raise OSError("HTTP CONNECT proxy response exceeds 16 KiB")
                chunk = stream.recv(1)
                if not chunk:
                    raise OSError("HTTP CONNECT proxy closed before its response")
                headers.extend(chunk)
            status = bytes(headers).split(b"\r\n", 1)[0].split(b" ")
            if len(status) < 2 or status[0] not in (b"HTTP/1.0", b"HTTP/1.1") or status[1] != b"200":
                code = status[1].decode("ascii", errors="replace") if len(status) > 1 else "invalid"
                raise OSError("HTTP CONNECT proxy rejected destination (status %s); check VPN readiness and TCP grants" % code)
        elif socks5:
            # tailscaled's local userspace SOCKS5 proxy uses no-auth negotiation.
            stream.sendall(b"\x05\x01\x00")
            if receive_exact(stream, 2) != b"\x05\x00":
                raise OSError("SOCKS5 proxy did not accept no-auth negotiation")
            address = ipaddress.ip_address(host)
            family = b"\x01" if address.version == 4 else b"\x04"
            stream.sendall(b"\x05\x01\x00" + family + address.packed + struct.pack("!H", port))
            version, status, reserved, family = receive_exact(stream, 4)
            if (version, status, reserved) != (5, 0, 0):
                raise OSError("SOCKS5 connection rejected (status %d)" % status)
            if family == 1:
                receive_exact(stream, 4)
            elif family == 4:
                receive_exact(stream, 16)
            elif family == 3:
                receive_exact(stream, receive_exact(stream, 1)[0])
            else:
                raise OSError("SOCKS5 proxy returned an invalid address type")
            receive_exact(stream, 2)
        stream.settimeout(None)
        return stream
    except BaseException:
        stream.close()
        raise


def private_directory(path):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise RuntimeError("socket directory must be owned by you, mode 0700, and not a symlink: " + str(path))


def prepare_socket_directory(path):
    """Create only missing private directories; return precisely those we own."""
    missing = []
    parent = path
    while not parent.exists():
        missing.append(parent)
        parent = parent.parent
    if parent.is_symlink():
        raise RuntimeError("refusing a symlink socket directory: " + str(parent))
    # /run/user and /tmp may be shared ancestors. The actual socket parent
    # and every directory this function creates must be private.
    created = []
    try:
        for directory in reversed(missing):
            directory.mkdir(mode=0o700)
            created.append(directory)
        private_directory(path)
        return created
    except BaseException:
        for directory in reversed(created):
            directory.rmdir()
        raise


class AgentProxy:
    """A bounded UNIX socket relay. The TCP endpoint is never listened on locally."""

    def __init__(self, socket_path, connect, idle_seconds=IDLE_SECONDS):
        self.path = Path(socket_path)
        self.connect = connect
        self.idle_seconds = idle_seconds
        self.stopped = threading.Event()
        self.capacity = threading.BoundedSemaphore(MAX_CONNECTIONS)
        self.listener = None
        self.inode = None
        self.connections = set()
        self.lock = threading.Lock()
        self.thread = None

    def start(self):
        private_directory(self.path.parent)
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            # bind fails on an existing socket. Never unlink another agent.
            self.listener.bind(str(self.path))
            os.chmod(self.path, 0o600)
            info = self.path.lstat()
            self.inode = (info.st_dev, info.st_ino)
            self.listener.listen(MAX_CONNECTIONS)
            self.listener.settimeout(0.2)
            self.thread = threading.Thread(target=self._accept, daemon=True)
            self.thread.start()
            return self
        except BaseException:
            self.close()
            raise

    def _accept(self):
        while not self.stopped.is_set():
            try:
                local, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if not self.capacity.acquire(blocking=False):
                local.close()
                continue
            with self.lock:
                self.connections.add(local)
            threading.Thread(target=self._forward, args=(local,), daemon=True).start()

    def _forward(self, local):
        remote = None
        try:
            remote = self.connect()
            with self.lock:
                if self.stopped.is_set():
                    return
                self.connections.add(remote)
            # Blocking sendall has its own timeout, bounding a peer that stops
            # reading. Selector timeout bounds waiting for a phone approval.
            local.settimeout(10)
            remote.settimeout(10)
            with selectors.DefaultSelector() as selector:
                selector.register(local, selectors.EVENT_READ, remote)
                selector.register(remote, selectors.EVENT_READ, local)
                last_activity = time.monotonic()
                while not self.stopped.is_set():
                    events = selector.select(min(1, self.idle_seconds))
                    if not events and time.monotonic() - last_activity >= self.idle_seconds:
                        return
                    for key, _ in events:
                        data = key.fileobj.recv(16384)
                        if not data:
                            selector.unregister(key.fileobj)
                            with contextlib.suppress(OSError):
                                key.data.shutdown(socket.SHUT_WR)
                            if not selector.get_map():
                                return
                            continue
                        key.data.sendall(data)
                        last_activity = time.monotonic()
        except OSError as error:
            if not self.stopped.is_set():
                # Do not log Assuan commands, data, signatures, or credentials.
                print("remote-agent: connection failed: " + str(error), file=sys.stderr)
        finally:
            for stream in (local, remote):
                if stream is not None:
                    with self.lock:
                        self.connections.discard(stream)
                    stream.close()
            self.capacity.release()

    def close(self):
        self.stopped.set()
        if self.listener is not None:
            self.listener.close()
        with self.lock:
            for stream in self.connections:
                with contextlib.suppress(OSError):
                    stream.shutdown(socket.SHUT_RDWR)
                stream.close()
        if self.thread is not None:
            self.thread.join(timeout=2)
        if self.inode is not None:
            with contextlib.suppress(FileNotFoundError):
                info = self.path.lstat()
                if stat.S_ISSOCK(info.st_mode) and (info.st_dev, info.st_ino) == self.inode:
                    self.path.unlink()


def gpg_run(arguments, environment, **kwargs):
    return subprocess.run(["gpg", "--batch", "--no-tty", "--no-autostart"] + arguments,
                          env=environment, check=True, **kwargs)


def run_session(options):
    command = options.command
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise RuntimeError("supply a command after --, for example: -- gpg --detach-sign file.txt")
    public_key = Path(options.public_key).resolve(strict=True)
    # umask also protects GnuPG files and a possible /run/user socket directory.
    previous_umask = os.umask(0o077)
    created = []
    try:
        with tempfile.TemporaryDirectory(prefix="openkeychain-agent-") as directory:
            home = Path(directory)
            private_directory(home)
            environment = dict(os.environ, GNUPGHOME=str(home))
            environment.pop("GPG_AGENT_INFO", None)
            (home / "gpg.conf").write_text("no-autostart\n", encoding="ascii")
            # Inspect before importing. --show-keys does not install key material.
            inspection = gpg_run(["--with-colons", "--show-keys", str(public_key)],
                                 environment, capture_output=True, text=True)
            kinds = [line.split(":", 1)[0] for line in inspection.stdout.splitlines()]
            if any(kind in ("sec", "ssb") for kind in kinds) or "pub" not in kinds:
                raise RuntimeError("--public-key must contain public OpenPGP keys only; use gpg --armor --export")
            gpg_run(["--import", str(public_key)], environment)
            private_keys = home / "private-keys-v1.d"
            if private_keys.exists() and any(private_keys.iterdir()):
                raise RuntimeError("refusing a session containing local private keys")
            result = subprocess.run(["gpgconf", "--list-dirs", "agent-socket"],
                                    env=environment, check=True, capture_output=True, text=True)
            socket_path = Path(result.stdout.strip())
            if not socket_path.is_absolute() or "\n" in str(socket_path):
                raise RuntimeError("gpgconf returned an invalid agent socket path")
            created = prepare_socket_directory(socket_path.parent)
            proxy = AgentProxy(socket_path, lambda: connect_remote(options.host, options.port, options.socks5,
                                                                  getattr(options, "http_connect", None)))
            try:
                proxy.start()
                print("remote-agent: using phone %s:%d; approve each signature on the phone" %
                      (options.host, options.port), file=sys.stderr)
                process = subprocess.Popen(command, env=environment)
                try:
                    try:
                        return process.wait()
                    except KeyboardInterrupt:
                        # Child receives SIGINT from the same terminal process group.
                        with contextlib.suppress(subprocess.TimeoutExpired):
                            return process.wait(timeout=5)
                        process.terminate()
                        return process.wait()
                finally:
                    if process.poll() is None:
                        process.terminate()
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait()
            finally:
                proxy.close()
    finally:
        for path in reversed(created):
            with contextlib.suppress(FileNotFoundError, OSError):
                path.rmdir()
        os.umask(previous_umask)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True, type=tailnet_address, help="phone's Tailscale IP")
    parser.add_argument("--port", type=port_number, default=17373)
    parser.add_argument("--public-key", required=True, help="public-key export from OpenKeychain")
    transport = parser.add_mutually_exclusive_group()
    transport.add_argument("--socks5", type=socks_address, help="local userspace Tailscale SOCKS5 proxy, e.g. 127.0.0.1:1055")
    transport.add_argument("--http-connect", type=connect_proxy_address,
                           help="authorized raw TCP proxy, e.g. managed cloud proxy:8088")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="command after --, e.g. git commit -S")
    options = parser.parse_args(argv)
    def terminate(_number, _frame):
        raise SystemExit(143)
    previous_sigterm = signal.signal(signal.SIGTERM, terminate)
    try:
        return run_session(options)
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print("remote-agent: " + str(error), file=sys.stderr)
        return 1
    finally:
        signal.signal(signal.SIGTERM, previous_sigterm)


if __name__ == "__main__":
    sys.exit(main())
