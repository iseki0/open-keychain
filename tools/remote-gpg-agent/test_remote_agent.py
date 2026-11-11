#!/usr/bin/env python3
"""Transport and GnuPG isolation tests; no real tailnet or phone required."""

import argparse
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import unittest
from unittest import mock

import remote_agent


class AddressTests(unittest.TestCase):
    def test_tailnet_addresses_only(self):
        for value in ("100.64.0.1", "100.127.255.254", "fd7a:115c:a1e0::42"):
            self.assertEqual(remote_agent.tailnet_address(value), value)
        for value in ("127.0.0.1", "10.0.0.1", "100.128.0.1", "::1", "phone.ts.net"):
            with self.assertRaises(argparse.ArgumentTypeError):
                remote_agent.tailnet_address(value)

    def test_loopback_socks_only(self):
        self.assertEqual(remote_agent.socks_address("[::1]:1055"), ("::1", 1055))
        self.assertEqual(remote_agent.socks_address("127.0.0.1:1055"), ("127.0.0.1", 1055))
        for value in ("10.0.0.1:1055", "localhost:1055", "127.0.0.1:0"):
            with self.assertRaises(argparse.ArgumentTypeError):
                remote_agent.socks_address(value)


class ProxyTests(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.TemporaryDirectory()
        self.path = Path(self.home.name) / "S.gpg-agent"

    def tearDown(self):
        self.home.cleanup()

    def test_binary_relay_and_half_close(self):
        local_upstream, server = socket.socketpair()
        def respond():
            with server:
                received = bytearray()
                while True:
                    data = server.recv(16384)
                    if not data:
                        break
                    received.extend(data)
                server.sendall(b"D " + bytes(received) + b"\nOK\n")
        worker = threading.Thread(target=respond)
        worker.start()
        proxy = remote_agent.AgentProxy(self.path, lambda: local_upstream).start()
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(3)
                client.connect(str(self.path))
                payload = bytes(range(256)) * 256
                client.sendall(payload)
                client.shutdown(socket.SHUT_WR)
                response = bytearray()
                while True:
                    data = client.recv(16384)
                    if not data:
                        break
                    response.extend(data)
                self.assertEqual(response, b"D " + payload + b"\nOK\n")
        finally:
            proxy.close()
            worker.join(timeout=3)
        self.assertFalse(self.path.exists())

    def test_never_removes_existing_socket(self):
        with socket.socket(socket.AF_UNIX) as original:
            original.bind(str(self.path))
            inode = self.path.stat().st_ino
            with self.assertRaises(OSError):
                remote_agent.AgentProxy(self.path, lambda: None).start()
            self.assertEqual(self.path.stat().st_ino, inode)

    def test_rejects_insecure_socket_parent(self):
        Path(self.home.name).chmod(0o755)
        with self.assertRaises(RuntimeError):
            remote_agent.AgentProxy(self.path, lambda: None).start()

    def test_idle_connection_is_closed(self):
        upstream, server = socket.socketpair()
        proxy = remote_agent.AgentProxy(self.path, lambda: upstream, idle_seconds=0.05).start()
        try:
            with socket.socket(socket.AF_UNIX) as client:
                client.settimeout(3)
                client.connect(str(self.path))
                self.assertEqual(client.recv(1), b"")
        finally:
            proxy.close()
            server.close()

    def test_socks_handshake_and_address(self):
        client, server = socket.socketpair()
        target = []
        def serve():
            with server:
                target.append(remote_agent.receive_exact(server, 3))
                server.sendall(b"\x05\x00")
                target.append(remote_agent.receive_exact(server, 10))
                server.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00OK")
        worker = threading.Thread(target=serve)
        worker.start()
        with mock.patch("socket.create_connection", return_value=client):
            result = remote_agent.connect_remote("100.101.102.103", 17373, ("127.0.0.1", 1055))
            self.assertEqual(remote_agent.receive_exact(result, 2), b"OK")
            result.close()
        worker.join(timeout=3)
        self.assertEqual(target, [b"\x05\x01\x00", b"\x05\x01\x00\x01\x64\x65\x66\x67\x43\xdd"])

    def test_http_connect_preserves_assuan_greeting(self):
        client, server = socket.socketpair()
        requests = []
        def serve():
            with server:
                request = bytearray()
                while not request.endswith(b"\r\n\r\n"):
                    request.extend(server.recv(1))
                requests.append(bytes(request))
                server.sendall(b"HTTP/1.1 200 Connection established\r\n\r\nOK phone\n")
        worker = threading.Thread(target=serve)
        worker.start()
        with mock.patch("socket.create_connection", return_value=client):
            result = remote_agent.connect_remote("100.101.102.103", 17373,
                                                 http_connect=("proxy", 8088))
            self.assertEqual(remote_agent.receive_exact(result, 9), b"OK phone\n")
            result.close()
        worker.join(timeout=3)
        self.assertEqual(requests, [b"CONNECT 100.101.102.103:17373 HTTP/1.1\r\nHost: 100.101.102.103:17373\r\n\r\n"])

    def test_http_connect_rejection_is_reported(self):
        client, server = socket.socketpair()
        server.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")
        with server, mock.patch("socket.create_connection", return_value=client):
            with self.assertRaisesRegex(OSError, "status 403"):
                remote_agent.connect_remote("100.101.102.103", 17373, http_connect=("proxy", 8088))


@unittest.skipUnless(shutil.which("gpg") and shutil.which("gpgconf"), "GnuPG required")
class GnuPGTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reference = tempfile.TemporaryDirectory()
        cls.environment = dict(os.environ, GNUPGHOME=cls.reference.name)
        subprocess.run(["gpg", "--batch", "--passphrase", "", "--quick-generate-key",
                        "Disposable proxy test <test@example.invalid>", "rsa2048", "sign", "0"],
                       env=cls.environment, check=True, capture_output=True)
        cls.public_key = Path(cls.reference.name) / "public.asc"
        cls.secret_key = Path(cls.reference.name) / "secret.asc"
        for path, option in ((cls.public_key, "--export"), (cls.secret_key, "--export-secret-keys")):
            path.write_bytes(subprocess.run(["gpg", "--batch", option], env=cls.environment,
                                            check=True, capture_output=True).stdout)

    @classmethod
    def tearDownClass(cls):
        # Only the disposable reference home ever has a local agent.
        subprocess.run(["gpgconf", "--kill", "gpg-agent"], env=cls.environment, check=True)
        cls.reference.cleanup()

    def test_gpg_connect_agent_uses_relay(self):
        with tempfile.TemporaryDirectory() as home:
            path = Path(home) / "S.gpg-agent"
            client, server = socket.socketpair()
            seen = []
            def respond():
                with server, server.makefile("rwb", buffering=0) as stream:
                    stream.write(b"OK test phone agent\n")
                    while True:
                        line = stream.readline()
                        if not line:
                            break
                        seen.append(line)
                        if line.startswith(b"GETINFO version"):
                            stream.write(b"D 2.4.7\nOK\n")
                        elif line.startswith(b"BYE"):
                            stream.write(b"OK\n")
                            break
                        else:
                            stream.write(b"OK\n")
            worker = threading.Thread(target=respond)
            worker.start()
            proxy = remote_agent.AgentProxy(path, lambda: client).start()
            try:
                result = subprocess.run(["gpg-connect-agent", "--raw-socket", str(path),
                                         "GETINFO version", "/bye"], capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(b"D 2.4.7", result.stdout)
                self.assertIn(b"GETINFO version\n", seen)
            finally:
                proxy.close()
                worker.join(timeout=3)

    def test_session_is_private_and_leaves_existing_home_untouched(self):
        options = argparse.Namespace(public_key=str(self.public_key), host="100.101.102.103",
                                     port=17373, socks5=None,
                                     command=["--", "python3", "-c",
                                              "import os,pathlib,stat,subprocess; p=pathlib.Path(os.environ['GNUPGHOME']); "
                                              "assert stat.S_IMODE(p.stat().st_mode)==0o700; "
                                              "agent_socket=pathlib.Path(subprocess.check_output("
                                              "['gpgconf','--list-dirs','agent-socket'],text=True).strip()); "
                                              "assert agent_socket.is_socket(); "
                                              "assert (p/'gpg.conf').read_text()=='no-autostart\\n'; "
                                              "assert not any((p/'private-keys-v1.d').glob('*')); "
                                              "raise SystemExit(17)"])
        existing = Path(subprocess.check_output(["gpgconf", "--list-dirs", "agent-socket"],
                                                env=self.environment, text=True).strip())
        before = existing.stat().st_ino
        self.assertEqual(remote_agent.run_session(options), 17)
        self.assertEqual(existing.stat().st_ino, before)

    def test_secret_export_is_rejected(self):
        options = argparse.Namespace(public_key=str(self.secret_key), host="100.101.102.103",
                                     port=17373, socks5=None, command=["--", "false"])
        with self.assertRaisesRegex(RuntimeError, "public OpenPGP keys only"):
            remote_agent.run_session(options)


if __name__ == "__main__":
    unittest.main()
