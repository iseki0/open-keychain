#!/usr/bin/env python3
"""Real GnuPG -> Python relay -> mock CONNECT -> Java AssuanSession -> test key.

No phone, user key, or external network is used. The Java fixture delegates
signing only to an agent created for this test's disposable reference home.
"""

import contextlib
import os
from pathlib import Path
import selectors
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading


ROOT = Path(__file__).resolve().parents[2]
PROTOCOL = ROOT / "remote-agent-protocol"
HELPER = Path(__file__).with_name("remote_agent.py")


def run(arguments, **options):
    return subprocess.run(arguments, check=True, **options)


def main():
    with tempfile.TemporaryDirectory(prefix="remote-agent-stack-") as directory:
        workspace = Path(directory)
        home = workspace / "reference"
        home.mkdir(mode=0o700)
        environment = dict(os.environ, GNUPGHOME=str(home))
        fixture = None
        proxy = None
        try:
            run(["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
                 "--quick-generate-key", "Full stack fixture <test@example.invalid>",
                 "rsa2048", "sign", "0"], env=environment, capture_output=True)
            listing = run(["gpg", "--with-colons", "--with-keygrip", "--list-keys"],
                          env=environment, capture_output=True, text=True).stdout
            fingerprint = next(line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:"))
            grip = next(line.split(":")[9] for line in listing.splitlines() if line.startswith("grp:"))
            public_key = workspace / "public.asc"
            public_key.write_bytes(run(["gpg", "--export", fingerprint], env=environment,
                                       capture_output=True).stdout)
            classes = workspace / "classes"
            classes.mkdir()
            production = sorted((PROTOCOL / "src/main/java").rglob("*.java"))
            test_sources = sorted((PROTOCOL / "src/test/java").rglob("*.java"))
            run(["java", "com.sun.tools.javac.Main", "-Xlint:-options", "-source", "8", "-target", "8",
                 "-d", str(classes)] + [str(source) for source in production])
            run(["java", "com.sun.tools.javac.Main", "-Xlint:-options", "-source", "17", "-target", "17",
                 "-cp", str(classes), "-d", str(classes)] + [str(source) for source in test_sources])
            with (workspace / "fixture.log").open("wb") as log:
                fixture = subprocess.Popen(["java", "-cp", str(classes),
                    "org.sufficientlysecure.keychain.remote.agent.TestAgentServer",
                    str(home), grip, "tcp:0"], stdout=subprocess.PIPE, stderr=log, text=True)
                with selectors.DefaultSelector() as ready:
                    ready.register(fixture.stdout, selectors.EVENT_READ)
                    if not ready.select(10):
                        raise RuntimeError("Java test fixture did not start in 10 seconds")
                    address = fixture.stdout.readline().strip()
                if not address.startswith("READY "):
                    raise RuntimeError("Java fixture failed to start: " + address)
                fixture_port = int(address.rsplit(":", 1)[1])

                class ConnectHandler(socketserver.BaseRequestHandler):
                    def handle(self):
                        self.request.settimeout(10)
                        header = bytearray()
                        while not header.endswith(b"\r\n\r\n"):
                            data = self.request.recv(1)
                            if not data or len(header) >= 16384:
                                return
                            header.extend(data)
                        if not header.startswith(b"CONNECT 100.101.102.103:17373 HTTP/1.1\r\n"):
                            self.request.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")
                            return
                        with socket.create_connection(("127.0.0.1", fixture_port), timeout=10) as upstream:
                            self.request.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                            with selectors.DefaultSelector() as traffic:
                                traffic.register(self.request, selectors.EVENT_READ, upstream)
                                traffic.register(upstream, selectors.EVENT_READ, self.request)
                                while True:
                                    events = traffic.select(10)
                                    if not events:
                                        return
                                    for key, _ in events:
                                        data = key.fileobj.recv(16384)
                                        if not data:
                                            return
                                        key.data.sendall(data)

                class ConnectServer(socketserver.ThreadingTCPServer):
                    daemon_threads = True

                proxy = ConnectServer(("127.0.0.1", 0), ConnectHandler)
                worker = threading.Thread(target=proxy.serve_forever, daemon=True)
                worker.start()
                prefix = [sys.executable, str(HELPER), "--host", "100.101.102.103",
                          "--public-key", str(public_key), "--http-connect",
                          "127.0.0.1:%d" % proxy.server_address[1], "--"]
                message = workspace / "message.txt"
                signature = workspace / "message.sig"
                message.write_text("Full Python/CONNECT/Assuan remote signing test\n")
                run(prefix + ["gpg", "--batch", "--digest-algo", "SHA256", "--local-user", fingerprint,
                              "--detach-sign", "--output", str(signature), str(message)], timeout=20)
                run(["gpg", "--verify", str(signature), str(message)], env=environment, timeout=10)
                repository = workspace / "repository"
                run(["git", "init", "-q", str(repository)])
                run(["git", "-C", str(repository), "config", "user.name", "Full stack fixture"])
                run(["git", "-C", str(repository), "config", "user.email", "test@example.invalid"])
                (repository / "message.txt").write_text("Full stack signed commit\n")
                run(["git", "-C", str(repository), "add", "message.txt"])
                run(prefix + ["git", "-C", str(repository), "-c", "user.signingkey=" + fingerprint,
                              "-c", "gpg.format=openpgp", "-c", "gpg.program=gpg",
                              "commit", "-q", "-S", "-m", "Full stack remote signing"], timeout=20)
                run(["git", "-C", str(repository), "verify-commit", "HEAD"], env=environment, timeout=10)
                print("Full stack: GnuPG detached signature and Git signed commit verified through Python + CONNECT + Java AssuanSession")
        finally:
            if proxy is not None:
                proxy.shutdown()
                proxy.server_close()
            if fixture is not None:
                fixture.terminate()
                with contextlib.suppress(subprocess.TimeoutExpired):
                    fixture.wait(timeout=5)
                if fixture.poll() is None:
                    fixture.kill()
                    fixture.wait()
                fixture.stdout.close()
            run(["gpgconf", "--kill", "gpg-agent"], env=environment)


if __name__ == "__main__":
    main()
