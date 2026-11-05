#!/usr/bin/env python3
"""Verify the production bridge OpenPGP encoder against GnuPG using disposable keys."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = Path("org/sufficientlysecure/keychain/remoteagent/crypto")


def main():
    java_home = os.environ.get("JAVA_HOME")
    java = str(Path(java_home) / "bin/java") if java_home else shutil.which("java")
    javac = str(Path(java_home) / "bin/javac") if java_home else shutil.which("javac")
    if not java or not javac:
        raise SystemExit("Set JAVA_HOME to a JDK 17 installation")
    cache = Path.home() / ".gradle/caches/modules-2/files-2.1/org.bouncycastle/bcprov-jdk18on/1.77"
    providers = list(cache.glob("*/*.jar"))
    pg = ROOT / "extern/bouncycastle/pg/build/libs/pg.jar"
    if not providers or not pg.is_file():
        raise SystemExit("Build :extern:bouncycastle:pg:jar first to resolve the pinned BC implementation")
    dependency_classpath = os.pathsep.join((str(pg), str(providers[0])))

    with tempfile.TemporaryDirectory(prefix="gpg-bridge-pgp-") as directory:
        temp = Path(directory)
        home = temp / "gpg"
        home.mkdir(mode=0o700)
        environment = dict(os.environ, GNUPGHOME=str(home))

        def gpg(*arguments, **kwargs):
            return subprocess.run(["gpg", "--batch", "--no-tty", *arguments], env=environment,
                                  check=True, capture_output=True, **kwargs)

        try:
            password = ("--pinentry-mode", "loopback", "--passphrase", "temporary bridge fixture")
            classes = temp / "classes"
            classes.mkdir()
            sources = [ROOT / "OpenKeychain/src/main/java" / PACKAGE / (name + ".java")
                       for name in ("BridgeSignature", "BridgePgpSigning", "RsaAgentCrypto")]
            sources.append(ROOT / "OpenKeychain/src/test/java" / PACKAGE / "BridgePgpInteropTest.java")
            subprocess.run([javac, "-cp", dependency_classpath, "-d", str(classes)]
                           + [str(source) for source in sources], check=True)
            cases = (
                ("commit", ("tree " + "1" * 40 + "\nauthor Test <test@example.invalid> 1700000000 +0000\n"
                            "committer Test <test@example.invalid> 1700000000 +0000\n\n测试提交\n").encode()),
                ("large", bytes(range(256)) * 4096),
            )
            for algorithm in ("rsa2048", "rsa1024", "ed25519", "nistp256", "dsa2048"):
                uid = "Bridge " + algorithm + " <" + algorithm + "@example.invalid>"
                gpg(*password, "--quick-generate-key", uid, algorithm, "cert", "0")
                listing = gpg("--with-colons", "--list-keys", uid).stdout.decode()
                primary = next(line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:"))
                # GnuPG's quick-add curve parser otherwise defaults nistp256 to
                # ECDH even when the separate usage argument says "sign".
                add_algorithm = algorithm + "/sign" if algorithm == "nistp256" else algorithm
                gpg(*password, "--quick-add-key", primary, add_algorithm, "sign", "0")
                listing = gpg("--with-colons", "--list-keys", primary).stdout.decode()
                fingerprints = [line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:")]
                signing_fingerprint = fingerprints[1]
                secret = temp / (algorithm + "-fixture-secret.pgp")
                secret.write_bytes(gpg(*password, "--export-secret-keys", primary).stdout)
                for name, content in cases:
                    data = temp / (algorithm + "-" + name + ".data")
                    data.write_bytes(content)
                    output = temp / (algorithm + "-" + name)
                    subprocess.run([java, "-cp", str(classes) + os.pathsep + dependency_classpath,
                                    "org.sufficientlysecure.keychain.remoteagent.crypto.BridgePgpInteropTest",
                                    str(secret), str(data), str(output), signing_fingerprint], check=True)
                    verification = gpg("--status-fd", "1", "--verify", str(output) + ".asc", str(data))
                    assert ("[GNUPG:] VALIDSIG " + signing_fingerprint + " ").encode() in verification.stdout
                    assert signing_fingerprint in Path(str(output) + ".status").read_text()
                    data.write_bytes(bytes([content[0] ^ 1]) + content[1:])
                    corrupted = subprocess.run(["gpg", "--batch", "--verify", str(output) + ".asc", str(data)],
                                               env=environment, capture_output=True)
                    assert corrupted.returncode != 0, "Altered bridge message verified"
                print("Verified gpg-bridge OpenPGP signing:", algorithm)
        finally:
            subprocess.run(["gpgconf", "--kill", "gpg-agent"], env=environment,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print("gpg-bridge OpenPGP interop passed: RSA/Ed25519/ECDSA/DSA subkeys, full-message SHA256, armor/status, 1 MiB and tamper rejection")


if __name__ == "__main__":
    main()
