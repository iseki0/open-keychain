#!/usr/bin/env python3
"""Check production Ed25519 agent identifiers and signatures against GnuPG/libgcrypt."""
import ctypes
import ctypes.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
JAVA_PACKAGE = Path("org/sufficientlysecure/keychain/remoteagent/crypto")


def main():
    java_home = os.environ.get("JAVA_HOME")
    javac = str(Path(java_home) / "bin/javac") if java_home else shutil.which("javac")
    java = str(Path(java_home) / "bin/java") if java_home else shutil.which("java")
    if not javac or not java:
        raise SystemExit("Set JAVA_HOME to a JDK 17 installation")
    cache = Path.home() / ".gradle/caches/modules-2/files-2.1/org.bouncycastle/bcprov-jdk18on/1.77"
    jars = list(cache.glob("*/*.jar"))
    pg = ROOT / "extern/bouncycastle/pg/build/libs/pg.jar"
    if not jars or not pg.is_file():
        raise SystemExit("Build :extern:bouncycastle:pg:jar first")
    library = ctypes.CDLL(ctypes.util.find_library("gcrypt"))
    library.gcry_check_version.restype = ctypes.c_char_p
    assert library.gcry_check_version(None)
    library.gcry_sexp_new.argtypes = [ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
                                      ctypes.c_size_t, ctypes.c_int]
    library.gcry_pk_get_keygrip.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    library.gcry_pk_get_keygrip.restype = ctypes.c_void_p
    library.gcry_pk_verify.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    library.gcry_sexp_release.argtypes = [ctypes.c_void_p]

    def sexp(raw):
        result = ctypes.c_void_p()
        assert library.gcry_sexp_new(ctypes.byref(result), raw, len(raw), 1) == 0
        return result

    def atom(raw):
        return str(len(raw)).encode() + b":" + raw

    def unescape(raw):
        result = bytearray()
        index = 0
        while index < len(raw):
            if raw[index] == 37:
                result.append(int(raw[index + 1:index + 3], 16))
                index += 3
            else:
                result.append(raw[index])
                index += 1
        return bytes(result)

    with tempfile.TemporaryDirectory(prefix="openkeychain-ed25519-") as directory:
        temp = Path(directory)
        home = temp / "gpg"
        home.mkdir(mode=0o700)
        environment = dict(os.environ, GNUPGHOME=str(home))
        try:
            def gpg(*arguments):
                return subprocess.run(["gpg", "--batch", "--no-tty", *arguments], env=environment,
                                      check=True, capture_output=True)

            gpg("--pinentry-mode", "loopback", "--passphrase", "", "--quick-generate-key",
                "Ed25519 fixture <ed25519@example.invalid>", "ed25519", "cert", "0")
            listing = gpg("--with-colons", "--with-keygrip", "--list-keys").stdout.decode()
            primary = next(line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:"))
            gpg("--pinentry-mode", "loopback", "--passphrase", "", "--quick-add-key", primary,
                "ed25519", "sign", "0")
            listing = gpg("--with-colons", "--with-keygrip", "--list-keys").stdout.decode()
            fingerprints = [line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:")]
            grips = [line.split(":")[9] for line in listing.splitlines() if line.startswith("grp:")]
            private = temp / "temporary-secret.pgp"
            private.write_bytes(gpg("--export-secret-keys", primary).stdout)
            classes = temp / "classes"
            classes.mkdir()
            classpath = os.pathsep.join((str(pg), str(jars[0])))
            sources = [ROOT / "OpenKeychain/src/main/java" / JAVA_PACKAGE / (name + ".java")
                       for name in ("RsaAgentCrypto", "Ed25519AgentCrypto")]
            sources.append(ROOT / "OpenKeychain/src/test/java" / JAVA_PACKAGE / "Ed25519AgentCryptoInteropTest.java")
            subprocess.run([javac, "-cp", classpath, "-d", str(classes)] + [str(path) for path in sources], check=True)
            for fingerprint, expected_grip in zip(fingerprints, grips):
                output = subprocess.check_output([java, "-cp", str(classes) + os.pathsep + classpath,
                    "org.sufficientlysecure.keychain.remoteagent.crypto.Ed25519AgentCryptoInteropTest",
                    str(private), fingerprint], text=True)
                records = [line.split() for line in output.splitlines()]
                values = {line[0]: line[1] for line in records if line[0] != "SIGNATURE"}
                public = sexp(bytes.fromhex(values["PUBLIC"]))
                try:
                    grip = ctypes.create_string_buffer(20)
                    assert library.gcry_pk_get_keygrip(public, grip)
                    assert grip.raw.hex().upper() == values["GRIP"] == expected_grip
                    for _, algorithm, digest_hex, signature_hex in (line for line in records if line[0] == "SIGNATURE"):
                        digest = bytes.fromhex(digest_hex)
                        signature_bytes = bytes.fromhex(signature_hex)
                        signature = sexp(signature_bytes)
                        data = sexp(b"(4:data(5:flags5:eddsa)(9:hash-algo6:sha512)(5:value" + atom(digest) + b"))")
                        bad_data = sexp(b"(4:data(5:flags5:eddsa)(9:hash-algo6:sha512)(5:value"
                                        + atom(bytes([digest[0] ^ 1]) + digest[1:]) + b"))")
                        try:
                            assert library.gcry_pk_verify(signature, data, public) == 0
                            assert library.gcry_pk_verify(signature, bad_data, public) != 0
                            # GnuPG's actual PKSIGN output must agree byte-for-byte with our Ed25519 encoding.
                            response = subprocess.check_output(["gpg-connect-agent", "SIGKEY " + expected_grip,
                                "SETHASH " + algorithm + " " + digest_hex, "PKSIGN", "/bye"], env=environment)
                            assert b"ERR " not in response, response
                            reference = b"".join(unescape(line[2:]) for line in response.splitlines() if line.startswith(b"D "))
                            assert reference == signature_bytes, "GnuPG PKSIGN differs from the production helper"
                        finally:
                            for value in (signature, data, bad_data):
                                library.gcry_sexp_release(value)
                finally:
                    library.gcry_sexp_release(public)
        finally:
            subprocess.run(["gpgconf", "--kill", "gpg-agent"], env=environment,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print("Ed25519 agent interop passed: primary/subkey keygrips, libgcrypt + GnuPG SHA256/384/512 PKSIGN, tamper rejection")


if __name__ == "__main__":
    main()
