#!/usr/bin/env python3
"""Check agent RSA output against Java, libgcrypt, and GnuPG (temporary test keys only)."""
import ctypes
import ctypes.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
JAVA_ROOT = "org/sufficientlysecure/keychain/remoteagent/crypto"


def run_test():
    java_home = os.environ.get("JAVA_HOME")
    javac = str(Path(java_home) / "bin/javac") if java_home else shutil.which("javac")
    java = str(Path(java_home) / "bin/java") if java_home else shutil.which("java")
    if not javac or not java:
        raise SystemExit("A JDK is required; set JAVA_HOME or add java and javac to PATH")
    lib = ctypes.CDLL(ctypes.util.find_library("gcrypt"))
    lib.gcry_check_version.restype = ctypes.c_char_p
    assert lib.gcry_check_version(None), "libgcrypt initialization failed"
    lib.gcry_sexp_new.argtypes = [ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
                                  ctypes.c_size_t, ctypes.c_int]
    lib.gcry_pk_get_keygrip.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    lib.gcry_pk_get_keygrip.restype = ctypes.c_void_p
    lib.gcry_pk_verify.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    lib.gcry_sexp_release.argtypes = [ctypes.c_void_p]

    def sexp(raw):
        result = ctypes.c_void_p()
        assert lib.gcry_sexp_new(ctypes.byref(result), raw, len(raw), 1) == 0
        return result

    def atom(raw):
        return str(len(raw)).encode() + b":" + raw

    with tempfile.TemporaryDirectory(prefix="openkeychain-rsa-test-") as temp:
        subprocess.run([javac, "-d", temp,
                        str(ROOT / "OpenKeychain/src/main/java" / JAVA_ROOT / "RsaAgentCrypto.java"),
                        str(ROOT / "OpenKeychain/src/test/java" / JAVA_ROOT / "RsaAgentCryptoInteropTest.java")],
                       check=True)
        output = subprocess.check_output([java, "-cp", temp,
            "org.sufficientlysecure.keychain.remoteagent.crypto.RsaAgentCryptoInteropTest"], text=True)
        records = [line.split() for line in output.splitlines()]
        values = {row[0]: row[1] for row in records if row[0] != "SIGNATURE"}
        public = sexp(bytes.fromhex(values["PUBLIC"]))
        try:
            grip = ctypes.create_string_buffer(20)
            assert lib.gcry_pk_get_keygrip(public, grip)
            assert grip.raw.hex().upper() == values["GRIP"], "libgcrypt keygrip mismatch"
            for _, algo, digest_hex, signature_hex in (r for r in records if r[0] == "SIGNATURE"):
                name = {"8": b"sha256", "9": b"sha384", "10": b"sha512"}[algo]
                digest = bytes.fromhex(digest_hex)
                signature = sexp(bytes.fromhex(signature_hex))
                data = sexp(b"(4:data(5:flags5:pkcs1)(4:hash" + atom(name) + atom(digest) + b"))")
                bad_data = sexp(b"(4:data(5:flags5:pkcs1)(4:hash" + atom(name)
                                + atom(bytes([digest[0] ^ 1]) + digest[1:]) + b"))")
                try:
                    assert lib.gcry_pk_verify(signature, data, public) == 0, "libgcrypt signature mismatch"
                    assert lib.gcry_pk_verify(signature, bad_data, public) != 0, "Bad digest accepted"
                finally:
                    lib.gcry_sexp_release(signature)
                    lib.gcry_sexp_release(data)
                    lib.gcry_sexp_release(bad_data)
        finally:
            lib.gcry_sexp_release(public)

        def mpi(integer):
            return integer.bit_length().to_bytes(2, "big") + integer.to_bytes((integer.bit_length()+7)//8, "big")

        # A bare RSA OpenPGP public-key packet is enough for GnuPG to calculate its keygrip.
        body = b"\x04" + (1700000000).to_bytes(4, "big") + b"\x01"
        body += mpi(int(values["MODULUS"], 16)) + mpi(int(values["EXPONENT"], 16))
        packet = b"\xc6\xff" + len(body).to_bytes(4, "big") + body
        gpg_home = Path(temp) / "gpg"
        gpg_home.mkdir(mode=0o700)
        result = subprocess.run(["gpg", "--homedir", str(gpg_home), "--batch", "--with-colons",
                                 "--with-keygrip", "--show-keys"], input=packet,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        gpg_grips = [line.split(":")[9] for line in result.stdout.decode().splitlines()
                     if line.startswith("grp:")]
        assert values["GRIP"] in gpg_grips, "GnuPG keygrip mismatch"
    print("RSA agent interop passed: GnuPG keygrip, libgcrypt + Java SHA256/384/512 signatures, invalid digest rejection")


if __name__ == "__main__":
    run_test()
