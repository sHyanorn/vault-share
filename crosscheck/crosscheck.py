"""Checks the web client against vaultshare.py, in both directions.

    python crosscheck.py check FILE          open what the client made (web/scripts/crosscheck.ts generate)
    python crosscheck.py generate FILE       make shares for the client to open (crosscheck.ts check)
    python crosscheck.py vectors FILE        write the fixed vectors of vectors.py
    python crosscheck.py check-vectors FILE  confirm FILE is what vectors.py writes, and passes

The first two files have the same shape: {"cases": [...], "wraps": [...]}, bytes in hex.
"""

import json
import os
import sys
import unicodedata

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import vaultshare as vs
import vectors

SIZES = [0, 1, vs.DATA - 1, vs.DATA, vs.DATA + 1, 2 * vs.DATA, 200_000]
NAME = "résumé 2026.pdf"
PASSWORD = "café horse 8chars"


def check_recorded() -> None:
    """The known answers in web/src/crypto/vectors.test.ts and password.test.ts,
    which the client generated itself, reproduced here independently."""
    file_key, meta_key, auth_key = vs.derive_keys(bytes(range(16)))
    assert file_key.hex() == "fd1e0811baf46a987bdd9be4c76d1f51f21655fcfe24e1291caff295373537aa"
    assert auth_key.hex() == "066df9b8e3e442ba85cedc1cfd5f77f76ff7d1068af2cffb5554ef5e95a65f8b"
    salt = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    body = vs.encrypt_body(file_key, b"vault-share", salt)
    assert body.hex() == salt.hex() + "00010000" + "00" + "b4d14b1186d9707199353fb3d115fbe362dd96edc66e93dc8bf28ba3"
    sealed = AESGCM(meta_key).encrypt(bytes.fromhex("a0a1a2a3a4a5a6a7a8a9aaab"), b'{"name":"a","type":"b","size":1}', None)
    assert sealed.hex() == (
        "8c0163137552505d5352d1ead9d3b53c2af5ccf07723b039de74e11d079269f36d3fb04c41bc288c30776528a2551726"
    )
    legacy = bytes.fromhex(
        "917e83a7c3568b5e021ad6f62ee03b445a45b0dbdd7c025fa6d619af6bca29aaf55d798c834af312bfe095838bfeac268d183d2e546c7acd6214f5c5"
    )
    assert vs.unwrap_secret(legacy, "pw").hex() == "00112233445566778899aabbccddeeff"
    print("recorded vectors: file, auth and metadata keys, a body and a wrapped secret reproduced")


def rejects(file_key: bytes, body: bytes) -> bool:
    try:
        vs.decrypt_body(file_key, body)
    except vs.FormatError:
        return True
    return False


def check(path: str) -> None:
    check_recorded()
    with open(path) as f:
        data = json.load(f)
    assert len(data["cases"]) == len(SIZES) and len(data["wraps"]) == 2
    for case in data["cases"]:
        file_key, meta_key, auth_key = vs.derive_keys(bytes.fromhex(case["secret"]))
        body, plain = bytes.fromhex(case["body"]), bytes.fromhex(case["plain"])
        assert auth_key.hex() == case["authKey"], "auth key"
        assert len(plain) == case["size"]
        assert vs.decrypt_body(file_key, body) == plain, "body"
        meta = vs.decrypt_metadata(meta_key, bytes.fromhex(case["meta"]))
        assert meta == {"name": case["name"], "type": case["type"], "size": case["size"]}, "metadata"
        assert (len(case["meta"]) // 2 - 28) % vs.META_PAD == 0, "metadata padding"
        assert vs.sign_challenge(auth_key, bytes.fromhex(case["challenge"])).hex() == case["sig"], "signature"
        changed = bytearray(body)
        changed[-1] ^= 1
        assert rejects(file_key, bytes(changed)), "a changed last byte was accepted"
        records = -(-(len(body) - vs.HEADER) // vs.RS)
        if records > 1:
            assert rejects(file_key, body[: vs.HEADER + (records - 1) * vs.RS]), "a cut body was accepted"
        print(f"size {case['size']}: {records} record(s), body, metadata, auth key and signature match; damage rejected")
    for wrap in data["wraps"]:
        secret = vs.unwrap_secret(bytes.fromhex(wrap["wrapped"]), wrap["password"])
        assert secret is not None and secret.hex() == wrap["secret"], "wrapped secret"
    print(f"{len(data['wraps'])} wrapped secrets open with their passwords")


def generate(path: str) -> None:
    cases = []
    for size in SIZES:
        secret, salt, plain = os.urandom(16), os.urandom(16), os.urandom(size)
        file_key, meta_key, auth_key = vs.derive_keys(secret)
        challenge = os.urandom(32)
        meta = {"name": NAME, "type": "application/pdf", "size": size}
        cases.append(
            {
                "secret": secret.hex(),
                "authKey": auth_key.hex(),
                "body": vs.encrypt_body(file_key, plain, salt).hex(),
                "plain": plain.hex(),
                "meta": vs.encrypt_metadata(meta_key, meta, os.urandom(12)).hex(),
                **meta,
                "challenge": challenge.hex(),
                "sig": vs.sign_challenge(auth_key, challenge).hex(),
            }
        )
    wraps = []
    for form in ("NFC", "NFD"):
        secret, password = os.urandom(16), unicodedata.normalize(form, PASSWORD)
        wrapped = vs.wrap_secret(secret, password, os.urandom(16), os.urandom(12))
        wraps.append({"password": password, "wrapped": wrapped.hex(), "secret": secret.hex()})
    with open(path, "w") as f:
        json.dump({"cases": cases, "wraps": wraps}, f)
    print(f"wrote {len(cases)} shares and {len(wraps)} wrapped secrets to {path}")


def write_vectors(path: str) -> None:
    with open(path, "w") as f:
        json.dump(vectors.build(), f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"wrote {path}")


if __name__ == "__main__":
    commands = {"check": check, "generate": generate, "vectors": write_vectors, "check-vectors": vectors.check}
    if len(sys.argv) != 3 or sys.argv[1] not in commands:
        sys.exit(__doc__)
    commands[sys.argv[1]](sys.argv[2])
