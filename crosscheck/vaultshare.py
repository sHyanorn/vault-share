"""The vault-share share format, written from docs/SPEC.md section 4 and
docs/DECISIONS.md D012 and D019, with pyca/cryptography for the primitives."""

import hashlib
import hmac
import json

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

SECRET_LENGTH = 16
RS = 65536
TAG = 16
DATA = RS - TAG - 1  # file bytes in every record but the last
HEADER = 16 + 4 + 1
META_PAD = 1024
META_MAX = 4096 - 12 - TAG
WRAPPED_LENGTH = 16 + 12 + SECRET_LENGTH + TAG


class FormatError(ValueError):
    """A body, blob or wrapped secret that the format does not allow."""


def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    # An empty salt and no salt are the same in RFC 5869: HashLen zero bytes.
    return HKDF(hashes.SHA256(), length, salt or None, info).derive(ikm)


def derive_keys(secret: bytes) -> tuple[bytes, bytes, bytes]:
    """fileKey, metaKey and authKey of a share."""
    if len(secret) != SECRET_LENGTH:
        raise FormatError("secret must be 16 bytes")
    return tuple(hkdf(secret, b"", f"vault-share/{label}".encode(), 32) for label in ("file", "meta", "auth"))


def record_keys(file_key: bytes, salt: bytes) -> tuple[AESGCM, bytes]:
    cek = hkdf(file_key, salt, b"Content-Encoding: aes256gcm\x00", 32)
    nonce_base = hkdf(file_key, salt, b"Content-Encoding: nonce\x00", 12)
    return AESGCM(cek), nonce_base


def record_nonce(nonce_base: bytes, seq: int) -> bytes:
    """The nonce base with the record index XORed into its last four bytes."""
    last = int.from_bytes(nonce_base[8:], "big") ^ seq
    return nonce_base[:8] + last.to_bytes(4, "big")


def encrypt_body(file_key: bytes, plaintext: bytes, salt: bytes) -> bytes:
    """Header, then records of DATA bytes each; the last record, always present, is marked 2."""
    aead, nonce_base = record_keys(file_key, salt)
    chunks = [plaintext[i : i + DATA] for i in range(0, len(plaintext), DATA)] or [b""]
    out = [salt + RS.to_bytes(4, "big") + b"\x00"]
    for seq, chunk in enumerate(chunks):
        delimiter = b"\x02" if seq == len(chunks) - 1 else b"\x01"
        out.append(aead.encrypt(record_nonce(nonce_base, seq), chunk + delimiter, None))
    return b"".join(out)


def decrypt_records(file_key: bytes, body: bytes):
    """Yields the file data of each record once it is authenticated, the way
    a streaming client releases it; raises at the first record that fails."""
    if len(body) < HEADER:
        raise FormatError("truncated header")
    salt, rs, idlen = body[:16], int.from_bytes(body[16:20], "big"), body[20]
    if rs != RS or idlen != 0:
        raise FormatError("unsupported header")
    records = [body[i : i + RS] for i in range(HEADER, len(body), RS)]
    if not records:
        raise FormatError("no records")
    aead, nonce_base = record_keys(file_key, salt)
    for seq, record in enumerate(records):
        last = seq == len(records) - 1
        try:
            padded = aead.decrypt(record_nonce(nonce_base, seq), record, None)
        except InvalidTag:
            raise FormatError(f"record {seq} fails authentication") from None
        data = padded.rstrip(b"\x00")
        if not data or data[-1] != (2 if last else 1):
            raise FormatError(f"record {seq} has the wrong delimiter")
        yield data[:-1]


def decrypt_body(file_key: bytes, body: bytes) -> bytes:
    return b"".join(decrypt_records(file_key, body))


def encrypt_metadata(meta_key: bytes, meta: dict, iv: bytes) -> bytes:
    """iv | AES-256-GCM(JSON padded with spaces to a multiple of 1024 bytes, at most 4068)."""
    fields = {"name": meta["name"], "type": meta["type"], "size": meta["size"]}
    plain = json.dumps(fields, separators=(",", ":"), ensure_ascii=False).encode()
    padded = min(-(-len(plain) // META_PAD) * META_PAD, META_MAX)
    plain += b" " * max(0, padded - len(plain))
    return iv + AESGCM(meta_key).encrypt(iv, plain, None)


def decrypt_metadata(meta_key: bytes, blob: bytes) -> dict:
    try:
        return json.loads(AESGCM(meta_key).decrypt(blob[:12], blob[12:], None))
    except InvalidTag:
        raise FormatError("metadata fails authentication") from None


def sign_challenge(auth_key: bytes, challenge: bytes) -> bytes:
    return hmac.new(auth_key, challenge, hashlib.sha256).digest()


def _wrapping_key(password: str, salt: bytes) -> AESGCM:
    key = Argon2id(salt=salt, length=32, iterations=2, lanes=1, memory_cost=65536).derive(password.encode())
    return AESGCM(key)


def wrap_secret(secret: bytes, password: str, salt: bytes, iv: bytes) -> bytes:
    """salt | iv | AES-256-GCM(secret), with no associated data."""
    return salt + iv + _wrapping_key(password, salt).encrypt(iv, secret, None)


def unwrap_secret(wrapped: bytes, password: str) -> bytes | None:
    """The secret, or None for a wrong password."""
    if len(wrapped) != WRAPPED_LENGTH:
        raise FormatError("wrapped secret has the wrong length")
    try:
        return _wrapping_key(password, wrapped[:16]).decrypt(wrapped[16:28], wrapped[28:], None)
    except InvalidTag:
        return None
