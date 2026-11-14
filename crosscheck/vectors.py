"""Fixed vectors for the share format (testdata/share_format_test.json), in
the style of Wycheproof's chunked-encryption vectors: valid boundary cases
and malformed streams, each with the plaintext a streaming decrypter may
release before it fails.

Records are built with raw AES-256-GCM rather than with vaultshare's
encrypter, so a stream can be wrong on purpose. Each record's data is the
GCM keystream at its position, which makes its ciphertext zero bytes but
for the delimiter, the padding and the tag; the ciphertext is stored zlib
compressed, as Wycheproof's CompressedHexBytes, and stays small even for
257 records."""

import hashlib
import zlib

import vaultshare as vs

SECRET = bytes(range(16))

NOTES = {
    "EmptyFinal": "The last record holds no data, after full records. RFC 8188 allows it, so another encoder may write it.",
    "Padding": "Zero bytes after the delimiter are padding (RFC 8188) and are removed.",
    "CounterRollover": "More than 256 records: the index XORed into the nonce reaches its next byte.",
    "HeaderFailure": "The header is cut, missing, or names a record size other than 65536 or a key id. It must be refused before any record is decrypted.",
    "Truncation": "The stream is cut: no last record, or a record or tag cut short.",
    "TrailingData": "Bytes follow the last record: garbage, or another validly encrypted record.",
    "Delimiter": "A record has the delimiter of another position, no delimiter, or a non-zero byte after it.",
    "ChunkReordering": "Records are swapped, repeated or dropped. The index in each nonce must make decryption fail.",
    "ModifiedCiphertext": "A byte of the header salt, a record or a tag is changed.",
    "WrongKey": "A valid stream opened with another secret.",
    "PartialPlaintext": (
        "The stream starts with valid records, whose data msgLength and msgSha256 describe. A streaming decrypter "
        "may release that prefix before it fails, never more, and must keep failing if read again."
    ),
}


class Stream:
    """Builds the records of one vector under the vector's own header salt."""

    def __init__(self, tc_id: int, secret: bytes = SECRET):
        self.salt = hashlib.sha256(b"vault-share vector %d" % tc_id).digest()[:16]
        file_key = vs.derive_keys(secret)[0]
        self.aead, self.nonce_base = vs.record_keys(file_key, self.salt)

    def header(self, rs: int = vs.RS, key_id: bytes = b"") -> bytes:
        return self.salt + rs.to_bytes(4, "big") + bytes([len(key_id)]) + key_id

    def record(self, seq: int, size: int, tail: bytes) -> tuple[bytes, bytes]:
        """Data of `size` bytes followed by `tail` (delimiter and padding),
        sealed under the nonce of record `seq`. Returns (data, record)."""
        nonce = vs.record_nonce(self.nonce_base, seq)
        data = self.aead.encrypt(nonce, bytes(size), None)[:size]
        return data, self.aead.encrypt(nonce, data + tail, None)

    def full(self, seq: int, delimiter: int = 1) -> tuple[bytes, bytes]:
        return self.record(seq, vs.DATA, bytes([delimiter]))

    def body(self, sizes: list[int]) -> tuple[list[bytes], list[bytes]]:
        """A valid stream: full records for every size but the last."""
        built = [self.record(seq, size, b"\x02" if seq == len(sizes) - 1 else b"\x01") for seq, size in enumerate(sizes)]
        return [d for d, _ in built], [r for _, r in built]


def sizes_for(length: int) -> list[int]:
    full, rest = divmod(length, vs.DATA)
    return [vs.DATA] * full + [rest] if rest or not full else [vs.DATA] * full


def cases():
    """(comment, flags, secret, ct, prefix): prefix is the data of the records
    a decrypter may release; for a valid vector it is the whole file."""
    tc = iter(range(1, 1000))

    def valid(comment, length, flags=()):
        s = Stream(next(tc))
        data, records = s.body(sizes_for(length))
        return comment, list(flags), SECRET, s.header() + b"".join(records), data, "valid"

    yield valid("empty file", 0)
    yield valid("one byte", 1)
    yield valid("one short record", vs.DATA - 1)
    yield valid("one full-size last record", vs.DATA)
    yield valid("a full record and a one-byte last record", vs.DATA + 1)
    yield valid("two full records, the second last", 2 * vs.DATA)
    yield valid("four records", 200_000)
    yield valid("257 records", 256 * vs.DATA + 1, ["CounterRollover"])

    s = Stream(next(tc))
    d0, r0 = s.full(0)
    d1, r1 = s.record(1, 0, b"\x02")
    yield "a full record and an empty last record", ["EmptyFinal"], SECRET, s.header() + r0 + r1, [d0, d1], "valid"

    s = Stream(next(tc))
    d0, r0 = s.record(0, 5, b"\x02" + bytes(10))
    yield "last record padded with zeros", ["Padding"], SECRET, s.header() + r0, [d0], "valid"

    def invalid(comment, flags, ct, prefix, secret=SECRET):
        if prefix:
            flags = flags + ["PartialPlaintext"]
        return comment, flags, secret, ct, prefix, "invalid"

    s = Stream(next(tc))
    yield invalid("empty body", ["HeaderFailure", "Truncation"], b"", [])
    yield invalid("header cut to 20 bytes", ["HeaderFailure", "Truncation"], s.header()[:20], [])
    yield invalid("header only, no records", ["HeaderFailure", "Truncation"], s.header(), [])

    s = Stream(next(tc))
    _, records = s.body([1])
    yield invalid("record size 4096 in the header", ["HeaderFailure"], s.header(rs=4096) + records[0], [])
    yield invalid("a key id in the header", ["HeaderFailure"], s.header(key_id=b"a") + records[0], [])

    s = Stream(next(tc))
    salt_changed = bytearray(s.header())
    salt_changed[0] ^= 1
    _, records = s.body([1])
    yield invalid("changed header salt", ["ModifiedCiphertext"], bytes(salt_changed) + records[0], [])

    s = Stream(next(tc))
    data, records = s.body([vs.DATA, vs.DATA, 7])
    yield invalid("cut before the last record", ["Truncation", "Delimiter"], s.header() + b"".join(records[:2]), data[:1])
    yield invalid("one full record that is not last", ["Truncation", "Delimiter"], s.header() + records[0], [])
    cut = s.header() + records[0] + records[1][: len(records[1]) // 2]
    yield invalid("second record cut in the middle", ["Truncation"], cut, data[:1])

    s = Stream(next(tc))
    _, records = s.body([10])
    yield invalid("last tag cut by one byte", ["Truncation"], s.header() + records[0][:-1], [])
    yield invalid("record shorter than a tag", ["Truncation"], s.header() + records[0][:10], [])

    s = Stream(next(tc))
    d0, r0 = s.full(0, delimiter=2)
    _, r1 = s.record(1, 3, b"\x02")
    yield invalid("two last records", ["Delimiter"], s.header() + r0 + r1, [])

    s = Stream(next(tc))
    d0, r0 = s.full(0)
    _, r1 = s.record(1, 3, b"\x02\x05")
    yield invalid("non-zero byte after the last delimiter", ["Delimiter"], s.header() + r0 + r1, [d0])
    _, r1 = s.record(1, 0, bytes(10))
    yield invalid("last record without a delimiter", ["Delimiter"], s.header() + r0 + r1, [d0])

    s = Stream(next(tc))
    data, records = s.body([vs.DATA, 9])
    yield invalid("garbage after a short last record", ["TrailingData"], s.header() + b"".join(records) + bytes(20), data[:1])
    s = Stream(next(tc))
    data, records = s.body([vs.DATA, vs.DATA])
    _, extra = s.record(2, 4, b"\x02")
    yield invalid(
        "a valid record after a full-size last record", ["TrailingData", "Delimiter"], s.header() + b"".join(records) + extra, data[:1]
    )
    yield invalid("garbage after a full-size last record", ["TrailingData", "Delimiter"], s.header() + b"".join(records) + bytes(5), data[:1])

    s = Stream(next(tc))
    data, records = s.body([vs.DATA, vs.DATA, 7])
    yield invalid("first two records swapped", ["ChunkReordering"], s.header() + records[1] + records[0] + records[2], [])
    yield invalid("first record repeated", ["ChunkReordering"], s.header() + records[0] + records[0] + records[2], data[:1])
    yield invalid("middle record dropped", ["ChunkReordering"], s.header() + records[0] + records[2], data[:1])
    changed = bytearray(records[1])
    changed[100] ^= 1
    yield invalid("changed byte in the second record", ["ModifiedCiphertext"], s.header() + records[0] + bytes(changed) + records[2], data[:1])
    changed = bytearray(records[2])
    changed[-1] ^= 1
    yield invalid("changed byte in the last tag", ["ModifiedCiphertext"], s.header() + records[0] + records[1] + bytes(changed), data[:2])

    s = Stream(next(tc))
    _, records = s.body([10])
    yield invalid("opened with another secret", ["WrongKey"], s.header() + records[0], [], secret=bytes(range(1, 17)))


def build() -> dict:
    tests = []
    for tc_id, (comment, flags, secret, ct, prefix, result) in enumerate(cases(), 1):
        msg = b"".join(prefix)
        tests.append(
            {
                "tcId": tc_id,
                "comment": comment,
                "flags": flags,
                "secret": secret.hex(),
                "ct": zlib.compress(ct, 9).hex(),
                "msgLength": len(msg),
                "msgSha256": hashlib.sha256(msg).hexdigest(),
                "result": result,
            }
        )
    return {
        "algorithm": "vault-share file format (D012)",
        "header": [
            "Generated by crosscheck/vectors.py. ct is zlib-compressed hex (Wycheproof CompressedHexBytes).",
            "Valid vectors decrypt to msgLength bytes with SHA-256 msgSha256; invalid ones must fail.",
        ],
        "notes": NOTES,
        "numberOfTests": len(tests),
        "testGroups": [{"type": "ShareFormatTest", "tests": tests}],
    }


def check(path: str) -> None:
    """The file must be what build() makes, and vaultshare must pass it."""
    import json

    with open(path) as f:
        stored = json.load(f)
    built = build()
    for test in stored["testGroups"][0]["tests"] + built["testGroups"][0]["tests"]:
        test["ct"] = zlib.decompress(bytes.fromhex(test["ct"])).hex()
    if stored != built:
        raise SystemExit(f"{path} differs from what vectors.py builds")
    for test in built["testGroups"][0]["tests"]:
        file_key = vs.derive_keys(bytes.fromhex(test["secret"]))[0]
        released = []
        try:
            for data in vs.decrypt_records(file_key, bytes.fromhex(test["ct"])):
                released.append(data)
            failed = False
        except vs.FormatError:
            failed = True
        msg = b"".join(released)
        if failed != (test["result"] == "invalid") or hashlib.sha256(msg).hexdigest() != test["msgSha256"]:
            raise SystemExit(f"tcId {test['tcId']} ({test['comment']}): vaultshare disagrees")
    print(f"{path}: {len(built['testGroups'][0]['tests'])} vectors, as built, and vaultshare passes them")
