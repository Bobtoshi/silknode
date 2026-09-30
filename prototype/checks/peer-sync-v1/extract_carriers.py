#!/usr/bin/env python3
"""Read-only intake of eight public carriers; retained metadata grants NO validity.

Use a frozen read-only backup, never open/recover a live node. The resulting bytes
must pass ordinary Node admission. No private note/proof generation or mining.
"""
import argparse
import hashlib
import json
import os
import stat
import struct


def bounded(path, cap):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1
        assert before.st_size <= cap
        chunks = []
        remaining = cap + 1
        while remaining:
            part = os.read(fd, min(remaining, 65536))
            if not part:
                break
            chunks.append(part)
            remaining -= len(part)
        value = b"".join(chunks)
        after = os.fstat(fd)
        assert (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                before.st_ctime_ns) == (after.st_dev, after.st_ino, after.st_size,
                after.st_mtime_ns, after.st_ctime_ns)
        assert len(value) == before.st_size
        return value
    finally:
        os.close(fd)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--baseline", required=True)
    p.add_argument("--baseline-sha256", required=True)
    p.add_argument("--backup", required=True)
    p.add_argument("--out", required=True)
    args = p.parse_args()
    for path in (args.baseline, args.backup, args.out):
        assert os.path.isabs(path) and os.path.realpath(path) == path
    baseline_bytes = bounded(args.baseline, 65536)
    assert hashlib.sha256(baseline_bytes).hexdigest() == args.baseline_sha256
    baseline = json.loads(baseline_bytes)
    assert baseline["domain"] == "3e156fe886be5b82188b5af94f48e4dac0017a8c061298ae7d136438c3bc987e"
    carriers = []
    for name, expected in baseline["entries"].items():
        if not name.startswith("store/") or not name.endswith(".obj"):
            continue
        basename = name.removeprefix("store/")
        assert len(basename) == 68 and all(c in "0123456789abcdef" for c in basename[:-4])
        value = bounded(os.path.join(args.backup, "store", basename), 8 * 1024 * 1024)
        assert len(value) == expected["size"]
        assert hashlib.sha256(value).hexdigest() == expected["sha256"] == basename[:-4]
        if value[:8] != b"SNF04VR1":
            continue
        length = struct.unpack("<I", value[8:12])[0]
        assert 680 <= length <= 90000 and len(value) >= 12 + length + 188
        carrier = value[12:12 + length]
        assert carrier[:12] == b"SLKMNDV4\0\x04\0\0"
        assert carrier[616:648].hex() == baseline["domain"]
        carriers.append(carrier)
    assert len(carriers) == 8
    # This exact existing linear fixture has strictly increasing timestamps.
    # Sorting is ONLY input order, not parent/work/clock/consensus acceptance.
    carriers.sort(key=lambda b: struct.unpack(">Q", b[456:464])[0])
    assert len({b[456:464] for b in carriers}) == 8
    frame = bytes([8]) + b"".join(struct.pack(">I", len(b)) + b for b in carriers)
    fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(frame)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        raise  # Preserve failed output, never silently overwrite or retry.
    print(json.dumps({"carriers": 8, "bytes": len(frame),
                      "sha256": hashlib.sha256(frame).hexdigest(),
                      "validity": "UNVERIFIED", "mining": False}))


if __name__ == "__main__":
    main()
