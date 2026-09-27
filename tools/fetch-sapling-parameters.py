#!/usr/bin/env python3
"""Explicit, pinned Sapling parameter acquisition; not needed for local-smoke."""

import argparse
import hashlib
import os
from pathlib import Path
import tempfile
import urllib.request


# Whole canonical ceremony files, matching silk-sapling-f04/src/parameters.rs.
# Upstream parameter bodies are not redistributed in this source package.
PARAMETERS = (
    (
        "sapling-spend.params",
        "https://download.z.cash/downloads/sapling-spend.params.part.1",
        47_958_396,
        "8270785a1a0d0bc77196f000ee6d221c9c9894f55307bd9357c3f0105d31ca63991ab91324160d8f53e2bbd3c2633a6eb8bdf5205d822e7f3f73edac51b2b70c",
    ),
    (
        "sapling-output.params",
        "https://download.z.cash/downloads/sapling-output.params.part.1",
        3_592_860,
        "657e3d38dbb5cb5e7dd2970e8b03d69b4787dd907285b5a7f0790dcc8072f60bf593b32cc2d1c030e00ff5ae64bf84c5c3beb84ddc841d48264b4a171744d028",
    ),
)


def fetch(destination: Path) -> None:
    # mkdir is exclusive: existing directories, files and symlinks all refuse.
    # Its parent must already exist. Never overwrite a user's parameter set.
    destination.mkdir(mode=0o700)
    with tempfile.TemporaryDirectory(prefix=".download-", dir=destination) as stage:
        for name, url, expected_size, expected_digest in PARAMETERS:
            total = 0
            digest = hashlib.blake2b(digest_size=64)
            request = urllib.request.Request(url, headers={"User-Agent": "SilkNode-parameter-fetch/1"})
            with urllib.request.urlopen(request, timeout=30) as response:
                if not response.geturl().startswith("https://"):
                    raise ValueError("refusing non-HTTPS parameter source")
                with (Path(stage) / name).open("xb") as output:
                    while chunk := response.read(min(64 * 1024, expected_size - total + 1)):
                        total += len(chunk)
                        if total > expected_size:
                            raise ValueError(f"{name}: length exceeds pin")
                        digest.update(chunk)
                        output.write(chunk)
                    output.flush()
                    os.fsync(output.fileno())
            if total != expected_size or digest.hexdigest() != expected_digest:
                raise ValueError(f"{name}: whole-file length/BLAKE2b-512 mismatch")
        # Publish only after BOTH files authenticate; link refuses any existing
        # destination. A filesystem error may leave one verified file, never an
        # unauthenticated file under a canonical parameter filename.
        for name, _, _, _ in PARAMETERS:
            os.link(Path(stage) / name, destination / name)
            print(f"verified: {name}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path, help="new directory under an existing parent")
    args = parser.parse_args()
    try:
        fetch(args.destination)
    except (OSError, ValueError) as error:
        parser.exit(1, f"Parameter acquisition refused: {error}. Existing files were not overwritten; inspect the requested directory before retrying.\n")


if __name__ == "__main__":
    main()
