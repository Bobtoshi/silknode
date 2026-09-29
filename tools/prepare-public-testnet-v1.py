#!/usr/bin/env python3
"""Explicit Linux first-join preparation; no service installation or networking."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shlex
import shutil
import stat
import subprocess
import sys

GIB = 1024 ** 3
DOMAIN = "3e156fe886be5b82188b5af94f48e4dac0017a8c061298ae7d136438c3bc987e"
CA_SHA256 = "3b45cde0f3bd37920bd376d22e66f4039620b943d511da34daced606e0433d4a"
LEAF_SHA256 = "20f2e023298a8d59678ec63b22a4a6e11929de52300461a995d032a8c2dd480c"
PARAMETERS = (
    ("sapling-spend.params", 47_958_396,
     "8270785a1a0d0bc77196f000ee6d221c9c9894f55307bd9357c3f0105d31ca63991ab91324160d8f53e2bbd3c2633a6eb8bdf5205d822e7f3f73edac51b2b70c"),
    ("sapling-output.params", 3_592_860,
     "657e3d38dbb5cb5e7dd2970e8b03d69b4787dd907285b5a7f0790dcc8072f60bf593b32cc2d1c030e00ff5ae64bf84c5c3beb84ddc841d48264b4a171744d028"),
)


def regular_bytes(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        meta = os.fstat(source.fileno())
        if not stat.S_ISREG(meta.st_mode) or meta.st_size > limit:
            raise ValueError(f"not a bounded regular file: {path}")
        data = source.read(limit + 1)
        if len(data) != meta.st_size:
            raise ValueError(f"input changed length: {path}")
        return data


def create_file(path, data, mode=0o444, owner=None):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as output:
        output.write(data)
        if owner is not None:
            os.fchown(output.fileno(), owner.pw_uid, owner.pw_gid)
        os.fchmod(output.fileno(), mode)
        output.flush()
        os.fsync(output.fileno())


def fresh_destination(path):
    if not path.is_absolute() or path.name in ("", ".", "..") or ".." in path.parts:
        raise ValueError("destination must be a new absolute directory")
    parent = path.parent.resolve(strict=True)
    # A root-owned, non-writable parent (or root-owned sticky /tmp) protects the
    # new root-owned directory from rename/substitution during privileged setup.
    for ancestor in (parent, *parent.parents):
        meta = ancestor.stat()
        if meta.st_uid != 0 or (meta.st_mode & 0o022 and not meta.st_mode & stat.S_ISVTX):
            raise ValueError("destination ancestors must be root-owned and protected from replacement")
    destination = parent / path.name
    if not re.fullmatch(r"/[A-Za-z0-9_./-]+", str(destination)) or destination.parts[1] in ("home", "root"):
        raise ValueError("use a simple path outside protected home directories, e.g. /var/tmp/silknode-join-v1")
    if os.path.lexists(destination):
        raise ValueError("destination already exists; existing state is never reused or overwritten")
    return destination


def run_command(binary, config, data, owner, command, *extra):
    return [
        "sudo", "/usr/bin/systemd-run", "--wait", "--pipe", "--collect",
        "--service-type=exec", f"--uid={owner.pw_uid}", f"--gid={owner.pw_gid}",
        "-p", "MemoryMax=4G", "-p", "MemorySwapMax=0", "-p", "TasksMax=4",
        "-p", "CPUQuota=100%", "-p", "RuntimeMaxSec=900", "-p", "TimeoutStopSec=10",
        "-p", "NoNewPrivileges=yes", "-p", "CapabilityBoundingSet=",
        "-p", "PrivateDevices=yes", "-p", "ProtectSystem=strict",
        "-p", "ProtectHome=yes", "-p", f"ReadWritePaths={data}",
        "-p", "SocketBindDeny=any", "-p", "RestrictAddressFamilies=AF_INET AF_UNIX",
        "-p", "UMask=0077", "-p", "LimitCORE=0", "-p", "Restart=no",
        "--", str(binary), command, "--config", str(config), *extra,
    ]


def prepare(args):
    if sys.platform != "linux" or os.geteuid() != 0:
        raise ValueError("explicit Linux sudo/root preparation required; node commands run unprivileged")
    if not args.accept_public_zero_value:
        raise ValueError("--accept-public-zero-value is required; no real assets or transferable rewards")
    owner = pwd.getpwnam(args.owner)
    if owner.pw_uid == 0:
        raise ValueError("choose an existing non-root node owner")
    destination = fresh_destination(args.destination)
    commands = ["/usr/bin/fallocate", "/usr/sbin/mkfs.ext4", "/usr/bin/mount", "/usr/bin/systemd-run"]
    if not all(os.access(command, os.X_OK) for command in commands) or not Path("/sys/fs/cgroup/cgroup.controllers").is_file():
        raise ValueError("requires Linux cgroup v2, systemd, util-linux and e2fsprogs; no packages installed")
    capacity = args.store_gib * GIB
    if shutil.disk_usage(destination.parent).free < capacity + 4 * GIB + 256 * 1024 ** 2:
        raise ValueError("insufficient backing reservation plus 4 GiB host margin")
    binary = regular_bytes(args.binary, 128 * 1024 ** 2)
    if not binary.startswith(b"\x7fELF"):
        raise ValueError("binary must be your compiled Linux ELF, not a script or download URL")
    ca_text = regular_bytes(Path(__file__).resolve().parents[1] / "testnet/public-v1/ca.der.hex", 16384)
    if hashlib.sha256(bytes.fromhex(ca_text.decode().strip())).hexdigest() != CA_SHA256:
        raise ValueError("bootstrap CA does not match the reviewed byte pin")
    parameters = []
    for name, size, pin in PARAMETERS:
        contents = regular_bytes(args.parameters / name, size)
        if len(contents) != size or hashlib.blake2b(contents).hexdigest() != pin:
            raise ValueError(f"{name}: whole-file length/BLAKE2b pin mismatch")
        parameters.append((name, contents))

    # All read-only preflights precede any mutation. This mkdir is exclusive.
    destination.mkdir(mode=0o711)
    os.chmod(destination, 0o711)
    public = destination / "public"
    public.mkdir(mode=0o755)
    volume = destination / "volume"
    volume.mkdir(mode=0o755)
    margin = destination / "host-margin"
    margin.mkdir(mode=0o755)
    for path in (public, volume, margin):
        os.chmod(path, 0o755)
    image = destination / "store.ext4"
    create_file(image, b"", 0o600)
    subprocess.run([commands[0], "-l", str(capacity), str(image)], check=True, timeout=30)
    # Format only the freshly created regular file, never a supplied device.
    # Finish zeroing before reserving again: lazy inode initialization on a
    # loop mount can otherwise punch holes in the already reserved backing file.
    subprocess.run([commands[1], "-q", "-F", "-m", "0", "-E",
                    "nodiscard,lazy_itable_init=0,lazy_journal_init=0", str(image)], check=True, timeout=30)
    subprocess.run([commands[0], "--keep-size", "-l", str(capacity), str(image)], check=True, timeout=30)
    if image.stat().st_size != capacity or image.stat().st_blocks * 512 < capacity:
        raise ValueError("backing image was not physically reserved")
    subprocess.run([commands[2], "-o", "loop,nodev,nosuid,noexec", str(image), str(volume)], check=True, timeout=30)
    if volume.stat().st_dev == margin.stat().st_dev:
        raise ValueError("capped volume and host margin must be separate filesystems")
    data = volume / "node"
    for path in (data, data / "pins"):
        path.mkdir(mode=0o700)
        os.chown(path, owner.pw_uid, owner.pw_gid)
        os.chmod(path, 0o700)
    executable = public / "silk-f04-testnet"
    create_file(executable, binary, 0o555)
    create_file(public / "ca.der.hex", ca_text)
    for name, contents in parameters:
        create_file(public / name, contents)
    config = {
        "schema": "silknode-public-testnet-config-v1", "accept_public_zero_value": True,
        "domain": DOMAIN, "store": str(data / "store"), "retained_head": str(data / "pins/head"),
        "host_margin": str(margin), "spend_parameters": str(public / "sapling-spend.params"),
        "output_parameters": str(public / "sapling-output.params"), "seed": "152.53.113.247:28444",
        "ca_der_hex": str(public / "ca.der.hex"), "seed_certificate_sha256": LEAF_SHA256,
        "reward_owner": secrets.token_hex(32), "listen": None,
        "server_certificate_der": None, "server_key_pkcs8_der": None,
    }
    config_path = data / "config.json"
    create_file(config_path, (json.dumps(config, indent=2) + "\n").encode(), 0o600, owner)
    receipt = {"schema": "silknode-first-join-preparation-v1", "owner_uid": owner.pw_uid,
               "owner_gid": owner.pw_gid, "capacity_bytes": capacity,
               "binary_sha256": hashlib.sha256(binary).hexdigest(), "config": str(config_path),
               "commands": [run_command(executable, config_path, data, owner, c) for c in ("init", "sync")]}
    create_file(destination / "preparation.json", (json.dumps(receipt, indent=2) + "\n").encode(), 0o444)
    if shutil.disk_usage(margin).free < 4 * GIB:
        raise ValueError("host margin exhausted during preparation; no node was started")
    for path in (data / "pins", data, volume, public, margin, destination, destination.parent):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    if image.stat().st_blocks * 512 < capacity:
        raise ValueError("backing reservation was lost during preparation; no node was started")
    print(f"Prepared fresh valueless node at {destination}; no node/service/network action performed.")
    print(f"Binary SHA256: {receipt['binary_sha256']}")
    print("Run these separately, in order; no unbounded fallback if resource control fails:")
    for command in receipt["commands"]:
        print(shlex.join(command))
    print("Optional mining, only after successful sync:")
    print(shlex.join(run_command(executable, config_path, data, owner, "mine", "--count", "1")))
    print("After every node command has ended, optional unmount (retains all data):")
    print(shlex.join(["sudo", "/usr/bin/umount", "--", str(volume)]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", required=True, type=Path, help="NEW absolute directory under a protected root-owned parent")
    parser.add_argument("--owner", required=True, help="existing non-root Linux account")
    parser.add_argument("--binary", required=True, type=Path, help="binary built from this Git checkout")
    parser.add_argument("--parameters", required=True, type=Path, help="existing canonical ceremony files")
    parser.add_argument("--store-gib", type=int, choices=range(1, 17), default=4)
    parser.add_argument("--accept-public-zero-value", action="store_true")
    args = parser.parse_args()
    try:
        prepare(args)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        parser.exit(1, f"Preparation refused/incomplete: {error}. No existing state was overwritten. If created, retain and inspect {args.destination}; do not retry into it. No automatic cleanup or recovery.\n")


if __name__ == "__main__":
    main()
