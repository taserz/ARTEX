#!/usr/bin/env python3
"""Create, verify, and restore a quiesced ARTEX Compose backup."""

import argparse
import base64
import binascii
import hashlib
import hmac
import io
import json
import os
import shutil
import stat
import sys
import tarfile
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath

from verified_backup_compose import BackupError, Compose


DATABASE = "database.dump"
RUNTIME = "runtime.tar.gz"
MANIFEST = "manifest.json"
RESTORE_MARKER = ".artex-restore-in-progress"
FORMAT = 1
CHUNK = 1024 * 1024
KEY_LIMIT = 4096
KEYS = ("keys/jwt.key", "keys/secret.key")


def private_file(path):
    return os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600), "wb")


def key_bytes(value):
    value = value.strip()
    for decode in (lambda data: base64.b64decode(data, validate=True), binascii.unhexlify):
        try:
            key = decode(value)
        except (ValueError, binascii.Error):
            continue
        if len(key) == 32:
            return key
    raise BackupError("the ARTEX encryption key must be 32 bytes encoded as base64 or hex")


def check_keys(keys):
    if set(keys) != set(KEYS) or len(keys[KEYS[0]].strip()) < 32:
        raise BackupError("backup requires a valid jwt.key and the active ARTEX encryption key")
    return key_bytes(keys[KEYS[1]])


def fingerprint(path):
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as source:
        for block in iter(lambda: source.read(CHUNK), b""):
            size += len(block)
            digest.update(block)
    return {"bytes": size, "sha256": digest.hexdigest()}


class FingerprintedReader:
    def __init__(self, source):
        self.source = source
        self.digest = hashlib.sha256()
        self.size = 0

    def read(self, size=-1):
        block = self.source.read(size)
        self.size += len(block)
        self.digest.update(block)
        return block


@contextmanager
def verified_input(path, expected):
    with path.open("rb") as original:
        source = FingerprintedReader(original)
        yield source
        # A tar reader can stop before the compressed file's last byte.
        while source.read(CHUNK):
            pass
        if {"bytes": source.size, "sha256": source.digest.hexdigest()} != expected:
            raise BackupError(f"backup size or SHA-256 mismatch: {path.name}")


def file_kind(path):
    info = path.lstat()
    attrs = getattr(info, "st_file_attributes", 0)
    if attrs & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0):
        raise BackupError(f"unsupported linked file: {path}")
    if stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode):
        return info
    raise BackupError(f"backup requires regular files and directories: {path}")


def archive_runtime(path, roots, override):
    def add(archive, source, name):
        info = file_kind(source)
        entry = archive.gettarinfo(str(source), arcname=name)
        if stat.S_ISDIR(info.st_mode):
            archive.addfile(entry)
            for child in sorted(source.iterdir()):
                if not (override and name == "keys" and child.name == "secret.key"):
                    add(archive, child, f"{name}/{child.name}")
        else:
            with source.open("rb") as original:
                archive.addfile(entry, original)

    with private_file(path) as output, tarfile.open(fileobj=output, mode="w:gz", dereference=True) as archive:
        for name, root in sorted(roots.items()):
            if not root.exists() or not stat.S_ISDIR(file_kind(root).st_mode):
                raise BackupError(f"required runtime directory is missing: {root}")
            add(archive, root, name)
        if override:
            key = base64.b64encode(key_bytes(override)) + b"\n"
            entry = tarfile.TarInfo("keys/secret.key")
            entry.mode = 0o600
            entry.size = len(key)
            owner = roots["keys"].stat()
            entry.uid, entry.gid = owner.st_uid, owner.st_gid
            archive.addfile(entry, io.BytesIO(key))


def archive_parts(name, roots):
    parts = name.split("/")
    if parts[0] not in roots or any(
        part in ("", ".", "..") or "\\" in part or ":" in part or "\x00" in part
        or PureWindowsPath(part).is_reserved() or part.endswith((".", " "))
        for part in parts
    ):
        raise BackupError(f"unsafe backup archive path: {name!r}")
    return parts


def apply_metadata(path, entry):
    if hasattr(os, "chown"):
        current = path.stat()
        if (current.st_uid, current.st_gid) != (entry.uid, entry.gid):
            os.chown(path, entry.uid, entry.gid)
    mode = entry.mode & (0o3777 if entry.isdir() else 0o777)
    if entry.name == "keys":
        mode = 0o700
    if entry.name in KEYS:
        mode = 0o600
    os.chmod(path, mode)
    os.utime(path, (entry.mtime, entry.mtime))


def inspect_runtime(path, roots, expected, destination=None):
    """Check tar members without following links, optionally staging their data."""
    directories = set()
    names = set()
    metadata = []
    keys = {}
    with verified_input(path, expected) as source, tarfile.open(fileobj=source, mode="r|gz") as archive:
        for entry in archive:
            parts = archive_parts(entry.name, roots)
            name = "/".join(parts)
            portable_name = name.casefold() if os.name == "nt" else name
            if portable_name in names or (len(parts) > 1 and "/".join(parts[:-1]) not in directories):
                raise BackupError(f"duplicate archive path or missing parent: {name!r}")
            names.add(portable_name)
            if not (entry.isdir() or entry.isfile()) or (len(parts) == 1 and not entry.isdir()):
                raise BackupError(f"unsupported archive entry: {name!r}")
            output = destination.joinpath(*parts) if destination is not None else None
            if entry.isdir():
                directories.add(name)
                if output is not None:
                    output.mkdir(mode=0o700)
                    metadata.append((output, entry))
                continue
            if name in KEYS:
                if entry.size > KEY_LIMIT:
                    raise BackupError("a backup key file is too large")
                with archive.extractfile(entry) as key:
                    keys[name] = key.read()
            if output is not None:
                with private_file(output) as restored:
                    if name in keys:
                        restored.write(keys[name])
                    else:
                        with archive.extractfile(entry) as original:
                            shutil.copyfileobj(original, restored, CHUNK)
                apply_metadata(output, entry)
    if not set(roots).issubset(directories):
        raise BackupError("runtime archive is missing required directories")
    key = check_keys(keys)
    for output, entry in reversed(metadata):
        apply_metadata(output, entry)
    return key


def verify_bundle(bundle):
    for name in (MANIFEST, DATABASE, RUNTIME):
        if not stat.S_ISREG(file_kind(bundle / name).st_mode):
            raise BackupError(f"backup component is not a regular file: {name}")
    with (bundle / MANIFEST).open("rb") as source:
        content = source.read(CHUNK + 1)
    if len(content) > CHUNK:
        raise BackupError("backup manifest is too large")
    manifest = json.loads(content)
    if not isinstance(manifest, dict) or manifest.get("format") != FORMAT:
        raise BackupError("unsupported backup manifest format")
    roots = manifest.get("runtime_roots")
    if roots not in (["data", "keys"], ["data", "keys", "skills"]):
        raise BackupError("invalid backup runtime directories")
    major = manifest.get("postgres_major")
    if type(major) is not int or major < 10:
        raise BackupError("invalid backup PostgreSQL version")
    files = manifest.get("files")
    if not isinstance(files, dict) or set(files) != {DATABASE, RUNTIME}:
        raise BackupError("backup manifest is missing required files")
    with verified_input(bundle / DATABASE, files[DATABASE]) as dump:
        if dump.read(5) != b"PGDMP":
            raise BackupError("backup database is not a PostgreSQL custom-format dump")
    inspect_runtime(bundle / RUNTIME, roots, files[RUNTIME])
    return manifest


def require_new_path(path):
    if path.exists() or path.is_symlink():
        raise BackupError(f"refusing to overwrite existing path: {path}")


def write_backup(compose, bundle):
    roots = compose.runtime_roots()
    for root in roots.values():
        if bundle.is_relative_to(root):
            raise BackupError("put the bundle outside the runtime directories it backs up")
    require_new_path(bundle)
    compose.require_quiescent()
    override = compose.source_secret_override().strip()
    major = compose.postgres_major()
    bundle.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".artex-backup-", dir=bundle.parent) as temp:
        staged = Path(temp)
        dump = staged / DATABASE
        with private_file(dump):
            pass
        compose.dump(dump)
        compose.validate_dump(dump)
        archive_runtime(staged / RUNTIME, roots, override)
        manifest = {
            "format": FORMAT,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "postgres_major": major,
            "runtime_roots": sorted(roots),
            "files": {name: fingerprint(staged / name) for name in (DATABASE, RUNTIME)},
        }
        with private_file(staged / MANIFEST) as output:
            output.write((json.dumps(manifest, indent=2) + "\n").encode("utf-8"))
        inspect_runtime(staged / RUNTIME, roots, manifest["files"][RUNTIME])
        compose.require_quiescent()
        if not hmac.compare_digest(override.encode(), compose.source_secret_override().strip().encode()):
            raise BackupError("the configured source encryption key changed during backup")
        require_new_path(bundle)
        staged.rename(bundle)


def restore_backup(compose, project, bundle):
    manifest = verify_bundle(bundle)
    roots = compose.runtime_roots()
    if sorted(roots) != manifest["runtime_roots"]:
        raise BackupError("target Compose runtime mounts do not match the backup")
    marker = project / RESTORE_MARKER
    require_new_path(marker)
    for root in roots.values():
        require_new_path(root)
    compose.require_quiescent()
    if compose.postgres_major() < manifest["postgres_major"]:
        raise BackupError("target PostgreSQL is older than the backup")
    compose.require_empty_database()

    with tempfile.TemporaryDirectory(prefix=".artex-restore-", dir=project) as temp:
        staged = Path(temp)
        dump = staged / DATABASE
        with verified_input(bundle / DATABASE, manifest["files"][DATABASE]) as source, private_file(dump) as output:
            shutil.copyfileobj(source, output, CHUNK)
        compose.validate_dump(dump)
        key = inspect_runtime(bundle / RUNTIME, roots, manifest["files"][RUNTIME], staged)
        override = compose.secret_override().strip()
        if override and not hmac.compare_digest(key_bytes(override), key):
            raise BackupError("target ARTEX_SECRET_KEY does not match the backup")
        for root in roots.values():
            root.parent.mkdir(parents=True, exist_ok=True)
        compose.require_quiescent()
        compose.require_empty_database()

        with private_file(marker) as marker_file:
            marker_file.write(b"Restore did not finish. Do not start ARTEX until recovery is verified.\n")
        published = []
        try:
            for name, root in sorted(roots.items()):
                require_new_path(root)
                (staged / name).rename(root)
                published.append((name, root))
            compose.restore(dump)
        except (Exception, KeyboardInterrupt):
            # A normal pg_restore error rolls back its single transaction. If
            # its outcome cannot be confirmed, retain files and the marker.
            try:
                compose.require_empty_database()
                for name, root in reversed(published):
                    root.rename(staged / name)
                marker.unlink()
            except (OSError, BackupError):
                print(f"restore status uncertain; leave ARTEX stopped and inspect {marker}", file=sys.stderr)
            raise
        marker.unlink()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    for action in ("backup", "verify", "restore"):
        sub = commands.add_parser(action)
        sub.add_argument("--bundle", type=Path, required=True, help="backup bundle directory")
        if action != "verify":
            sub.add_argument("--project-dir", type=Path, default=Path.cwd(), help="Compose project directory")
            sub.add_argument("--compose-file", action="append", default=[], help="Compose file, relative to project directory (repeatable)")
            sub.add_argument("--project-name", help="explicit Compose project name")
    args = parser.parse_args(argv)
    try:
        bundle = args.bundle.resolve()
        if args.action == "verify":
            verify_bundle(bundle)
            print(f"Bundle checksums, archive paths, and key formats verified: {bundle}")
        else:
            project = args.project_dir.resolve(strict=True)
            compose = Compose(project, args.compose_file, args.project_name)
            if args.action == "backup":
                write_backup(compose, bundle)
                print(f"Verified backup written: {bundle}")
            else:
                restore_backup(compose, project, bundle)
                print(f"Restore complete. PostgreSQL and runtime files restored to {project}.")
    except (BackupError, OSError, ValueError, EOFError, tarfile.TarError) as error:
        print(f"{args.action} failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
