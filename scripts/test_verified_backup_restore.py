#!/usr/bin/env python3
"""Run the verified backup drill against disposable PostgreSQL deployments.

Requires Docker Compose and the pinned PostgreSQL image. Both projects have
isolated databases and unexposed ports. The ARTEX service never starts.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import unittest
import uuid


SCRIPT = Path(__file__).with_name("verified_backup.py").resolve()
SCHEMA = SCRIPT.parent.parent / "db"
POSTGRES_IMAGE = "postgres:16-alpine@sha256:f2f98726820d0342055351c6e9d36e705f5bfffb3dd53ff556325114b08afb6d"
DB_USER = "drill_operator"
DB_NAME = "drill_store"
DB_PASSWORD = "local-disposable-restore-fixture"
JWT_KEY = b"0123456789abcdef0123456789abcdef"
SECRET_KEY = bytes(range(32))
CAPTURE_ID = "synthetic-saved-capture"
BODY = bytes(range(256)) * 64 + b"retained restore evidence"
BLOB_HASH = hashlib.sha256(BODY).hexdigest()
INDEX_PATH = Path("data/traffic/_index/index.sqlite")
BLOB_PATH = Path(f"data/traffic/_blobs/sha256/{BLOB_HASH[:2]}/{BLOB_HASH}.bin")
SKILL_PATH = Path("skills/local-notes/notes.txt")


class VerifiedBackupRestoreTest(unittest.TestCase):
    def setUp(self) -> None:
        self.env = {key: value for key, value in os.environ.items() if not key.upper().startswith("COMPOSE_")}
        self.temp = tempfile.TemporaryDirectory(prefix="artex-backup-drill-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.run_id = uuid.uuid4().hex[:16]

    def run_cmd(self, command: list[str], *, sql: str | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            command, input=sql, text=True, encoding="utf-8", errors="replace",
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self.env,
            cwd=self.root, timeout=180, check=False,
        )

    def passed(self, result: subprocess.CompletedProcess[str]) -> str:
        self.assertEqual(result.returncode, 0, f"{result.args!r}\n{result.stderr}\n{result.stdout}")
        return result.stdout.strip()

    def project(self, label: str) -> tuple[Path, str]:
        path = self.root / label
        path.mkdir()
        name = f"artex-backup-drill-{label}-{self.run_id}"
        config = {
            "services": {
                "postgres": {
                    "image": POSTGRES_IMAGE,
                    "environment": {
                        "POSTGRES_USER": DB_USER,
                        "POSTGRES_DB": DB_NAME,
                        "POSTGRES_PASSWORD": DB_PASSWORD,
                    },
                    "volumes": ["pgdata:/var/lib/postgresql/data"],
                    "healthcheck": {
                        "test": ["CMD", "pg_isready", "-h", "127.0.0.1", "-U", DB_USER, "-d", DB_NAME],
                        "interval": "1s",
                        "timeout": "2s",
                        "retries": 45,
                    },
                },
                "artex": {
                    "image": POSTGRES_IMAGE,
                    "environment": {
                        "ARTEX_PG_HOST": "postgres",
                        "ARTEX_PG_PORT": "5432",
                        "ARTEX_PG_USER": DB_USER,
                        "ARTEX_PG_DBNAME": DB_NAME,
                        "ARTEX_JWT_KEY_DIR": "/app/keys",
                    },
                    "volumes": ["./data:/app/data", "./keys:/app/keys", "./skills:/app/skills"],
                },
            },
            "volumes": {"pgdata": {}},
        }
        # JSON is a subset of YAML. Use absolute paths on the command line for
        # both creation and cleanup, with a distinct random project name.
        (path / "compose.yaml").write_text(json.dumps(config), encoding="utf-8")
        project = (path, name)
        self.addCleanup(self.cleanup_project, project)
        self.passed(self.compose(project, "up", "-d", "--wait", "--wait-timeout", "65", "postgres"))
        return project

    def compose(
        self, project: tuple[Path, str], *args: str, sql: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        path, name = project
        return self.run_cmd([
            "docker", "compose", "--project-directory", str(path), "--project-name", name,
            "--file", str(path / "compose.yaml"), *args,
        ], sql=sql)

    def cleanup_project(self, project: tuple[Path, str]) -> None:
        path, name = project
        if path.parent.resolve() != self.root or not name.endswith(self.run_id):
            raise RuntimeError(f"refusing to clean unrecognized drill project {name}")
        self.passed(self.compose(project, "down", "--volumes"))

    def query(self, project: tuple[Path, str], sql: str) -> str:
        return self.passed(self.compose(
            project, "exec", "-T", "postgres", "psql", "-X", "--no-password", "-qAt",
            "--set", "ON_ERROR_STOP=1", "-U", DB_USER, "-d", DB_NAME, sql=sql,
        ))

    def cli(self, action: str, bundle: Path, project: tuple[Path, str] | None = None) -> subprocess.CompletedProcess[str]:
        command = [sys.executable, str(SCRIPT), action, "--bundle", str(bundle)]
        if project is not None:
            path, name = project
            command.extend(["--project-dir", str(path), "--project-name", name])
        return self.run_cmd(command)

    def write_runtime_fixture(self, project: Path) -> None:
        blob = project / BLOB_PATH
        blob.parent.mkdir(parents=True)
        blob.write_bytes(BODY)
        notes = project / SKILL_PATH
        notes.parent.mkdir(parents=True)
        notes.write_bytes(b"Operator recovery reference fixture\n")
        keys = project / "keys"
        keys.mkdir(mode=0o700)
        for name, value in (
            ("jwt.key", JWT_KEY),
            ("secret.key", base64.b64encode(SECRET_KEY) + b"\n"),
        ):
            path = keys / name
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as output:
                output.write(value)

        # Copy a quiescent SQLite snapshot whose committed evidence exists only
        # in its WAL. Omitting the WAL still yields an openable but empty index.
        destination = project / INDEX_PATH
        destination.parent.mkdir(parents=True)
        scratch = self.root / "wal-fixture.sqlite"
        connection = sqlite3.connect(scratch)
        try:
            self.assertEqual(connection.execute("PRAGMA journal_mode=WAL").fetchone(), ("wal",))
            connection.execute("CREATE TABLE exchanges (id TEXT PRIMARY KEY, resp_blob TEXT NOT NULL)")
            connection.commit()
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            connection.execute("INSERT INTO exchanges VALUES (?, ?)", (CAPTURE_ID, BLOB_HASH))
            connection.commit()
            shutil.copyfile(scratch, destination)
            shutil.copyfile(Path(f"{scratch}-wal"), Path(f"{destination}-wal"))
        finally:
            connection.close()

    def test_clean_instance_restore(self) -> None:
        source = self.project("source")
        target = self.project("target")
        self.write_runtime_fixture(source[0])
        schema_files = [SCHEMA / "schema.sql", *sorted((SCHEMA / "migrations").glob("*.sql"))]
        self.query(source, "\n".join(path.read_text(encoding="utf-8") for path in schema_files))
        # pgcrypto supplies an independent decrypt-on-restore check. The drill
        # uses a known synthetic value, not any of the user's credentials.
        self.query(source, f"""
            CREATE EXTENSION pgcrypto;
            CREATE TABLE public.restore_drill_finding (
                id bigint PRIMARY KEY REFERENCES findings(id), capture_id text, blob_sha256 text, sealed bytea
            );
            WITH finding AS (
                INSERT INTO findings(name, severity, status)
                VALUES ('Restore drill finding', 'low', 'confirmed') RETURNING id
            )
            INSERT INTO public.restore_drill_finding
            SELECT id, '{CAPTURE_ID}', '{BLOB_HASH}',
                pgp_sym_encrypt('restored opaque fixture', '{SECRET_KEY.hex()}')
            FROM finding;
        """)

        backup = self.root / "backup"
        self.passed(self.cli("backup", backup, source))
        self.passed(self.cli("verify", backup))

        # The effective Compose key wins over any stale on-disk copy.
        config_file = source[0] / "compose.yaml"
        config = json.loads(config_file.read_text(encoding="utf-8"))
        config["services"]["artex"]["environment"]["ARTEX_SECRET_KEY"] = SECRET_KEY.hex()
        config_file.write_text(json.dumps(config), encoding="utf-8")
        self.passed(self.compose(source, "create", "artex"))
        config["services"]["artex"]["environment"]["ARTEX_SECRET_KEY"] = "ee" * 32
        config_file.write_text(json.dumps(config), encoding="utf-8")
        (source[0] / "keys/secret.key").write_text("ff" * 32, encoding="ascii")
        backup = self.root / "override-backup"
        self.passed(self.cli("backup", backup, source))
        self.passed(self.cli("verify", backup))

        damaged = self.root / "damaged-backup"
        shutil.copytree(backup, damaged)
        with (damaged / "database.dump").open("ab") as dump:
            dump.write(b"unexpected trailing bytes")
        self.assertNotEqual(self.cli("verify", damaged).returncode, 0)
        self.assertNotEqual(self.cli("restore", damaged, target).returncode, 0)
        self.assertEqual(self.query(target, "SELECT to_regclass('public.restore_drill_finding');"), "")
        self.assertFalse((target[0] / "data").exists())
        self.assertFalse((target[0] / "keys").exists())

        self.query(target, "CREATE TABLE public.already_present (v text); INSERT INTO public.already_present VALUES ('untouched');")
        self.assertNotEqual(self.cli("restore", backup, target).returncode, 0)
        self.assertEqual(self.query(target, "SELECT v FROM public.already_present;"), "untouched")
        self.assertFalse((target[0] / "data").exists())
        self.assertFalse((target[0] / "keys").exists())
        self.query(target, "DROP TABLE public.already_present;")

        target_config_file = target[0] / "compose.yaml"
        target_config = json.loads(target_config_file.read_text(encoding="utf-8"))
        target_env = target_config["services"]["artex"]["environment"]
        target_env["ARTEX_SECRET_KEY"] = "dd" * 32
        target_config_file.write_text(json.dumps(target_config), encoding="utf-8")
        mismatch = self.cli("restore", backup, target)
        self.assertNotEqual(mismatch.returncode, 0)
        self.assertIn("target ARTEX_SECRET_KEY does not match", mismatch.stderr)
        self.assertFalse((target[0] / "data").exists())
        self.assertEqual(self.query(target, "SELECT to_regclass('public.restore_drill_finding');"), "")
        del target_env["ARTEX_SECRET_KEY"]
        target_config_file.write_text(json.dumps(target_config), encoding="utf-8")

        self.passed(self.cli("restore", backup, target))
        restored_key = (target[0] / "keys/secret.key").read_text(encoding="ascii").strip()
        key_bytes = bytes.fromhex(restored_key) if len(restored_key) == 64 else base64.b64decode(restored_key, validate=True)
        self.assertEqual(key_bytes, SECRET_KEY)
        restored_jwt_key = (target[0] / "keys/jwt.key").read_bytes()
        self.assertEqual(hmac.digest(restored_jwt_key, b"restore drill", "sha256"), hmac.digest(JWT_KEY, b"restore drill", "sha256"))
        if os.name != "nt":
            for name in ("secret.key", "jwt.key"):
                self.assertEqual((target[0] / "keys" / name).stat().st_mode & 0o077, 0)

        row = self.query(target, f"""
            SELECT capture_id, blob_sha256, pgp_sym_decrypt(sealed, '{key_bytes.hex()}'), name, status
            FROM public.restore_drill_finding JOIN findings USING (id);
        """).split("|")
        self.assertEqual(row, [CAPTURE_ID, BLOB_HASH, "restored opaque fixture", "Restore drill finding", "confirmed"])
        index = target[0] / INDEX_PATH
        self.assertTrue(Path(f"{index}-wal").is_file())
        connection = sqlite3.connect(index)
        try:
            self.assertEqual(connection.execute("PRAGMA integrity_check").fetchone(), ("ok",))
            stored_hash = connection.execute("SELECT resp_blob FROM exchanges WHERE id=?", (row[0],)).fetchone()
            self.assertEqual(stored_hash, (row[1],))
        finally:
            connection.close()
        restored_blob = (target[0] / BLOB_PATH).read_bytes()
        self.assertEqual(hashlib.sha256(restored_blob).hexdigest(), row[1])
        self.assertEqual(restored_blob, BODY)
        self.assertEqual((target[0] / SKILL_PATH).read_bytes(), (source[0] / SKILL_PATH).read_bytes())
        print("Verified clean restore of PostgreSQL, SQLite WAL evidence, the linked blob, keys and mounted skills.", flush=True)

    def test_verify_rejects_unsafe_tar_members(self) -> None:
        for member_name, member_type in (("data/../../outside", tarfile.REGTYPE), ("data/link", tarfile.SYMTYPE)):
            with self.subTest(member=member_name):
                bundle = self.root / uuid.uuid4().hex
                bundle.mkdir()
                (bundle / "database.dump").write_bytes(b"PGDMP fixture")
                with tarfile.open(bundle / "runtime.tar.gz", "w:gz") as archive:
                    root = tarfile.TarInfo("data")
                    root.type = tarfile.DIRTYPE
                    archive.addfile(root)
                    member = tarfile.TarInfo(member_name)
                    member.type = member_type
                    member.linkname = "../../outside" if member.issym() else ""
                    archive.addfile(member)
                files = {}
                for name in ("database.dump", "runtime.tar.gz"):
                    content = (bundle / name).read_bytes()
                    files[name] = {"bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}
                manifest = {"format": 1, "runtime_roots": ["data", "keys"], "postgres_major": 16, "files": files}
                (bundle / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
                result = self.cli("verify", bundle)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("unsafe backup archive path" if member.isfile() else "unsupported archive entry", result.stderr)


if __name__ == "__main__":
    unittest.main()
