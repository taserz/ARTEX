"""Docker Compose operations for verified local ARTEX backups."""

from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import re
import subprocess
from typing import BinaryIO


class BackupError(RuntimeError):
    """An operator-facing error safe to print without exposing credentials."""


@dataclass(frozen=True)
class _Layout:
    roots: dict[str, Path]
    pg_user: str
    pg_database: str
    secret_override: str = field(repr=False)


_RUNTIME_MOUNTS = {"/app/data": "data", "/app/keys": "keys", "/app/skills": "skills"}
_STOPPED_STATES = {"created", "exited", "dead"}


# Read credentials from the postgres container's existing environment. Supply
# the socket explicitly to keep inherited libpq configuration from changing the
# destination. The database name is checked below before reaching libpq.
_PG_ENV = (
    'unset PGSERVICE PGSERVICEFILE PGHOSTADDR PGPORT PGOPTIONS; '
    'user=${POSTGRES_USER:-postgres}; database=${POSTGRES_DB:-$user}; '
    'case "$database" in *"="*|postgresql://*|postgres://*) exit 2;; esac; '
)
_PG_ARGS = '--host=/var/run/postgresql --username="$user" --dbname="$database"'
_PSQL = _PG_ENV + 'exec psql --no-psqlrc --no-password --tuples-only --no-align -v ON_ERROR_STOP=1 ' + _PG_ARGS + ' "$@"'
_DUMP = _PG_ENV + 'exec pg_dump --no-password --format=custom ' + _PG_ARGS
_RESTORE = _PG_ENV + ('exec pg_restore --no-password --single-transaction --exit-on-error '
                      '--no-owner --no-privileges ' + _PG_ARGS)


# A freshly initialized PostgreSQL database has the standard schemas and
# PL/pgSQL. Schema dependencies catch public relations, types, functions and
# other objects without having to list each of their system catalogs.
_EMPTY_QUERY = """
SELECT NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname NOT IN ('pg_catalog','information_schema','public','pg_toast')
    UNION ALL
    SELECT 1 FROM pg_catalog.pg_depend WHERE refclassid='pg_catalog.pg_namespace'::pg_catalog.regclass
      AND refobjid='public'::pg_catalog.regnamespace
    UNION ALL SELECT 1 FROM pg_catalog.pg_extension WHERE extname <> 'plpgsql'
    UNION ALL SELECT 1 FROM pg_catalog.pg_largeobject_metadata
    UNION ALL SELECT 1 FROM pg_catalog.pg_foreign_server
    UNION ALL SELECT 1 FROM pg_catalog.pg_event_trigger
    UNION ALL SELECT 1 FROM pg_catalog.pg_publication
    UNION ALL SELECT 1 FROM pg_catalog.pg_subscription WHERE subdbid=(
        SELECT oid FROM pg_catalog.pg_database WHERE datname=pg_catalog.current_database()
    )
    UNION ALL SELECT 1 FROM pg_catalog.pg_prepared_xacts WHERE database=pg_catalog.current_database()
    UNION ALL SELECT 1 FROM pg_catalog.pg_stat_activity WHERE datname=pg_catalog.current_database()
      AND pid <> pg_catalog.pg_backend_pid() AND backend_type='client backend'
)
"""


class Compose:
    def __init__(self, project_dir: Path, compose_files: list[str], project_name: str | None):
        self._project_dir = project_dir.resolve()
        self._command = ["docker", "compose", "--project-directory", str(self._project_dir)]
        if project_name:
            self._command.extend(["--project-name", project_name])
        for compose_file in compose_files:
            self._command.extend(["--file", compose_file])
        self._layout: _Layout | None = None
        self._major: int | None = None

    def _run(
        self,
        args: list[str],
        action: str,
        *,
        source: BinaryIO | None = None,
        destination: BinaryIO | None = None,
        engine: bool = False,
    ) -> bytes:
        try:
            result = subprocess.run(
                [*(["docker"] if engine else self._command), *args],
                cwd=self._project_dir,
                stdin=source if source is not None else subprocess.DEVNULL,
                stdout=destination if destination is not None else subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        except OSError as exc:
            raise BackupError(f"could not {action}; check Docker Compose and the project directory") from exc
        if result.returncode != 0:
            # Compose config errors can echo secrets, and a failed restore can
            # echo SQL row content. Keep command output out of operator logs.
            raise BackupError(f"could not {action} (Docker Compose exited {result.returncode})")
        return result.stdout or b""

    def _load_layout(self, *, refresh: bool = False) -> _Layout:
        if self._layout is not None and not refresh:
            return self._layout
        raw = self._run(["config", "--format", "json"], "read Compose configuration")
        try:
            services = json.loads(raw)["services"]
            app = services["artex"]
            app_env = app["environment"]
            pg_env = services["postgres"]["environment"]
            pg_user = pg_env.get("POSTGRES_USER") or "postgres"
            pg_db = pg_env.get("POSTGRES_DB") or pg_user
            mounts = app["volumes"]
            override = app_env.get("ARTEX_SECRET_KEY") or ""
        except (AttributeError, KeyError, TypeError, UnicodeDecodeError, ValueError) as exc:
            raise BackupError("expected artex and postgres services in the Compose configuration") from exc
        self._check_app_environment(app_env, pg_user, pg_db)
        if app.get("command") is not None or app.get("entrypoint") is not None:
            raise BackupError("verified backups require the standard ARTEX Compose command and entrypoint")
        roots = self._mount_roots(mounts)
        if self._layout is not None and (roots, pg_user, pg_db) != (
            self._layout.roots, self._layout.pg_user, self._layout.pg_database,
        ):
            raise BackupError("Compose runtime mounts or PostgreSQL settings changed during backup")
        self._layout = _Layout(roots, pg_user, pg_db, override)
        return self._layout

    @staticmethod
    def _check_app_environment(app_env: dict[str, str], pg_user: str, pg_db: str) -> None:
        if (
            app_env.get("ARTEX_PG_DSN")
            or app_env.get("ARTEX_PG_HOST") != "postgres"
            or str(app_env.get("ARTEX_PG_PORT") or "5432") != "5432"
            or app_env.get("ARTEX_PG_USER") != pg_user
            or app_env.get("ARTEX_PG_DBNAME") != pg_db
            or pg_user.strip() != pg_user
            or pg_db.strip() != pg_db
            or app_env.get("ARTEX_JWT_KEY_DIR") != "/app/keys"
        ):
            raise BackupError("verified backups require the Compose postgres service and /app/keys")

    def _mount_roots(self, mounts: list[dict], *, inspected: bool = False) -> dict[str, Path]:
        roots: dict[str, Path] = {}
        for mount in mounts:
            target = (mount.get("Destination" if inspected else "target") or "").rstrip("/")
            label = _RUNTIME_MOUNTS.get(target)
            if label is None:
                if any(target.startswith(root + "/") or root.startswith(target + "/") for root in _RUNTIME_MOUNTS):
                    raise BackupError("additional mounts may not overlap ARTEX runtime bind mounts")
                continue
            source = mount.get("Source" if inspected else "source")
            if label in roots or mount.get("Type" if inspected else "type") != "bind" or not isinstance(source, str) or not source:
                raise BackupError(f"expected one host bind mount for /app/{label}")
            if inspected:
                source = self._inspected_source(source)
            roots[label] = self._runtime_path(source, label)
        if not {"data", "keys"}.issubset(roots):
            raise BackupError("verified backups require host bind mounts for /app/data and /app/keys")
        for name, path in roots.items():
            if any(path.is_relative_to(other) for other_name, other in roots.items() if other_name != name):
                raise BackupError("Compose runtime bind mounts must be distinct, non-overlapping directories")
        return roots

    @staticmethod
    def _inspected_source(source: str) -> str:
        if os.name == "nt":
            match = re.fullmatch(r"(?:/run/desktop/mnt/host|/host_mnt)/([A-Za-z])/(.+)", source)
            if match:
                source = match.group(1) + ":/" + match.group(2)
        if not Path(source).is_absolute():
            raise BackupError("could not match a stopped ARTEX container's bind mount to a host path")
        return source

    def _runtime_path(self, source: str, label: str) -> Path:
        path = self._project_dir / Path(source)
        if (
            path == self._project_dir
            or not path.is_relative_to(self._project_dir)
            or ".." in path.parts
            or path.resolve() != path
        ):
            raise BackupError(f"/app/{label} must be bound to a directory inside the Compose project without symlinks")
        for component in (path, *path.parents):
            if component == self._project_dir:
                break
            if component.is_symlink() or (component.exists() and not component.is_dir()):
                raise BackupError(f"/app/{label} must be bound to a directory inside the Compose project without symlinks")
        return path

    def runtime_roots(self) -> dict[str, Path]:
        return self._load_layout().roots.copy()

    def secret_override(self) -> str:
        return self._load_layout().secret_override

    def require_quiescent(self) -> None:
        self._load_layout()
        self._stopped_app_containers()

    def _stopped_app_containers(self) -> list[dict]:
        raw = self._run(["ps", "--all", "--format", "json", "artex"], "check whether ARTEX is stopped")
        try:
            # Compose releases have used both a JSON array and one object per
            # line for this output. An empty result means no ARTEX container.
            if raw.lstrip().startswith(b"["):
                rows = json.loads(raw)
            else:
                rows = [json.loads(line) for line in raw.splitlines() if line.strip()]
            stopped = all(row["State"] in _STOPPED_STATES for row in rows)
        except (KeyError, TypeError, UnicodeDecodeError, ValueError) as exc:
            raise BackupError("could not determine whether ARTEX is stopped") from exc
        if not stopped:
            raise BackupError("stop the ARTEX Compose service and all other ARTEX writers before continuing")
        return rows

    def source_secret_override(self) -> str:
        """Check the stopped containers' actual runtime and read their active key."""
        layout = self._load_layout(refresh=True)
        rows = self._stopped_app_containers()
        if not rows:
            return layout.secret_override
        ids = [row.get("ID") for row in rows]
        if any(not isinstance(cid, str) or not re.fullmatch(r"[0-9a-f]{12,64}", cid) for cid in ids):
            raise BackupError("could not identify the stopped ARTEX containers")
        raw = self._run(["inspect", "--type", "container", *ids], "inspect the stopped ARTEX containers", engine=True)
        keys = set()
        try:
            containers = json.loads(raw)
            if len(containers) != len(ids):
                raise BackupError("the stopped ARTEX containers changed during backup")
            for container in containers:
                state = container["State"]
                if state["Status"] not in _STOPPED_STATES or any(state.get(flag) for flag in ("Running", "Paused", "Restarting")):
                    raise BackupError("stop the ARTEX Compose service and all other ARTEX writers before continuing")
                env = {}
                for variable in container["Config"]["Env"]:
                    name, _, value = variable.partition("=")
                    if name in env and env[name] != value:
                        raise BackupError("the stopped ARTEX container has conflicting environment settings")
                    env[name] = value
                self._check_app_environment(env, layout.pg_user, layout.pg_database)
                if self._mount_roots(container["Mounts"], inspected=True) != layout.roots:
                    raise BackupError("the stopped ARTEX container's bind mounts do not match the Compose settings")
                keys.add(env.get("ARTEX_SECRET_KEY", ""))
        except (AttributeError, KeyError, TypeError, UnicodeDecodeError, ValueError) as exc:
            raise BackupError("could not determine the stopped ARTEX container runtime") from exc
        if len(keys) != 1:
            raise BackupError("the stopped ARTEX containers disagree on the active encryption key")
        return keys.pop()

    def _psql(self, query: str, action: str) -> bytes:
        return self._run(["exec", "-T", "postgres", "sh", "-c", _PSQL, "sh", "-c", query], action).strip()

    def postgres_major(self) -> int:
        if self._major is not None:
            return self._major
        layout = self._load_layout()
        raw = self._psql(
            "SELECT pg_catalog.json_build_array(current_user,pg_catalog.current_database(),"
            "pg_catalog.current_setting('server_version_num')::integer)",
            "identify the running PostgreSQL database; start the postgres service first",
        )
        try:
            user, database, version = json.loads(raw)
            major = version // 10000
        except (TypeError, UnicodeDecodeError, ValueError) as exc:
            raise BackupError("could not identify the running PostgreSQL database") from exc
        if user != layout.pg_user or database != layout.pg_database or major < 10:
            raise BackupError("the running PostgreSQL database does not match the Compose settings; check the postgres service")
        self._major = major
        return major

    def dump(self, path: Path) -> None:
        self.postgres_major()
        with path.open("wb") as dump:
            self._run(["exec", "-T", "postgres", "sh", "-c", _DUMP], "dump PostgreSQL", destination=dump)

    def validate_dump(self, path: Path) -> None:
        self.postgres_major()
        with path.open("rb") as dump:
            self._run(["exec", "-T", "postgres", "pg_restore", "--list"], "read the PostgreSQL dump", source=dump)

    def require_empty_database(self) -> None:
        self.postgres_major()
        if self._psql(_EMPTY_QUERY, "check the restore database") != b"t":
            raise BackupError("restore requires a fresh PostgreSQL database without other client sessions")

    def restore(self, path: Path) -> None:
        self.require_empty_database()
        with path.open("rb") as dump:
            self._run(["exec", "-T", "postgres", "sh", "-c", _RESTORE], "restore PostgreSQL", source=dump)
