"""Versioned release snapshots, verified upgrades, rollback, and broken-MCP recovery."""

from __future__ import annotations

from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import shutil
import sqlite3
import stat
import subprocess
import sys
from typing import Any
from uuid import uuid4

from . import __version__
from .state import SCHEMA_VERSION, State

if os.name == "nt":
    import ntsecuritycon
    import win32api
    import win32con
    import win32security


class ReleaseError(RuntimeError):
    """Structured fail-closed error for release/rollback operations."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _now_utc_compact() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def default_releases_dir(state_dir: Path) -> Path:
    resolved = state_dir.absolute()
    return resolved.parent / f"{resolved.name}-releases"


def _check_no_reparse(path: Path) -> None:
    if path.exists():
        if path.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise ReleaseError("RELEASE_PATH_UNSAFE", f"Release path cannot be a Windows reparse point: {path}")
    for parent in path.parents:
        if parent.exists() and (parent.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT):
            raise ReleaseError("RELEASE_PATH_UNSAFE", f"Release path cannot use a reparse ancestor: {parent}")


def _verify_owner_acl(path: Path) -> None:
    if os.name != "nt":
        return
    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
    owner = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
    system = win32security.CreateWellKnownSid(win32security.WinLocalSystemSid, None)
    descriptor = win32security.GetNamedSecurityInfo(
        str(path),
        win32security.SE_FILE_OBJECT,
        win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION,
    )
    if descriptor.GetSecurityDescriptorOwner() != owner:
        raise ReleaseError("RELEASE_ACL_UNSAFE", "Release directory must be owned by the current Windows user.")
    acl = descriptor.GetSecurityDescriptorDacl()
    if acl is None or not 1 <= acl.GetAceCount() <= 2:
        raise ReleaseError("RELEASE_ACL_UNSAFE", "Release ACL must allow only the owner and SYSTEM.")
    for index in range(acl.GetAceCount()):
        (kind, _flags), _rights, sid = acl.GetAce(index)
        if kind != win32security.ACCESS_ALLOWED_ACE_TYPE or sid not in (owner, system):
            raise ReleaseError("RELEASE_ACL_UNSAFE", "Unexpected ACE on release directory.")


def _validate_releases_boundary(state_dir: Path, releases_dir: Path, package_root: Path) -> tuple[Path, Path, Path]:
    s_abs = state_dir.absolute()
    r_abs = releases_dir.absolute()
    p_abs = package_root.absolute()
    if not r_abs.is_absolute() or not r_abs.parent.is_dir():
        raise ReleaseError("RELEASE_PATH_UNSAFE", "Releases directory must be absolute inside an existing parent.")
    for forbidden in (s_abs, p_abs):
        if r_abs == forbidden or forbidden in r_abs.parents or r_abs in forbidden.parents:
            raise ReleaseError(
                "RELEASE_PATH_UNSAFE",
                "Releases directory must remain strictly outside state_dir and package_root.",
            )
    _check_no_reparse(r_abs)
    return s_abs, r_abs, p_abs


def ensure_releases_dir(releases_dir: Path, *, state_dir: Path | None = None, package_root: Path | None = None) -> Path:
    r_abs = releases_dir.absolute()
    if state_dir is not None and package_root is not None:
        _validate_releases_boundary(state_dir, r_abs, package_root)
    else:
        _check_no_reparse(r_abs)
    if not r_abs.exists():
        r_abs.mkdir()
        if os.name == "nt":
            token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
            owner = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
            system = win32security.CreateWellKnownSid(win32security.WinLocalSystemSid, None)
            acl = win32security.ACL()
            inherit = win32con.OBJECT_INHERIT_ACE | win32con.CONTAINER_INHERIT_ACE
            for sid in (owner, system):
                acl.AddAccessAllowedAceEx(win32security.ACL_REVISION, inherit, ntsecuritycon.FILE_ALL_ACCESS, sid)
            win32security.SetNamedSecurityInfo(
                str(r_abs),
                win32security.SE_FILE_OBJECT,
                win32security.DACL_SECURITY_INFORMATION | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
                None, None, acl, None,
            )
    _verify_owner_acl(r_abs)
    (r_abs / "snapshots").mkdir(exist_ok=True)
    (r_abs / "quarantine").mkdir(exist_ok=True)
    return r_abs


def _atomic_write_json(path: Path, data: dict[str, Any]) -> None:
    tmp = path.with_name(f".{path.name}.{uuid4().hex[:8]}.tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=True, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, path)


def _read_pointers(releases_dir: Path) -> dict[str, Any]:
    ptr_file = releases_dir / "pointers.json"
    if not ptr_file.is_file():
        return {"current": None, "previous": None, "last_known_good": None, "history": []}
    data = json.loads(ptr_file.read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict):
        raise ReleaseError("RELEASE_CORRUPT", "pointers.json must be a JSON object.")
    return {
        "current": data.get("current"),
        "previous": data.get("previous"),
        "last_known_good": data.get("last_known_good"),
        "history": list(data.get("history") or []),
    }


def _sha256_file(path: Path) -> str:
    with path.open("rb") as fh:
        return hashlib.file_digest(fh, "sha256").hexdigest()


def _collect_code_files(package_root: Path) -> list[tuple[str, Path]]:
    items: list[tuple[str, Path]] = []
    pkg_dir = package_root / "edge_bridge"
    if not pkg_dir.is_dir():
        raise ReleaseError("INVALID_PACKAGE_ROOT", f"Missing edge_bridge directory under {package_root}")
    for fpath in sorted(pkg_dir.rglob("*")):
        if not fpath.is_file():
            continue
        if "__pycache__" in fpath.parts or fpath.suffix.casefold() in {".pyc", ".pyo"}:
            continue
        items.append((fpath.relative_to(package_root).as_posix(), fpath))

    scripts_dir = package_root / "scripts"
    if scripts_dir.is_dir():
        for fpath in sorted(scripts_dir.rglob("*")):
            if not fpath.is_file():
                continue
            if "__pycache__" in fpath.parts or fpath.suffix.casefold() in {".pyc", ".pyo"}:
                continue
            items.append((fpath.relative_to(package_root).as_posix(), fpath))

    for root_file in ("pyproject.toml", "uv.lock"):
        candidate = package_root / root_file
        if candidate.is_file():
            items.append((root_file, candidate))
    return items


def _detect_package_version(package_root: Path) -> str:
    init_file = package_root / "edge_bridge" / "__init__.py"
    if init_file.is_file():
        text = init_file.read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            if line.strip().startswith("__version__"):
                parts = line.split("=", 1)
                if len(parts) == 2:
                    val = parts[1].strip().strip("\"'")
                    if val:
                        return val
    return __version__


def _best_effort_stop_broker(state_dir: Path) -> dict[str, Any]:
    discovery = state_dir / "broker.json"
    if not discovery.is_file():
        return {"broker_was_running": False, "stopped": False}
    try:
        from .broker import call_broker

        call_broker(state_dir, "local", "owner_stop")
        return {"broker_was_running": True, "stopped": True, "method": "owner_stop"}
    except Exception:
        pass
    if os.name == "nt":
        state_str = str(state_dir.absolute())
        ps_cmd = (
            "if ($PSHome) { $env:PSModulePath = (Join-Path $PSHome 'Modules') + [IO.Path]::PathSeparator + $env:PSModulePath }; "
            f"$target = {json.dumps(state_str)}; "
            "$procs = Get-CimInstance Win32_Process | Where-Object { "
            "$_.CommandLine -and $_.CommandLine -like '*edge_bridge.cli*' "
            "-and $_.CommandLine -like '*start*' -and $_.CommandLine.Contains($target) }; "
            "foreach ($p in $procs) { Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue }; "
            "Write-Output ($procs | Measure-Object).Count"
        )
        try:
            proc = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            return {
                "broker_was_running": True,
                "stopped": proc.returncode == 0,
                "method": "win32_process_match",
            }
        except Exception:
            pass
    return {"broker_was_running": True, "stopped": False}


def _safe_rel_posix(rel: str) -> Path:
    if (
        not isinstance(rel, str)
        or not rel
        or "\\" in rel
        or ":" in rel
        or rel.startswith("/")
        or "\x00" in rel
    ):
        raise ReleaseError("RELEASE_CORRUPT", f"Unsafe manifest relative path: {rel!r}")
    win = PureWindowsPath(rel)
    pure = PurePosixPath(rel)
    parts = rel.split("/")
    if (
        win.is_absolute()
        or pure.is_absolute()
        or not pure.parts
        or any(part in {"", ".", ".."} for part in parts)
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        raise ReleaseError("RELEASE_CORRUPT", f"Unsafe manifest relative path: {rel!r}")
    return Path(*pure.parts)


def verify_release_snapshot(snapshot_dir: Path) -> dict[str, Any]:
    manifest_path = snapshot_dir / "manifest.json"
    if not manifest_path.is_file():
        raise ReleaseError("RELEASE_CORRUPT", f"Missing manifest.json in {snapshot_dir}")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    except ValueError as exc:
        raise ReleaseError("RELEASE_CORRUPT", f"Invalid JSON in {manifest_path}") from exc
    if not isinstance(manifest, dict) or not isinstance(manifest.get("files"), list):
        raise ReleaseError("RELEASE_CORRUPT", "Malformed release manifest structure.")

    code_dir = snapshot_dir / "code"
    if not code_dir.is_dir():
        raise ReleaseError("RELEASE_CORRUPT", f"Missing code/ snapshot directory in {snapshot_dir}")
    code_base = code_dir.resolve()

    expected_paths: set[str] = set()
    for entry in manifest["files"]:
        rel = entry.get("path")
        expected_hash = entry.get("sha256")
        expected_size = entry.get("size")
        if not isinstance(rel, str) or not isinstance(expected_hash, str) or type(expected_size) is not int:
            raise ReleaseError("RELEASE_CORRUPT", "Malformed file entry in release manifest.")
        rel_path = _safe_rel_posix(rel)
        target = code_dir / rel_path
        if not target.resolve().is_relative_to(code_base):
            raise ReleaseError("RELEASE_CORRUPT", f"Manifest relative path escapes snapshot code/: {rel!r}")
        if not target.is_file():
            raise ReleaseError("RELEASE_HASH_MISMATCH", f"Missing snapshot file: {rel}")
        actual_size = target.stat().st_size
        actual_hash = _sha256_file(target)
        if actual_size != expected_size or actual_hash != expected_hash:
            raise ReleaseError("RELEASE_HASH_MISMATCH", f"Snapshot file integrity mismatch for {rel}")
        expected_paths.add(rel_path.as_posix())

    actual_paths = {p.relative_to(code_dir).as_posix() for p in code_dir.rglob("*") if p.is_file()}
    extra = actual_paths - expected_paths
    if extra:
        raise ReleaseError("RELEASE_HASH_MISMATCH", f"Unexpected extra files in snapshot code/: {sorted(extra)[:5]}")

    db_meta = manifest.get("db_backup")
    if db_meta is not None:
        db_file = snapshot_dir / "state-backup.sqlite3"
        if not db_file.is_file():
            raise ReleaseError("RELEASE_CORRUPT", "Manifest references state-backup.sqlite3, which is missing.")
        if db_file.stat().st_size != db_meta.get("size_bytes") or _sha256_file(db_file) != db_meta.get("sha256"):
            raise ReleaseError("RELEASE_HASH_MISMATCH", "Snapshot SQLite backup digest mismatch.")
        with closing(sqlite3.connect(db_file, timeout=5)) as conn:
            check = conn.execute("PRAGMA integrity_check").fetchone()
        if not check or str(check[0]).lower() != "ok":
            raise ReleaseError("RELEASE_CORRUPT", "Snapshot SQLite backup failed PRAGMA integrity_check.")

    return manifest


def create_release(
    state_dir: Path,
    package_root: Path,
    *,
    releases_dir: Path | None = None,
    profile_path: Path | None = None,
    notes: str = "",
    mark_current: bool = True,
    mark_good: bool = True,
) -> dict[str, Any]:
    s_abs = state_dir.absolute()
    p_abs = package_root.resolve(strict=True)
    r_target = (releases_dir or default_releases_dir(s_abs)).absolute()
    r_abs = ensure_releases_dir(r_target, state_dir=s_abs, package_root=p_abs)

    version = _detect_package_version(p_abs)
    release_id = f"{version}-{_now_utc_compact()}-{uuid4().hex[:8]}"
    snap_dir = r_abs / "snapshots" / release_id
    code_dir = snap_dir / "code"
    code_dir.mkdir(parents=True)

    file_entries: list[dict[str, Any]] = []
    for rel, src in _collect_code_files(p_abs):
        dest = code_dir / _safe_rel_posix(rel)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)
        file_entries.append({
            "path": rel,
            "sha256": _sha256_file(dest),
            "size": dest.stat().st_size,
        })

    db_file = s_abs / "state.sqlite3"
    db_backup_info: dict[str, Any] | None = None
    instance_id: str | None = None
    schema_version: int | None = None
    projects_count = 0
    if db_file.is_file():
        store = State(db_file)
        snap = store.health_snapshot()
        instance_id = snap["instance_id"]
        schema_version = snap["schema_version"]
        projects_count = snap["projects"]
        backup_dest = snap_dir / "state-backup.sqlite3"
        b_info = store.backup_to(backup_dest)
        db_backup_info = {
            "filename": "state-backup.sqlite3",
            "size_bytes": b_info["size_bytes"],
            "sha256": b_info["sha256"],
            "integrity_check": b_info["integrity_check"],
        }

    profile_ref: dict[str, Any] | None = None
    if profile_path is not None:
        resolved_prof = profile_path.resolve(strict=True)
        profile_ref = {
            "path": str(resolved_prof),
            "sha256": _sha256_file(resolved_prof),
        }

    credential_presence = {
        "owner_token_present": (s_abs / "owner.token").is_file(),
        "edge_token_present": (s_abs / "edge.token").is_file(),
        "ipc_cert_present": (s_abs / "ipc.pem").is_file(),
        "ipc_key_present": (s_abs / "ipc-key.pem").is_file(),
    }

    manifest = {
        "manifest_version": 1,
        "release_id": release_id,
        "bridge_version": version,
        "created_at_utc": _now_iso(),
        "verified_good": bool(mark_good),
        "notes": notes,
        "instance_id": instance_id,
        "schema_version": schema_version,
        "projects_count": projects_count,
        "files": file_entries,
        "db_backup": db_backup_info,
        "tunnel_profile_ref": profile_ref,
        "credential_presence": credential_presence,
    }
    _atomic_write_json(snap_dir / "manifest.json", manifest)

    try:
        pointers = _read_pointers(r_abs)
    except Exception:
        pointers = {"current": None, "previous": None, "last_known_good": None, "history": []}

    if mark_current:
        if pointers.get("current") and pointers["current"] != release_id:
            pointers["previous"] = pointers["current"]
        pointers["current"] = release_id
    if mark_good:
        pointers["last_known_good"] = release_id
    history = [item for item in pointers.get("history", []) if item.get("release_id") != release_id]
    history.append({
        "release_id": release_id,
        "bridge_version": version,
        "created_at_utc": manifest["created_at_utc"],
        "verified_good": bool(mark_good),
        "notes": notes,
    })
    pointers["history"] = history[-50:]
    _atomic_write_json(r_abs / "pointers.json", pointers)

    return {
        "release_id": release_id,
        "releases_dir": str(r_abs),
        "snapshot_dir": str(snap_dir),
        "bridge_version": version,
        "verified_good": bool(mark_good),
        "file_count": len(file_entries),
        "instance_id": instance_id,
        "schema_version": schema_version,
        "db_backup": db_backup_info,
        "credential_presence": credential_presence,
        "pointers": pointers,
    }


def list_releases(state_dir: Path, *, releases_dir: Path | None = None) -> dict[str, Any]:
    s_abs = state_dir.absolute()
    r_abs = (releases_dir or default_releases_dir(s_abs)).absolute()
    if not r_abs.exists():
        return {"releases_dir": str(r_abs), "initialized": False, "pointers": None, "snapshots": []}
    _check_no_reparse(r_abs)
    _verify_owner_acl(r_abs)
    pointers_error = None
    try:
        pointers = _read_pointers(r_abs)
    except Exception as exc:
        pointers = None
        pointers_error = str(exc)

    snapshots_root = r_abs / "snapshots"
    snapshots: list[dict[str, Any]] = []
    if snapshots_root.is_dir():
        for item in sorted(snapshots_root.iterdir(), reverse=True):
            if not item.is_dir():
                continue
            mfile = item / "manifest.json"
            if not mfile.is_file():
                continue
            try:
                m = json.loads(mfile.read_text(encoding="utf-8"))
                snapshots.append({
                    "release_id": m.get("release_id", item.name),
                    "bridge_version": m.get("bridge_version"),
                    "created_at_utc": m.get("created_at_utc"),
                    "verified_good": bool(m.get("verified_good")),
                    "instance_id": m.get("instance_id"),
                    "schema_version": m.get("schema_version"),
                    "file_count": len(m.get("files") or []),
                    "has_db_backup": m.get("db_backup") is not None,
                    "notes": m.get("notes", ""),
                })
            except Exception:
                snapshots.append({"release_id": item.name, "corrupt": True})
    return {
        "releases_dir": str(r_abs),
        "initialized": True,
        "pointers": pointers,
        "pointers_error": pointers_error,
        "snapshots": snapshots,
    }


def _verify_restored_package(state_dir: Path, package_root: Path) -> dict[str, Any]:
    comp = subprocess.run(
        [sys.executable, "-m", "compileall", "-q", "edge_bridge", "scripts"],
        cwd=str(package_root),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=30,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
    )
    if comp.returncode != 0:
        return {
            "ok": False,
            "stage": "compileall",
            "returncode": comp.returncode,
            "stderr": (comp.stderr or comp.stdout)[:500],
        }
    requests = [
        {"jsonrpc": "2.0", "id": "openai-mcp-discover", "method": "server/discover"},
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "release_verifier", "version": "1.0"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "bridge_info", "arguments": {}}},
    ]
    payload = "\n".join(json.dumps(req) for req in requests) + "\n"
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "edge_bridge.cli", "--state-dir", str(state_dir), "mcp", "--principal", "edge"],
            input=payload.encode("utf-8"),
            cwd=str(package_root),
            capture_output=True,
            timeout=20,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
    except Exception as exc:
        return {"ok": False, "stage": "mcp_stdio", "error": str(exc)}

    replies: dict[Any, dict[str, Any]] = {}
    for line in proc.stdout.decode("utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        if "id" in msg:
            replies[msg["id"]] = msg

    discover_ok = replies.get("openai-mcp-discover", {}).get("error", {}).get("code") == -32601
    init_ok = "result" in replies.get(1, {})
    tools = replies.get(2, {}).get("result", {}).get("tools", [])
    info_res = replies.get(3, {}).get("result", {})
    info_structured = info_res.get("structuredContent", {}) if isinstance(info_res, dict) else {}
    info_handled = ("result" in replies.get(3, {}) and not info_res.get("isError")) or (
        info_res.get("isError") is True and info_structured.get("code") == "BROKER_OFFLINE"
    )
    ok = proc.returncode == 0 and discover_ok and init_ok and len(tools) == 33 and info_handled
    return {
        "ok": ok,
        "stage": "mcp_stdio",
        "returncode": proc.returncode,
        "discover_clean_32601": discover_ok,
        "initialize_ok": init_ok,
        "tool_count": len(tools),
        "info_handled": info_handled,
        "stderr": proc.stderr.decode("utf-8", errors="replace")[:400] if not ok else "",
    }


def _check_live_db_compatible(live_db: Path, target_schema_version: int | None) -> tuple[bool, str]:
    if not live_db.is_file():
        return False, "missing"
    try:
        with closing(sqlite3.connect(live_db, timeout=5)) as conn:
            check = conn.execute("PRAGMA integrity_check").fetchone()
            if not check or str(check[0]).lower() != "ok":
                return False, "integrity_check_failed"
            if target_schema_version is not None:
                row = conn.execute("SELECT schema_version FROM instance WHERE slot = 1").fetchone()
                if row is None:
                    return False, "missing_instance_row"
                if int(row[0]) > int(target_schema_version):
                    return False, f"incompatible_schema_version:{row[0]}>{target_schema_version}"
        return True, "ok"
    except Exception as exc:
        return False, f"sqlite_error:{type(exc).__name__}"


def _quarantine_and_restore_db(state_dir: Path, releases_dir: Path, snapshot_dir: Path) -> dict[str, Any]:
    backup_src = snapshot_dir / "state-backup.sqlite3"
    if not backup_src.is_file():
        raise ReleaseError("RELEASE_CORRUPT", "Cannot restore SQLite database: snapshot has no state-backup.sqlite3.")
    live_db = state_dir / "state.sqlite3"
    quarantined_path: str | None = None
    stamp = _now_utc_compact() + "-" + uuid4().hex[:6]
    quarantine_dir = releases_dir / "quarantine"
    quarantine_dir.mkdir(exist_ok=True)
    for suffix in ("", "-wal", "-shm"):
        candidate = state_dir / f"state.sqlite3{suffix}"
        if candidate.is_file():
            dest = quarantine_dir / f"state-{stamp}.sqlite3{suffix}"
            shutil.move(str(candidate), str(dest))
            if suffix == "":
                quarantined_path = str(dest)

    with closing(sqlite3.connect(backup_src, timeout=5)) as src, closing(sqlite3.connect(live_db, timeout=5)) as dst:
        src.backup(dst)
        check = dst.execute("PRAGMA integrity_check").fetchone()
    if not check or str(check[0]).lower() != "ok":
        raise ReleaseError("RELEASE_CORRUPT", "Restored SQLite database failed PRAGMA integrity_check.")
    return {
        "db_restored": True,
        "quarantined_db": quarantined_path,
        "restored_sha256": _sha256_file(live_db),
    }


def _apply_snapshot_code(package_root: Path, snapshot_dir: Path, manifest: dict[str, Any]) -> None:
    code_dir = snapshot_dir / "code"
    code_base = code_dir.resolve()
    pkg_base = package_root.resolve()
    expected_rels = {entry["path"] for entry in manifest["files"]}

    # Remove unexpected files introduced in edge_bridge/ or scripts/ by broken updates
    for subdir in ("edge_bridge", "scripts"):
        root_sub = package_root / subdir
        if root_sub.is_dir():
            for existing in list(root_sub.rglob("*")):
                if "__pycache__" in existing.parts:
                    continue
                if existing.is_file():
                    rel = existing.relative_to(package_root).as_posix()
                    if rel not in expected_rels:
                        existing.unlink()
            pycache = root_sub / "__pycache__"
            if pycache.is_dir():
                shutil.rmtree(pycache, ignore_errors=True)
        for pycache in root_sub.rglob("__pycache__") if root_sub.is_dir() else []:
            shutil.rmtree(pycache, ignore_errors=True)

    for rel in sorted(expected_rels):
        rel_path = _safe_rel_posix(rel)
        src = code_dir / rel_path
        dst = package_root / rel_path
        if not src.resolve().is_relative_to(code_base) or not dst.resolve().is_relative_to(pkg_base):
            raise ReleaseError("RELEASE_CORRUPT", f"Manifest relative path escapes root boundary: {rel!r}")
        dst.parent.mkdir(parents=True, exist_ok=True)
        tmp = dst.with_name(f".{dst.name}.{uuid4().hex[:8]}.tmp")
        shutil.copyfile(src, tmp)
        os.replace(tmp, dst)


def rollback_release(
    state_dir: Path,
    package_root: Path,
    *,
    target_release_id: str | None = None,
    releases_dir: Path | None = None,
    restore_db: bool = False,
    verify: bool = True,
) -> dict[str, Any]:
    s_abs = state_dir.absolute()
    p_abs = package_root.resolve(strict=True)
    r_target = (releases_dir or default_releases_dir(s_abs)).absolute()
    r_abs = ensure_releases_dir(r_target, state_dir=s_abs, package_root=p_abs)

    try:
        pointers = _read_pointers(r_abs)
    except Exception:
        pointers = {"current": None, "previous": None, "last_known_good": None, "history": []}

    resolved_id = target_release_id
    if not resolved_id:
        prev_id = pointers.get("previous")
        good_id = pointers.get("last_known_good")
        cur_id = pointers.get("current")
        if prev_id and prev_id != cur_id and (r_abs / "snapshots" / prev_id).is_dir():
            resolved_id = prev_id
        elif good_id and (r_abs / "snapshots" / good_id).is_dir():
            resolved_id = good_id
        elif prev_id and (r_abs / "snapshots" / prev_id).is_dir():
            resolved_id = prev_id
    if not resolved_id:
        raise ReleaseError("RELEASE_NOT_FOUND", "No target release snapshot available for rollback.")

    snap_dir = r_abs / "snapshots" / resolved_id
    if not snap_dir.is_dir():
        raise ReleaseError("RELEASE_NOT_FOUND", f"Release snapshot not found: {resolved_id}")

    manifest = verify_release_snapshot(snap_dir)
    stop_info = _best_effort_stop_broker(s_abs)
    _apply_snapshot_code(p_abs, snap_dir, manifest)

    live_db = s_abs / "state.sqlite3"
    db_ok, db_reason = _check_live_db_compatible(live_db, manifest.get("schema_version"))
    db_result: dict[str, Any] = {"db_restored": False, "db_status": db_reason}
    if manifest.get("db_backup") is not None and (restore_db or not db_ok):
        db_result = _quarantine_and_restore_db(s_abs, r_abs, snap_dir)
        db_result["db_status"] = "restored_from_snapshot" if not restore_db else "restored_by_request"

    new_pointers = {
        "current": resolved_id,
        "previous": pointers.get("current") if pointers.get("current") != resolved_id else pointers.get("previous"),
        "last_known_good": resolved_id if manifest.get("verified_good") else pointers.get("last_known_good"),
        "history": pointers.get("history", []),
    }
    _atomic_write_json(r_abs / "pointers.json", new_pointers)

    verification = _verify_restored_package(s_abs, p_abs) if verify else {"ok": True, "skipped": True}
    if verify and not verification.get("ok"):
        raise ReleaseError("ROLLBACK_VERIFICATION_FAILED", f"Post-rollback verification failed: {verification}")

    return {
        "status": "ROLLED_BACK",
        "release_id": resolved_id,
        "bridge_version": manifest.get("bridge_version"),
        "releases_dir": str(r_abs),
        "broker_stop": stop_info,
        **db_result,
        "verification": verification,
        "pointers": new_pointers,
    }


def recover_bridge(
    state_dir: Path,
    package_root: Path,
    *,
    releases_dir: Path | None = None,
    restore_db: bool = False,
    verify: bool = True,
) -> dict[str, Any]:
    s_abs = state_dir.absolute()
    p_abs = package_root.resolve(strict=True)
    r_target = (releases_dir or default_releases_dir(s_abs)).absolute()
    r_abs = ensure_releases_dir(r_target, state_dir=s_abs, package_root=p_abs)

    candidates: list[str] = []
    try:
        pointers = _read_pointers(r_abs)
        for key in ("last_known_good", "previous", "current"):
            val = pointers.get(key)
            if isinstance(val, str) and val and val not in candidates:
                candidates.append(val)
    except Exception:
        pass

    snapshots_root = r_abs / "snapshots"
    if snapshots_root.is_dir():
        for entry in sorted(snapshots_root.iterdir(), reverse=True):
            if entry.is_dir() and entry.name not in candidates:
                candidates.append(entry.name)

    selected: str | None = None
    for cid in candidates:
        cdir = snapshots_root / cid
        if not cdir.is_dir():
            continue
        try:
            manifest = verify_release_snapshot(cdir)
        except ReleaseError:
            continue
        if manifest.get("verified_good"):
            selected = cid
            break

    if selected is None:
        raise ReleaseError("RELEASE_NOT_FOUND", "No verified good release snapshot found for recovery.")

    return rollback_release(
        s_abs,
        p_abs,
        target_release_id=selected,
        releases_dir=r_abs,
        restore_db=restore_db,
        verify=verify,
    )


def upgrade_from_directory(
    state_dir: Path,
    package_root: Path,
    source_dir: Path,
    *,
    releases_dir: Path | None = None,
    profile_path: Path | None = None,
    run_probe: bool = True,
    auto_rollback: bool = True,
) -> dict[str, Any]:
    s_abs = state_dir.absolute()
    p_abs = package_root.resolve(strict=True)
    src_abs = source_dir.resolve(strict=True)
    if not (src_abs / "edge_bridge").is_dir():
        raise ReleaseError("INVALID_ARGUMENT", f"Upgrade source directory must contain edge_bridge/: {src_abs}")

    pre = create_release(
        s_abs,
        p_abs,
        releases_dir=releases_dir,
        profile_path=profile_path,
        notes="pre-upgrade",
        mark_current=True,
        mark_good=True,
    )
    pre_id = pre["release_id"]
    r_abs = Path(pre["releases_dir"])
    _best_effort_stop_broker(s_abs)

    # Apply candidate code from source_dir into package_root
    src_files = _collect_code_files(src_abs)
    src_rels = {rel for rel, _ in src_files}
    for subdir in ("edge_bridge", "scripts"):
        root_sub = p_abs / subdir
        if root_sub.is_dir():
            for existing in list(root_sub.rglob("*")):
                if "__pycache__" in existing.parts:
                    continue
                if existing.is_file() and existing.relative_to(p_abs).as_posix() not in src_rels:
                    existing.unlink()
            for pycache in root_sub.rglob("__pycache__"):
                shutil.rmtree(pycache, ignore_errors=True)
    for rel, src_file in src_files:
        dst = p_abs / _safe_rel_posix(rel)
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src_file, dst)

    candidate = create_release(
        s_abs,
        p_abs,
        releases_dir=r_abs,
        profile_path=profile_path,
        notes=f"upgrade-candidate-from:{src_abs.name}",
        mark_current=True,
        mark_good=False,
    )
    cand_id = candidate["release_id"]

    verification = _verify_restored_package(s_abs, p_abs) if run_probe else {"ok": True, "skipped": True}
    if not verification.get("ok"):
        if not auto_rollback:
            raise ReleaseError("UPGRADE_VERIFICATION_FAILED", f"Upgrade candidate failed verification: {verification}")
        rb = rollback_release(
            s_abs,
            p_abs,
            target_release_id=pre_id,
            releases_dir=r_abs,
            restore_db=False,
            verify=True,
        )
        return {
            "status": "ROLLED_BACK",
            "upgraded": False,
            "rolled_back": True,
            "failed_release_id": cand_id,
            "restored_release_id": pre_id,
            "candidate_verification": verification,
            "rollback": rb,
        }

    # Promote candidate to verified_good & last_known_good
    cand_manifest_path = r_abs / "snapshots" / cand_id / "manifest.json"
    cand_manifest = json.loads(cand_manifest_path.read_text(encoding="utf-8"))
    cand_manifest["verified_good"] = True
    _atomic_write_json(cand_manifest_path, cand_manifest)

    pointers = _read_pointers(r_abs)
    pointers["current"] = cand_id
    pointers["previous"] = pre_id
    pointers["last_known_good"] = cand_id
    for entry in pointers["history"]:
        if entry.get("release_id") == cand_id:
            entry["verified_good"] = True
    _atomic_write_json(r_abs / "pointers.json", pointers)

    return {
        "status": "UPGRADED",
        "upgraded": True,
        "rolled_back": False,
        "release_id": cand_id,
        "previous_release_id": pre_id,
        "bridge_version": candidate["bridge_version"],
        "verification": verification,
        "pointers": pointers,
    }
