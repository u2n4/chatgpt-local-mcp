"""P1 worker orchestration prep: resource admission, DAG readiness, isolation contracts, fail-closed gates."""

from __future__ import annotations

import ctypes as ct
from ctypes import wintypes as wt
from pathlib import Path
import threading
import time
from typing import Any

from . import runner
from .state import State
from .worker_account import AccountObservation, IncludedOnlyPolicy, evaluate_included_only


class WorkerError(RuntimeError):
    """Structured fail-closed error for P1 worker management."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class _MemoryStatusEx(ct.Structure):
    _fields_ = [
        ("dwLength", wt.DWORD),
        ("dwMemoryLoad", wt.DWORD),
        ("ullTotalPhys", ct.c_uint64),
        ("ullAvailPhys", ct.c_uint64),
        ("ullTotalPageFile", ct.c_uint64),
        ("ullAvailPageFile", ct.c_uint64),
        ("ullTotalVirtual", ct.c_uint64),
        ("ullAvailVirtual", ct.c_uint64),
        ("ullAvailExtendedVirtual", ct.c_uint64),
    ]


class _FileTime(ct.Structure):
    _fields_ = [
        ("dwLowDateTime", wt.DWORD),
        ("dwHighDateTime", wt.DWORD),
    ]


class _IoCounters(ct.Structure):
    _fields_ = [
        ("ReadOperationCount", ct.c_uint64),
        ("WriteOperationCount", ct.c_uint64),
        ("OtherOperationCount", ct.c_uint64),
        ("ReadTransferCount", ct.c_uint64),
        ("WriteTransferCount", ct.c_uint64),
        ("OtherTransferCount", ct.c_uint64),
    ]


def _ft_to_int(ft: _FileTime) -> int:
    return (int(ft.dwHighDateTime) << 32) | int(ft.dwLowDateTime)


_CPU_LOCK = threading.Lock()
_PREV_CPU_TIMES: tuple[int, int, int] | None = None
_GPU_CACHE: tuple[float, dict[str, Any]] | None = None


def _read_system_times() -> tuple[int, int, int] | None:
    try:
        kernel32 = ct.WinDLL("kernel32", use_last_error=True)
        idle, kernel, user = _FileTime(), _FileTime(), _FileTime()
        if not kernel32.GetSystemTimes(ct.byref(idle), ct.byref(kernel), ct.byref(user)):
            return None
        return _ft_to_int(idle), _ft_to_int(kernel), _ft_to_int(user)
    except Exception:
        return None


def _read_disk_and_io() -> dict[str, int]:
    free_mb = 0
    read_bytes = 0
    write_bytes = 0
    try:
        kernel32 = ct.WinDLL("kernel32", use_last_error=True)
        free_avail = ct.c_uint64(0)
        total_bytes = ct.c_uint64(0)
        total_free = ct.c_uint64(0)
        if kernel32.GetDiskFreeSpaceExW(
            ct.c_wchar_p(str(Path.cwd().anchor or "C:\\")),
            ct.byref(free_avail),
            ct.byref(total_bytes),
            ct.byref(total_free),
        ):
            free_mb = int(free_avail.value // (1024 * 1024))
        proc_handle = kernel32.GetCurrentProcess()
        counters = _IoCounters()
        if kernel32.GetProcessIoCounters(proc_handle, ct.byref(counters)):
            read_bytes = int(counters.ReadTransferCount)
            write_bytes = int(counters.WriteTransferCount)
    except Exception:
        pass
    return {
        "disk_free_mb": free_mb,
        "process_io_read_bytes": read_bytes,
        "process_io_write_bytes": write_bytes,
    }


def _sample_gpu_cached(*, force: bool = False) -> dict[str, Any]:
    global _GPU_CACHE
    now = time.monotonic()
    if not force and _GPU_CACHE is not None and (now - _GPU_CACHE[0]) < 30.0:
        return _GPU_CACHE[1]
    import os
    import shutil
    import subprocess

    smi = shutil.which("nvidia-smi")
    info: dict[str, Any] = {
        "gpu_available": False,
        "gpu_name": None,
        "gpu_utilization_percent": None,
        "gpu_memory_used_mb": None,
        "gpu_memory_total_mb": None,
    }
    if smi:
        try:
            proc = subprocess.run(
                [smi, "--query-gpu=name,utilization.gpu,memory.used,memory.total", "--format=csv,noheader,nounits"],
                capture_output=True,
                text=True,
                timeout=1.5,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                first = proc.stdout.strip().splitlines()[0]
                parts = [p.strip() for p in first.split(",")]
                if len(parts) >= 4:
                    info = {
                        "gpu_available": True,
                        "gpu_name": parts[0],
                        "gpu_utilization_percent": float(parts[1]),
                        "gpu_memory_used_mb": int(float(parts[2])),
                        "gpu_memory_total_mb": int(float(parts[3])),
                    }
        except Exception:
            pass
    _GPU_CACHE = (now, info)
    return info


def sample_host_resources(*, sample_cpu_window: bool = False, include_gpu: bool = False) -> dict[str, Any]:
    """Read live Windows RAM, CPU, Disk/IO, and optional GPU counters without stalling."""
    global _PREV_CPU_TIMES
    ram_total_mb = 0
    ram_avail_mb = 0
    ram_used_pct = 0
    try:
        kernel32 = ct.WinDLL("kernel32", use_last_error=True)
        mem = _MemoryStatusEx()
        mem.dwLength = ct.sizeof(_MemoryStatusEx)
        if kernel32.GlobalMemoryStatusEx(ct.byref(mem)):
            ram_total_mb = int(mem.ullTotalPhys // (1024 * 1024))
            ram_avail_mb = int(mem.ullAvailPhys // (1024 * 1024))
            ram_used_pct = int(mem.dwMemoryLoad)
    except Exception:
        pass

    cpu_pct: float | None = None
    with _CPU_LOCK:
        prev = _PREV_CPU_TIMES
        cur = _read_system_times()
        if prev is None and cur is not None and sample_cpu_window:
            prev = cur
            time.sleep(0.05)
            cur = _read_system_times()
        if prev is not None and cur is not None:
            d_idle = cur[0] - prev[0]
            d_total = (cur[1] - prev[1]) + (cur[2] - prev[2])
            if d_total > 0:
                cpu_pct = round(max(0.0, min(100.0, 100.0 * (d_total - d_idle) / d_total)), 2)
        if cur is not None:
            _PREV_CPU_TIMES = cur

    disk_io = _read_disk_and_io()
    gpu = _sample_gpu_cached() if include_gpu else (_GPU_CACHE[1] if _GPU_CACHE is not None else {
        "gpu_available": False, "gpu_name": None, "gpu_utilization_percent": None,
        "gpu_memory_used_mb": None, "gpu_memory_total_mb": None,
    })

    return {
        "ram_total_mb": ram_total_mb,
        "ram_available_mb": ram_avail_mb,
        "ram_used_percent": ram_used_pct,
        "cpu_percent": cpu_pct,
        **disk_io,
        **gpu,
    }


def check_resource_admission(
    store: State,
    *,
    max_ram_percent: int = 85,
    min_free_ram_mb: int = 1024,
    max_concurrent_workers: int = 2,
    sample_cpu_window: bool = False,
) -> dict[str, Any]:
    """Evaluate host capacity admission before allowing any future worker dispatch."""
    res = sample_host_resources(sample_cpu_window=sample_cpu_window)
    health = store.health_snapshot()
    reasons: list[str] = []
    if res["ram_total_mb"] > 0:
        if res["ram_used_percent"] > max_ram_percent:
            reasons.append(f"RAM usage {res['ram_used_percent']}% exceeds {max_ram_percent}% cap.")
        if res["ram_available_mb"] < min_free_ram_mb:
            reasons.append(f"Available RAM {res['ram_available_mb']} MiB below {min_free_ram_mb} MiB reserve.")
    if health["active_workers"] >= max_concurrent_workers:
        reasons.append(f"Active workers ({health['active_workers']}) reached limit ({max_concurrent_workers}).")
    return {
        "admitted": len(reasons) == 0,
        "reasons": reasons,
        "resources": res,
        "active_jobs": health["active_jobs"],
        "active_workers": health["active_workers"],
    }


def build_worker_isolation_spec(
    *,
    worker_id: str,
    project_id: str,
    task_id: str,
    profile: dict[str, Any],
    parent_capabilities: set[str],
    workspace_path: Path,
) -> dict[str, Any]:
    """Build a least-privilege isolation contract enforcing worker_caps <= parent_caps."""
    requested = set(profile.get("allowed_capabilities") or [])
    if not requested <= parent_capabilities:
        raise WorkerError(
            "PRIVILEGE_ESCALATION_DENIED",
            "Worker profile capabilities must be a subset of the parent task grant.",
        )
    return {
        "worker_id": worker_id,
        "project_id": project_id,
        "task_id": task_id,
        "profile": profile["name"],
        "effective_capabilities": sorted(requested),
        "isolation_mode": profile.get("isolation_mode", "codex-sandbox-mxc"),
        "workspace_path": str(workspace_path),
        "network_enabled": False,
        "billing_policy": "INCLUDED_ONLY",
        "llm_spend_enabled": False,
        "max_memory_mb": profile.get("max_memory_mb", 512),
        "max_cpu_pct": profile.get("max_cpu_pct", 25),
    }


class WorkerManager:
    """P1-prepared worker coordinator (fail-closed until MXC and included-only gates verify)."""

    def __init__(self, store: State):
        self.store = store

    def status(self, project_id: str | None = None, principal: str = "local", *, record_sample: bool = False) -> dict[str, Any]:
        listing = self.store.list_workers(project_id=project_id, principal=principal)
        admission = check_resource_admission(self.store)
        diag = runner.diagnose()["workers"]
        if record_sample:
            self.store.record_resource_sample(
                cpu_percent=admission["resources"]["cpu_percent"],
                ram_total_mb=admission["resources"]["ram_total_mb"],
                ram_available_mb=admission["resources"]["ram_available_mb"],
                ram_used_percent=admission["resources"]["ram_used_percent"],
                active_jobs=admission["active_jobs"],
                active_workers=admission["active_workers"],
                sample_json=admission,
            )
        return {
            **diag,
            "profiles": listing["profiles"],
            "workers": listing["workers"],
            "admission": admission,
        }

    def start_worker(
        self,
        *,
        project_id: str,
        principal: str,
        task_id: str,
        profile_name: str,
        policy: IncludedOnlyPolicy | None = None,
        observed: AccountObservation | None = None,
        now: float | None = None,
    ) -> dict[str, Any]:
        # Hard fail-closed order:
        # 1. Verify MXC whole-worker isolation gate (currently blocks in P0)
        runner.require_workers()
        # 2. If enabled in future, enforce INCLUDED_ONLY subscription verification
        if policy is None or observed is None or now is None:
            raise WorkerError("ACCOUNT_USAGE_UNVERIFIED", "Fresh included-only account metadata observation is required.")
        decision = evaluate_included_only(policy, observed, now=now)
        if not decision.allowed:
            raise WorkerError(decision.code, f"Worker launch blocked by billing policy: {decision.code}.")
        raise WorkerError("WORKER_CAPABILITY_NOT_VERIFIED", "Worker execution remains disabled in P0.")

    def cancel_worker(self, worker_id: str, principal: str) -> dict[str, Any]:
        return self.store.cancel_worker_record(worker_id, principal)
