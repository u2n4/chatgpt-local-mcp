"""Stage 0 reproducible Python v0.2.0 baseline benchmark on disposable fixtures."""
from __future__ import annotations

import concurrent.futures
import json
import os
import platform
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from edge_bridge.broker import Broker, Handler, call_broker, create_tokens, make_server_tls, setup_state, LoopbackServer
from edge_bridge.files import ProjectFiles
from edge_bridge.state import State


def _working_set_bytes() -> int | None:
    if os.name != "nt":
        return None
    import ctypes as ct
    from ctypes import wintypes as wt

    class PROCESS_MEMORY_COUNTERS(ct.Structure):
        _fields_ = [
            ("cb", wt.DWORD),
            ("PageFaultCount", wt.DWORD),
            ("PeakWorkingSetSize", ct.c_size_t),
            ("WorkingSetSize", ct.c_size_t),
            ("QuotaPeakPagedPoolUsage", ct.c_size_t),
            ("QuotaPagedPoolUsage", ct.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ct.c_size_t),
            ("QuotaNonPagedPoolUsage", ct.c_size_t),
            ("PagefileUsage", ct.c_size_t),
            ("PeakPagefileUsage", ct.c_size_t),
        ]

    psapi = ct.WinDLL("psapi", use_last_error=True)
    kernel32 = ct.WinDLL("kernel32", use_last_error=True)
    pmc = PROCESS_MEMORY_COUNTERS()
    pmc.cb = ct.sizeof(pmc)
    if psapi.GetProcessMemoryInfo(kernel32.GetCurrentProcess(), ct.byref(pmc), pmc.cb):
        return int(pmc.WorkingSetSize)
    return None


def _percentiles(samples_ms: list[float]) -> dict:
    s = sorted(samples_ms)
    n = len(s)
    if n == 0:
        return {"n": 0, "min_ms": None, "p50_ms": None, "p95_ms": None, "p99_ms": None, "max_ms": None, "mean_ms": None}
    return {
        "n": n,
        "min_ms": round(s[0], 3),
        "p50_ms": round(s[min(n - 1, int((n - 1) * 0.50))], 3),
        "p95_ms": round(s[min(n - 1, int((n - 1) * 0.95))], 3),
        "p99_ms": round(s[min(n - 1, int((n - 1) * 0.99))], 3),
        "max_ms": round(s[-1], 3),
        "mean_ms": round(statistics.fmean(s), 3),
    }


def run_benchmark(output_json: Path) -> dict:
    with tempfile.TemporaryDirectory(prefix="eb_bench_py_") as tmp:
        root = Path(tmp)
        state = root / "state"
        proj = root / "fixture_project"
        proj.mkdir()
        setup_state(state)

        # Fixed payload fixtures: 4 KiB and 64 KiB
        (proj / "small_4k.txt").write_text(("alpha beta gamma delta 0123456789\n" * 128)[:4096], encoding="utf-8")
        (proj / "medium_64k.txt").write_text(("telemetry_row,2026-11-19T00:00:00Z,10.5,m/s\n" * 1600)[:65536], encoding="utf-8")
        for i in range(40):
            (proj / f"mod_{i:02d}.py").write_text(f"def fn_{i}(x):\n    return x + {i}\n", encoding="utf-8")

        store = State(state / "state.sqlite3")
        tokens = create_tokens(state)
        broker = Broker(store, state)
        tls = make_server_tls(state)
        server = LoopbackServer(("127.0.0.1", 0), Handler)
        server.socket = tls.wrap_socket(server.socket, server_side=True, do_handshake_on_connect=False)
        server.tokens = tokens
        server.broker = broker
        server.nonce_lock = threading.Lock()
        server.nonces = {}
        port = server.server_address[1]
        (state / "broker.json").write_text(
            json.dumps({"port": port, "instance_id": store.instance_id}),
            encoding="utf-8",
        )
        t = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        t.start()

        try:
            # Register project and grant edge read
            reg = call_broker(state, "local", "owner_register", {"root": str(proj), "name": "Bench Fixture"})
            pid = reg["project_id"]
            call_broker(state, "local", "owner_grant_edge", {"project_id": pid})

            idle_ws_bytes = _working_set_bytes()

            # Warmup
            for _ in range(10):
                call_broker(state, "edge", "file_read", {"project_id": pid, "path": "small_4k.txt", "limit": 65536})

            results: dict[str, dict] = {}
            for label, rel_path in (("read_4k_warm", "small_4k.txt"), ("read_64k_warm", "medium_64k.txt")):
                conc_map: dict[str, dict] = {}
                for conc in (1, 2, 4, 8):
                    n_req = 120
                    latencies: list[float] = []
                    errors = 0

                    def _one(_idx: int) -> float:
                        t0 = time.perf_counter()
                        res = call_broker(state, "edge", "file_read", {"project_id": pid, "path": rel_path, "limit": 65536})
                        dt = (time.perf_counter() - t0) * 1000.0
                        assert res["hash"] and len(res["content"]) > 0
                        return dt

                    t_batch0 = time.perf_counter()
                    with concurrent.futures.ThreadPoolExecutor(max_workers=conc) as pool:
                        futs = [pool.submit(_one, i) for i in range(n_req)]
                        for f in futs:
                            try:
                                latencies.append(f.result())
                            except Exception:
                                errors += 1
                    batch_s = time.perf_counter() - t_batch0
                    conc_map[f"c{conc}"] = {
                        **_percentiles(latencies),
                        "errors": errors,
                        "throughput_rps": round(len(latencies) / max(batch_s, 1e-6), 2),
                    }
                results[label] = conc_map

            # file_list benchmark (42 files)
            list_lat = []
            for _ in range(80):
                t0 = time.perf_counter()
                call_broker(state, "edge", "file_list", {"project_id": pid, "path": ".", "limit": 100})
                list_lat.append((time.perf_counter() - t0) * 1000.0)
            results["file_list_42files"] = _percentiles(list_lat)

            # checkpoint submission latency (local durable write ack)
            ckpt_lat = []
            for i in range(40):
                t0 = time.perf_counter()
                call_broker(
                    state,
                    "local",
                    "task_checkpoint",
                    {
                        "project_id": pid,
                        "task_id": "bench_task",
                        "operation_id": f"bench-ckpt-{i}",
                        "summary": f"Benchmark checkpoint {i}",
                        "objective": "Measure local SQLite WAL commit latency",
                    },
                )
                ckpt_lat.append((time.perf_counter() - t0) * 1000.0)
            results["task_checkpoint_durable_ack"] = _percentiles(ckpt_lat)

            post_ws_bytes = _working_set_bytes()
        finally:
            server.shutdown()
            server.server_close()

    report = {
        "captured_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "subject": "edge-project-bridge-python-v0.2.0",
        "environment": {
            "os": platform.platform(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "sqlite_runtime": sqlite3.sqlite_version,
            "cpu_count": os.cpu_count(),
        },
        "memory": {
            "working_set_idle_mib": round(idle_ws_bytes / (1024 * 1024), 2) if idle_ws_bytes else None,
            "working_set_post_mib": round(post_ws_bytes / (1024 * 1024), 2) if post_ws_bytes else None,
            "note": "In-process broker + client harness working set (single Python process)",
        },
        "workloads": results,
    }
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


if __name__ == "__main__":
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("benchmarks/raw/python-v0.2.0-baseline.json")
    data = run_benchmark(out)
    print(json.dumps(data, indent=2))
