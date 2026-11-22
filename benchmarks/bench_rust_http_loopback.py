"""Apples-to-apples Loopback HTTP benchmark for Rust `edge-bridge.exe serve` (/api/v1/call)
matching the exact workload sizes and concurrency levels (c1/c2/c4/c8) of bench_python_baseline.py.
"""
from __future__ import annotations

import concurrent.futures
from datetime import datetime, timezone
import http.client
import json
import os
from pathlib import Path
import statistics
import subprocess
import sys
import tempfile
import time

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from compat.python.rust_bridge import find_rust_binary, invoke_rust_cli


def _percentiles(samples: list[float]) -> dict:
    s = sorted(samples)
    n = len(s)
    return {
        "n": n,
        "min_ms": round(s[0], 3),
        "p50_ms": round(s[min(n - 1, int((n - 1) * 0.50))], 3),
        "p95_ms": round(s[min(n - 1, int((n - 1) * 0.95))], 3),
        "p99_ms": round(s[min(n - 1, int((n - 1) * 0.99))], 3),
        "max_ms": round(s[-1], 3),
        "mean_ms": round(statistics.fmean(s), 3),
    }


def main() -> None:
    rust_bin = find_rust_binary(REPO)
    assert rust_bin is not None
    with tempfile.TemporaryDirectory(prefix="eb_bench_rhttp_") as tmp:
        root = Path(tmp)
        state = root / "state"
        proj = root / "fixture"
        proj.mkdir()
        (proj / "small_4k.txt").write_text(("alpha beta gamma delta 0123456789\n" * 128)[:4096], encoding="utf-8")
        (proj / "medium_64k.txt").write_text(("telemetry_row,2026-11-19T00:00:00Z,10.5,m/s\n" * 1600)[:65536], encoding="utf-8")

        reg = invoke_rust_cli(["register", str(proj), "--name", "Bench HTTP", "--grant-edge"], state_dir=state, repo_root=REPO)
        pid = reg["project_id"]

        proc = subprocess.Popen(
            [str(rust_bin), "--state-dir", str(state), "serve", "--port", "0"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, stdin=subprocess.DEVNULL,
        )
        try:
            disc = state / "rust-broker.json"
            t_wait = time.monotonic() + 10.0
            while not disc.is_file() and time.monotonic() < t_wait:
                time.sleep(0.05)
            port = json.loads(disc.read_text(encoding="utf-8"))["port"]
            edge_tok = (state / "edge.token").read_text(encoding="utf-8").strip()

            def call_once(fname: str) -> float:
                body = json.dumps({"method": "file_read", "params": {"project_id": pid, "path": fname, "limit": 65536}}).encode()
                t0 = time.perf_counter()
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
                try:
                    conn.request(
                        "POST",
                        "/api/v1/call",
                        body=body,
                        headers={
                            "Host": f"127.0.0.1:{port}",
                            "Content-Type": "application/json",
                            "X-Bridge-Token": edge_tok,
                        },
                    )
                    resp = conn.getresponse()
                    raw = resp.read()
                    assert resp.status == 200
                    assert json.loads(raw)["ok"] is True
                finally:
                    conn.close()
                return (time.perf_counter() - t0) * 1000.0

            # Warmup
            for _ in range(10):
                call_once("small_4k.txt")

            out_workloads = {}
            for label, fname in (("http_read_4k_warm", "small_4k.txt"), ("http_read_64k_warm", "medium_64k.txt")):
                cmap = {}
                for conc in (1, 2, 4, 8):
                    lats = []
                    errs = 0
                    tb = time.perf_counter()
                    with concurrent.futures.ThreadPoolExecutor(max_workers=conc) as pool:
                        futs = [pool.submit(call_once, fname) for _ in range(120)]
                        for f in futs:
                            try:
                                lats.append(f.result())
                            except Exception:
                                errs += 1
                    dt = time.perf_counter() - tb
                    cmap[f"c{conc}"] = {
                        **_percentiles(lats),
                        "errors": errs,
                        "throughput_rps": round(len(lats) / max(dt, 1e-6), 2),
                    }
                out_workloads[label] = cmap

            report = {
                "captured_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "subject": "edge-project-bridge-rust-v0.4.0-loopback-http",
                "host": os.environ.get("COMPUTERNAME", "unknown"),
                "workloads": out_workloads,
            }
            out_path = REPO / "benchmarks" / "raw" / "rust-v0.4.0-http-loopback.json"
            out_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
            print(json.dumps(report, indent=2))
        finally:
            proc.terminate()
            proc.wait(timeout=5)


if __name__ == "__main__":
    main()
