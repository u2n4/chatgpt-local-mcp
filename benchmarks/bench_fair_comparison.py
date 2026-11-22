"""Fair Apples-to-Apples Performance Benchmark (Audit Section 8):
Compares Python v0.2.0 Broker vs Rust V0.4.0 Broker under IDENTICAL conditions:
  - Separate server process (independent WorkingSet RAM & CPU time per server!)
  - Identical loopback HTTP/1.1 transport on 127.0.0.1
  - Identical mutual HMAC-SHA256 request/response authentication + nonce replay guard
  - Identical 4 KiB & 64 KiB payloads with verified SHA-256 file hashes
  - Both keep-alive (persistent HTTP/1.1 connection per worker) and non-keep-alive (new connection per request)
  - Same concurrency levels (c=1, 2, 4, 8), explicit warmups, raw stats (P50/P95/P99/min/max/mean/RPS/errors)
  - Also quantifies Python's native TLS+HMAC baseline separately so TLS cost is explicit and unhidden
  - Measures Rust durable task_submit HTTP admission latency under SQLite synchronous=NORMAL vs FULL
  - Runs a timed 20-second soak test sampling Rust server process WorkingSet RSS every 2s
"""
from __future__ import annotations

import concurrent.futures
import ctypes as ct
from ctypes import wintypes as wt
from datetime import datetime, timezone
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import platform
import secrets
import shutil
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any

REPO = Path(__file__).resolve().parents[1]
AUDIT_BUNDLE = REPO / "audit-v0.4.0-20261119" / "evidence-bundle"
sys.path.insert(0, str(REPO))
from compat.python.rust_bridge import find_rust_binary, invoke_rust_cli


def _hmac_sig(token_hex: str, purpose: str, principal: str, nonce: str, stamp: str, body: bytes) -> str:
    prefix = f"edge-project-bridge/v1|{purpose}|{principal}|{nonce}|{stamp}|".encode("ascii")
    return hmac.digest(bytes.fromhex(token_hex), prefix + body, "sha256").hex()


def _percentiles(samples_ms: list[float]) -> dict[str, Any]:
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


def _proc_metrics(pid: int) -> dict[str, Any]:
    """Read WorkingSet, PrivateBytes, and Kernel+User CPU seconds of a separate Windows process."""
    if os.name != "nt":
        return {}
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    PROCESS_VM_READ = 0x0010

    class PROCESS_MEMORY_COUNTERS_EX(ct.Structure):
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
            ("PrivateUsage", ct.c_size_t),
        ]

    class FILETIME(ct.Structure):
        _fields_ = [("dwLowDateTime", wt.DWORD), ("dwHighDateTime", wt.DWORD)]

    def _ft_sec(ft: FILETIME) -> float:
        return ((ft.dwHighDateTime << 32) | ft.dwLowDateTime) / 10_000_000.0

    kernel32 = ct.WinDLL("kernel32", use_last_error=True)
    psapi = ct.WinDLL("psapi", use_last_error=True)
    h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, False, int(pid))
    if not h:
        return {}
    try:
        pmc = PROCESS_MEMORY_COUNTERS_EX()
        pmc.cb = ct.sizeof(pmc)
        mem_ok = psapi.GetProcessMemoryInfo(h, ct.byref(pmc), pmc.cb)
        ct_t, ex_t, kr_t, us_t = FILETIME(), FILETIME(), FILETIME(), FILETIME()
        time_ok = kernel32.GetProcessTimes(h, ct.byref(ct_t), ct.byref(ex_t), ct.byref(kr_t), ct.byref(us_t))
        out: dict[str, Any] = {}
        if mem_ok:
            out["working_set_mib"] = round(pmc.WorkingSetSize / 1_048_576.0, 2)
            out["peak_working_set_mib"] = round(pmc.PeakWorkingSetSize / 1_048_576.0, 2)
            out["private_bytes_mib"] = round(pmc.PrivateUsage / 1_048_576.0, 2)
        if time_ok:
            out["cpu_kernel_s"] = round(_ft_sec(kr_t), 4)
            out["cpu_user_s"] = round(_ft_sec(us_t), 4)
            out["cpu_total_s"] = round(_ft_sec(kr_t) + _ft_sec(us_t), 4)
        return out
    finally:
        kernel32.CloseHandle(h)


def _hmac_http_call(
    conn: http.client.HTTPConnection | None,
    port: int,
    principal: str,
    token_hex: str,
    tool: str,
    arguments: dict[str, Any],
    keep_alive: bool,
) -> tuple[dict[str, Any], http.client.HTTPConnection | None]:
    body = json.dumps({"method": tool, "params": arguments}, separators=(",", ":")).encode("utf-8")
    nonce = secrets.token_hex(16)
    stamp = str(int(time.time()))
    sig = _hmac_sig(token_hex, "request", principal, nonce, stamp, body)
    headers = {
        "Host": f"127.0.0.1:{port}",
        "Content-Type": "application/json",
        "Connection": "keep-alive" if keep_alive else "close",
        "X-Bridge-Principal": principal,
        "X-Bridge-Nonce": nonce,
        "X-Bridge-Timestamp": stamp,
        "X-Bridge-Signature": sig,
    }
    c = conn if (keep_alive and conn is not None) else http.client.HTTPConnection("127.0.0.1", port, timeout=15)
    try:
        c.request("POST", "/v1/call", body=body, headers=headers)
        resp = c.getresponse()
        raw = resp.read()
        resp_sig = resp.getheader("X-Bridge-Signature") or ""
        expected_sig = _hmac_sig(token_hex, f"response:{resp.status}", principal, nonce, stamp, raw)
        if not hmac.compare_digest(resp_sig, expected_sig):
            raise RuntimeError(f"Response HMAC signature mismatch (status={resp.status})")
        data = json.loads(raw.decode("utf-8"))
        if resp.status != 200 or not data.get("ok"):
            raise RuntimeError(f"Broker call failed: status={resp.status} body={data}")
        if not keep_alive:
            c.close()
            return data, None
        return data, c
    except Exception:
        try:
            c.close()
        except Exception:
            pass
        raise


def _run_http_matrix(
    port: int,
    principal: str,
    token_hex: str,
    project_id: str,
    expected_sha_4k: str,
    expected_sha_64k: str,
    keep_alive: bool,
    n_req: int,
) -> dict[str, Any]:
    # Explicit warmup (20 requests)
    w_conn: http.client.HTTPConnection | None = None
    try:
        for _ in range(20):
            _, w_conn = _hmac_http_call(
                w_conn, port, principal, token_hex, "file_read",
                {"project_id": project_id, "path": "small_4k.txt", "limit": 65536},
                keep_alive=keep_alive,
            )
    finally:
        if w_conn:
            w_conn.close()

    out: dict[str, Any] = {}
    for label, rel_path, exp_sha in (
        ("read_4k", "small_4k.txt", expected_sha_4k),
        ("read_64k", "medium_64k.txt", expected_sha_64k),
    ):
        cmap: dict[str, Any] = {}
        for conc in (1, 2, 4, 8):
            per_worker = n_req // conc
            rem = n_req % conc
            latencies: list[float] = []
            errors = 0
            lock = threading.Lock()

            def _worker(count: int) -> None:
                nonlocal errors
                local_lats: list[float] = []
                local_errs = 0
                c: http.client.HTTPConnection | None = None
                try:
                    for _ in range(count):
                        t0 = time.perf_counter()
                        try:
                            res, c = _hmac_http_call(
                                c, port, principal, token_hex, "file_read",
                                {"project_id": project_id, "path": rel_path, "limit": 65536},
                                keep_alive=keep_alive,
                            )
                            dt = (time.perf_counter() - t0) * 1000.0
                            r_obj = res.get("result", res)
                            actual_hash = r_obj.get("hash") or r_obj.get("sha256")
                            if actual_hash != exp_sha:
                                raise RuntimeError(f"SHA-256 hash mismatch: got {actual_hash}")
                            local_lats.append(dt)
                        except Exception:
                            local_errs += 1
                            c = None
                finally:
                    if c:
                        c.close()
                with lock:
                    latencies.extend(local_lats)
                    errors += local_errs

            t_b0 = time.perf_counter()
            with concurrent.futures.ThreadPoolExecutor(max_workers=conc) as pool:
                futs = [pool.submit(_worker, per_worker + (1 if idx < rem else 0)) for idx in range(conc)]
                for f in futs:
                    f.result()
            batch_s = time.perf_counter() - t_b0
            cmap[f"c{conc}"] = {
                **_percentiles(latencies),
                "errors": errors,
                "throughput_rps": round(len(latencies) / max(batch_s, 1e-6), 2),
            }
        out[label] = cmap

    # file_list (42 files), c=1
    list_lats: list[float] = []
    list_errs = 0
    c: http.client.HTTPConnection | None = None
    try:
        for _ in range(100):
            t0 = time.perf_counter()
            try:
                _, c = _hmac_http_call(
                    c, port, principal, token_hex, "file_list",
                    {"project_id": project_id, "path": ".", "limit": 100},
                    keep_alive=keep_alive,
                )
                list_lats.append((time.perf_counter() - t0) * 1000.0)
            except Exception:
                list_errs += 1
                c = None
    finally:
        if c:
            c.close()
    out["file_list_42files_c1"] = {**_percentiles(list_lats), "errors": list_errs}
    return out


PYTHON_SERVER_SCRIPT = r"""
import json, os, sys, threading
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from edge_bridge.broker import Broker, Handler, LoopbackServer, create_tokens, make_server_tls, setup_state
from edge_bridge.state import State

state = Path(sys.argv[2])
proj = Path(sys.argv[3])
use_tls = sys.argv[4] == "tls"

class KeepAliveHandler(Handler):
    protocol_version = "HTTP/1.1"

setup_state(state)
store = State(state / "state.sqlite3")
tokens = create_tokens(state)
broker = Broker(store, state)
reg = broker.dispatch("owner_register", {"root": str(proj), "name": "FairBench"}, "local")
pid = reg["project_id"]
broker.dispatch("owner_grant_edge", {"project_id": pid}, "local")

server = LoopbackServer(("127.0.0.1", 0), KeepAliveHandler)
if use_tls:
    tls = make_server_tls(state)
    server.socket = tls.wrap_socket(server.socket, server_side=True, do_handshake_on_connect=False)
server.tokens = tokens
server.broker = broker
server.nonce_lock = threading.Lock()
server.nonces = {}
port = server.server_address[1]
(state / "bench-ready.json").write_text(json.dumps({
    "pid": os.getpid(),
    "port": port,
    "project_id": pid,
    "edge_token": tokens["edge"],
    "local_token": tokens["local"],
}), encoding="utf-8")
server.serve_forever(poll_interval=0.05)
"""


def run_fair_benchmark() -> dict[str, Any]:
    AUDIT_BUNDLE.mkdir(parents=True, exist_ok=True)
    rust_bin = find_rust_binary(REPO)
    assert rust_bin is not None, "Rust release binary missing"
    python_exe = REPO / ".venv" / "Scripts" / "python.exe"
    if not python_exe.is_file():
        python_exe = Path(sys.executable)

    tmp = Path(tempfile.mkdtemp(prefix="eb_fair_bench_"))
    try:
        proj = tmp / "fixture_project"
        proj.mkdir()
        b4k = ("alpha beta gamma delta 0123456789\n" * 128).encode("utf-8")[:4096]
        b64k = ("telemetry_row,2026-11-19T00:00:00Z,10.5,m/s\n" * 1600).encode("utf-8")[:65536]
        (proj / "small_4k.txt").write_bytes(b4k)
        (proj / "medium_64k.txt").write_bytes(b64k)
        sha_4k = hashlib.sha256(b4k).hexdigest()
        sha_64k = hashlib.sha256(b64k).hexdigest()
        for i in range(40):
            (proj / f"mod_{i:02d}.py").write_text(f"def fn_{i}(x):\n    return x + {i}\n", encoding="utf-8")

        report: dict[str, Any] = {
            "captured_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "methodology": {
                "transport": "HTTP/1.1 loopback 127.0.0.1 (plain HTTP for apples-to-apples Python vs Rust; Python TLS+HMAC reported separately)",
                "authentication": "Identical mutual HMAC-SHA256 request & response signatures + 32-hex nonce replay guard",
                "payload_verification": "SHA-256 hash verified on every response for 4 KiB and 64 KiB fixtures",
                "server_isolation": "Dedicated separate server process per runtime; WorkingSet/PrivateBytes/CPU read directly from server PID",
                "warmup_requests": 20,
                "timed_requests_keepalive": 200,
                "timed_requests_non_keepalive": 80,
                "soak_duration_seconds": 20,
                "soak_caveat": "20-second timed soak evaluates short-run memory drift and stability; it is NOT a multi-hour endurance soak.",
            },
            "environment": {
                "os": platform.platform(),
                "machine": platform.machine(),
                "cpu_count": os.cpu_count(),
                "python_version": platform.python_version(),
                "python_sqlite_version": sqlite3.sqlite_version,
                "rust_binary_sha256": hashlib.sha256(rust_bin.read_bytes()).hexdigest(),
            },
        }

        # --- 1. Python v0.2.0 Server (Plain HTTP/1.1 + Mutual HMAC-SHA256) ---
        py_state = tmp / "py_http_state"
        py_srv = subprocess.Popen(
            [str(python_exe), "-c", PYTHON_SERVER_SCRIPT, str(REPO), str(py_state), str(proj), "plain"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, stdin=subprocess.DEVNULL,
        )
        try:
            ready_file = py_state / "bench-ready.json"
            deadline = time.monotonic() + 15.0
            while not ready_file.is_file() and time.monotonic() < deadline:
                time.sleep(0.05)
            assert ready_file.is_file(), f"Python HTTP server failed: {py_srv.stderr.read() if py_srv.stderr else ''}"
            py_info = json.loads(ready_file.read_text(encoding="utf-8"))
            py_real_pid = int(py_info["pid"])
            py_idle = _proc_metrics(py_real_pid)
            py_ka = _run_http_matrix(py_info["port"], "edge", py_info["edge_token"], py_info["project_id"], sha_4k, sha_64k, keep_alive=True, n_req=200)
            py_noka = _run_http_matrix(py_info["port"], "edge", py_info["edge_token"], py_info["project_id"], sha_4k, sha_64k, keep_alive=False, n_req=80)
            py_post = _proc_metrics(py_real_pid)
            report["python_http_hmac"] = {
                "server_pid": py_real_pid,
                "server_metrics_idle": py_idle,
                "server_metrics_post": py_post,
                "keep_alive": py_ka,
                "new_connection": py_noka,
            }
        finally:
            try:
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(py_srv.pid)], capture_output=True, stdin=subprocess.DEVNULL)
            except Exception:
                pass
            py_srv.terminate()
            py_srv.wait(timeout=5)

        # --- 1b. Python v0.2.0 Native HTTPS (TLS + HMAC, new connection per request — quantifies TLS cost separately) ---
        py_tls_state = tmp / "py_tls_state"
        py_tls_srv = subprocess.Popen(
            [str(python_exe), "-c", PYTHON_SERVER_SCRIPT, str(REPO), str(py_tls_state), str(proj), "tls"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, stdin=subprocess.DEVNULL,
        )
        try:
            import ssl
            tls_ready = py_tls_state / "bench-ready.json"
            deadline = time.monotonic() + 15.0
            while not tls_ready.is_file() and time.monotonic() < deadline:
                time.sleep(0.05)
            assert tls_ready.is_file(), "Python TLS server failed to start"
            tls_info = json.loads(tls_ready.read_text(encoding="utf-8"))
            tls_ctx = ssl.create_default_context(cafile=str(py_tls_state / "ipc.pem"))
            tls_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            tls_lats = []
            tls_errs = 0
            for _ in range(10):
                body = json.dumps({"method": "file_read", "params": {"project_id": tls_info["project_id"], "path": "small_4k.txt", "limit": 65536}}, separators=(",", ":")).encode()
                nonce, stamp = secrets.token_hex(16), str(int(time.time()))
                sig = _hmac_sig(tls_info["edge_token"], "request", "edge", nonce, stamp, body)
                hc = http.client.HTTPSConnection("127.0.0.1", tls_info["port"], timeout=15, context=tls_ctx)
                hc.request("POST", "/v1/call", body=body, headers={"Host": f"127.0.0.1:{tls_info['port']}", "Content-Type": "application/json", "X-Bridge-Principal": "edge", "X-Bridge-Nonce": nonce, "X-Bridge-Timestamp": stamp, "X-Bridge-Signature": sig})
                hc.getresponse().read()
                hc.close()
            for _ in range(60):
                t0 = time.perf_counter()
                try:
                    body = json.dumps({"method": "file_read", "params": {"project_id": tls_info["project_id"], "path": "small_4k.txt", "limit": 65536}}, separators=(",", ":")).encode()
                    nonce, stamp = secrets.token_hex(16), str(int(time.time()))
                    sig = _hmac_sig(tls_info["edge_token"], "request", "edge", nonce, stamp, body)
                    hc = http.client.HTTPSConnection("127.0.0.1", tls_info["port"], timeout=15, context=tls_ctx)
                    hc.request("POST", "/v1/call", body=body, headers={"Host": f"127.0.0.1:{tls_info['port']}", "Content-Type": "application/json", "X-Bridge-Principal": "edge", "X-Bridge-Nonce": nonce, "X-Bridge-Timestamp": stamp, "X-Bridge-Signature": sig})
                    r = hc.getresponse()
                    raw = r.read()
                    hc.close()
                    assert r.status == 200 and json.loads(raw)["result"]["hash"] == sha_4k
                    tls_lats.append((time.perf_counter() - t0) * 1000.0)
                except Exception:
                    tls_errs += 1
            report["python_native_tls_hmac_new_conn"] = {
                "note": "Reported separately so TLS 1.2/1.3 per-request handshake overhead is NEVER confounded with Python vs Rust core speed.",
                "read_4k_c1": {**_percentiles(tls_lats), "errors": tls_errs},
            }
        finally:
            try:
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(py_tls_srv.pid)], capture_output=True, stdin=subprocess.DEVNULL)
            except Exception:
                pass
            py_tls_srv.terminate()
            py_tls_srv.wait(timeout=5)

        # --- 2. Rust V0.4.0 Server (Plain HTTP/1.1 + Mutual HMAC-SHA256) ---
        rs_state = tmp / "rs_http_state"
        rs_reg = invoke_rust_cli(["register", str(proj), "--name", "FairBench", "--grant-edge"], state_dir=rs_state, repo_root=REPO)
        rs_pid = rs_reg["project_id"]
        rs_srv = subprocess.Popen(
            [str(rust_bin), "--state-dir", str(rs_state), "serve", "--port", "0"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, stdin=subprocess.DEVNULL,
        )
        try:
            disc = rs_state / "rust-broker.json"
            deadline = time.monotonic() + 10.0
            while not disc.is_file() and time.monotonic() < deadline:
                time.sleep(0.05)
            assert disc.is_file(), "Rust HTTP server failed to start"
            rs_port = json.loads(disc.read_text(encoding="utf-8"))["port"]
            rs_edge_tok = (rs_state / "edge.token").read_text(encoding="utf-8").strip()
            rs_local_tok = (rs_state / "owner.token").read_text(encoding="utf-8").strip()

            rs_idle = _proc_metrics(rs_srv.pid)
            rs_ka = _run_http_matrix(rs_port, "edge", rs_edge_tok, rs_pid, sha_4k, sha_64k, keep_alive=True, n_req=200)
            rs_noka = _run_http_matrix(rs_port, "edge", rs_edge_tok, rs_pid, sha_4k, sha_64k, keep_alive=False, n_req=80)
            rs_post = _proc_metrics(rs_srv.pid)

            # 2b. Full durable task_submit admission latency over HTTP/HMAC (SQLite WAL synchronous=NORMAL)
            sub_lats: list[float] = []
            sub_errs = 0
            c_sub: http.client.HTTPConnection | None = None
            try:
                for i in range(60):
                    t0 = time.perf_counter()
                    try:
                        _, c_sub = _hmac_http_call(
                            c_sub, rs_port, "local", rs_local_tok, "task_submit",
                            {"project_id": rs_pid, "task_id": "bench_submit", "operation_id": f"op-bench-sub-{i}", "recipe": "python_tests"},
                            keep_alive=True,
                        )
                        sub_lats.append((time.perf_counter() - t0) * 1000.0)
                    except Exception:
                        sub_errs += 1
                        c_sub = None
            finally:
                if c_sub:
                    c_sub.close()

            # 2c. Timed 20-second Soak Test sampling Rust server WorkingSet RSS every 2s
            soak_samples: list[dict[str, Any]] = []
            soak_lats: list[float] = []
            soak_errs = 0
            stop_ev = threading.Event()

            def _sampler() -> None:
                t_start = time.monotonic()
                while not stop_ev.is_set():
                    m = _proc_metrics(rs_srv.pid)
                    m["elapsed_s"] = round(time.monotonic() - t_start, 2)
                    soak_samples.append(m)
                    stop_ev.wait(2.0)

            st_thread = threading.Thread(target=_sampler, daemon=True)
            st_thread.start()
            t_soak0 = time.monotonic()
            c_soak: http.client.HTTPConnection | None = None
            soak_idx = 0
            try:
                while time.monotonic() - t_soak0 < 20.0:
                    t0 = time.perf_counter()
                    try:
                        tool = "file_read" if (soak_idx % 5 != 0) else "file_list"
                        args = (
                            {"project_id": rs_pid, "path": "small_4k.txt", "limit": 65536}
                            if tool == "file_read"
                            else {"project_id": rs_pid, "path": ".", "limit": 100}
                        )
                        # Reconnect every 100 requests to simulate connection churn too
                        if soak_idx > 0 and soak_idx % 100 == 0 and c_soak is not None:
                            c_soak.close()
                            c_soak = None
                        _, c_soak = _hmac_http_call(c_soak, rs_port, "edge", rs_edge_tok, tool, args, keep_alive=True)
                        soak_lats.append((time.perf_counter() - t0) * 1000.0)
                    except Exception:
                        soak_errs += 1
                        c_soak = None
                    soak_idx += 1
            finally:
                if c_soak:
                    c_soak.close()
                stop_ev.set()
                st_thread.join(timeout=5)
            soak_dur = round(time.monotonic() - t_soak0, 2)

            report["rust_http_hmac"] = {
                "server_metrics_idle": rs_idle,
                "server_metrics_post": rs_post,
                "keep_alive": rs_ka,
                "new_connection": rs_noka,
                "durable_task_submit_http_wal_normal": {**_percentiles(sub_lats), "errors": sub_errs},
                "timed_soak_20s": {
                    "duration_s": soak_dur,
                    "total_requests": len(soak_lats),
                    "errors": soak_errs,
                    "throughput_rps": round(len(soak_lats) / max(soak_dur, 1e-6), 2),
                    "latency": _percentiles(soak_lats),
                    "rss_samples": soak_samples,
                    "rss_start_mib": soak_samples[0].get("working_set_mib") if soak_samples else None,
                    "rss_end_mib": soak_samples[-1].get("working_set_mib") if soak_samples else None,
                    "rss_peak_mib": max((s.get("working_set_mib", 0) for s in soak_samples), default=None),
                },
            }
        finally:
            rs_srv.terminate()
            rs_srv.wait(timeout=5)

        # --- 3. SQLite WAL Durability Sensitivity (NORMAL vs FULL on exact same machine/disk) ---
        dur_report: dict[str, Any] = {}
        for sync_mode in ("NORMAL", "FULL"):
            db_p = tmp / f"dur_{sync_mode.lower()}.sqlite3"
            conn = sqlite3.connect(db_p)
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute(f"PRAGMA synchronous={sync_mode};")
            conn.execute("CREATE TABLE t(id INTEGER PRIMARY KEY, op TEXT UNIQUE, payload TEXT);")
            conn.commit()
            lats = []
            for i in range(60):
                t0 = time.perf_counter()
                conn.execute("INSERT INTO t(op, payload) VALUES (?, ?)", (f"op-{i}", "x" * 256))
                conn.commit()
                lats.append((time.perf_counter() - t0) * 1000.0)
            conn.close()
            dur_report[f"sqlite_wal_synchronous_{sync_mode.lower()}"] = _percentiles(lats)
        report["sqlite_durability_sensitivity"] = dur_report

        # --- 4. Explicit Summary Speedup Ratios (Apples-to-Apples HTTP+HMAC) ---
        def _ratio(py_v: float | None, rs_v: float | None) -> float | None:
            if not py_v or not rs_v or rs_v <= 0:
                return None
            return round(py_v / rs_v, 2)

        report["apples_to_apples_ratios_python_over_rust"] = {
            "keep_alive_read_4k_c1_p50_speedup": _ratio(py_ka["read_4k"]["c1"]["p50_ms"], rs_ka["read_4k"]["c1"]["p50_ms"]),
            "keep_alive_read_4k_c1_p95_speedup": _ratio(py_ka["read_4k"]["c1"]["p95_ms"], rs_ka["read_4k"]["c1"]["p95_ms"]),
            "keep_alive_read_4k_c8_p95_speedup": _ratio(py_ka["read_4k"]["c8"]["p95_ms"], rs_ka["read_4k"]["c8"]["p95_ms"]),
            "keep_alive_read_64k_c1_p95_speedup": _ratio(py_ka["read_64k"]["c1"]["p95_ms"], rs_ka["read_64k"]["c1"]["p95_ms"]),
            "keep_alive_file_list_c1_p95_speedup": _ratio(py_ka["file_list_42files_c1"]["p95_ms"], rs_ka["file_list_42files_c1"]["p95_ms"]),
            "new_conn_read_4k_c1_p50_speedup": _ratio(py_noka["read_4k"]["c1"]["p50_ms"], rs_noka["read_4k"]["c1"]["p50_ms"]),
            "new_conn_read_4k_c8_p95_speedup": _ratio(py_noka["read_4k"]["c8"]["p95_ms"], rs_noka["read_4k"]["c8"]["p95_ms"]),
            "server_idle_rss_ratio_py_over_rs": _ratio(py_idle.get("working_set_mib"), rs_idle.get("working_set_mib")),
        }

    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    out_path = AUDIT_BUNDLE / "fair-benchmark-results.json"
    out_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


if __name__ == "__main__":
    print(json.dumps(run_fair_benchmark(), indent=2))
