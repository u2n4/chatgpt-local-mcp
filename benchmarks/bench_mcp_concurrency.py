"""Measure authenticated loopback MCP clients using a disposable Rust broker.

Run with --output-dir NEW_DIRECTORY. Client processes use independent persistent
HTTP connections and intentionally reuse JSON-RPC IDs across connections. The
synthetic clients exercise the transport and broker, not programming providers.
"""
from __future__ import annotations

import argparse
from collections import Counter
import ctypes as ct
from ctypes import wintypes as wt
from datetime import datetime, timezone
import hashlib
import http.client
import json
import math
import multiprocessing as mp
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time

LEGACY = "2025-11-25"
MODERN = "2026-07-28"
READ_SIZE = 65_536
SLOW_BATCH_ITEMS = 8
SLOW_READ_DELAY = 0.175


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def write_json(path, obj):
    pending = path.with_suffix(".partial")
    pending.write_text(json.dumps(obj, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    pending.replace(path)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def fixture_bytes(label):
    marker = f"BRIDGE-BENCH-{label}\n".encode("ascii")
    return (marker * (READ_SIZE // len(marker) + 1))[:READ_SIZE]


def run_cli(cli, *args):
    proc = subprocess.run(
        [*cli, *map(str, args)], capture_output=True, text=True, encoding="utf-8",
        check=True, timeout=30,
    )
    return json.loads(proc.stdout)


class RpcClient:
    def __init__(self, port, token, protocol, label):
        self.port = port
        self.token = token
        self.protocol = protocol
        self.label = label
        self.connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)

    def send(self, request_id, method, params):
        headers = {
            "Accept": "application/json, text/event-stream",
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }
        frame = {"jsonrpc": "2.0", "method": method, "params": dict(params)}
        if request_id is not None:
            frame["id"] = request_id
        if method != "initialize":
            headers["MCP-Protocol-Version"] = self.protocol
        if self.protocol == MODERN:
            headers["Mcp-Method"] = method
            if method == "tools/call":
                headers["Mcp-Name"] = params["name"]
            frame["params"]["_meta"] = {"io.modelcontextprotocol/protocolVersion": MODERN}
        self.connection.request("POST", "/mcp", json.dumps(frame), headers)
        sock = self.connection.sock
        require(sock is not None, "HTTP connection has no socket")
        return sock.getsockname()[1]

    def receive(self, request_id):
        response = self.connection.getresponse()
        raw = response.read(4 * 1024 * 1024 + 1)
        require(len(raw) <= 4 * 1024 * 1024, "response limit exceeded")
        frame = json.loads(raw) if raw else {}
        wait_header = response.getheader("x-bridge-queue-wait-ms")
        wait_ms = None if wait_header is None else float(wait_header)
        if wait_ms is not None:
            require(math.isfinite(wait_ms) and wait_ms >= 0, "invalid queue wait")
        if request_id is not None and ("result" in frame or "error" in frame):
            require(frame.get("id") == request_id, "JSON-RPC response ID mismatch")
        return response.status, frame, wait_ms

    def call(self, request_id, method, params, read_delay=0.0):
        port = self.send(request_id, method, params)
        if read_delay:
            time.sleep(read_delay)
        status, frame, queue_wait = self.receive(request_id)
        return status, frame, queue_wait, port

    def handshake(self):
        if self.protocol == MODERN:
            status, frame, _, _ = self.call(0, "server/discover", {})
            require(status == 200 and MODERN in frame["result"]["supportedVersions"],
                    "modern discovery failed")
            require(frame["result"]["resultType"] == "complete", "modern result type missing")
        else:
            status, frame, _, _ = self.call(0, "initialize", {
                "protocolVersion": LEGACY, "capabilities": {},
                "clientInfo": {"name": self.label, "version": "1"},
            })
            require(status == 200 and frame["result"]["protocolVersion"] == LEGACY,
                    "legacy initialization failed")
            status, _, _, _ = self.call(None, "notifications/initialized", {})
            require(status in (200, 202, 204), "initialization notification failed")
        status, frame, _, _ = self.call(0, "tools/list", {})
        require(status == 200 and {"file_read", "file_read_batch", "file_search", "git_status", "project_status"}
                <= {tool["name"] for tool in frame["result"]["tools"]}, "required tools missing")

    def close(self):
        self.connection.close()


def tool_result(status, frame):
    """Return an error code or a checked successful MCP result."""
    result = frame.get("result", {})
    structured = result.get("structuredContent", {})
    for layer in (structured, frame.get("error", {}).get("data"), frame):
        if isinstance(layer, dict) and layer.get("code") == "RESOURCE_BUSY":
            return layer["code"], None, layer.get("details", {})
    if result.get("isError"):
        return structured["code"], None, {}
    require(status == 200 and result.get("isError") is False, f"unexpected tool HTTP status {status}")
    require(isinstance(structured.get("result"), dict), "missing structured tool result")
    return "OK", structured["result"], {}


def command_for(client, index, pressure, project, label):
    read = ("file_read", {"project_id": project, "path": "payload.txt", "limit": READ_SIZE})
    if pressure and client == 0 and index % 8 == 0:
        items = [{"path": "payload.txt", "limit": READ_SIZE} for _ in range(SLOW_BATCH_ITEMS)]
        return "file_read_batch", {"project_id": project, "items": items}
    search = ("file_search", {"project_id": project, "query": f"BENCH-MARKER-{label}", "limit": 1})
    git = ("git_status", {"project_id": project, "max_entries": 30})
    info = ("project_status", {"project_id": project})
    if pressure and client != 0:
        return (search, search, read, info, git)[index % 5]
    if client == 0 or client % 3 == 0:
        return (read, search, info, read)[index % 4]
    if client % 3 == 1:
        return (git, read, info, read)[index % 4]
    return (info, read, search, read)[index % 4]


def check_result(tool, result, project, label, expected_bytes, expected_hash):
    if tool == "file_read":
        require(result["content"].encode("ascii") == expected_bytes
                and result["hash"] == expected_hash, "read returned unexpected bytes or hash")
    elif tool == "file_read_batch":
        require(result["project_id"] == project and len(result["items"]) == SLOW_BATCH_ITEMS,
                "batch result identity or item count mismatch")
        for item in result["items"]:
            require(item["ok"], "batch read item failed")
            check_result("file_read", item["result"], project, label, expected_bytes, expected_hash)
    elif tool == "file_search":
        hits = result["hits"]
        require(len(hits) == 1 and hits[0]["path"] == "zz-marker.txt"
                and hits[0]["preview"] == f"BENCH-MARKER-{label}",
                "search returned another project's data or no expected hit")
    elif tool == "project_status":
        require(result["project"]["project_id"] == project, "project status identity mismatch")
    elif tool == "git_status":
        require(result["branch"] == f"bench-{label}", "git branch identity mismatch")


def client_work(out, port, token, idx, project, label, seconds, gap, pressure,
                ready, start_event):
    protocol = LEGACY if idx % 2 == 0 else MODERN
    client = RpcClient(port, token, protocol, f"bench-{idx:02}")
    path = out / f"client-{idx:02}.jsonl"
    expected_bytes = fixture_bytes(label)
    expected_hash = digest(expected_bytes)
    with path.open("x", encoding="utf-8", buffering=1) as log:
        def record(sample):
            log.write(json.dumps(sample, separators=(",", ":"), allow_nan=False) + "\n")

        try:
            client.handshake()
            ready.set()
            require(start_event.wait(40), "client start barrier timed out")
            end = time.perf_counter() + seconds
            index = 1
            while time.perf_counter() < end:
                tool, args = command_for(idx, index, pressure, project, label)
                params = {"name": tool, "arguments": args}
                started = time.perf_counter_ns()
                slow_delay = SLOW_READ_DELAY if tool == "file_read_batch" else 0.0
                record_row = {"event": "call", "client_index": idx,
                              "request_id": index, "start_ns": started,
                              "tool": tool, "slow_read_delay_ms": slow_delay * 1000}
                try:
                    status, frame, queue_wait, local_port = client.call(
                        index, "tools/call", params, read_delay=slow_delay,
                    )
                    code, value, details = tool_result(status, frame)
                    if code == "OK":
                        check_result(tool, value, project, label, expected_bytes, expected_hash)
                    elif code == "RESOURCE_BUSY":
                        require(details.get("retry_after_ms", 0) > 0, "missing backpressure retry window")
                        record_row.update(busy_reason=details.get("reason"),
                                          retry_after_ms=details["retry_after_ms"])
                    record_row.update(code=code, local_port=local_port, http_status=status,
                                      queue_wait_ms=queue_wait)
                except (TimeoutError, OSError, http.client.HTTPException) as exc:
                    record_row["code"] = "TIMEOUT" if isinstance(exc, TimeoutError) else type(exc).__name__
                    client.close()
                except (AssertionError, KeyError, UnicodeError, ValueError) as exc:
                    record_row["code"] = "RESPONSE_ASSERTION_FAILED"
                    record_row["check"] = str(exc) if isinstance(exc, AssertionError) else type(exc).__name__
                finally:
                    record_row["end_ns"] = time.perf_counter_ns()
                    record(record_row)
                if idx == 0 and index == 2:
                    interrupted = time.perf_counter_ns()
                    try:
                        abandoned_port = client.send(-1, "tools/call", {
                            "name": "file_search", "arguments": {
                                "project_id": project, "query": f"BENCH-MARKER-{label}",
                            },
                        })
                    finally:
                        client.close()
                    status, pong, _, reconnect_port = client.call(-2, "ping", {})
                    check = status == 200 and "result" in pong and reconnect_port != abandoned_port
                    record({"event": "disconnect_reconnect", "start_ns": interrupted,
                            "end_ns": time.perf_counter_ns(), "abandoned_local_port": abandoned_port,
                            "reconnect_local_port": reconnect_port, "ok": check})
                index += 1
                if gap:
                    time.sleep(min(gap, max(0.0, end - time.perf_counter())))
        except Exception as exc:
            record({"event": "client_failure", "error_type": type(exc).__name__,
                    "check": str(exc) if isinstance(exc, AssertionError) else None})
            raise
        finally:
            client.close()


class WinProcessTimes(ct.Structure):
    _fields_ = [("low", wt.DWORD), ("high", wt.DWORD)]

    def seconds(self):
        return ((self.high << 32) | self.low) / 10_000_000


class WinMemoryCounters(ct.Structure):
    _fields_ = [("size", wt.DWORD), ("page_faults", wt.DWORD),
                ("peak_working_set", ct.c_size_t), ("working_set", ct.c_size_t),
                ("peak_paged_pool", ct.c_size_t), ("paged_pool", ct.c_size_t),
                ("peak_nonpaged_pool", ct.c_size_t), ("nonpaged_pool", ct.c_size_t),
                ("pagefile", ct.c_size_t), ("peak_pagefile", ct.c_size_t),
                ("private_bytes", ct.c_size_t)]


def resources(pid):
    if os.name != "nt":
        return {}
    kernel = ct.WinDLL("kernel32", use_last_error=True)
    psapi = ct.WinDLL("psapi", use_last_error=True)
    kernel.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
    kernel.OpenProcess.restype = wt.HANDLE
    kernel.CloseHandle.argtypes = [wt.HANDLE]
    kernel.CloseHandle.restype = wt.BOOL
    kernel.GetProcessTimes.argtypes = [wt.HANDLE] + [ct.POINTER(WinProcessTimes)] * 4
    kernel.GetProcessTimes.restype = wt.BOOL
    kernel.GetProcessHandleCount.argtypes = [wt.HANDLE, ct.POINTER(wt.DWORD)]
    kernel.GetProcessHandleCount.restype = wt.BOOL
    psapi.GetProcessMemoryInfo.argtypes = [wt.HANDLE, ct.POINTER(WinMemoryCounters), wt.DWORD]
    psapi.GetProcessMemoryInfo.restype = wt.BOOL

    handle = kernel.OpenProcess(0x1000 | 0x0010, False, pid)
    if not handle:
        return {"probe_error": ct.get_last_error()}
    try:
        memory = WinMemoryCounters()
        memory.size = ct.sizeof(memory)
        times = [WinProcessTimes() for _ in range(4)]
        handles = wt.DWORD()
        measured = {}
        if psapi.GetProcessMemoryInfo(handle, ct.byref(memory), memory.size):
            measured["working_set_bytes"] = memory.working_set
            measured["peak_working_set_bytes"] = memory.peak_working_set
            measured["private_bytes"] = memory.private_bytes
        if kernel.GetProcessTimes(handle, *(ct.byref(value) for value in times)):
            measured["cpu_seconds"] = times[2].seconds() + times[3].seconds()
        if kernel.GetProcessHandleCount(handle, ct.byref(handles)):
            measured["open_handles"] = handles.value
        return measured
    finally:
        kernel.CloseHandle(handle)


def sample_broker(pid, state):
    wal = state / "state.sqlite3-wal"
    try:
        wal_bytes = wal.stat().st_size
    except FileNotFoundError:
        wal_bytes = 0
    return {"at_ns": time.perf_counter_ns(), "wal_bytes": wal_bytes, **resources(pid)}


def percentile(samples):
    ordered = sorted(samples)
    if not ordered:
        return None
    return {f"p{p}": round(ordered[max(0, math.ceil(len(ordered) * p / 100) - 1)], 3)
            for p in (50, 95, 99)} | {"n": len(ordered), "max": round(ordered[-1], 3)}


def stats(rows):
    codes = Counter(row["code"] for row in rows)
    window_ns = (max(row["end_ns"] for row in rows) - min(row["start_ns"] for row in rows)
                 if rows else 0)
    return {
        "counts": dict(codes),
        "success_latency_ms": percentile((row["end_ns"] - row["start_ns"]) / 1e6
                                         for row in rows if row["code"] == "OK"),
        "successful_fast_latency_ms": percentile(
            (row["end_ns"] - row["start_ns"]) / 1e6 for row in rows
            if row["code"] == "OK" and not row["slow_read_delay_ms"]
            and row["tool"] in ("project_status", "file_read")),
        "busy_latency_ms": percentile((row["end_ns"] - row["start_ns"]) / 1e6
                                      for row in rows if row["code"] == "RESOURCE_BUSY"),
        "busy_reasons": dict(Counter(row.get("busy_reason") or "unspecified" for row in rows
                                     if row["code"] == "RESOURCE_BUSY")),
        "queue_wait_ms": percentile(row["queue_wait_ms"] for row in rows
                                    if row.get("queue_wait_ms") is not None),
        "throughput_ok_rps": round(codes["OK"] * 1e9 / window_ns, 3) if window_ns else 0.0,
        "connection_ports": sorted({row["local_port"] for row in rows if "local_port" in row}),
        "slow_reads_attempted": sum(bool(row["slow_read_delay_ms"]) for row in rows),
        "slow_reads": sum(bool(row["slow_read_delay_ms"]) and row["code"] == "OK" for row in rows),
    }


def overlap(rows):
    points = [(row[key], delta) for row in rows if row["code"] == "OK"
              for key, delta in (("start_ns", 1), ("end_ns", -1))]
    current = peak = 0
    for _, delta in sorted(points):
        current += delta
        peak = max(peak, current)
    return peak


def phase(out, broker, state, port, token, projects, count, duration, interval, pressure):
    out.mkdir()
    ctx = mp.get_context("spawn")
    start_event = ctx.Event()
    ready_events = [ctx.Event() for _ in range(count)]
    clients = [
        ctx.Process(target=client_work, args=(
            out, port, token, idx, *projects[idx % len(projects)], duration, interval,
            pressure, ready_events[idx], start_event,
        ))
        for idx in range(count)
    ]
    started = []
    resources_path = out / "broker-resources.jsonl"
    with resources_path.open("x", encoding="utf-8", buffering=1) as telemetry:
        def sample():
            telemetry.write(json.dumps(sample_broker(broker.pid, state)) + "\n")

        sample()
        try:
            for process in clients:
                process.start()
                started.append(process)
            start_limit = time.perf_counter() + 35
            for event in ready_events:
                require(event.wait(max(0, start_limit - time.perf_counter())), "client did not initialize")
            begin = time.perf_counter_ns()
            start_event.set()
            deadline = time.perf_counter() + duration + 20
            next_sample = time.perf_counter()
            while any(process.is_alive() for process in clients):
                require(broker.poll() is None, "broker exited during workload")
                require(time.perf_counter() < deadline, "client deadline exceeded")
                if time.perf_counter() >= next_sample:
                    sample()
                    next_sample = time.perf_counter() + 5.0
                time.sleep(0.1)
            end = time.perf_counter_ns()
            sample()
        finally:
            for process in started:
                if process.is_alive():
                    process.terminate()
                process.join(5)
    all_rows = []
    by_client = {}
    disconnect = None
    for idx, process in enumerate(clients):
        client_id = f"client-{idx:02}"
        events = [json.loads(line) for line in (out / f"{client_id}.jsonl").read_text(encoding="utf-8").splitlines()]
        calls = [event for event in events if event["event"] == "call"]
        all_rows.extend(calls)
        by_client[client_id] = {
            "process_id": process.pid, "protocol": LEGACY if idx % 2 == 0 else MODERN,
            "exit_code": process.exitcode, **stats(calls),
            "by_tool": {tool: stats([row for row in calls if row["tool"] == tool])
                        for tool in sorted({row["tool"] for row in calls})},
        }
        if idx == 0:
            disconnect = next((event for event in events if event["event"] == "disconnect_reconnect"), None)
    total = stats(all_rows)
    if disconnect:
        disconnect["other_successful_requests_overlapped"] = sum(
            row["client_index"] != 0 and row["code"] == "OK"
            and row["start_ns"] < disconnect["end_ns"] and disconnect["start_ns"] < row["end_ns"]
            for row in all_rows)
    peak = overlap(all_rows)
    allowed_codes = {"OK", "RESOURCE_BUSY"} if pressure else {"OK"}
    elapsed = (end - begin) / 1e9
    fast_latency = total["successful_fast_latency_ms"]
    # The 100 ms budget in the acceptance document applies to normal
    # 8-client metadata and <=64 KiB reads.
    budget = ({"target_ms": 100, "observed_p95_ms": fast_latency["p95"],
               "passed": fast_latency["p95"] <= 100} if count == 8 and fast_latency else None)
    passed = (peak >= min(3, count) and elapsed >= duration
              and bool(disconnect and disconnect["ok"]) and (count != 8 or bool(budget and budget["passed"]))
              and (not pressure or total["slow_reads"] > 0)
              and all(v["exit_code"] == 0 and v["counts"].get("OK", 0) > 0
                      and set(v["counts"]) <= allowed_codes for v in by_client.values()))
    return {"requested_seconds": duration, "elapsed_seconds": round(elapsed, 3),
            "interval_seconds": interval, "client_count": count, "pressure": pressure,
            "window_start_ns": begin, "window_end_ns": end, "fast_latency_budget": budget,
            "peak_overlapping_successful_requests": peak, "disconnect_reconnect": disconnect,
            "total": total, "clients": by_client, "passed": passed}


def check_edge_boundaries(port, token, public_project, private_project):
    client = RpcClient(port, token, LEGACY, "bench-boundaries")
    try:
        client.handshake()
        probes = (
            ("file_read", {"project_id": private_project, "path": "payload.txt"},
             {"PROJECT_NOT_GRANTED", "BRIDGE_POLICY_DENIED"}),
            ("task_submit", {"project_id": public_project, "task_id": "bench-denied",
                             "operation_id": "bench-denied"}, {"BRIDGE_POLICY_DENIED"}),
            ("file_write", {"project_id": public_project, "path": "payload.txt",
                            "content": "must not write", "operation_id": "deny-mutation"},
             {"BRIDGE_POLICY_DENIED"}),
        )
        outcomes = {}
        for idx, (name, arguments, expected) in enumerate(probes, 1):
            status, frame, _, _ = client.call(idx, "tools/call", {"name": name, "arguments": arguments})
            code, _, _ = tool_result(status, frame)
            outcomes[name] = {"code": code, "passed": code in expected}
        return outcomes
    finally:
        client.close()


def prepare(cli, sandbox):
    projects = []
    for label in ("alpha", "bravo", "charlie", "private"):
        project = sandbox / f"project-{label}"
        project.mkdir()
        (project / "payload.txt").write_bytes(fixture_bytes(label))
        (project / "zz-marker.txt").write_text(f"BENCH-MARKER-{label}\n", encoding="ascii")
        if label != "private":
            corpus = project / "corpus"
            corpus.mkdir()
            file_bytes = b"Search load fixture with no marker.\n" * 1800
            for index in range(32):
                (corpus / f"row-{index:02}.txt").write_bytes(file_bytes)
        subprocess.run(
            ["git", "-C", str(project), "init", "--quiet", "--initial-branch", f"bench-{label}"],
            check=True, capture_output=True, timeout=10,
        )
        args = ["register", project, "--name", f"Benchmark {label}"]
        if label != "private":
            args.append("--grant-edge")
        result = run_cli(cli, *args)
        projects.append((result["project_id"], label))
    return projects


def wait_for_port(broker, state):
    deadline = time.monotonic() + 15
    discovery = state / "rust-broker.json"
    while time.monotonic() < deadline:
        require(broker.poll() is None, "broker failed to start")
        try:
            port = json.loads(discovery.read_text(encoding="utf-8"))["port"]
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return port
        except (FileNotFoundError, OSError, json.JSONDecodeError):
            time.sleep(0.05)
    raise TimeoutError("broker readiness deadline exceeded")


def measure(args):
    binary = args.binary.resolve(strict=True)
    out = args.output_dir.resolve()
    out.mkdir(parents=True, exist_ok=False)
    report = {
        "status": "RUNNING", "started_at_utc": datetime.now(timezone.utc).isoformat(),
        "binary_sha256": digest(binary.read_bytes()), "transport": "MCP HTTP loopback",
        "harness_sha256": digest(Path(__file__).read_bytes()),
        "auth": "synthetic shared edge bearer", "read_size_bytes": READ_SIZE,
        "slow_consumer": {"batch_payload_bytes": SLOW_BATCH_ITEMS * READ_SIZE,
                          "delay_before_response_read_ms": SLOW_READ_DELAY * 1000},
        "search_corpus_files_per_project": 32, "phases": {},
    }
    write_json(out / "summary.json", report)
    try:
        with tempfile.TemporaryDirectory(prefix="edge-mcp-fixture-", dir=out) as temporary:
            sandbox = Path(temporary)
            state = sandbox / "state"
            cli = [str(binary), "--state-dir", str(state)]
            projects = prepare(cli, sandbox)
            with (out / "broker.stderr.log").open("xb") as stderr:
                broker = subprocess.Popen(
                    [*cli, "serve", "--port", "0"], stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL, stderr=stderr,
                )
                try:
                    port = wait_for_port(broker, state)
                    token = (state / "edge.token").read_text(encoding="utf-8").strip()
                    report["idle_broker"] = sample_broker(broker.pid, state)
                    report["edge_boundaries"] = check_edge_boundaries(port, token, projects[0][0], projects[-1][0])
                    phases = [(f"clients-{count}", count, args.matrix_seconds, count == 16)
                              for count in args.clients]
                    if args.soak_seconds:
                        phases.append(("soak", args.soak_clients, args.soak_seconds, args.soak_clients == 16))
                    for name, count, duration, pressure in phases:
                        interval = args.soak_interval if name == "soak" else (0.0 if pressure else args.interval)
                        print(f"{name}: {count} client processes, {duration:g}s", flush=True)
                        result = phase(out / name, broker, state, port, token, projects[:-1],
                                       count, duration, interval, pressure)
                        report["phases"][name] = result
                        write_json(out / "summary.json", report)
                        print(f"{name}: {result['total']['counts']}, peak={result['peak_overlapping_successful_requests']}, "
                              f"passed={result['passed']}", flush=True)
                finally:
                    if broker.poll() is None:
                        broker.terminate()
                    try:
                        broker.wait(timeout=8)
                    except subprocess.TimeoutExpired:
                        broker.kill()
                        broker.wait(timeout=8)
    except BaseException as exc:
        report["status"] = "ERROR"
        report["error_type"] = type(exc).__name__
        write_json(out / "summary.json", report)
        raise
    passed = (all(row["passed"] for row in report["phases"].values())
              and all(row["passed"] for row in report["edge_boundaries"].values()))
    report["status"] = "PASS" if passed else "FAIL"
    report["ended_at_utc"] = datetime.now(timezone.utc).isoformat()
    write_json(out / "summary.json", report)
    return 0 if passed else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--clients", type=int, nargs="+", default=(3, 8, 16), choices=(3, 8, 16))
    parser.add_argument("--matrix-seconds", type=float, default=12.0)
    parser.add_argument("--interval", type=float, default=0.02)
    parser.add_argument("--soak-seconds", type=float, default=0.0)
    parser.add_argument("--soak-clients", type=int, default=8, choices=(3, 8, 16))
    parser.add_argument("--soak-interval", type=float, default=0.15)
    args = parser.parse_args()
    if (not all(map(math.isfinite, (args.matrix_seconds, args.interval, args.soak_seconds, args.soak_interval)))
            or args.matrix_seconds < 1 or min(args.interval, args.soak_seconds, args.soak_interval) < 0
            or len(set(args.clients)) != len(args.clients)):
        parser.error("use distinct client counts and finite non-negative timings; matrix requires at least 1s")
    return measure(args)


if __name__ == "__main__":
    raise SystemExit(main())
