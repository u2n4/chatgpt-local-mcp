"""Isolated HTTP MCP acceptance tests for writes, durable queueing and MXC cancellation."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, contextmanager, ExitStack
import ctypes as ct
from ctypes import wintypes as wt
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import traceback

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from benchmarks.bench_mcp_concurrency import (
    LEGACY, MODERN, RpcClient, digest, run_cli, tool_result, wait_for_port, write_json,
)

# The child is a deterministic test workload. Its PID marker identifies the
# process; a native SYNCHRONIZE handle subsequently pins its identity.
LONG_TEST = """\
import subprocess
import sys
import unittest
from pathlib import Path

class Example(unittest.TestCase):
    def test_sleep(self):
        with subprocess.Popen([sys.executable, '-I', '-S', '-B', '-c',
                               'import time; time.sleep(45)']) as child:
            marker = Path('child-started.partial')
            marker.write_text(str(child.pid), encoding='ascii')
            marker.rename('child-started.pid')
            child.wait()
"""


class Blocked(RuntimeError):
    """An environmental precondition prevented running a scenario."""


def check(condition, reason):
    if not condition:
        raise AssertionError(reason)


def rpc(client, request_id, tool, args):
    started = time.perf_counter_ns()
    status, frame, wait, port = client.call(request_id, "tools/call", {
        "name": tool, "arguments": args,
    })
    code, value, details = tool_result(status, frame)
    finished = time.perf_counter_ns()
    error_message = frame.get("result", {}).get("structuredContent", {}).get("message")
    return {"code": code, "value": value, "details": details, "error_message": error_message, "start_ns": started,
            "end_ns": finished, "ms": (finished - started) / 1_000_000, "local_port": port,
            "http_status": status, "queue_wait_ms": wait, "tool": tool, "request_id": request_id}


def observation(row):
    # Strip raw result objects. Local responses can include state paths and
    # delegated data that do not belong in acceptance evidence.
    return {key: value for key, value in row.items() if key not in {"value", "error_message"}}


def result(row, code="OK"):
    check(row["code"] == code, f"{row['tool']}: expected {code}, received {row['code']}")
    return row["value"]


class FixtureBroker:
    def __init__(self, binary, root, evidence):
        self.root = root
        self.state = root / "state"
        self.evidence = evidence
        self.cli = [str(binary), "--state-dir", str(self.state), "--environment-kind", "synthetic"]
        self.broker = None
        self.project = root / "shared-project"
        self.project.mkdir()
        self.note = self.project / "note.txt"
        self.note.write_bytes(b"original synthetic preimage\n")
        self.project_id = self.register(self.project, True)
        self.private_project = root / "another-synthetic-project"
        self.private_project.mkdir()
        (self.private_project / "marker.txt").write_bytes(b"owner-only fixture")
        self.private_id = self.register(self.private_project, False)
        self.db = self.state / "state.sqlite3"

    def register(self, root, grant_edge):
        args = ["register", root, "--name", root.name]
        if grant_edge:
            args.append("--grant-edge")
        return run_cli(self.cli, *args)["project_id"]

    def start(self):
        check(self.broker is None, "fixture already has a broker process")
        (self.state / "rust-broker.json").unlink(missing_ok=True)
        with (self.evidence / "broker.stderr.log").open("ab") as stderr:
            self.broker = subprocess.Popen(
                [*self.cli, "serve", "--port", "0"], stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=stderr,
            )
        self.port = wait_for_port(self.broker, self.state)
        self.tokens = {kind: (self.state / f"{kind}.token").read_text(encoding="utf-8").strip()
                       for kind in ("owner", "edge", "executor")}
        check(len(set(self.tokens.values())) == 3, "fixture trust identities share credentials")
        return self.broker.pid

    def stop(self):
        if self.broker is None:
            return
        try:
            if self.broker.poll() is None:
                self.broker.terminate()
            try:
                self.broker.wait(timeout=8)
            except subprocess.TimeoutExpired:
                self.broker.kill()
                self.broker.wait(timeout=5)
        finally:
            self.broker = None

    @contextmanager
    def connect(self, kind, label, protocol=LEGACY):
        client = RpcClient(self.port, self.tokens[kind], protocol, label)
        try:
            client.handshake()
            yield client
        finally:
            client.close()

    def task(self, identifier, **extra):
        return {"project_id": self.project_id, "task_id": identifier,
                "operation_id": identifier, "recipe": "python_tests", **extra}

    def job(self, run_id, **extra):
        return {"project_id": self.project_id, "job_id": run_id, **extra}

    def runs(self, identifier):
        with closing(sqlite3.connect(f"{self.db.as_uri()}?mode=ro", uri=True, timeout=1)) as reader:
            return reader.execute(
                "SELECT run_id, state FROM durable_runs WHERE operation_id = ? ORDER BY run_id",
                (identifier,),
            ).fetchall()

    def owner_command(self, runtime, run_id, timeout=28):
        return [*self.cli, "run-queued-python-tests", run_id, "--runtime-root", str(runtime),
                "--file", "tests/__init__.py", "--file", "tests/test_example.py",
                "--timeout-seconds", str(timeout)]


def same_preimage(fixture, _runtime):
    original = fixture.note.read_bytes()
    expected_hash = digest(original)
    ready = threading.Barrier(2)
    replacements = (b"candidate alpha\n", b"candidate bravo\n")

    def edit(index, client):
        read = result(rpc(client, 1, "file_read", {"project_id": fixture.project_id, "path": "note.txt"}))
        check(read["hash"] == expected_hash, "writer read a different preimage")
        ready.wait(5)
        return rpc(client, 2, "file_write", {
            "project_id": fixture.project_id, "operation_id": f"edit-{index}",
            "path": "note.txt", "content": replacements[index].decode("ascii"),
            "expected_hash": read["hash"],
        })

    with fixture.connect("owner", "first-writer") as first, \
            fixture.connect("owner", "second-writer", MODERN) as second, \
            ThreadPoolExecutor(max_workers=2) as workers:
        pending = [workers.submit(edit, idx, client) for idx, client in enumerate((first, second))]
        rows = [future.result(timeout=15) for future in pending]

    check(sorted(row["code"] for row in rows) == ["OK", "VERSION_CONFLICT"],
          f"concurrent patch outcomes: {[(r['code'], r['error_message']) for r in rows]}")
    winner = next(index for index, row in enumerate(rows) if row["code"] == "OK")
    check(fixture.note.read_bytes() == replacements[winner], "winning bytes were not retained")
    after_hash = digest(replacements[winner])
    check(rows[winner]["value"]["postimage_hashes"]["note.txt"] == after_hash, "postimage hash mismatch")
    overlap = max(row["start_ns"] for row in rows) < min(row["end_ns"] for row in rows)
    check(overlap, "the competing MCP request windows did not overlap")
    return {"preimage_sha256": expected_hash, "postimage_sha256": after_hash,
            "winner": winner, "requests_overlap": overlap, "calls": [observation(row) for row in rows]}


def durable_restart(fixture, _runtime):
    with fixture.connect("owner", "ack") as owner:
        ack = rpc(owner, 1, "task_submit", fixture.task("ack-committed"))
        accepted = result(ack)
        check(accepted["created"] and accepted["state"] == "queued", "job ack was not a fresh queued run")
        check(accepted["execution_mode"] == "queue_only" and bool(accepted["accepted_at"]), "durable ack contract incomplete")
        check(fixture.runs("ack-committed") == [(accepted["run_id"], "queued")],
              "independent SQLite reader could not see the acknowledged run")

    operation = fixture.task("reply-dropped")
    with fixture.connect("owner", "drop-reply", MODERN) as disconnected:
        sent_ns = time.perf_counter_ns()
        drop_port = disconnected.send(1, "tools/call", {"name": "task_submit", "arguments": operation})
        durable = []
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not durable:
            durable = fixture.runs("reply-dropped")
            if not durable:
                time.sleep(.02)
        check(len(durable) == 1 and durable[0][1] == "queued", "discarded reply run was not durably queued")
        visible_ns = time.perf_counter_ns()
        # Leave the response unread, simulating the caller losing its acknowledgement.
    dropped_ns = time.perf_counter_ns()
    run_id = durable[0][0]
    with fixture.connect("owner", "replay") as retry:
        replay = rpc(retry, 2, "task_submit", operation)
        value = result(replay)
        check((value["run_id"], value["created"], value["idempotent_replay"]) == (run_id, False, True),
              "replay changed the durable run identity")
        mismatch = rpc(retry, 3, "task_submit", {**operation, "task_id": "changed-payload"})
        result(mismatch, "IDEMPOTENCY_PAYLOAD_MISMATCH")
        check(fixture.runs("reply-dropped") == durable, "replay or mismatch created a second run")
    prior_pid = fixture.broker.pid
    fixture.stop()
    restarted_pid = fixture.start()
    with fixture.connect("owner", "post-restart", MODERN) as restarted:
        status = rpc(restarted, 1, "job_get", fixture.job(run_id))
        check(result(status)["state"] == "queued", "safe queued job did not survive broker restart")
        resumed = rpc(restarted, 2, "task_submit", operation)
        check(result(resumed)["run_id"] == run_id and resumed["value"]["idempotent_replay"],
              "restart forgot the operation's deduplication record")
        cancel = rpc(restarted, 3, "job_cancel", fixture.job(run_id))
        check(result(cancel)["state"] == "cancelled", "never-started run did not cancel immediately")
        check(fixture.runs("reply-dropped") == [(run_id, "cancelled")], "cancel was not durable")
    return {"ack_visible_in_sqlite": True, "dropped_sent_ns": sent_ns,
            "dropped_commit_visible_ns": visible_ns, "dropped_disconnect_ns": dropped_ns,
            "dropped_local_port": drop_port, "restart_before_pid": prior_pid, "restart_after_pid": restarted_pid,
            "run_state_after_restart": "queued", "final_state": "cancelled",
            "calls": [observation(row) for row in (ack, replay, mismatch, status, resumed, cancel)]}


def sqlite_contention(fixture, _runtime):
    with fixture.connect("owner", "contended-writer") as owner, \
            fixture.connect("edge", "wal-reader", MODERN) as edge, \
            ThreadPoolExecutor(max_workers=2) as workers, \
            closing(sqlite3.connect(fixture.db, timeout=1, isolation_level=None)) as writer:
        writer.execute("BEGIN IMMEDIATE")
        held_ns = time.perf_counter_ns()
        try:
            barrier = threading.Barrier(2)

            def contend():
                barrier.wait(5)
                return rpc(owner, 1, "task_submit", fixture.task("sqlite-busy"))

            def read():
                barrier.wait(5)
                # Sample a short series to exercise read demand across the write wait.
                samples = []
                for index in range(5):
                    samples.append(rpc(edge, index + 1, "file_read", {
                        "project_id": fixture.project_id, "path": "note.txt",
                    }))
                    time.sleep(.02)
                return samples

            write_pending = workers.submit(contend)
            reads_pending = workers.submit(read)
            busy = write_pending.result(timeout=12)
            reads = reads_pending.result(timeout=12)
            check(not fixture.runs("sqlite-busy"), "BUSY unexpectedly created a durable run")
        finally:
            writer.execute("ROLLBACK")
            released_ns = time.perf_counter_ns()
        result(busy, "RESOURCE_BUSY")
        check(busy["details"].get("reason") == "sqlite_busy", "wrong backpressure reason")
        check(busy["details"].get("retry_after_ms", 0) > 0, "missing retry window")
        check(all(result(row)["hash"] == digest(fixture.note.read_bytes()) for row in reads),
              "an overlapping read returned incorrect data")
        overlapping_reads = sum(row["start_ns"] < busy["end_ns"] and busy["start_ns"] < row["end_ns"] for row in reads)
        check(overlapping_reads > 0, "the contended write did not overlap a read")
        retry = rpc(owner, 2, "task_submit", fixture.task("sqlite-busy"))
        check(result(retry)["created"] is True, "retry did not create the formerly rejected run")
    return {"writer_lock_start_ns": held_ns, "writer_lock_end_ns": released_ns,
            "read_request_windows_overlapping_busy": overlapping_reads,
            "calls": [observation(row) for row in (busy, *reads, retry)]}


def delegated_revoke(fixture, runtime):
    grant = run_cli(fixture.cli, "grant-create", fixture.project_id, "--requester", "executor:default",
                    "--writable-path", "note.txt", "--recipe", "python_tests",
                    "--recipe", "read_output", "--recipe", "default")["grant_id"]
    extra = {"grant_id": grant}
    calls = []

    def call(client, tool, args, code="OK"):
        row = rpc(client, len(calls) + 1, tool, args)
        calls.append(observation(row))
        return result(row, code)

    with fixture.connect("executor", "delegate", MODERN) as executor, \
            fixture.connect("edge", "read-only") as edge, \
            fixture.connect("owner", "grant-owner") as owner:
        check(call(executor, "bridge_info", {})["principal"] == "executor:default", "wrong executor identity")
        check(call(edge, "bridge_info", {})["remote_mode"] == "edge_read", "wrong edge mode")
        operation = fixture.task("delegated", **extra)
        call(edge, "task_submit", operation, "BRIDGE_POLICY_DENIED")
        call(executor, "task_submit", {**operation, "project_id": fixture.private_id}, "PROJECT_NOT_GRANTED")
        queued = call(executor, "task_submit", operation)
        run_id = queued["run_id"]
        check(queued["created"] and queued["state"] == "queued", "delegated grant did not admit a durable request")
        status = call(executor, "job_get", fixture.job(run_id, **extra))
        check(status["state"] == "queued" and "output_dir" not in status, "delegated status leaked private run fields")
        call(executor, "job_output", fixture.job(run_id, **extra))
        owner_run = call(owner, "task_submit", fixture.task("owner-only"))["run_id"]
        call(executor, "job_get", fixture.job(owner_run, **extra), "BRIDGE_POLICY_DENIED")
        call(executor, "job_cancel", fixture.job(owner_run, **extra), "BRIDGE_POLICY_DENIED")
        check(call(owner, "job_get", fixture.job(owner_run))["state"] == "queued", "unauthorized cancellation changed the owner's job")
        # The present MXC handoff intentionally accepts local-owner requests only.
        tests = fixture.project / "tests"
        tests.mkdir()
        (tests / "__init__.py").write_bytes(b"")
        (tests / "test_example.py").write_text(LONG_TEST, encoding="utf-8")
        refusal = subprocess.run(fixture.owner_command(runtime, run_id), capture_output=True,
                                 text=True, encoding="utf-8", timeout=20)
        check(refusal.returncode != 0 and "unclaimed local Python test request" in refusal.stderr
              and fixture.runs("delegated") == [(run_id, "queued")],
              "delegated request crossed the local-only MXC admission boundary")
        revocation = run_cli(fixture.cli, "grant-revoke", grant)
        check(revocation["revoked"] is True, "test grant was not revoked")
        call(executor, "job_get", fixture.job(run_id, **extra), "PROJECT_NOT_GRANTED")
        call(executor, "task_submit", fixture.task("new-after-revoke", **extra), "PROJECT_NOT_GRANTED")
        call(executor, "task_submit", operation, "PROJECT_NOT_GRANTED")
        check(not fixture.runs("new-after-revoke"), "revoked grant admitted new work")
        # Reuse the same HTTP connections to detect a stale authorization cache.
        edge_read = call(edge, "file_read", {"project_id": fixture.project_id, "path": "note.txt"})
        check(edge_read["content"] == fixture.note.read_text(encoding="utf-8"),
              "unrelated edge reader was affected by grant revocation")
        cleaned = call(owner, "job_cancel", fixture.job(run_id))
        check(cleaned["state"] == "cancelled", "owner did not retain control after revocation")
    return {"delegated_admission": "queue_only", "delegated_mxc_refused": True,
            "same_executor_connection_rechecked_after_revoke": True, "calls": calls}


@contextmanager
def process_handle(pid):
    kernel = ct.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
    kernel.OpenProcess.restype = wt.HANDLE
    kernel.WaitForSingleObject.argtypes = [wt.HANDLE, wt.DWORD]
    kernel.WaitForSingleObject.restype = wt.DWORD
    kernel.CloseHandle.argtypes = [wt.HANDLE]
    kernel.CloseHandle.restype = wt.BOOL
    handle = kernel.OpenProcess(0x00100000, False, pid)  # SYNCHRONIZE
    if not handle:
        raise ct.WinError(ct.get_last_error())
    try:
        def wait(ms=0):
            state = kernel.WaitForSingleObject(handle, ms)
            if state == 0xFFFFFFFF:
                raise ct.WinError(ct.get_last_error())
            return state

        yield wait
    finally:
        kernel.CloseHandle(handle)


def wait_for_child(run_dir, owner):
    deadline = time.monotonic() + 18
    while time.monotonic() < deadline and owner.poll() is None:
        markers = list(run_dir.glob("mxc-state/jobs/job_*/workspace/child-started.pid"))
        if markers:
            check(len(markers) == 1, "multiple child markers were created")
            return int(markers[0].read_text(encoding="ascii"))
        time.sleep(.05)
    if owner.poll() is None:
        raise RuntimeError("supervised job did not reach the child marker deadline")
    stdout, stderr = owner.communicate()
    try:
        response = json.loads(stdout)
    except json.JSONDecodeError:
        if any(token in stderr.lower() for token in ("access is denied", "exebox", "desktop", "mxc")):
            raise Blocked("MXC supervisor did not start in this desktop; see isolated supervisor logs")
        raise
    receipt = response.get("mxc_receipt") or {}
    if receipt.get("mxc_verified") is False and receipt.get("failure_code"):
        raise Blocked(f"MXC containment gate returned {receipt['failure_code']}")
    raise RuntimeError(f"owner exited before child marker, status {response.get('run', {}).get('state')}")


def cancel_mxc(fixture, runtime):
    if sys.platform != "win32":
        raise Blocked("MXC acceptance requires Windows")
    if not (runtime / ".venv" / "Scripts" / "python.exe").is_file():
        raise Blocked("approved Python runtime is absent")
    tests = fixture.project / "tests"
    tests.mkdir()
    (tests / "__init__.py").write_bytes(b"")
    (tests / "test_example.py").write_text(LONG_TEST, encoding="utf-8")
    source_hash = digest((tests / "test_example.py").read_bytes())
    # Exercise real discovery across a modest synthetic corpus while the child sleeps.
    search = fixture.project / "corpus"
    search.mkdir()
    filler = b"synthetic filler line\n" * 2400
    for index in range(32):
        (search / f"{index:03}.txt").write_bytes(filler)
    (search / "zz-proof.txt").write_bytes(b"mxctest-isolated-search-hit\n")

    calls = []
    with fixture.connect("owner", "cancel-owner") as canceller, \
            fixture.connect("edge", "read-search") as reader, \
            fixture.connect("owner", "job-status", MODERN) as observer:
        queued = rpc(canceller, 1, "task_submit", fixture.task("actual-mxc"))
        run_id = result(queued)["run_id"]
        job = fixture.job(run_id)
        run_dir = fixture.state / "runs" / run_id
        with subprocess.Popen(fixture.owner_command(runtime, run_id), stdin=subprocess.DEVNULL,
                              encoding="utf-8", stdout=subprocess.PIPE, stderr=subprocess.PIPE) as owner:
            try:
                child_pid = wait_for_child(run_dir, owner)
                with ExitStack() as pinned:
                    child_wait = pinned.enter_context(process_handle(child_pid))
                    initial = rpc(observer, 1, "job_get", job)
                    running = result(initial)
                    check(running["state"] == "running" and running["pid"] > 0, "MXC run is not running")
                    supervisor_wait = pinned.enter_context(process_handle(running["pid"]))
                    wrong = rpc(canceller, 2, "job_cancel", {**job, "project_id": fixture.private_id})
                    result(wrong, "BRIDGE_POLICY_DENIED")
                    check(child_wait() == 0x102 and supervisor_wait() == 0x102, "supervised processes had exited")
                    child_alive_ns = time.perf_counter_ns()

                    # Three distinct HTTP connections start work while the child
                    # is live. Only the cancellation client can terminate it.
                    barrier = threading.Barrier(3)

                    def search_work():
                        barrier.wait(5)
                        return rpc(reader, 2, "file_search", {
                            "project_id": fixture.project_id, "path": "corpus",
                            "query": "mxctest-isolated-search-hit", "limit": 1,
                        })

                    def status_work():
                        barrier.wait(5)
                        return rpc(observer, 2, "job_get", job)

                    def cancel_work():
                        barrier.wait(5)
                        return rpc(canceller, 3, "job_cancel", job)

                    with ThreadPoolExecutor(max_workers=3) as workers:
                        futures = [workers.submit(work) for work in (search_work, status_work, cancel_work)]
                        search_result, polling, cancel = [future.result(timeout=12) for future in futures]
                    hits = result(search_result)["hits"]
                    check(len(hits) == 1 and hits[0]["path"] == "corpus/zz-proof.txt", "wrong concurrent search hit")
                    check(result(polling)["state"] in {"running", "cancelling", "cancelled"}, "status returned another run")
                    check(result(cancel)["state"] == "cancelling", "job did not move to cancelling")
                    check(len({row["local_port"] for row in (search_result, polling, cancel)}) == 3,
                          "concurrency did not use three independent TCP connections")
                    check(polling["ms"] <= 250 and cancel["ms"] <= 250, "control response exceeded 250 ms")
                    stdout, stderr = owner.communicate(timeout=12)
                    check(owner.returncode == 0, "owner supervisor did not finish successfully")
                    outcome = json.loads(stdout)
                    check(outcome["run"]["state"] == "cancelled", "owner did not confirm terminal cancelled state")
                    check(child_wait(2500) == 0 and supervisor_wait(2500) == 0,
                          "a process handle remained unsignaled after the Job Object cancelled")
                    ended_ns = time.perf_counter_ns()
                    calls.extend((queued, initial, wrong, search_result, polling, cancel))
            finally:
                if owner.poll() is None:
                    try:
                        rpc(canceller, 99, "job_cancel", job)
                        owner.communicate(timeout=8)
                    except (OSError, subprocess.TimeoutExpired):
                        owner.kill()
                        owner.wait(timeout=5)
        final = rpc(observer, 3, "job_get", job)
        check(result(final)["state"] == "cancelled", "broker did not persist the cancellation")
        calls.append(final)
    check(digest((tests / "test_example.py").read_bytes()) == source_hash,
          "job modified the parent's approved test source")
    trial = (search_result, polling, cancel)
    overlap_ns = max(0, min(row["end_ns"] for row in trial) - max(row["start_ns"] for row in trial))
    return {"state_after_cancel": "cancelled", "child_alive_ns": child_alive_ns,
            "terminated_confirmed_ns": ended_ns, "child_pid": child_pid,
            "supervisor_pid": running["pid"], "independent_process_handles_signaled": True,
            "three_client_request_overlap_ms": overlap_ns / 1e6,
            "request_windows_began_after_live_child_probe": all(row["start_ns"] > child_alive_ns for row in trial),
            "test_source_sha256": source_hash, "calls": [observation(row) for row in calls]}


TESTS = {test.__name__: test for test in (same_preimage, durable_restart, sqlite_contention, delegated_revoke, cancel_mxc)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--case", action="append", choices=tuple(TESTS))
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    runtime = args.runtime_root.resolve(strict=True)
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    summary = {"binary_sha256": digest(binary.read_bytes()),
               "test_sha256": digest(Path(__file__).read_bytes()), "cases": {},
               "started_at_utc": datetime.now(timezone.utc).isoformat(), "status": "RUNNING"}
    for name in args.case or TESTS:
        print(f"Running {name}", flush=True)
        report = output / name
        report.mkdir()
        with tempfile.TemporaryDirectory(prefix="synthetic-", dir=report) as temp:
            try:
                fixture = FixtureBroker(binary, Path(temp), report)
                try:
                    fixture.start()
                    evidence = TESTS[name](fixture, runtime)
                finally:
                    fixture.stop()
            except Blocked as exc:
                case = {"verdict": "BLOCKED", "reason": str(exc)}
            except Exception as exc:
                # Keep a local traceback while only printing the exception class.
                (report / "failure.txt").write_text(traceback.format_exc(), encoding="utf-8")
                case = {"verdict": "FAIL", "error_type": type(exc).__name__}
            else:
                case = {"verdict": "PASS", **evidence}
        summary["cases"][name] = case
        write_json(output / "summary.json", summary)
        print(f"{name}: {case['verdict']}", flush=True)
    verdicts = {case["verdict"] for case in summary["cases"].values()}
    summary["status"] = "FAIL" if "FAIL" in verdicts else "BLOCKED" if "BLOCKED" in verdicts else "PASS"
    summary["ended_at_utc"] = datetime.now(timezone.utc).isoformat()
    write_json(output / "summary.json", summary)
    return 0 if summary["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
