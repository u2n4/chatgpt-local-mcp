"""Private handoff from the Rust owner to the existing MXC job supervisor."""

import hashlib
import json
import os
from pathlib import Path
import sys
import time


MAX_REQUEST_BYTES = 64 * 1024


def run(request):
    sys.path.insert(0, sys.argv[1])
    from edge_bridge.broker import protected_path, require_state_writer_token, setup_state
    from edge_bridge.jobs import (
        Jobs, POWERSHELL_PREFIX, PROJECT_TEST_COMMAND, _seal_snapshot, validate_project_test_files,
    )
    from edge_bridge import runner
    from edge_bridge.state import State

    source = {"root": request["root"], "root_identity": request["root_identity"]}
    files = request["files"]
    # Rust selected these exact paths using the broker's filename policy.
    source_allowlist = frozenset(files)

    def before_create():
        Path(request["launch_ready"]).touch(exist_ok=False)
        if sys.stdin.buffer.readline(16) != b"start\n":
            raise runner.RunnerBlocked("QUEUE_LAUNCH_DENIED", "The owner did not authorize workload creation.")
    if request["recipe"] == "python_tests":
        runtime = "python"
        command = PROJECT_TEST_COMMAND
    elif request["recipe"] == "powershell_script":
        runtime = "powershell"
        command = (*POWERSHELL_PREFIX, files[0])
    else:
        raise ValueError("Unknown supervisor recipe")
    approved = validate_project_test_files(source, runtime, files, source_allowlist=source_allowlist)
    require_state_writer_token()
    runner.require_execution()
    state_path = Path(request["state"])
    if state_path.exists():
        raise ValueError("MXC worker state already exists")
    setup_state(state_path)
    state = State(state_path / "state.sqlite3")
    project = state.register_project(source["root"], "Rust queued test snapshot", source["root_identity"])
    state.set_test_scope(project["project_id"], runtime, approved)
    delegated = bool(request["delegated"])
    timeout_seconds = request["timeout_seconds"]
    max_timeout = 60 if delegated else 120
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int) or not 1 <= timeout_seconds <= max_timeout:
        raise runner.RunnerBlocked("INVALID_GRANT_LIMITS", "The requested timeout_seconds cannot be applied.")
    job_limits = runner.resolve_job_limits({
        "memory_bytes": request.get("max_memory_bytes", runner.MAX_TEST_MEMORY),
        "processes": request.get("max_processes", runner.MAX_TEST_PROCESSES),
        "log_bytes": request.get("max_output_bytes", runner.MAX_TEST_LOG_BYTES),
    })
    if delegated:
        workspace_limit = request.get("workspace_limit", runner.MAX_WORKSPACE_BYTES)
        if isinstance(workspace_limit, bool) or not isinstance(workspace_limit, int) or not 1 <= workspace_limit <= runner.MAX_WORKSPACE_BYTES:
            raise runner.RunnerBlocked("INVALID_GRANT_LIMITS", "The requested workspace_limit cannot be applied.")
    else:
        workspace_limit = None
    jobs = Jobs(state, state_path, protected_path, source_allowlist=source_allowlist,
                before_create=before_create,
                workspace_limit=workspace_limit,
                job_limits=job_limits)
    admitted = jobs.start(
        project, "local", "rust-mxc-queue", request["run_id"], runtime,
        list(command), ".", timeout_seconds,
    )
    job_id = admitted["job_id"]
    cancel_path = Path(request["cancel"])
    cancel_requested = False
    while True:
        job = state.get_job(project["project_id"], "local", job_id)
        if job["status"] not in {"queued", "running", "cancelling"}:
            break
        if not cancel_requested and cancel_path.exists():
            jobs.cancel(project["project_id"], "local", job_id, "rust-owner-cancel")
            cancel_requested = True
        time.sleep(0.04)
    evidence = job.get("evidence") or {}
    policy = evidence.get("policy") or {}
    canaries = policy.get("canaries") or {}
    expected_canaries = {
        "outside_read": "denied", "outside_write": "denied", "external_hardlink": "denied",
        "loopback": "denied", "runtime_write": "denied", "runtime_hardlink": "denied",
        "ipv6_loopback": "denied", "host_named_pipe": "denied", "child_outside_read": "denied",
        "credential_environment": "absent",
    }
    verified = (
        policy.get("backend") == "codex-sandbox-mxc"
        and policy.get("network") == "disabled"
        and policy.get("ownership") == "windows_job_list_at_create_kill_on_close"
        and all(canaries.get(name) == result for name, result in expected_canaries.items())
    )
    snapshot = evidence.get("snapshot", [])
    sealed_files = evidence.get("sealed_files", [])
    workload_started = evidence.get("workload_started") is True
    if workload_started and verified and not sealed_files and snapshot and job["status"] != "unknown_after_restart":
        # The supervisor confirms cleanup before publishing a terminal state. Seal
        # the input files here if its success-only postimage seal was unavailable.
        workspace = jobs._job_dir(job_id) / "workspace"
        sealed_files = _seal_snapshot(workspace, evidence["workspace_identity"], snapshot)
    baseline = {item["path"]: item["snapshot_sha256"] for item in snapshot}
    sealed = {item["path"]: item.get("sha256") for item in sealed_files}
    if workload_started and verified and baseline and sealed:
        command = policy["command"]
        executable, *argv = command[command.index("--") + 1:]
        if runtime == "powershell":
            # The runner rechecked this pin with read and path locks held until exit.
            executable_hash = policy["powershell_sha256"]
        else:
            with Path(executable).open("rb") as program:
                executable_hash = hashlib.file_digest(program, "sha256").hexdigest()

        def snapshot_hash(files):
            return hashlib.sha256(json.dumps(files, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

        provenance = {
            "snapshot_before_sha256": snapshot_hash(baseline),
            "snapshot_after_sha256": snapshot_hash(sealed),
            "executable": Path(executable).name,
            "executable_sha256": executable_hash,
            "argv": argv,
            "codex_version": policy["codex_version"],
            "codex_sha256": policy["codex_sha256"],
        }
    else:
        provenance = None
    return {
        "job_id": job_id,
        "status": job["status"],
        "exit_code": job["exit_code"],
        "failure_code": evidence.get("failure_code"),
        "diagnostic": evidence.get("diagnostic_hint"),
        "mxc_verified": verified,
        "workload_started": workload_started,
        "policy_sha256": policy.get("profile_sha256") if verified else None,
        "verified_canaries": expected_canaries if verified else {},
        "test_snapshot_unchanged": sealed == baseline if sealed and baseline else None,
        "provenance": provenance,
        "approved_files": approved,
    }


# Wait for the owner process to attach this helper to its Windows Job Object.
try:
    with Path(sys.argv[2]).open("x", encoding="ascii") as ready:
        ready.write(str(os.getpid()))
    request_line = sys.stdin.buffer.readline(MAX_REQUEST_BYTES)
    if not request_line.endswith(b"\n"):
        raise ValueError("The supervisor did not receive a complete request line")
    request = json.loads(request_line)
    response = run(request)
except Exception as error:
    response = {"status": "failed", "failure_code": getattr(error, "code", type(error).__name__)}
    if response["failure_code"] in {"ISOLATION_NOT_VERIFIED", "STATE_TOKEN_OWNER_MISMATCH"}:
        response["diagnostic"] = str(error)
print(json.dumps(response, ensure_ascii=True), flush=True)
