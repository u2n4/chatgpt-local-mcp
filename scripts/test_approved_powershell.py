from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from edge_bridge.broker import call_broker  # noqa: E402

MARKER = "EPB_APPROVED_POWERSHELL_OK"
READY = "Edge Project Bridge ready on 127.0.0.1:"


def _fail(msg: str) -> RuntimeError:
    return RuntimeError(msg)


def _run_cli(base: list[str], *args: str, timeout: float = 30.0) -> str:
    import subprocess
    proc = subprocess.run([*base, *args], capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout or "").strip()[-2000:]
        raise _fail(f"CLI {' '.join(args)} failed rc={proc.returncode}: {tail}")
    return proc.stdout


def _sanitize_command(command):
    if not isinstance(command, list):
        return []
    clean = []
    for part in command:
        s = str(part)
        if s.endswith("pwsh.exe"):
            clean.append("pwsh.exe")
        elif "\\" in s or "/" in s:
            clean.append(Path(s).name)
        else:
            clean.append(s)
    return clean


def main(argv: list[str] | None = None) -> int:
    start = time.monotonic()
    parser = argparse.ArgumentParser(description="Exercise approved PowerShell via real Edge Bridge broker")
    parser.add_argument("--output-dir", required=True, help="output directory")
    args = parser.parse_args(argv)

    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=False)

    project = output_dir / "project"
    state = output_dir / "state"
    result_path = output_dir / "result.json"
    project.mkdir()

    check = project / "check.ps1"
    fixture = b"Write-Output 'EPB_APPROVED_POWERSHELL_OK'\r\n"
    check.write_bytes(fixture)
    before_bytes = check.read_bytes()
    before_hash = hashlib.sha256(before_bytes).hexdigest()

    broker_stdout_path = output_dir / "broker-stdout.txt"
    broker_stdout_path.touch(exist_ok=True)

    result: dict = {"cases": [], "elapsed_seconds": 0.0, "exit_code": 1}
    proc = None
    stdout_handle = None
    try:
        import subprocess

        base = [sys.executable, "-m", "edge_bridge.cli", "--state-dir", str(state)]
        _run_cli(base, "install")

        stdout_handle = open(broker_stdout_path, "w", encoding="utf-8")
        proc = subprocess.Popen(base + ["start"], stdout=stdout_handle,
                                stderr=subprocess.STDOUT, text=True, cwd=str(ROOT))

        deadline = time.monotonic() + 30.0
        ready = False
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                text = broker_stdout_path.read_text(encoding="utf-8", errors="replace")
                raise _fail(f"broker exited rc={proc.returncode} before ready: {text.strip()[-2000:]}")
            try:
                text = broker_stdout_path.read_text(encoding="utf-8", errors="replace")
            except FileNotFoundError:
                text = ""
            if READY in text:
                ready = True
                break
            time.sleep(0.25)
        if not ready:
            raise _fail(f"timed out waiting for '{READY}' in broker stdout file")

        out = _run_cli(base, "register", str(project), "--name", "approved-powershell")
        try:
            reg = json.loads(out)
        except ValueError as exc:
            raise _fail(f"register project stdout not JSON: {(out or '')[:2000]} ({exc})")
        project_id = reg.get("project_id") if isinstance(reg, dict) else None
        if not project_id:
            raise _fail(f"register project response missing project_id: {(out or '')[:2000]}")

        _run_cli(base, "grant-powershell", str(project_id), check.name)

        cases = [
            ("modern", ["-NoProfile", "-NonInteractive", "-File", check.name]),
            ("legacy", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", check.name]),
        ]
        for label, argv_ps in cases:
            task_id = str(uuid.uuid4())
            operation_id = str(uuid.uuid4())
            resp = call_broker(state, "local", "process_start", {
                "project_id": project_id,
                "task_id": task_id,
                "operation_id": operation_id,
                "executable": "powershell",
                "argv": list(argv_ps),
                "cwd_relative": ".",
                "timeout_seconds": 22,
            })
            job_id = resp["job_id"]

            job = {}
            jdeadline = time.monotonic() + 40.0
            while time.monotonic() < jdeadline:
                jresp = call_broker(state, "local", "job_get", {"project_id": project_id, "job_id": job_id})
                job = jresp
                status = str(job.get("status") or "")
                if status in ("succeeded", "failed", "timed_out", "cancelled"):
                    break
                time.sleep(0.5)

            status = str(job.get("status") or "")
            if status != "succeeded":
                raise _fail(f"{label} job not succeeded (status={status!r}) after deadline")
            if job.get("exit_code") != 0:
                raise _fail(f"{label} job exit_code {job.get('exit_code')!r} != 0")
            output_text = call_broker(
                state, "local", "job_output", {"project_id": project_id, "job_id": job_id}
            )["output"]
            if MARKER not in output_text:
                raise _fail(f"{label} marker {MARKER!r} missing from job output")

            evidence = job.get("evidence") or {}
            policy = evidence.get("policy") or {}
            if policy.get("backend") != "codex-sandbox-mxc":
                raise _fail(f"{label} policy.backend {policy.get('backend')!r} != 'codex-sandbox-mxc'")
            if policy.get("network") != "disabled":
                raise _fail(f"{label} policy.network {policy.get('network')!r} != 'disabled'")
            canaries = policy.get("canaries") or {}
            for key in ("outside_read", "outside_write", "loopback"):
                if str(canaries.get(key) or "").lower() != "denied":
                    raise _fail(f"{label} policy.canaries.{key} {canaries.get(key)!r} != denied")

            command = policy.get("command")
            if not isinstance(command, list) or "--" not in [str(x) for x in command]:
                raise _fail(f"{label} policy.command missing '--' separator")
            tail = [str(x) for x in command][[str(x) for x in command].index("--") + 1:]
            if len(tail) != 5 or Path(tail[0]).name.lower() != "pwsh.exe":
                raise _fail(f"{label} pinned pwsh.exe guard failed: {tail!r}")
            if tail[1:4] != ["-NoProfile", "-NonInteractive", "-File"]:
                raise _fail(f"{label} exact -NoProfile -NonInteractive -File guard failed: {tail!r}")
            if "ExecutionPolicy" in tail or any("ExecutionPolicy" in x for x in [str(x) for x in command]):
                raise _fail(f"{label} ExecutionPolicy override present in policy.command")
            if tail[4].lower() != "check.ps1" and not str(tail[4]).endswith("check.ps1"):
                raise _fail(f"{label} script-path guard failed: {tail!r}")

            result["cases"].append({
                "label": label,
                "operation_id": operation_id,
                "status": status,
                "exit_code": job.get("exit_code"),
                "marker_found": MARKER in output_text,
                "policy_backend": policy.get("backend"),
                "policy_network": policy.get("network"),
                "policy_command": _sanitize_command(command),
            })

        after_bytes = check.read_bytes()
        after_hash = hashlib.sha256(after_bytes).hexdigest()
        if after_bytes != before_bytes or after_hash != before_hash:
            raise _fail("fixture bytes changed (hash mismatch)")
        result["fixture_hash"] = before_hash
        result["fixture_unchanged"] = True
        result["exit_code"] = 0
    except Exception as exc:  # noqa: BLE001
        result["error"] = str(exc)[:4000]
        print(f"test_approved_powershell failed: {exc}", file=sys.stderr)
    finally:
        if stdout_handle is not None:
            try:
                stdout_handle.flush()
            except Exception:
                pass
            try:
                stdout_handle.close()
            except Exception:
                pass
        if proc is not None and proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=10)
            except Exception:
                try:
                    proc.kill()
                    proc.wait(timeout=5)
                except Exception:
                    pass
        result["elapsed_seconds"] = round(time.monotonic() - start, 3)
        try:
            result_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        except Exception as exc:
            print(f"test_approved_powershell could not write result.json: {exc}", file=sys.stderr)
    return result["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
