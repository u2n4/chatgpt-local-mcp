"""Run delegated requests through the Windows owner queue worker and real MXC."""

from contextlib import closing, contextmanager
import hashlib
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from compat.python.rust_bridge import find_rust_binary


REPO = Path(__file__).resolve().parents[2]


def find_worker_binary():
    override = os.environ.get("CARGO_TARGET_DIR")
    if not override:
        return find_rust_binary(REPO)
    target = REPO / override
    candidates = (target / triple / profile / "edge-bridge.exe"
                  for triple in ("x86_64-pc-windows-gnullvm", "") for profile in ("release", "debug"))
    return next((path for path in candidates if path.is_file()), None)


def make_runtime(runtime, hook="", *, direct_python=False):
    """Keep the test runtime and project roots disjoint, even with TEMP in the repo."""
    import _winapi

    package = runtime / "edge_bridge"
    package.mkdir(parents=True)
    if direct_python:
        # The venv redirector holds its own copy of stdin open. Use the real
        # interpreter when the fixture needs to close the last pipe reader.
        (runtime / ".venv").mkdir()
        _winapi.CreateJunction(str(Path(sys._base_executable).parent), str(runtime / ".venv" / "Scripts"))
        site_packages = REPO / ".venv" / "Lib" / "site-packages"
        hook = f"import site\nsite.addsitedir({str(site_packages)!r})\n" + hook
    else:
        _winapi.CreateJunction(str(REPO / ".venv"), str(runtime / ".venv"))
    (package / "runner.py").touch()  # The wrapper package imports the real runner.
    package_init = (REPO / "edge_bridge" / "__init__.py").read_text(encoding="utf-8")
    (package / "__init__.py").write_text(
        package_init + f"\n__path__ = [{str(REPO / 'edge_bridge')!r}]\n" + hook, encoding="utf-8",
    )
    return runtime


class TestWorkerBinaryLocation(unittest.TestCase):
    def test_matches_legacy_default_and_honors_cargo_target_override(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ):
            root = Path(temporary)
            default = root / "target" / "release" / "edge-bridge.exe"
            override = root / "isolated" / "x86_64-pc-windows-gnullvm" / "debug" / "edge-bridge.exe"
            for binary in (default, override):
                binary.parent.mkdir(parents=True)
                binary.touch()
            with patch(f"{__name__}.REPO", root):
                os.environ.pop("CARGO_TARGET_DIR", None)
                self.assertEqual(find_worker_binary(), default)
                os.environ["CARGO_TARGET_DIR"] = str(root / "isolated")
                self.assertEqual(find_worker_binary(), override)


@unittest.skipUnless(sys.platform == "win32", "Uses Windows MXC")
class TestQueueWorker(unittest.TestCase):
    def setUp(self):
        binary = find_worker_binary()
        self.assertIsNotNone(binary, "Build the release binary before running the MXC acceptance suite")
        temp = tempfile.TemporaryDirectory(prefix="bridge-queue-worker-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.state = self.root / "state"
        self.project = self.root / "project"
        self.tests = self.project / "tests"
        self.tests.mkdir(parents=True)
        (self.tests / "__init__.py").write_bytes(b"")
        self.cli = [str(binary), "--state-dir", str(self.state)]
        self.project_id = self.command("register", str(self.project), "--name", "Queued fixture")["project_id"]

    def command(self, *args):
        result = subprocess.run(self.cli + list(args), capture_output=True, encoding="utf-8", timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        return json.loads(result.stdout)

    def mcp(self, tool, arguments, principal="local"):
        request = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": arguments}}
        result = subprocess.run(self.cli + ["mcp", "--principal", principal], input=json.dumps(request) + "\n",
                                capture_output=True, encoding="utf-8", timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        answer = json.loads(result.stdout)["result"]
        self.assertFalse(answer["isError"], answer)
        return answer["structuredContent"]["result"]

    def queue(self, recipe="python_tests", args=(), *, task_id="worker-fixture", grant=None):
        if grant is None:
            grant = self.command("grant-create", self.project_id, "--profile", "pro-review")["grant_id"]
        accepted = self.mcp("task_submit", {"project_id": self.project_id, "task_id": task_id,
                            "operation_id": task_id, "grant_id": grant, "recipe": recipe, "args": list(args)},
                            "executor:default")
        self.assertEqual(accepted["state"], "queued")
        return accepted["run_id"], grant

    def worker_command(self, runtime=None, allow_environment_credentials=True, allow_work_exec=False):
        if runtime is None:
            runtime = self.root / "runtime"
            if not runtime.exists():
                make_runtime(runtime)
        # The machine that runs the tests may keep credentials in its persistent environment.
        allow = ["--allow-environment-credentials"] if allow_environment_credentials else []
        if allow_work_exec:
            allow.append("--allow-work-exec")
        return self.cli + ["worker", "--once", "--runtime-root", str(runtime)] + allow

    def worker(self, runtime=None, *, allow_work_exec=False):
        result = subprocess.run(
            self.worker_command(runtime, allow_work_exec=allow_work_exec),
            capture_output=True, encoding="utf-8", timeout=90,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return [json.loads(line) for line in result.stdout.splitlines()]

    def run_state(self, run_id):
        return self.mcp("job_get", {"project_id": self.project_id, "job_id": run_id})

    def output(self, run_id, grant=None):
        principal = "executor:default" if grant else "local"
        params = {"project_id": self.project_id, "job_id": run_id, "limit": 1, "cursor": 0}
        if grant:
            params["grant_id"] = grant
        chunks = []
        while True:
            page = self.mcp("job_output", params, principal)
            if not page["chunks"]:
                return "".join(chunks)
            self.assertEqual(len(page["chunks"]), 1)
            self.assertGreater(page["next_seq"], params["cursor"])
            self.assertLessEqual(len(page["chunks"][0]["content"].encode()), 4096)
            chunks.append(page["chunks"][0]["content"])
            params["cursor"] = page["next_seq"]

    def python_test(self, body):
        (self.tests / "test_worker.py").write_text(body, encoding="utf-8")

    def completed(self, run_id, expected):
        details, = self.worker()
        self.assertEqual(details["run"]["state"], expected, details)
        self.assertEqual(self.run_state(run_id)["state"], expected)
        self.assert_raw_removed(run_id)
        return details

    def assert_raw_removed(self, run_id):
        run = self.state / "runs" / run_id
        self.assertEqual(list(run.glob("mxc-*")), [])

    def assert_signed_capture(self, details):
        manifest = Path(details["evidence_manifest_path"])
        result = self.command("verify-evidence", str(manifest), "--artifacts-dir", str(manifest.parent))
        self.assertTrue(result["overall_verified"], result)
        return json.loads(manifest.read_text(encoding="utf-8"))

    def test_worker_runs_discovered_unittests_and_pages_redacted_output(self):
        (self.project / "helper.py").write_text("def add(a, b): return a + b\n", encoding="utf-8")
        self.python_test("""\
import sys
import unittest
from helper import add

class Example(unittest.TestCase):
    def test_add(self):
        self.assertEqual(add(2, 3), 5)
        print('x' * 4080 + ' sk-' + 'SYNTHETIC' * 3)
        print('WORKER_STDERR_MARKER', file=sys.stderr)
""")
        run_id, grant = self.queue()
        details = self.completed(run_id, "succeeded")
        self.assertEqual(details["run"]["exit_code"], 0)
        self.assertEqual(details["test_counts"]["passed"], 1)
        output = self.output(run_id, grant)
        self.assertIn("WORKER_STDERR_MARKER", output)
        self.assertIn("[REDACTED:openai_or_sk_key]", output)
        self.assertNotIn("SYNTHETIC" * 3, output)
        manifest = self.assert_signed_capture(details)
        self.assertEqual(manifest["conclusions"]["overall_verdict"], "NOT_TESTED")
        self.assertIn("reported by the workload", manifest["conclusions"]["provenance_disclaimer"])
        job = self.mcp("job_get", {"project_id": self.project_id, "job_id": run_id,
                                  "grant_id": grant}, "executor:default")
        self.assertEqual(job["workload_report"], {
            "source": "workload", "exit_code": 0,
            "test_counts": {"executed": 1, "passed": 1, "failed": 0, "skipped": 0},
        })
        self.assertEqual(job["outcome"]["verification_outcome"], "NOT_TESTED")

    def test_failed_unittest_remains_visible(self):
        self.python_test("""\
import unittest

class Example(unittest.TestCase):
    def test_failure(self):
        self.fail('WORKER_EXPECTED_FAILURE')
""")
        run_id, grant = self.queue()
        details = self.completed(run_id, "failed")
        self.assertTrue(details["mxc_receipt"]["mxc_verified"], details)
        self.assertEqual(details["run"]["exit_code"], 1)
        self.assertIn("WORKER_EXPECTED_FAILURE", self.output(run_id, grant))
        self.assert_signed_capture(details)

    def test_powershell_runs_pinned_file_recipe(self):
        script = self.project / "check.ps1"
        script.write_text("Write-Output 'WORKER_POWERSHELL_MARKER'\n", encoding="utf-8")
        run_id, grant = self.queue("powershell_script", [script.name])
        details = self.completed(run_id, "succeeded")
        receipt = details["mxc_receipt"]
        self.assertEqual(receipt["provenance"]["executable"].lower(), "pwsh.exe")
        self.assertEqual(receipt["provenance"]["argv"][:3], ["-NoProfile", "-NonInteractive", "-File"])
        self.assertIn("WORKER_POWERSHELL_MARKER", self.output(run_id, grant))
        self.assert_signed_capture(details)

    def test_files_the_requester_wrote_are_never_executed(self):
        self.python_test("""\
import pathlib
import unittest

class Example(unittest.TestCase):
    def test_review_folder_is_not_in_the_workspace(self):
        workspace = pathlib.Path(__file__).resolve().parents[1]
        self.assertEqual([entry.name for entry in workspace.iterdir() if entry.name == '_pro'], [])
""")
        grant = self.command("grant-create", self.project_id, "--profile", "pro-review")["grant_id"]
        planted_test = ("import unittest\nclass Planted(unittest.TestCase):\n"
                        "    def test_planted(self): print('REQUESTER_PYTHON_RAN')\n")
        for number, (path, content) in enumerate([
            ("_pro/reports/planted.ps1", "Write-Output 'REQUESTER_SCRIPT_RAN'\n"),
            ("_pro/__init__.py", ""),
            ("_pro/test_planted.py", planted_test),
        ]):
            self.mcp("file_write", {"project_id": self.project_id, "grant_id": grant, "operation_id": f"plant-{number}",
                                    "path": path, "content": content}, "executor:default")
        for number, path in enumerate(["_pro/reports/planted.ps1", "_PRO/Reports/planted.ps1", "_PRO~1/reports/planted.ps1"]):
            run_id, _ = self.queue("powershell_script", [path], task_id=f"planted-script-{number}", grant=grant)
            details = self.completed(run_id, "failed")
            self.assertEqual(details["failure_code"], "SCRIPT_INSIDE_REQUESTER_WRITABLE_PATH", path)
            self.assertNotIn("REQUESTER_SCRIPT_RAN", self.output(run_id, grant))
        run_id, _ = self.queue(task_id="planted-python", grant=grant)
        details = self.completed(run_id, "succeeded")
        self.assertEqual(details["test_counts"]["executed"], 1)
        self.assertNotIn("REQUESTER_PYTHON_RAN", self.output(run_id, grant))

    def test_files_in_the_review_folder_cannot_use_up_the_test_budget(self):
        self.python_test("import unittest\nclass Example(unittest.TestCase):\n    def test_ok(self): pass\n")
        folder = self.project / "_pro" / "reports"
        folder.mkdir(parents=True)
        for number in range(1050):
            (folder / f"note_{number}.json").write_text("{}", encoding="utf-8")
        run_id, _ = self.queue(task_id="crowded-review-folder")
        details = self.completed(run_id, "succeeded")
        self.assertEqual(details["test_counts"]["executed"], 1)

    def test_a_folder_any_grant_made_writable_stays_out_of_every_run(self):
        self.python_test("import unittest\nclass Example(unittest.TestCase):\n    def test_ok(self): pass\n")
        notes = self.project / "notes"
        notes.mkdir()
        (notes / "left.ps1").write_text("Write-Output 'EARLIER_GRANT_SCRIPT_RAN'\n", encoding="utf-8")
        earlier = self.command("grant-create", self.project_id, "--writable-path", "notes/**")["grant_id"]
        self.command("grant-revoke", earlier)
        run_id, grant = self.queue("powershell_script", ["notes/left.ps1"], task_id="earlier-grant-script")
        details = self.completed(run_id, "failed")
        self.assertEqual(details["failure_code"], "SCRIPT_INSIDE_REQUESTER_WRITABLE_PATH")
        self.assertNotIn("EARLIER_GRANT_SCRIPT_RAN", self.output(run_id, grant))

    def submit_refused(self, grant, task_id):
        request = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "task_submit", "arguments": {
            "project_id": self.project_id, "task_id": task_id, "operation_id": task_id, "grant_id": grant,
            "recipe": "python_tests", "args": []}}}
        result = subprocess.run(self.cli + ["mcp", "--principal", "executor:default"], input=json.dumps(request) + "\n",
                                capture_output=True, encoding="utf-8", timeout=20)
        answer = json.loads(result.stdout)["result"]
        self.assertTrue(answer["isError"], answer)
        return answer["structuredContent"]

    def test_a_grant_that_can_write_project_files_cannot_queue_a_run(self):
        self.python_test("import unittest\nclass Example(unittest.TestCase):\n    def test_ok(self): pass\n")
        for number, paths in enumerate([["src/**"], ["_pro/**", "src/**"], ["_pro/"]]):
            arguments = [item for path in paths for item in ("--writable-path", path)]
            grant = self.command("grant-create", self.project_id, *arguments)["grant_id"]
            error = self.submit_refused(grant, f"project-writer-{number}")
            self.assertEqual(error["code"], "BRIDGE_POLICY_DENIED", paths)
            self.assertIn("cannot queue a run", error["message"])
        self.assertEqual(self.worker(), [])

    def test_a_grant_for_one_file_does_not_remove_its_folder_from_the_run(self):
        self.python_test("import unittest\nclass Example(unittest.TestCase):\n    def test_ok(self): pass\n")
        (self.tests / "test_named.py").write_text(
            "import unittest\nclass Named(unittest.TestCase):\n    def test_named(self): pass\n", encoding="utf-8")
        self.command("grant-create", self.project_id, "--writable-path", "tests/_")
        self.command("grant-create", self.project_id, "--writable-path", "tests/test_named.py")
        run_id, _ = self.queue(task_id="one-file-grant")
        details = self.completed(run_id, "succeeded")
        self.assertEqual(details["test_counts"]["executed"], 1)

    def test_credentials_in_the_persistent_environment_stop_a_run_unless_the_owner_allows_it(self):
        self.python_test("import unittest\nclass Example(unittest.TestCase):\n    def test_ok(self): pass\n")
        found = self.command("environment-check")
        self.assertTrue(found["readable"])
        self.assertEqual(len(found["credential_like_names"]), found["credential_like_count"])
        run_id, grant = self.queue(task_id="unchecked")
        result = subprocess.run(self.worker_command(allow_environment_credentials=False), capture_output=True,
                                encoding="utf-8", timeout=90)
        self.assertEqual(result.returncode, 0, result.stderr)
        if found["credential_like_count"] == 0:
            self.assertEqual(self.run_state(run_id)["state"], "succeeded")
            return
        details, = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual(self.run_state(run_id)["state"], "failed")
        # No assertion here may print the refusal: a regression could put real names in it.
        self.assertTrue(details["failure_code"] == (
            f"PERSISTENT_ENVIRONMENT_HOLDS_CREDENTIALS: {found['credential_like_count']} entries in the user or machine "
            "environment look like credentials, and a run can read them. The owner can list them with "
            "`edge-bridge environment-check`, then move them out of the persistent environment or start the worker "
            "with --allow-environment-credentials."))
        self.assert_no_workload_manifest(run_id)
        run_id, _ = self.queue(task_id="allowed", grant=grant)
        self.completed(run_id, "succeeded")

    def test_a_second_registered_project_stops_queued_runs(self):
        self.python_test("import unittest\nclass Example(unittest.TestCase):\n    def test_ok(self): pass\n")
        run_id, grant = self.queue(task_id="alone")
        self.completed(run_id, "succeeded")
        other = self.root / "other"
        other.mkdir()
        self.command("register", str(other), "--name", "Second fixture")
        run_id, _ = self.queue(task_id="with-a-neighbour", grant=grant)
        details = self.completed(run_id, "failed")
        self.assertIn("exactly one registered project", details["failure_code"])
        self.assert_no_workload_manifest(run_id)

    def test_a_folder_with_an_unusable_path_does_not_stop_discovery(self):
        self.python_test("import unittest\nclass Example(unittest.TestCase):\n    def test_ok(self): pass\n")
        verbatim = "\\\\?\\" + str(self.project)
        os.makedirs(verbatim + "\\archive.")
        self.addCleanup(os.rmdir, verbatim + "\\archive.")
        deep = self.project
        for _ in range(4):
            deep = deep / ("d" * 200)
        os.makedirs("\\\\?\\" + str(deep))
        run_id, _ = self.queue(task_id="unusable-folder")
        details = self.completed(run_id, "succeeded")
        self.assertEqual(details["test_counts"]["executed"], 1)

    def test_containment_denies_live_write_outside_read_and_network(self):
        outside = self.root / "outside.txt"
        outside.write_bytes(b"harmless external fixture")
        live_target = self.project / "unexpected.txt"
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            self.python_test(f"""\
from pathlib import Path
import socket
import unittest

class Example(unittest.TestCase):
    def test_boundaries(self):
        with self.assertRaises(PermissionError):
            Path({str(live_target)!r}).write_text('unexpected', encoding='ascii')
        print('LIVE_WRITE_DENIED')
        with self.assertRaises(PermissionError):
            Path({str(outside)!r}).read_bytes()
        print('OUTSIDE_READ_DENIED')
        with socket.socket() as probe:
            probe.settimeout(1)
            self.assertEqual(probe.connect_ex(('127.0.0.1', {listener.getsockname()[1]})), 10013)
        print('NETWORK_DENIED')
""")
            before = {path.relative_to(self.project): path.read_bytes() for path in self.project.rglob("*") if path.is_file()}
            run_id, grant = self.queue()
            self.completed(run_id, "succeeded")
            output = self.output(run_id, grant)
            for marker in ("LIVE_WRITE_DENIED", "OUTSIDE_READ_DENIED", "NETWORK_DENIED"):
                self.assertIn(marker, output)
        after = {path.relative_to(self.project): path.read_bytes() for path in self.project.rglob("*") if path.is_file()}
        self.assertEqual(before, after)

    def test_snapshot_uses_broker_protected_file_rules(self):
        names = {
            "credentials.py": False, "CREDENTIALS.json": False, "secrets.json": False,
            ".env": False, ".env.dev": False, "config.env": False, "key.pem": False,
            "credentials_extra.py": True, "secrets_extra.json": True, "settings.py": True,
        }
        for name in names:
            (self.project / name).write_text("0\n", encoding="utf-8")
        self.python_test(f"""\
import unittest
from pathlib import Path

class Example(unittest.TestCase):
    def test_snapshot_names(self):
        for name, allowed in {names!r}.items():
            self.assertEqual(Path(name).exists(), allowed, name)
""")
        listing = self.mcp("file_list", {"project_id": self.project_id, "recursive": True})
        listed = {entry["path"] for entry in listing["entries"]}
        run_id, _ = self.queue()
        details = self.completed(run_id, "succeeded")
        selected = set(details["mxc_receipt"]["approved_files"])
        for name, allowed in names.items():
            with self.subTest(name=name):
                self.assertEqual(name in listed, allowed)
                self.assertEqual(name in selected, name in listed)

    def test_root_auth_json_is_skipped_and_never_reaches_sandbox_or_output(self):
        sentinel = "DUMMY_AUTH_MARKER_98765"
        (self.project / "auth.json").write_text(json.dumps({"marker": sentinel}), encoding="utf-8")
        self.python_test("""\
import unittest
from pathlib import Path

class Example(unittest.TestCase):
    def test_auth_json_absent(self):
        self.assertFalse(Path("auth.json").exists())
""")
        run_id, grant = self.queue(task_id="skip-auth-json")
        details = self.completed(run_id, "succeeded")
        self.assertEqual(details["test_counts"]["passed"], 1)
        selected = details["mxc_receipt"]["approved_files"]
        self.assertNotIn("auth.json", selected)
        output = self.output(run_id, grant)
        self.assertNotIn("auth.json", output)
        self.assertNotIn(sentinel, output)
        job = self.mcp("job_get", {"project_id": self.project_id, "job_id": run_id, "grant_id": grant}, "executor:default")
        self.assertNotIn("auth.json", json.dumps(job))
        self.assertNotIn(sentinel, json.dumps(job))
        artifact = self.mcp("artifact_read", {
            "project_id": self.project_id, "grant_id": grant,
            "artifact_id": job["evidence_manifest_id"],
        }, "executor:default")
        self.assertNotIn("auth.json", json.dumps(artifact))
        self.assertNotIn(sentinel, json.dumps(artifact))

    def test_credential_shaped_metadata_does_not_stop_queue(self):
        self.python_test("import unittest\nclass Example(unittest.TestCase):\n    def test_ok(self): pass\n")
        synthetic_id = "sk-" + "SYNTHETIC" * 3
        denied_run, grant = self.queue(task_id="older-fixture")
        # Exercise a row queued by an older adapter. Current MCP admission
        # already rejects credential-shaped identifiers.
        with closing(sqlite3.connect(self.state / "state.sqlite3")) as db:
            (stored,) = db.execute("SELECT command_json FROM durable_runs WHERE run_id = ?", (denied_run,)).fetchone()
            payload = json.loads(stored)
            payload["task_id"] = synthetic_id
            encoded = json.dumps(payload, separators=(",", ":"))
            db.execute("UPDATE durable_runs SET task_id = ?, command_json = ?, payload_digest = ? WHERE run_id = ?",
                       (synthetic_id, encoded, hashlib.sha256(encoded.encode()).hexdigest(), denied_run))
            db.commit()
        next_run, _ = self.queue(task_id="clean-fixture", grant=grant)
        denied, completed = self.worker()
        self.assertEqual((denied["run"]["run_id"], denied["run"]["state"]), (denied_run, "failed"))
        self.assertEqual(denied["failure_code"], "QUEUE_METADATA_NOT_EXPORTABLE")
        self.assertNotIn(synthetic_id, json.dumps(denied))
        self.assertFalse((self.state / "runs" / denied_run).exists())
        self.assertEqual((completed["run"]["run_id"], completed["run"]["state"]), (next_run, "succeeded"))
        self.assert_raw_removed(next_run)

    def test_workspace_size_cap_terminates_and_removes_snapshot(self):
        self.python_test("""\
import time
import unittest

class Example(unittest.TestCase):
    def test_workspace_growth(self):
        with open("sized-fixture.bin", "wb") as fixture:
            fixture.truncate(256 * 1024 * 1024 + 1)
        time.sleep(15)
""")
        run_id, grant = self.queue()
        details = self.completed(run_id, "failed")
        self.assertEqual(details["mxc_receipt"]["failure_code"], "JOB_WORKSPACE_LIMIT_EXCEEDED")
        self.assertIn("JOB_WORKSPACE_LIMIT_EXCEEDED", self.output(run_id, grant))

    @contextmanager
    def paused_after_preflight(self, run_id, *, expect_workload=False, pause_at_gate=False, ignore_cancel=False,
                               expect_raw_removed=True, pause_at_receipt=False):
        arrived, release, created, cancellation_seen = (
            self.root / name for name in ("arrived", "release", "create-requested", "cancellation-seen")
        )
        runtime = make_runtime(self.root / "instrumented-runtime", f"""\\
from . import jobs, runner
from pathlib import Path
import json
import sys
import time

is_target = Path(sys.argv[2]).parent.name == {run_id!r}

def pause():
    Path({str(arrived)!r}).touch()
    deadline = time.monotonic() + 15
    while not Path({str(release)!r}).exists():
        if time.monotonic() >= deadline:
            raise RuntimeError("Fixture timed out at its barrier.")
        time.sleep(.01)

prepare = runner.prepare_recipe
def pause_after_preflight(*args, **kwargs):
    policy = prepare(*args, **kwargs)
    if is_target and not ({pause_at_gate!r} or {pause_at_receipt!r}):
        pause()
    return policy
runner.prepare_recipe = pause_after_preflight

cancel = jobs.Jobs.cancel
def observe_cancel(*args, **kwargs):
    result = None if {ignore_cancel!r} else cancel(*args, **kwargs)
    Path({str(cancellation_seen)!r}).touch()
    return result
jobs.Jobs.cancel = observe_cancel

create = runner._create_contained_process
def observe_gate(argv, workspace, control, job, stdin, output, before_create):
    def gate():
        if not is_target or argv[-1] != "-v":
            before_create()
            return
        if {pause_at_gate!r}:
            pause()
        before_create()
        Path({str(created)!r}).touch()
    return create(argv, workspace, control, job, stdin, output, gate)
runner._create_contained_process = observe_gate

dumps = json.dumps
def pause_before_publishing_receipt(value, *args, **kwargs):
    if is_target and {pause_at_receipt!r} and isinstance(value, dict) and "mxc_verified" in value:
        pause()
    return dumps(value, *args, **kwargs)
json.dumps = pause_before_publishing_receipt
""")
        with subprocess.Popen(self.worker_command(runtime), stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, encoding="utf-8") as worker:
            try:
                deadline = time.monotonic() + 25
                while not arrived.exists():
                    if worker.poll() is not None or time.monotonic() >= deadline:
                        self.fail(f"Worker never reached the preflight barrier: {worker.communicate(timeout=3)}")
                    time.sleep(.025)
                self.assertEqual(self.run_state(run_id)["state"], "running" if pause_at_receipt else "admitted")
                results = []
                yield results
                release.touch()
                stdout, stderr = worker.communicate(timeout=30)
                self.assertEqual(worker.returncode, 0, stderr)
                results.extend(json.loads(line) for line in stdout.splitlines())
                self.assertEqual(created.exists(), expect_workload, stdout)
                if not expect_workload:
                    self.assertNotIn("pid", self.run_state(run_id))
                if expect_raw_removed:
                    self.assert_raw_removed(run_id)
            finally:
                if worker.poll() is None:
                    worker.kill()
                    worker.communicate(timeout=10)

    def test_revocation_after_preflight_prevents_process_creation(self):
        self.python_test("import unittest\nclass Example(unittest.TestCase):\n    def test_unused(self): pass\n")
        run_id, grant = self.queue()
        with self.paused_after_preflight(run_id):
            self.command("grant-revoke", grant)
        self.assertEqual(self.run_state(run_id)["state"], "failed")

    def wait_for_marker(self, marker, timeout=8):
        deadline = time.monotonic() + timeout
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(.01)
        self.assertTrue(marker.exists(), f"Fixture marker did not appear: {marker.name}")

    def assert_no_workload_manifest(self, run_id):
        self.assertIsNone(self.run_state(run_id).get("evidence_manifest_id"))
        self.assertFalse((self.state / "runs" / run_id / "evidence-manifest.json").exists())
        with closing(sqlite3.connect(self.state / "state.sqlite3")) as db:
            count, = db.execute("SELECT count(*) FROM evidence_manifests WHERE run_id = ?", (run_id,)).fetchone()
        self.assertEqual(count, 0)

    def test_cancel_after_preflight_prevents_process_creation(self):
        self.python_test("import unittest\nclass Example(unittest.TestCase):\n    def test_unused(self): pass\n")
        run_id, grant = self.queue()
        with self.paused_after_preflight(run_id):
            cancelling = self.mcp("job_cancel", {"project_id": self.project_id, "job_id": run_id,
                                  "grant_id": grant, "recipe": "python_tests"}, "executor:default")
            self.assertEqual(cancelling["state"], "cancelling")
            self.wait_for_marker(self.root / "cancellation-seen")
        self.assertEqual(self.run_state(run_id)["state"], "cancelled")
        self.assert_no_workload_manifest(run_id)

    def test_cancel_inside_launch_gate_is_refused_without_evidence(self):
        self.python_test("import unittest\nclass Example(unittest.TestCase):\n    def test_unused(self): pass\n")
        run_id, grant = self.queue()
        # Leave the supervisor waiting at the launch gate and suppress its
        # cancellation delivery so only the Rust atomic predicate can refuse it.
        with self.paused_after_preflight(run_id, pause_at_gate=True, ignore_cancel=True):
            cancelling = self.mcp("job_cancel", {"project_id": self.project_id, "job_id": run_id,
                                  "grant_id": grant, "recipe": "python_tests"}, "executor:default")
            self.assertEqual(cancelling["state"], "cancelling")
        self.assertEqual(self.run_state(run_id)["state"], "cancelled")
        self.assert_no_workload_manifest(run_id)

    def test_busy_launch_rechecks_cancellation_and_keeps_draining(self):
        self.python_test("import unittest\nclass Example(unittest.TestCase):\n    def test_ok(self): pass\n")
        first, grant = self.queue(task_id="busy-gate")
        second, _ = self.queue(task_id="after-busy-gate", grant=grant)
        with self.paused_after_preflight(first, pause_at_gate=True, ignore_cancel=True) as results:
            with closing(sqlite3.connect(self.state / "state.sqlite3")) as db:
                db.execute("BEGIN IMMEDIATE")
                db.execute("UPDATE durable_runs SET state = 'cancelling' WHERE run_id = ?", (first,))
                (self.root / "release").touch()
                self.wait_for_marker(self.state / "runs" / first / "mxc-launch-ready")
                time.sleep(.35)  # Exceed the store's 75 ms busy timeout.
                db.commit()
        self.assertEqual([(r["run"]["run_id"], r["run"]["state"]) for r in results],
                         [(first, "cancelled"), (second, "succeeded")])
        self.assert_no_workload_manifest(first)

    def test_busy_finalization_stores_one_complete_output_batch(self):
        self.python_test(
            "import unittest\nclass Example(unittest.TestCase):\n"
            "    def test_output(self): print('z' * 12000 + 'BATCH_END')\n"
        )
        run_id, grant = self.queue()
        with self.paused_after_preflight(run_id, expect_workload=True, pause_at_receipt=True) as results:
            with closing(sqlite3.connect(self.state / "state.sqlite3")) as db:
                db.execute("BEGIN IMMEDIATE")
                (self.root / "release").touch()
                receipt = self.state / "runs" / run_id / "mxc-receipt.json"
                deadline = time.monotonic() + 8
                while receipt.stat().st_size == 0 and time.monotonic() < deadline:
                    time.sleep(.01)
                self.assertGreater(receipt.stat().st_size, 0)
                time.sleep(.35)  # Keep the write lock after the receipt becomes available.
                self.assertFalse((receipt.parent / "evidence-manifest.json").exists())
                db.commit()
        details, = results
        self.assertEqual(details["run"]["state"], "succeeded", details)
        self.assert_signed_capture(details)
        self.assertEqual(self.output(run_id, grant).count("BATCH_END"), 1)
        self.assertGreaterEqual(details["run"]["output_seq"], 3)

    def test_evidence_store_failure_stops_worker_and_leaves_no_manifest(self):
        self.python_test("import unittest\nclass Example(unittest.TestCase):\n    def test_ok(self): pass\n")
        first, grant = self.queue(task_id="evidence-store-fault")
        second, _ = self.queue(task_id="after-store-fault", grant=grant)
        with closing(sqlite3.connect(self.state / "state.sqlite3")) as db:
            # Fail the manifest insert after signing, while leaving recovery writes available.
            db.executescript("""
                CREATE TRIGGER reject_evidence_insert BEFORE INSERT ON evidence_manifests
                BEGIN SELECT RAISE(ABORT, 'fixture evidence store fault'); END;
            """)
        result = subprocess.run(self.worker_command(), capture_output=True, encoding="utf-8", timeout=90)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("Queue evidence store write failed", result.stderr)
        self.assertNotIn("QUEUE_EVIDENCE_REJECTED", result.stdout + result.stderr + self.output(first))
        self.assertEqual(self.run_state(first)["state"], "unknown")
        self.assert_no_workload_manifest(first)
        self.assert_raw_removed(first)
        self.assertEqual(self.run_state(second)["state"], "queued")
        with closing(sqlite3.connect(self.state / "state.sqlite3")) as db:
            db.execute("DROP TRIGGER reject_evidence_insert")
        details, = self.worker()
        self.assertEqual((details["run"]["run_id"], details["run"]["state"]), (second, "succeeded"))
        self.assertEqual(self.run_state(first)["state"], "unknown")

    def test_cancel_after_workload_exit_is_reflected_in_signed_evidence(self):
        self.python_test("import unittest\nclass Example(unittest.TestCase):\n    def test_ok(self): pass\n")
        run_id, grant = self.queue()
        with self.paused_after_preflight(run_id, expect_workload=True,
                                         pause_at_receipt=True, ignore_cancel=True) as results:
            result = self.mcp("job_cancel", {"project_id": self.project_id, "job_id": run_id,
                              "grant_id": grant, "recipe": "python_tests"}, "executor:default")
            self.assertEqual(result["state"], "cancelling")
        details, = results
        self.assertEqual(details["mxc_receipt"]["status"], "succeeded", details)
        self.assertEqual(self.run_state(run_id)["state"], "cancelled")
        manifest = self.assert_signed_capture(details)
        self.assertTrue(manifest["execution"]["cancelled"])
        self.assertFalse(manifest["execution"]["timed_out"])
        self.assertEqual(manifest["execution"]["outcome_triad"]["verification_outcome"], "CANCELLED")
        with closing(sqlite3.connect(self.state / "state.sqlite3")) as db:
            stored, = db.execute("SELECT manifest_json FROM evidence_manifests WHERE run_id = ?", (run_id,)).fetchone()
        self.assertEqual(json.loads(stored), manifest)
        self.assertEqual(self.run_state(run_id)["evidence_manifest_id"], manifest["identity"]["manifest_id"])

    def test_cleanup_failure_is_signed_as_unconfirmed(self):
        import win32con
        import win32file

        self.python_test("import unittest\nclass Example(unittest.TestCase):\n    def test_ok(self): pass\n")
        run_id, _ = self.queue()
        path = self.state / "runs" / run_id / "mxc-supervisor.pid"
        lock = None
        try:
            with self.paused_after_preflight(run_id, expect_workload=True, expect_raw_removed=False) as results:
                lock = win32file.CreateFile(str(path), win32con.GENERIC_READ, win32con.FILE_SHARE_READ,
                                            None, win32con.OPEN_EXISTING, 0, None)
            details, = results
            self.assertEqual(details["run"]["state"], "succeeded", details)
            self.assertTrue(path.exists())
            manifest = self.assert_signed_capture(details)
            self.assertFalse(manifest["execution"]["cleanup_confirmed"])
        finally:
            if lock is not None:
                lock.Close()
        self.assertEqual(self.worker(), [])
        self.assert_raw_removed(run_id)

    def test_oversized_snapshot_fails_and_worker_drains_next_run(self):
        self.python_test("import unittest\nclass Example(unittest.TestCase):\n    def test_ok(self): pass\n")
        extra = self.project / "data"
        extra.mkdir()
        for i in range(127):
            (extra / f"fixture_{i}.json").write_text("{}", encoding="utf-8")
        script = self.project / "check.ps1"
        script.write_text("Write-Output 'SECOND_RUN'\n", encoding="utf-8")
        first, grant = self.queue(task_id="over-budget")
        second, _ = self.queue("powershell_script", [script.name], task_id="after-budget", grant=grant)
        rejected, completed = self.worker()
        self.assertEqual((rejected["run"]["run_id"], rejected["run"]["state"]), (first, "failed"))
        self.assertTrue(rejected["failure_code"].startswith("RESOURCE_BUDGET_EXCEEDED:"), rejected)
        self.assertIn("129", rejected["failure_code"])
        self.assertIn("128", rejected["failure_code"])
        self.assertIn("129", self.output(first, grant))
        self.assertNotIn("mxc_receipt", rejected)
        self.assert_no_workload_manifest(first)
        self.assertEqual((completed["run"]["run_id"], completed["run"]["state"]), (second, "succeeded"))
        self.assertIn("SECOND_RUN", self.output(second))

    def test_early_supervisor_exit_fails_only_its_run(self):
        self.python_test("import unittest\nclass Example(unittest.TestCase):\n    def test_ok(self): pass\n")
        first, grant = self.queue(task_id="early-exit")
        second, _ = self.queue(task_id="after-early-exit", grant=grant)
        runtime = make_runtime(self.root / "exit-runtime", f"""\\
import os
import sys
from pathlib import Path

if Path(sys.argv[2]).parent.name == {first!r}:
    os._exit(23)
""")
        failed, completed = self.worker(runtime)
        self.assertEqual((failed["run"]["run_id"], failed["run"]["state"]), (first, "failed"))
        self.assertEqual(failed["failure_code"], "QUEUE_SUPERVISOR_EXITED_EARLY")
        self.assert_no_workload_manifest(first)
        self.assert_raw_removed(first)
        self.assertEqual((completed["run"]["run_id"], completed["run"]["state"]), (second, "succeeded"))

    def test_closed_supervisor_pipe_fails_only_its_run(self):
        self.python_test("import unittest\nclass Example(unittest.TestCase):\n    def test_ok(self): pass\n")
        first, grant = self.queue(task_id="closed-pipe")
        second, _ = self.queue(task_id="after-closed-pipe", grant=grant)
        runtime = make_runtime(self.root / "broken-pipe-runtime", f"""\\
from . import runner
from pathlib import Path
import os
import sys
import time

run = Path(sys.argv[2]).parent
if run.name == {first!r}:
    def close_pipe(*args, **kwargs):
        os.close(0)
        (run / "mxc-launch-ready").touch()
        time.sleep(30)
        raise RuntimeError("The owner should stop this fixture on the broken pipe.")
    runner.launch_recipe = close_pipe
""", direct_python=True)
        failed, completed = self.worker(runtime)
        self.assertEqual((failed["run"]["run_id"], failed["run"]["state"]), (first, "failed"))
        self.assertEqual(failed["failure_code"], "QUEUE_SUPERVISOR_EXITED_EARLY")
        self.assert_no_workload_manifest(first)
        self.assert_raw_removed(first)
        self.assertEqual((completed["run"]["run_id"], completed["run"]["state"]), (second, "succeeded"))

    def test_protected_powershell_script_is_refused_before_supervisor_start(self):
        script = self.project / "credentials.ps1"
        script.write_text("Write-Output 'PROTECTED_SCRIPT'\n", encoding="utf-8")
        run_id, _ = self.queue("powershell_script", [script.name])
        details = self.completed(run_id, "failed")
        self.assertIn("protected snapshot source path", details["failure_code"])
        self.assertNotIn("pid", details["run"])
        self.assertFalse((self.state / "runs" / run_id).exists())
        self.assert_no_workload_manifest(run_id)

    def test_evidence_rejection_keeps_draining_after_cleanup(self):
        self.python_test("import unittest\nclass Example(unittest.TestCase):\n    def test_ok(self): pass\n")
        first, grant = self.queue(task_id="signing-failure")
        second, _ = self.queue(task_id="next-run", grant=grant)
        with self.paused_after_preflight(first, expect_workload=True) as results:
            (self.state / "runs" / first / "evidence-manifest.json").touch()
        rejected, completed = results
        self.assertEqual((rejected["run"]["run_id"], rejected["run"]["state"]), (first, "failed"))
        self.assertEqual(rejected["failure_code"], "QUEUE_EVIDENCE_REJECTED")
        self.assertEqual(rejected["run"]["outcome"]["execution_outcome"], "FAIL")
        self.assertEqual(rejected["run"]["outcome"]["verification_outcome"], "NOT_TESTED")
        self.assertEqual((completed["run"]["run_id"], completed["run"]["state"]), (second, "succeeded"))
        self.assert_raw_removed(second)

    def test_revoked_grant_never_starts(self):
        run_id, grant = self.queue()
        self.command("grant-revoke", grant)
        details = self.completed(run_id, "failed")
        self.assertIn("revoked", details["failure_code"].lower())
        self.assertIn("revoked", self.output(run_id).lower())
        self.assertFalse((self.state / "runs" / run_id).exists())

    def test_cancelled_queued_request_never_starts(self):
        run_id, grant = self.queue()
        result = self.mcp("job_cancel", {"project_id": self.project_id, "job_id": run_id,
                          "grant_id": grant, "recipe": "python_tests"}, "executor:default")
        self.assertEqual(result["state"], "cancelled")
        self.assertEqual(self.worker(), [])
        self.assertEqual(self.run_state(run_id)["state"], "cancelled")
        self.assertFalse((self.state / "runs" / run_id).exists())

    @contextmanager
    def active_worker_child(self):
        import win32api
        import win32con

        self.python_test("""\
from pathlib import Path
import subprocess
import sys
import unittest

class Example(unittest.TestCase):
    def test_wait(self):
        child = subprocess.Popen([sys.executable, '-I', '-S', '-B', '-c', 'import time; time.sleep(45)'])
        Path('workload_ready').write_text(str(child.pid), encoding='ascii')
        child.wait()
""")
        run_id, grant = self.queue()
        with subprocess.Popen(self.worker_command(), stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, encoding="utf-8") as worker:
            try:
                deadline = time.monotonic() + 25
                backend = self.state / "runs" / run_id / "mxc-state" / "jobs"
                while time.monotonic() < deadline and worker.poll() is None:
                    markers = list(backend.glob("job_*/workspace/workload_ready"))
                    if markers and markers[0].stat().st_size:
                        break
                    time.sleep(.05)
                else:
                    self.fail(f"Protected workload did not start. Worker status: {worker.poll()}")
                child_pid = int(markers[0].read_text(encoding="ascii"))
                child = win32api.OpenProcess(win32con.SYNCHRONIZE, False, child_pid)
                try:
                    yield run_id, grant, worker, child
                finally:
                    child.Close()
            finally:
                if worker.poll() is None:
                    worker.kill()
                    worker.wait(timeout=10)

    def test_running_subprocess_is_cancelled_after_cleanup(self):
        import win32con
        import win32event

        with self.active_worker_child() as (run_id, grant, worker, child):
            result = self.mcp("job_cancel", {"project_id": self.project_id, "job_id": run_id,
                              "grant_id": grant, "recipe": "python_tests"}, "executor:default")
            self.assertEqual(result["state"], "cancelling")
            stdout, stderr = worker.communicate(timeout=20)
            self.assertEqual(worker.returncode, 0, stderr)
            self.assertEqual(win32event.WaitForSingleObject(child, 0), win32con.WAIT_OBJECT_0)
        details = json.loads(stdout)
        self.assertEqual(details["run"]["state"], "cancelled", details)
        self.assertEqual(self.run_state(run_id)["state"], "cancelled")
        self.assert_raw_removed(run_id)
        self.assert_signed_capture(details)

    def test_killed_worker_is_reconciled_without_replaying_the_run(self):
        import win32con
        import win32event

        with self.active_worker_child() as (run_id, _, worker, child):
            self.assertEqual(self.run_state(run_id)["state"], "running")
            worker.kill()
            worker.communicate(timeout=10)
            self.assertEqual(win32event.WaitForSingleObject(child, 5000), win32con.WAIT_OBJECT_0)
        self.assertEqual(self.worker(), [])
        self.assertEqual(self.run_state(run_id)["state"], "unknown")
        self.assert_raw_removed(run_id)

    def test_python_tests_work_requires_allow_work_exec_and_standard_python_tests_still_skips_pro_work(self):
        (self.project / "calc.py").write_text("def add(a, b): return a + b\n", encoding="utf-8")
        self.python_test("""\
import unittest
from calc import add

class CalcTests(unittest.TestCase):
    def test_add(self):
        self.assertEqual(add(2, 3), 5)
""")
        grant = self.command("grant-create", self.project_id, "--profile", "pro-agent")["grant_id"]
        self.mcp(
            "work_copy",
            {"project_id": self.project_id, "grant_id": grant, "workspace": "fix-1", "paths": ["calc.py", "tests"]},
            "executor:default",
        )
        self.mcp(
            "file_write",
            {
                "project_id": self.project_id,
                "grant_id": grant,
                "operation_id": "plant-work-test",
                "path": "_pro/work/fix-1/tests/test_planted_work.py",
                "content": (
                    "import unittest\nclass PlantedWork(unittest.TestCase):\n"
                    "    def test_planted(self): print('PRO_WORK_PLANTED_RAN')\n"
                ),
            },
            "executor:default",
        )

        # Standard python_tests under pro-agent still never executes anything under _pro/work/.
        std_run, _ = self.queue("python_tests", [], task_id="std-skips-pro-work", grant=grant)
        std_details = self.completed(std_run, "succeeded")
        self.assertEqual(std_details["test_counts"]["executed"], 1)
        self.assertNotIn("PRO_WORK_PLANTED_RAN", self.output(std_run, grant))

        # python_tests_work without --allow-work-exec is refused before snapshot creation.
        work_run, _ = self.queue("python_tests_work", ["fix-1"], task_id="work-no-flag", grant=grant)
        refused, = self.worker(allow_work_exec=False)
        self.assertEqual((refused["run"]["run_id"], refused["run"]["state"]), (work_run, "failed"))
        self.assertEqual(refused["failure_code"], "WORK_EXEC_NOT_ENABLED", refused)
        self.assertFalse((self.state / "runs" / work_run).exists())
        self.assert_no_workload_manifest(work_run)

    def test_python_tests_work_runs_work_copy_with_selector_hidden_filter_and_signed_work_evidence(self):
        # Plant a failing live project bug, copy into _pro/work/fix-1, and fix only the work copy.
        (self.project / "calc.py").write_text("def add(a, b): return a - b\n", encoding="utf-8")
        self.python_test("""\
from pathlib import Path
import unittest
from calc import add

class CalcTests(unittest.TestCase):
    def test_add(self):
        self.assertFalse(Path('.env').exists())
        self.assertEqual(add(2, 3), 5)

    def test_other(self):
        self.assertEqual(add(10, 4), 14)
""")
        grant = self.command("grant-create", self.project_id, "--profile", "pro-agent")["grant_id"]
        self.mcp(
            "work_copy",
            {"project_id": self.project_id, "grant_id": grant, "workspace": "fix-1", "paths": ["calc.py", "tests"]},
            "executor:default",
        )
        self.mcp(
            "work_edit",
            {
                "project_id": self.project_id,
                "grant_id": grant,
                "workspace": "fix-1",
                "operation_id": "fix-calc",
                "edits": [{"path": "calc.py", "replacements": [{"old_text": "a - b", "new_text": "a + b"}]}],
            },
            "executor:default",
        )
        # Drop a hidden file inside the workspace on disk; it must never enter the sandbox snapshot.
        (self.project / "_pro" / "work" / "fix-1" / ".env").write_text("SECRET_TOKEN=work_hidden_sentinel\n", encoding="utf-8")

        found = self.command("environment-check")
        run_all, _ = self.queue("python_tests_work", ["fix-1"], task_id="work-all", grant=grant)
        details, = self.worker(allow_work_exec=True)
        if found["credential_like_count"] > 0:
            # Persistent-env credentials stay mandatory for python_tests_work even with --allow-environment-credentials.
            self.assertEqual(details["run"]["state"], "failed")
            self.assertTrue(
                details["failure_code"].startswith("PERSISTENT_ENVIRONMENT_HOLDS_CREDENTIALS:"),
                "Expected mandatory credential refusal for python_tests_work",
            )
            self.assertFalse((self.state / "runs" / run_all).exists())
            self.assert_no_workload_manifest(run_all)
            return

        self.assertEqual(details["run"]["state"], "succeeded", details)
        self.assertEqual(details["test_counts"]["executed"], 2)
        self.assertEqual(details["test_counts"]["passed"], 2)
        self.assertNotIn(".env", details["mxc_receipt"]["approved_files"])
        self.assertNotIn("work_hidden_sentinel", self.output(run_all, grant))
        self.assert_raw_removed(run_all)
        manifest = self.assert_signed_capture(details)
        self.assertEqual(manifest["authorization"]["executor_identity"], "local-owner-mxc-work-copy-worker")
        self.assertEqual(manifest["conclusions"]["overall_verdict"], "NOT_TESTED")
        self.assertTrue(
            any("_pro/work/fix-1" in note and "live project files were not tested" in note
                for note in manifest["conclusions"]["untested_areas"]),
            manifest["conclusions"]["untested_areas"],
        )
        # Live project file remains unmodified with the planted bug.
        self.assertEqual((self.project / "calc.py").read_text(encoding="utf-8"), "def add(a, b): return a - b\n")

        # Targeted single-test selector runs only the selected test method.
        run_one, _ = self.queue(
            "python_tests_work",
            ["fix-1", "tests.test_worker.CalcTests.test_add"],
            task_id="work-single",
            grant=grant,
        )
        one_details, = self.worker(allow_work_exec=True)
        self.assertEqual(one_details["run"]["state"], "succeeded", one_details)
        self.assertEqual(one_details["test_counts"]["executed"], 1)
        self.assertEqual(one_details["test_counts"]["passed"], 1)
        self.assert_raw_removed(run_one)
        self.assert_signed_capture(one_details)

    def test_79_file_project_with_136k_module_and_no_tests_init_runs_python_tests(self):
        (self.tests / "__init__.py").unlink()
        pkg = self.project / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("", encoding="utf-8")
        big_text = "VALUE = 42\n# " + ("x" * (136 * 1024 - 20)) + "\n"
        (pkg / "big_module.py").write_text(big_text, encoding="utf-8")
        for idx in range(74):
            (pkg / f"mod_{idx:02d}.py").write_text(f"N = {idx}\n", encoding="utf-8")
        (self.tests / "helper.py").write_text("OFFSET = 8\n", encoding="utf-8")
        (self.project / "secrets.json").write_text('{"secret": "DO_NOT_COPY"}\n', encoding="utf-8")
        methods = "\n".join(
            f"    def test_case_{idx:02d}(self): self.assertEqual(big_module.VALUE + helper.OFFSET, 50)"
            for idx in range(88)
        )
        self.python_test(
            "from pathlib import Path\nimport unittest\nfrom pkg import big_module\nimport helper\n"
            "class LargeSuite(unittest.TestCase):\n"
            "    def test_hygiene(self):\n"
            "        self.assertFalse(Path('secrets.json').exists())\n"
            "        self.assertFalse(Path('tests/__init__.py').exists())\n"
            f"{methods}\n"
        )
        (self.tests / "test_extra.py").write_text(
            "import unittest\nfrom pkg import big_module\n"
            "class Extra(unittest.TestCase):\n"
            "    def test_one(self): self.assertEqual(big_module.VALUE, 42)\n",
            encoding="utf-8",
        )
        # 76 pkg files + tests/helper.py + tests/test_worker.py + tests/test_extra.py = 79 files, 90 tests.
        run_id, grant = self.queue(task_id="large-no-init")
        details = self.completed(run_id, "succeeded")
        self.assertEqual(len(details["mxc_receipt"]["approved_files"]), 79)
        self.assertEqual(details["test_counts"], {"executed": 90, "passed": 90, "failed": 0, "skipped": 0})
        self.assertFalse((self.tests / "__init__.py").exists())
        self.assertNotIn("secrets.json", details["mxc_receipt"]["approved_files"])
        self.assertNotIn("DO_NOT_COPY", self.output(run_id, grant))
        self.assert_signed_capture(details)

    def test_snapshot_limit_refusals_report_limit_and_measured_value(self):
        self.python_test("import unittest\nclass Example(unittest.TestCase):\n    def test_ok(self): pass\n")
        grant = self.command("grant-create", self.project_id, "--profile", "pro-review")["grant_id"]

        # 1. Per-file > 256 KiB.
        huge = self.project / "huge_mod.py"
        huge.write_text("SECRET_BODY_MARKER\n" + ("a" * (256 * 1024)), encoding="utf-8")
        r1, _ = self.queue(task_id="lim-file", grant=grant)
        d1 = self.completed(r1, "failed")
        self.assertTrue(d1["failure_code"].startswith("RESOURCE_BUDGET_EXCEEDED:"), d1)
        self.assertIn("huge_mod.py", d1["failure_code"])
        self.assertIn("262144", d1["failure_code"])
        self.assertNotIn("SECRET_BODY_MARKER", d1["failure_code"])
        self.assertIn("huge_mod.py", self.output(r1, grant))
        huge.unlink()

        # 2. Total bytes > 4 MiB.
        bulk = self.project / "bulk"
        bulk.mkdir()
        chunk = "b" * (250 * 1024)
        for i in range(17):
            (bulk / f"b_{i:02d}.py").write_text(chunk, encoding="utf-8")
        r2, _ = self.queue(task_id="lim-total", grant=grant)
        d2 = self.completed(r2, "failed")
        self.assertTrue(d2["failure_code"].startswith("RESOURCE_BUDGET_EXCEEDED:"), d2)
        self.assertIn("total size", d2["failure_code"])
        self.assertIn("4194304", d2["failure_code"])
        for p in bulk.iterdir():
            p.unlink()
        bulk.rmdir()

        # 3. Entry count > 1,000.
        entries = self.project / "entries"
        entries.mkdir()
        for i in range(1001):
            (entries / f"e_{i:04d}.txt").write_text("x", encoding="utf-8")
        r3, _ = self.queue(task_id="lim-entries", grant=grant)
        d3 = self.completed(r3, "failed")
        self.assertTrue(d3["failure_code"].startswith("RESOURCE_BUDGET_EXCEEDED:"), d3)
        self.assertIn("1001", d3["failure_code"])
        self.assertIn("1000", d3["failure_code"])

    def test_python_tests_work_without_tests_init_runs_full_and_selector(self):
        (self.tests / "__init__.py").unlink()
        (self.project / "calc.py").write_text("def add(a, b): return a - b\n", encoding="utf-8")
        (self.tests / "helper.py").write_text("BONUS = 0\n", encoding="utf-8")
        self.python_test(
            "from pathlib import Path\nimport unittest\nfrom calc import add\nimport helper\n"
            "class CalcTests(unittest.TestCase):\n"
            "    def test_add(self):\n"
            "        self.assertFalse(Path('tests/__init__.py').exists())\n"
            "        self.assertEqual(add(2, 3) + helper.BONUS, 5)\n"
            "    def test_other(self):\n"
            "        self.assertEqual(add(10, 4), 14)\n"
        )
        grant = self.command("grant-create", self.project_id, "--profile", "pro-agent")["grant_id"]
        self.mcp(
            "work_copy",
            {"project_id": self.project_id, "grant_id": grant, "workspace": "no-init", "paths": ["calc.py", "tests"]},
            "executor:default",
        )
        self.mcp(
            "work_edit",
            {
                "project_id": self.project_id,
                "grant_id": grant,
                "workspace": "no-init",
                "operation_id": "fix-calc-no-init",
                "edits": [{"path": "calc.py", "replacements": [{"old_text": "a - b", "new_text": "a + b"}]}],
            },
            "executor:default",
        )
        found = self.command("environment-check")
        run_all, _ = self.queue("python_tests_work", ["no-init"], task_id="work-no-init-all", grant=grant)
        details, = self.worker(allow_work_exec=True)
        if found["credential_like_count"] > 0:
            self.assertEqual(details["run"]["state"], "failed")
            self.assertTrue(details["failure_code"].startswith("PERSISTENT_ENVIRONMENT_HOLDS_CREDENTIALS:"))
            return
        self.assertEqual(details["run"]["state"], "succeeded", details)
        self.assertEqual(details["test_counts"], {"executed": 2, "passed": 2, "failed": 0, "skipped": 0})
        self.assertFalse((self.tests / "__init__.py").exists())
        self.assertFalse((self.project / "_pro" / "work" / "no-init" / "tests" / "__init__.py").exists())

        run_one, _ = self.queue(
            "python_tests_work",
            ["no-init", "tests.test_worker.CalcTests.test_add"],
            task_id="work-no-init-one",
            grant=grant,
        )
        one_details, = self.worker(allow_work_exec=True)
        self.assertEqual(one_details["run"]["state"], "succeeded", one_details)
        self.assertEqual(one_details["test_counts"], {"executed": 1, "passed": 1, "failed": 0, "skipped": 0})
        self.assertFalse((self.project / "_pro" / "work" / "no-init" / "tests" / "__init__.py").exists())


if __name__ == "__main__":
    unittest.main()
