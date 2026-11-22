"""Exercise local queue approval against the real Windows MXC runner."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

from tests.e2e.test_v050_queue_worker import find_worker_binary, make_runtime


ACTIVE_TEST = """\
from pathlib import Path
import subprocess
import sys
import unittest

class Example(unittest.TestCase):
    def test_wait(self):
        child = subprocess.Popen([sys.executable, '-I', '-S', '-B', '-c', 'import time; time.sleep(45)'])
        Path('queued_mxc_ready.txt').write_text('child started', encoding='ascii')
        print('QUEUED_MXC_CHILD_RUNNING', flush=True)
        child.wait()
"""


@unittest.skipUnless(sys.platform == "win32", "Uses Windows MXC")
class TestQueuedMxc(unittest.TestCase):
    def setUp(self):
        self.bin = find_worker_binary()
        self.assertIsNotNone(self.bin, "Build the release binary before running the MXC acceptance suite")
        temp = tempfile.TemporaryDirectory(prefix="bridge-mxc-acceptance-")
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        self.state = root / "state"
        self.tests = root / "project" / "tests"
        self.tests.mkdir(parents=True)
        (self.tests / "__init__.py").write_bytes(b"")
        self.cli = [str(self.bin), "--state-dir", str(self.state)]
        self.project_id = self.register(self.tests.parent)
        self.runtime = make_runtime(root / "runtime")

    def register(self, root):
        result = subprocess.run(
            self.cli + ["register", str(root), "--name", "Fixture", "--grant-edge"],
            encoding="utf-8", capture_output=True, check=True, timeout=20,
        )
        return json.loads(result.stdout)["project_id"]

    def mcp(self, method, arguments, principal="local"):
        request = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": method, "arguments": arguments}}
        process = subprocess.run(
            self.cli + ["mcp", "--principal", principal], input=json.dumps(request) + "\n",
            encoding="utf-8", capture_output=True, check=True, timeout=20,
        )
        self.assertEqual(process.stderr, "")
        return json.loads(process.stdout)["result"]

    def queue(self, name, extra_arguments=()):
        args = {"project_id": self.project_id, "task_id": name, "operation_id": name,
                "recipe": "python_tests", "args": list(extra_arguments)}
        result = self.mcp("task_submit", args)
        self.assertFalse(result["isError"], result)
        return args, result["structuredContent"]["result"]["run_id"]

    def owner_command(self, run_id, timeout=30):
        return self.cli + ["run-queued-python-tests", run_id, "--runtime-root", str(self.runtime),
                           "--file", "tests/__init__.py", "--file", "tests/test_example.py",
                           "--timeout-seconds", str(timeout)]

    def run_owned(self, run_id, timeout=30):
        process = subprocess.run(self.owner_command(run_id, timeout), encoding="utf-8",
                                 capture_output=True, check=True, timeout=timeout + 30)
        return json.loads(process.stdout)

    def wait_for_workload(self, run_id, owner):
        deadline = time.monotonic() + 18
        while time.monotonic() < deadline and owner.poll() is None:
            directory = self.state / "runs" / run_id / "mxc-state" / "jobs"
            for marker in directory.glob("job_*/workspace/queued_mxc_ready.txt"):
                if marker.read_text(encoding="ascii") == "child started":
                    return
            time.sleep(.05)
        self.fail("The protected child did not start")

    def save_evidence(self, name, fields):
        destination = os.environ.get("EPB_MXC_QUEUE_EVIDENCE")
        if destination:
            result = {"binary_sha256": hashlib.sha256(self.bin.read_bytes()).hexdigest(), **fields}
            (Path(destination) / name).write_text(json.dumps(result, indent=2), encoding="utf-8")

    def test_success_duplicate_and_edge_scope(self):
        content = ("import unittest\nclass Example(unittest.TestCase):\n"
                   "    def test_sum(self):\n"
                   "        print('Bearer ' + 'SYNTHETIC' * 3)\n"
                   "        self.assertEqual(2+2, 4)\n")
        path = self.tests / "test_example.py"
        path.write_text(content, encoding="utf-8")
        original = path.read_bytes()
        args, run_id = self.queue("success")
        result = self.run_owned(run_id)
        self.assertEqual(result["run"]["state"], "succeeded", result)
        self.assertEqual(result["run"]["run_id"], run_id)
        self.assertTrue(result["mxc_receipt"]["mxc_verified"])
        self.assertEqual(len(result["mxc_receipt"]["verified_canaries"]), 10)
        self.assertTrue(result["mxc_receipt"]["test_snapshot_unchanged"])
        self.assertEqual(result["test_counts"], {"executed": 1, "passed": 1, "failed": 0, "skipped": 0})
        self.assertEqual(path.read_bytes(), original)
        manifest_path = Path(result["evidence_manifest_path"])
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(manifest["identity"]["manifest_id"], result["run"]["evidence_manifest_id"])
        self.assertEqual(manifest["identity"]["run_id"], run_id)
        self.assertEqual(manifest["source"]["source_hash_before"], manifest["source"]["source_hash_after"])
        self.assertEqual(manifest["conclusions"]["overall_verdict"], "PASS")
        redacted_log = manifest_path.parent / "test-results-redacted.log"
        original_log = redacted_log.read_bytes()
        self.assertIn(b"[REDACTED:bearer_token]", original_log)
        self.assertNotIn(b"SYNTHETIC" * 3, original_log)
        verify_command = self.cli + ["verify-evidence", str(manifest_path), "--artifacts-dir", str(manifest_path.parent)]
        verified = subprocess.run(verify_command, capture_output=True, encoding="utf-8", check=True, timeout=15)
        verification = json.loads(verified.stdout)
        self.assertTrue(verification["overall_verified"], verification)
        self.assertTrue(verification["device_key_trusted"])
        self.assertTrue(verification["artifacts_hashes_verified"])
        redacted_log.write_bytes(original_log + b"\nchanged by the integrity fixture\n")
        tampered = subprocess.run(verify_command, capture_output=True, encoding="utf-8", timeout=15)
        self.assertNotEqual(tampered.returncode, 0)
        self.assertFalse(json.loads(tampered.stdout)["artifacts_hashes_verified"])
        redacted_log.write_bytes(original_log)
        duplicate = subprocess.run(self.owner_command(run_id), encoding="utf-8", capture_output=True, timeout=20)
        self.assertNotEqual(duplicate.returncode, 0)
        self.assertIn("BridgePolicyDenied", duplicate.stderr)
        replay = self.mcp("task_submit", args)["structuredContent"]["result"]
        self.assertEqual((replay["run_id"], replay["state"], replay["idempotent_replay"]), (run_id, "succeeded", True))
        denied = self.mcp("task_submit", args, "edge")
        self.assertEqual(denied["structuredContent"]["code"], "BRIDGE_POLICY_DENIED")
        _, unsupported = self.queue("arguments", ["unsupported-argument"])
        refusal = subprocess.run(self.owner_command(unsupported), encoding="utf-8", capture_output=True, timeout=20)
        self.assertNotEqual(refusal.returncode, 0)
        self.assertIn("BridgePolicyDenied", refusal.stderr)
        self.assertFalse((self.state / "runs" / unsupported).exists())
        self.save_evidence("success.json", {"run_id": run_id, "state": "succeeded", "mxc": result["mxc_receipt"],
            "test_counts": result["test_counts"], "replayed_once": True, "edge_denied": True, "arguments_denied": True,
            "evidence_verification": verification, "changed_artifact_rejected": True, "log_redaction_checked": True})

    def test_actual_child_cancellation_respects_project_scope(self):
        (self.tests / "test_example.py").write_text(ACTIVE_TEST, encoding="utf-8")
        _, run_id = self.queue("cancel")
        separate = self.tests.parent.parent / "other-project"
        separate.mkdir()
        other_id = self.register(separate)
        with subprocess.Popen(self.owner_command(run_id), encoding="utf-8",
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE) as owner:
            try:
                self.wait_for_workload(run_id, owner)
                refusal = self.mcp("job_cancel", {"project_id": other_id, "job_id": run_id})
                self.assertEqual(refusal["structuredContent"]["code"], "BRIDGE_POLICY_DENIED")
                accepted = self.mcp("job_cancel", {"project_id": self.project_id, "job_id": run_id})
                self.assertEqual(accepted["structuredContent"]["result"]["state"], "cancelling")
                stdout, stderr = owner.communicate(timeout=15)
                self.assertEqual(owner.returncode, 0, stderr)
            finally:
                if owner.poll() is None:
                    self.mcp("job_cancel", {"project_id": self.project_id, "job_id": run_id})
                    try:
                        owner.communicate(timeout=10)
                    except subprocess.TimeoutExpired:
                        owner.kill()
                        owner.wait(timeout=5)
        result = json.loads(stdout)
        self.assertEqual(result["run"]["state"], "cancelled")
        self.assertEqual(result["verification"], "NOT_TESTED")
        self.save_evidence("cancel.json", {"run_id": run_id, "state": "cancelled",
            "active_child_observed_before_cancel": True, "wrong_project_denied": True, "outer_job_empty": True})

    def test_zero_tests_are_signed_as_not_tested(self):
        (self.tests / "test_example.py").write_text("import unittest\n", encoding="utf-8")
        _, run_id = self.queue("zero-tests")
        result = self.run_owned(run_id)
        self.assertEqual(result["run"]["state"], "failed", result)
        self.assertEqual(result["test_counts"]["executed"], 0)
        manifest_path = Path(result["evidence_manifest_path"])
        verified = subprocess.run(self.cli + ["verify-evidence", str(manifest_path), "--artifacts-dir",
            str(manifest_path.parent)], capture_output=True, encoding="utf-8", check=True, timeout=15)
        report = json.loads(verified.stdout)
        self.assertTrue(report["overall_verified"])
        self.assertEqual(report["reported_verdict"], "NOT_TESTED")
        self.save_evidence("zero-tests.json", {"run_id": run_id, "executed": 0, "verification": report})

    def test_timeout_stops_started_snapshot(self):
        (self.tests / "test_example.py").write_text(ACTIVE_TEST, encoding="utf-8")
        _, run_id = self.queue("timeout")
        result = self.run_owned(run_id, timeout=12)
        self.assertEqual(result["run"]["state"], "timed_out", result)
        self.assertTrue(result["mxc_receipt"]["mxc_verified"])
        directory = self.state / "runs" / run_id
        self.assertEqual(list(directory.glob("mxc-*")), [])
        self.assertIn("QUEUED_MXC_CHILD_RUNNING", (directory / "test-results-redacted.log").read_text(encoding="utf-8"))
        self.save_evidence("timeout.json", {"run_id": run_id, "state": "timed_out",
            "active_child_observed_before_timeout": True, "outer_job_empty": True})


if __name__ == "__main__":
    unittest.main()
