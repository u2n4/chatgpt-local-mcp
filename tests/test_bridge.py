import asyncio
import json
import os
import shutil
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from edge_bridge.broker import BridgeError, call_broker, read_token, setup_state, signature
from edge_bridge.mcp_server import TOOL_SPECS

HERE = Path(__file__).resolve().parents[1]


class BridgeSmokeTest(unittest.TestCase):
    def setUp(self):
        self.fixture = tempfile.TemporaryDirectory(dir=os.environ.get("EPB_TEST_PARENT"))
        self.addCleanup(self.fixture.cleanup)
        root = Path(self.fixture.name)
        self.state = root / "state"
        self.project = root / "project"
        self.project.mkdir()
        self.outside = root / "outside.txt"
        self.outside.write_text("outside synthetic canary", encoding="utf-8")
        (self.project / "hello.txt").write_text("synthetic hello", encoding="utf-8")
        setup_state(self.state)
        self.process = None
        self.addCleanup(self.stop_broker)
        self.start_broker()

    def start_broker(self):
        discovery = self.state / "broker.json"
        previous = discovery.stat().st_ino if discovery.is_file() else None
        self.process = subprocess.Popen(
            [sys.executable, "-m", "edge_bridge.cli", "--state-dir", str(self.state), "start"],
            cwd=HERE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        for _ in range(100):
            if self.process.poll() is not None:
                stdout, stderr = self.process.communicate()
                self.fail(f"Broker startup exited: {stdout} {stderr}")
            if discovery.is_file() and discovery.stat().st_ino != previous:
                return
            time.sleep(0.05)
        self.fail("Broker did not publish its discovery entry.")

    def stop_broker(self):
        if self.process is None:
            return
        if self.process.poll() is None:
            try:
                self.local("owner_stop")
                self.process.wait(5)
            except (BridgeError, subprocess.TimeoutExpired):
                self.process.kill()
                self.process.wait(5)
        self.process.communicate()
        self.process = None

    def local(self, method, values=None):
        return call_broker(self.state, "local", method, values)

    def register(self):
        return self.local("owner_register", {"root": str(self.project), "name": "Acceptance fixture"})["project_id"]

    @staticmethod
    def rpc_error(error):
        return json.loads(error.read().decode("utf-8"))["code"]

    def test_auth_origin_and_scope(self):
        project_id = self.register()
        url = f'https://127.0.0.1:{json.loads((self.state / "broker.json").read_text())["port"]}/v1/call'
        tls = ssl.create_default_context(cafile=str(self.state / "ipc.pem"))
        body = json.dumps({"method": "bridge_info", "params": {}}).encode()
        with self.assertRaises(HTTPError) as unauthorized:
            urlopen(Request(url, data=body, headers={"Content-Type": "application/json"}), context=tls, timeout=2)
        self.assertEqual(self.rpc_error(unauthorized.exception), "AUTH_REQUIRED")
        nonce, stamp = secrets.token_hex(16), str(int(time.time()))
        signed = {"Content-Type": "application/json", "X-Bridge-Principal": "local",
                  "X-Bridge-Nonce": nonce, "X-Bridge-Timestamp": stamp,
                  "X-Bridge-Signature": signature(read_token(self.state, "local"), "request", "local", nonce, stamp, body)}
        with self.assertRaises(HTTPError) as untrusted_origin:
            urlopen(Request(url, data=body, headers={**signed, "Origin": "https://example.test"}), context=tls, timeout=2)
        self.assertEqual(self.rpc_error(untrusted_origin.exception), "IPC_REQUEST_DENIED")
        signed_request = Request(url, data=body, headers=signed)
        with urlopen(signed_request, context=tls, timeout=2) as response:
            self.assertTrue(json.loads(response.read())["ok"])
        with self.assertRaises(HTTPError) as replay:
            urlopen(signed_request, context=tls, timeout=2)
        self.assertEqual(self.rpc_error(replay.exception), "AUTH_REQUIRED")

        edge = lambda method, args=None: call_broker(self.state, "edge", method, args)
        with self.assertRaises(BridgeError) as denied:
            edge("file_read", {"project_id": project_id, "path": "hello.txt"})
        self.assertEqual(denied.exception.code, "PROJECT_NOT_GRANTED")
        self.local("owner_grant_edge", {"project_id": project_id})
        with self.assertRaises(BridgeError) as denied:
            edge("owner_grant_edge", {"project_id": project_id})
        self.assertEqual(denied.exception.code, "AUTH_REQUIRED")
        with self.assertRaises(BridgeError) as denied:
            edge("file_delete", {"project_id": project_id, "path": "hello.txt"})
        self.assertEqual(denied.exception.code, "BRIDGE_POLICY_DENIED")
        self.assertEqual(denied.exception.details["rejection_layer"], "bridge")
        with self.assertRaises(BridgeError) as escape:
            edge("file_read", {"project_id": project_id, "path": "../outside.txt"})
        self.assertEqual(escape.exception.code, "PATH_OUTSIDE_ROOT")
        self.local("owner_revoke_edge", {"project_id": project_id})
        with self.assertRaises(BridgeError) as denied:
            edge("project_status", {"project_id": project_id})
        self.assertEqual(denied.exception.code, "PROJECT_NOT_GRANTED")

    def test_stdio_resume_and_repeat_after_real_restart(self):
        project_id = self.register()
        first_instance = self.local("bridge_info")["instance_id"]
        request = {
            "project_id": project_id, "path": "modified.txt", "content": "change from fixture",
            "expected_hash": None, "operation_id": "file-once",
        }
        original = self.local("file_write", request)
        self.assertEqual(original, self.local("file_write", request))
        with self.assertRaises(BridgeError):
            self.local("file_write", {**request, "content": "different"})
        self.assertEqual((self.project / "modified.txt").read_text(), "change from fixture")
        self.local("task_checkpoint", {
            "project_id": project_id, "task_id": "smoke", "operation_id": "checkpoint-1",
            "summary": "Prepared synthetic fixture", "objective": "Exercise durable state",
            "next_action": "Inspect test output",
        })
        artifact = self.local("owner_record_artifact", {
            "project_id": project_id, "task_id": "smoke", "path": "modified.txt",
        })
        self.local("owner_grant_edge", {"project_id": project_id})
        args = {"project_id": project_id, "task_id": "smoke"}

        async def read_via_stdio():
            adapter = StdioServerParameters(
                command=sys.executable,
                args=["-m", "edge_bridge.cli", "--state-dir", str(self.state), "mcp", "--principal", "edge"],
                cwd=HERE,
            )
            async with stdio_client(adapter) as (reader, writer):
                async with ClientSession(reader, writer) as client:
                    await client.initialize()
                    tools = {tool.name: tool for tool in (await client.list_tools()).tools}
                    self.assertEqual(set(tools), set(TOOL_SPECS))
                    self.assertTrue(tools["file_read"].annotations.readOnlyHint)
                    self.assertFalse(tools["file_write"].annotations.readOnlyHint)
                    self.assertFalse(tools["process_start"].annotations.readOnlyHint)
                    self.assertNotIn("computer_use", tools)
                    unsupported = await client.call_tool("computer_use", {})
                    self.assertTrue(unsupported.isError)
                    self.assertEqual(unsupported.structuredContent["code"], "METHOD_NOT_FOUND")
                    self.assertFalse(tools["file_write"].inputSchema["additionalProperties"])
                    response = await client.call_tool("file_read", {"project_id": project_id, "path": "hello.txt"})
                    self.assertFalse(response.isError, response)
                    self.assertIn("synthetic hello", json.dumps(response.structuredContent))
                    invalid = await client.call_tool("file_read", {"project_id": project_id, "path": "hello.txt", "extra": "denied"})
                    self.assertTrue(invalid.isError)
                    refused = await client.call_tool("file_write", request)
                    self.assertTrue(refused.isError)
                    self.assertEqual(refused.structuredContent["code"], "BRIDGE_POLICY_DENIED")
                    self.assertEqual(refused.structuredContent["host_capability"], "not_tested")
                    artifact_read = await client.call_tool("artifact_read", {
                        "project_id": project_id, "artifact_id": artifact["artifact_id"],
                    })
                    self.assertFalse(artifact_read.isError, artifact_read)
                    self.assertEqual(artifact_read.structuredContent["result"]["hash"], artifact["sha256"].removeprefix("sha256:"))
                    resume = await client.call_tool("project_resume", args)
                    self.assertFalse(resume.isError, resume)
                    return resume.structuredContent["result"]

        before = asyncio.run(read_via_stdio())
        self.stop_broker()
        self.start_broker()
        after = asyncio.run(read_via_stdio())
        self.assertEqual(before, after)
        self.assertEqual(after["next_action"], "Inspect test output")
        self.assertEqual(self.local("bridge_info")["instance_id"], first_instance)
        self.assertEqual(self.local("file_write", request), original)
        written_hash = self.local("file_read", {"project_id": project_id, "path": "modified.txt"})["hash"]
        self.local("file_write", {**request, "content": "later revision", "expected_hash": written_hash,
                                  "operation_id": "file-two"})
        with self.assertRaises(BridgeError) as changed:
            self.local("artifact_read", {"project_id": project_id, "artifact_id": artifact["artifact_id"]})
        self.assertEqual(changed.exception.code, "VERSION_CONFLICT")
        with self.assertRaises(BridgeError) as command:
            self.local("process_start", {
                "project_id": project_id, "task_id": "smoke", "executable": "python",
                "argv": ["-c", "raise RuntimeError('must never launch')"], "operation_id": "blocked-process",
            })
        self.assertEqual(command.exception.code, "EXECUTION_REQUEST_UNSUPPORTED")
        self.assertEqual(self.local("project_status", {"project_id": project_id})["jobs"], [])
        with self.assertRaises(BridgeError):
            self.local("worker_start", {
                "project_id": project_id, "task_id": "smoke", "role": "review",
                "objective": "must never launch", "scope": [], "operation_id": "blocked-worker",
            })

    def test_stale_listener_does_not_receive_plaintext(self):
        self.stop_broker()
        captured = []
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as fake:
            fake.bind(("127.0.0.1", 0))
            fake.listen(1)
            fake.settimeout(3)

            def capture():
                with fake.accept()[0] as connection:
                    connection.settimeout(3)
                    captured.append(connection.recv(8192))

            peer = threading.Thread(target=capture, daemon=True)
            peer.start()
            (self.state / "broker.json").write_text(
                json.dumps({"port": fake.getsockname()[1]}), encoding="utf-8",
            )
            with self.assertRaises(BridgeError) as denied:
                self.local("bridge_info", {"secret_canary": "do-not-send-plaintext"})
            self.assertEqual(denied.exception.code, "BROKER_OFFLINE")
            peer.join(4)
        self.assertTrue(captured)
        self.assertEqual(captured[0][:1], b"\x16")  # TLS handshake record
        self.assertNotIn(b"do-not-send-plaintext", captured[0])
        self.assertNotIn(read_token(self.state, "local").encode(), captured[0])

    def test_real_calculator_job_and_restart(self):
        for source in (HERE / "examples" / "calculator").glob("*.py"):
            shutil.copyfile(source, self.project / source.name)
        project = self.register()
        before = self.local("file_read", {"project_id": project, "path": "calculator.py"})
        corrected = before["content"].replace("a - b", "a + b")
        self.local("file_write", {
            "project_id": project, "path": "calculator.py", "content": corrected,
            "expected_hash": before["hash"], "operation_id": "fix-calculator",
        })
        example = {
            "project_id": project, "task_id": "calculator", "operation_id": "run-example",
            "executable": "python", "argv": ["-B", "-m", "unittest", "-v"], "timeout_seconds": 30,
        }
        job = self.local("process_start", example)
        address = {"project_id": project, "job_id": job["job_id"]}
        repeat = self.local("process_start", example)
        self.assertEqual(repeat["job_id"], job["job_id"])
        self.assertFalse(repeat["created"])
        with self.assertRaises(BridgeError):
            self.local("process_start", {**example, "timeout_seconds": 31})
        end = time.monotonic() + 35
        status = self.local("job_get", address)
        while status["status"] in ("queued", "running", "cancelling") and time.monotonic() < end:
            time.sleep(0.1)
            status = self.local("job_get", address)
        self.assertEqual(status["status"], "succeeded", status)
        self.assertEqual(status["exit_code"], 0)
        self.assertEqual(status["evidence"]["policy"]["canaries"]["external_hardlink"], "denied")
        self.assertEqual(len(self.local("project_status", {"project_id": project})["jobs"]), 1)
        output = self.local("job_output", address)
        self.assertIn("Ran 2 tests", output["output"])
        self.assertIn("OK", output["output"])
        source_file = self.project / "calculator.py"
        snapshot_file = Path(status["evidence"]["policy"]["cwd"]) / "calculator.py"
        self.assertEqual(source_file.read_bytes(), corrected.encode("utf-8"))
        self.assertNotEqual(source_file.stat().st_ino, snapshot_file.stat().st_ino)
        self.assertFalse((self.project / "contained-write.txt").exists())
        self.stop_broker()
        self.start_broker()
        self.assertEqual(self.local("job_get", address), status)
        self.assertEqual(self.local("job_output", address), output)

    def test_real_broker_cancel_and_crash_reconciliation(self):
        for source in (HERE / "examples" / "calculator").glob("*.py"):
            shutil.copyfile(source, self.project / source.name)
        project = self.register()
        args = {"project_id": project, "task_id": "lifecycle", "executable": "python",
                "argv": ["-B", "-m", "unittest", "-v"], "timeout_seconds": 30}
        job = self.local("process_start", {**args, "operation_id": "startup-cancel"})
        address = {"project_id": project, "job_id": job["job_id"]}
        cancellation = {**address, "operation_id": "cancel-request"}
        receipt = self.local("job_cancel", cancellation)
        self.assertTrue(receipt["cancellation_requested"])
        self.assertEqual(self.local("job_cancel", cancellation), receipt)
        end = time.monotonic() + 15
        while self.local("job_get", address)["status"] == "cancelling" and time.monotonic() < end:
            time.sleep(0.05)
        self.assertEqual(self.local("job_get", address)["status"], "cancelled")
        self.assertNotIn("Ran 2 tests", self.local("job_output", address)["output"])

        crash_args = {**args, "operation_id": "crash-on-start"}
        launched = self.local("process_start", crash_args)
        self.process.kill()
        self.process.wait(5)
        self.process.communicate()
        self.process = None
        self.start_broker()
        resumed = self.local("process_start", crash_args)
        self.assertFalse(resumed["created"])
        self.assertEqual(resumed["job_id"], launched["job_id"])
        self.assertEqual(resumed["status"], "unknown_after_restart")

    def test_real_blender_job_and_timeout(self):
        shutil.copyfile(HERE / "examples" / "blender" / "build_knot.py", self.project / "build_knot.py")
        project = self.register()
        base = {"project_id": project, "task_id": "blender", "executable": "blender",
                "argv": ["--background", "--factory-startup", "--disable-autoexec", "--python", "build_knot.py"]}

        def run(operation_id, timeout):
            job = self.local("process_start", {**base, "operation_id": operation_id, "timeout_seconds": timeout})
            if operation_id == "complete-blender":
                with self.assertRaises(BridgeError) as busy:
                    self.local("process_start", {**base, "operation_id": "another-active-job", "timeout_seconds": 45})
                self.assertEqual(busy.exception.code, "RESOURCE_BUDGET_EXCEEDED")
            address = {"project_id": project, "job_id": job["job_id"]}
            end = time.monotonic() + 50
            while time.monotonic() < end:
                current = self.local("job_get", address)
                if current["status"] not in ("queued", "running", "cancelling"):
                    return current
                time.sleep(0.1)
            self.fail("Blender job did not return an outcome.")

        timeout = run("timeout-blender", 1)
        self.assertEqual(timeout["status"], "timed_out", timeout)
        result = run("complete-blender", 45)
        self.assertEqual(result["status"], "succeeded", result)
        self.assertEqual(result["exit_code"], 0)
        artifacts = result["evidence"]["artifacts"]
        self.assertTrue(artifacts["geometry"]["manifold"])
        self.assertEqual(artifacts["geometry"]["vertices"], 17280)
        self.assertEqual({file["path"] for file in artifacts["files"]}, {"knot.blend", "knot.glb"})
        self.assertFalse((self.project / "knot.blend").exists())
        self.assertFalse((self.project / "knot.glb").exists())

    def test_owner_granted_nested_python_suite_and_revocation(self):
        for name in ("src", "tests"):
            directory = self.project / name
            directory.mkdir()
            (directory / "__init__.py").write_text("", encoding="utf-8")
        (self.project / "src" / "math_ops.py").write_text("def total(values):\n    return 0\n", encoding="utf-8")
        tests = self.project / "tests" / "test_math_ops.py"
        tests.write_text(
            "import unittest\nfrom src.math_ops import total\n"
            "class MathTests(unittest.TestCase):\n"
            "    def test_total(self):\n        self.assertEqual(total([3, 4]), 7)\n",
            encoding="utf-8",
        )
        project = self.register()
        project_args = {"project_id": project}
        request = {
            **project_args, "task_id": "approved-tests", "operation_id": "first-project-test",
            "executable": "python", "argv": ["-B", "-m", "unittest", "discover", "-s", "tests", "-t", ".", "-v"],
            "timeout_seconds": 30,
        }
        with self.assertRaises(BridgeError) as no_permission:
            self.local("process_start", request)
        self.assertEqual(no_permission.exception.code, "PYTHON_TEST_SCOPE_REQUIRED")
        grant_files = ["src/__init__.py", "src/math_ops.py", "tests/__init__.py", "tests/test_math_ops.py"]
        with self.assertRaises(BridgeError) as bad_grant:
            self.local("owner_grant_python_tests", {**project_args, "files": grant_files + ["../outside.py"]})
        self.assertEqual(bad_grant.exception.code, "INVALID_TEST_SCOPE")
        grant = self.local("owner_grant_python_tests", {**project_args, "files": grant_files})
        self.assertTrue(grant["enabled"])
        self.local("owner_grant_edge", project_args)
        with self.assertRaises(BridgeError) as remote:
            call_broker(self.state, "edge", "process_start", request)
        self.assertEqual(remote.exception.code, "BRIDGE_POLICY_DENIED")

        version = self.local("file_read", {**project_args, "path": "src/math_ops.py"})
        self.local("file_write", {**project_args, "path": "src/math_ops.py",
                                "content": "def total(values):\n    return sum(values)\n",
                                "expected_hash": version["hash"], "operation_id": "fix-without-regrant"})

        def run(call):
            job = self.local("process_start", call)
            address = {**project_args, "job_id": job["job_id"]}
            end = time.monotonic() + 35
            while time.monotonic() < end:
                result = self.local("job_get", address)
                if result["status"] not in {"queued", "running", "cancelling"}:
                    return result, self.local("job_output", address)
                time.sleep(0.1)
            self.fail("Project test job did not complete.")

        result, output = run(request)
        self.assertEqual(result["status"], "succeeded", result)
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["evidence"]["policy"]["canaries"]["host_named_pipe"], "denied")
        self.assertEqual(result["evidence"]["policy"]["canaries"]["ipv6_loopback"], "denied")
        self.assertIn("Ran 1 test", output["output"])
        snapshot = Path(result["evidence"]["policy"]["cwd"])
        self.assertFalse((snapshot / "hello.txt").exists())
        self.assertNotEqual((snapshot / "src" / "math_ops.py").stat().st_ino,
                            (self.project / "src" / "math_ops.py").stat().st_ino)
        tests.write_text("import os\nos.write(1, b'x' * (400 * 1024))\n", encoding="utf-8")
        flooded, _ = run({**request, "operation_id": "bounded-output"})
        self.assertEqual(flooded["status"], "failed", flooded)
        self.assertEqual(flooded["evidence"]["failure_code"], "JOB_LOG_LIMIT_EXCEEDED")
        self.assertEqual((Path(flooded["evidence"]["policy"]["cwd"]).parent / "control" / "job.log").stat().st_size,
                         256 * 1024)

        self.stop_broker()
        self.start_broker()
        scope = self.local("project_status", project_args)["python_test_scope"]
        self.assertEqual(scope["files"], sorted(grant_files))
        tests.write_text("import time\ntime.sleep(10)\n", encoding="utf-8")
        ongoing = self.local("process_start", {**request, "operation_id": "revocation-will-stop"})
        ongoing_addr = {**project_args, "job_id": ongoing["job_id"]}
        end = time.monotonic() + 35
        while self.local("job_get", ongoing_addr)["status"] == "queued" and time.monotonic() < end:
            time.sleep(0.05)
        self.assertEqual(self.local("job_get", ongoing_addr)["status"], "running")
        renewed = self.local("owner_revoke_python_tests", project_args)
        self.assertFalse(renewed["enabled"])
        self.assertTrue(renewed["cancellation_requested"])
        end = time.monotonic() + 15
        verdict = self.local("job_get", ongoing_addr)
        while verdict["status"] == "cancelling" and time.monotonic() < end:
            time.sleep(0.05)
            verdict = self.local("job_get", ongoing_addr)
        self.assertEqual(verdict["status"], "cancelled")
        self.assertEqual(verdict["evidence"]["stop_reason"], "test_scope_revoked")
        with self.assertRaises(BridgeError) as revoked:
            self.local("process_start", {**request, "operation_id": "denied-after-revocation"})
        self.assertEqual(revoked.exception.code, "PYTHON_TEST_SCOPE_REQUIRED")

    def test_owner_granted_node_esm_and_child_scope(self):
        for directory in ("src", "tests"):
            (self.project / directory).mkdir()
        source = self.project / "src" / "weighted.mjs"
        source.write_text("export const weighted = (x, y) => x + 2 * y;\n", encoding="utf-8")
        tests = f"""import {{ test }} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {{ weighted }} from '../src/weighted.mjs';
test('nested ESM source loads', () => assert.equal(weighted(3, 4), 11));
test('node test child remains in snapshot', () => {{
    fs.writeFileSync('node-effect.txt', 'inside snapshot');
    assert.equal(fs.readFileSync('node-effect.txt', 'utf8'), 'inside snapshot');
    assert.throws(() => fs.readFileSync({json.dumps(self.outside.as_posix())}), /EACCES|EPERM/);
    assert.equal(process.env.OPENAI_API_KEY, undefined);
    assert.equal(process.env.NODE_OPTIONS, undefined);
}});
"""
        (self.project / "tests" / "weighted.test.mjs").write_text(tests, encoding="utf-8")
        project = self.register()
        args = {"project_id": project, "task_id": "approved-node", "operation_id": "node-check",
                "executable": "node", "argv": ["--test", "--test-concurrency=1", "tests/*.test.mjs"],
                "timeout_seconds": 30}
        with self.assertRaises(BridgeError) as denied:
            self.local("process_start", args)
        self.assertEqual(denied.exception.code, "NODE_TEST_SCOPE_REQUIRED")
        scope = {"project_id": project, "files": ["src/weighted.mjs", "tests/weighted.test.mjs"]}
        self.local("owner_grant_node_tests", scope)
        status = self.local("project_status", {"project_id": project})
        self.assertIsNone(status["python_test_scope"])
        self.assertEqual(status["node_test_scope"]["files"], scope["files"])
        job = self.local("process_start", args)
        address = {"project_id": project, "job_id": job["job_id"]}
        end = time.monotonic() + 35
        while time.monotonic() < end:
            result = self.local("job_get", address)
            if result["status"] not in {"queued", "running", "cancelling"}:
                break
            time.sleep(0.1)
        self.assertEqual(result["status"], "succeeded", result)
        self.assertEqual(result["exit_code"], 0)
        output = self.local("job_output", address)["output"]
        self.assertIn("pass 2", output)
        policy = result["evidence"]["policy"]
        self.assertEqual(policy["recipe"], "node_tests")
        self.assertEqual(policy["canaries"]["external_hardlink"], "denied")
        self.assertFalse((self.project / "node-effect.txt").exists())
        self.assertEqual((Path(policy["cwd"]) / "node-effect.txt").read_text(), "inside snapshot")

    def test_sealed_job_changes_require_approval_and_preserve_newer_source(self):
        for directory in ("src", "tests"):
            (self.project / directory).mkdir()
        alpha, beta = self.project / "src" / "alpha.mjs", self.project / "src" / "beta.mjs"
        alpha.write_bytes(b"export const alpha = 1;\n")
        beta.write_bytes(b"export const beta = 2;\n")
        (self.project / "tests" / "transform.test.mjs").write_text("""import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
test('perform a two-file change inside snapshot', () => {
    fs.writeFileSync('src/alpha.mjs', 'export const alpha = 11;\\n');
    fs.writeFileSync('src/beta.mjs', 'export const beta = 22;\\n');
    assert.match(fs.readFileSync('src/alpha.mjs', 'utf8'), /11/);
    fs.writeFileSync('unapproved-output.mjs', 'export default 3;');
});
""", encoding="utf-8")
        project = self.register()
        self.local("owner_grant_node_tests", {
            "project_id": project, "files": ["src/alpha.mjs", "src/beta.mjs", "tests/transform.test.mjs"],
        })
        self.local("owner_grant_edge", {"project_id": project})
        job = self.local("process_start", {
            "project_id": project, "task_id": "two-file-transform", "operation_id": "transform-1",
            "executable": "node", "argv": ["--test", "--test-concurrency=1", "tests/*.test.mjs"],
            "timeout_seconds": 30,
        })
        address = {"project_id": project, "job_id": job["job_id"]}
        end = time.monotonic() + 35
        while time.monotonic() < end:
            result = self.local("job_get", address)
            if result["status"] not in {"queued", "running", "cancelling"}:
                break
            time.sleep(0.1)
        self.assertEqual(result["status"], "succeeded", result)
        preview = self.local("job_changes", address)
        by_path = {item["path"]: item for item in preview["changes"]}
        self.assertEqual(set(by_path), {"src/alpha.mjs", "src/beta.mjs"})
        self.assertEqual(by_path["src/alpha.mjs"]["status"], "ready")
        self.assertIn("+export const alpha = 11;", by_path["src/alpha.mjs"]["diff"])
        self.assertEqual(alpha.read_bytes(), b"export const alpha = 1;\n")
        self.assertFalse((self.project / "unapproved-output.mjs").exists())
        with self.assertRaises(BridgeError) as denied:
            call_broker(self.state, "edge", "job_changes", address)
        self.assertEqual(denied.exception.details["reason"], "LOCAL_JOB_REVIEW_ONLY")

        beta.write_bytes(b"export const beta = 9;\n")
        selected = [{"path": path, "output_sha256": by_path[path]["output_sha256"]} for path in sorted(by_path)]
        with self.assertRaises(BridgeError) as conflict:
            self.local("owner_apply_job_changes", {
                **address, "operation_id": "apply-both", "selection": selected,
            })
        self.assertEqual(conflict.exception.code, "VERSION_CONFLICT")
        self.assertEqual(alpha.read_bytes(), b"export const alpha = 1;\n")
        self.assertEqual(beta.read_bytes(), b"export const beta = 9;\n")
        safe = {**address, "operation_id": "apply-selected", "selection": selected[:1]}
        applied = self.local("owner_apply_job_changes", safe)
        self.assertEqual(self.local("owner_apply_job_changes", safe), applied)
        self.assertEqual(alpha.read_bytes(), b"export const alpha = 11;\n")
        self.assertEqual(beta.read_bytes(), b"export const beta = 9;\n")

        sealed_beta = Path(result["evidence"]["policy"]["cwd"]) / "src" / "beta.mjs"
        sealed_beta.write_bytes(b"export const beta = 77;\n")
        after_tamper = self.local("job_changes", address)
        beta_status = next(item["status"] for item in after_tamper["changes"] if item["path"] == "src/beta.mjs")
        self.assertEqual(beta_status, "output_changed")
        with self.assertRaises(BridgeError) as bad_digest:
            self.local("owner_apply_job_changes", {
                **address, "operation_id": "apply-tampered",
                "selection": selected[1:],
            })
        self.assertEqual(bad_digest.exception.code, "VERSION_CONFLICT")


if __name__ == "__main__":
    unittest.main()

