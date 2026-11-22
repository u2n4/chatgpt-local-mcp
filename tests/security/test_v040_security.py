"""Stage 2-6 Security Boundary & Parity Tests against compiled Rust edge-bridge.exe."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))
from compat.python.rust_bridge import find_rust_binary, invoke_rust_cli


class TestV040SecurityBoundaries(unittest.TestCase):
    def setUp(self):
        self.rust_bin = find_rust_binary(REPO)
        if self.rust_bin is None:
            self.skipTest("Rust edge-bridge.exe not built yet")

    def _mcp(self, state_dir: Path, principal: str, reqs: list[dict]) -> list[dict]:
        proc = subprocess.run(
            [str(self.rust_bin), "--state-dir", str(state_dir), "mcp", "--principal", principal],
            input="\n".join(json.dumps(r) for r in reqs) + "\n",
            capture_output=True, text=True, timeout=20, check=True,
        )
        self.assertEqual(proc.stderr, "")
        return [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]

    def test_synthetic_secret_canaries_and_windows_path_hazards_denied(self):
        with tempfile.TemporaryDirectory(prefix="eb_sec_") as tmp:
            root = Path(tmp)
            state_dir = root / "state"
            proj = root / "proj"
            proj.mkdir()
            (proj / "ok.txt").write_bytes(b"hello world\n")
            (proj / ".env").write_bytes(b"SYNTHETIC_CANARY=do_not_read\n")
            (proj / "secrets.js").write_bytes(b"export const k = 'synthetic';\n")

            reg = invoke_rust_cli(["register", str(proj), "--name", "SecTest", "--grant-edge"], state_dir=state_dir, repo_root=REPO)
            pid = reg["project_id"]

            resps = self._mcp(state_dir, "edge", [
                {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "file_read", "arguments": {"project_id": pid, "path": "ok.txt"}}},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "file_read", "arguments": {"project_id": pid, "path": ".env"}}},
                {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "file_read", "arguments": {"project_id": pid, "path": "secrets.js"}}},
                {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "file_read", "arguments": {"project_id": pid, "path": "../escape.txt"}}},
                {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "file_read", "arguments": {"project_id": pid, "path": "ok.txt:ads"}}},
                {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "file_read", "arguments": {"project_id": pid, "path": "CON"}}},
                {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "file_read", "arguments": {"project_id": pid, "path": "//server/share/a"}}},
            ])
            by_id = {r["id"]: r["result"] for r in resps}
            self.assertFalse(by_id[1]["isError"])
            self.assertEqual(
                by_id[1]["structuredContent"]["result"]["hash"],
                hashlib.sha256(b"hello world\n").hexdigest(),
            )
            for idx in (2, 3, 4, 5, 6, 7):
                self.assertTrue(by_id[idx]["isError"], f"Expected error for id={idx}")

    def test_idempotency_payload_mismatch_rejected(self):
        with tempfile.TemporaryDirectory(prefix="eb_idem_") as tmp:
            root = Path(tmp)
            state_dir = root / "state"
            proj = root / "proj"
            proj.mkdir()
            (proj / "tests").mkdir()
            (proj / "tests" / "__init__.py").write_text("", encoding="utf-8")
            (proj / "tests" / "test_ok.py").write_text(
                "import unittest\nclass T(unittest.TestCase):\n    def test_a(self): self.assertEqual(1,1)\n",
                encoding="utf-8",
            )
            reg = invoke_rust_cli(["register", str(proj), "--name", "IdemProj"], state_dir=state_dir, repo_root=REPO)
            pid = reg["project_id"]
            py = str(REPO / ".venv" / "Scripts" / "python.exe")

            first = invoke_rust_cli([
                "run-job", "--project-id", pid, "--task-id", "t1", "--operation-id", "op-same-1",
                "--cwd", str(proj), "--executable", py,
                "--arg", "-B", "--arg", "-m", "--arg", "unittest", "--arg", "discover", "--arg", "-s", "--arg", "tests", "--arg", "-t", "--arg", ".", "--arg", "-v",
            ], state_dir=state_dir, repo_root=REPO)
            self.assertEqual(first["manifest"]["conclusions"]["overall_verdict"], "PASS")

            # Same operation_id with DIFFERENT payload -> MUST fail with IdempotencyPayloadMismatch
            bad = subprocess.run([
                str(self.rust_bin), "--state-dir", str(state_dir),
                "run-job", "--project-id", pid, "--task-id", "t1", "--operation-id", "op-same-1",
                "--cwd", str(proj), "--executable", py, "--arg", "-c", "--arg", "print('different')",
            ], capture_output=True, text=True, stdin=subprocess.DEVNULL)
            self.assertNotEqual(bad.returncode, 0)
            self.assertIn("IdempotencyPayloadMismatch", bad.stderr)


if __name__ == "__main__":
    unittest.main()
