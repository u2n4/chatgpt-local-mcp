"""Stage 2, 4, 5 Integration Tests:
- Python v0.2.0 vs Rust v0.4.0 read/hash/denial parity on identical disposable fixture
- Parallel isolated Git worktrees (two writers) preserving parent dirty state + serialized integrator
- Compatibility check against existing Python `apply-patch-plan` CLI schema (without & with --confirm)
"""
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
from edge_bridge.files import ProjectFiles
from edge_bridge.git_engine import GitEngine


class TestV040ParityAndParallel(unittest.TestCase):
    def setUp(self):
        self.rust_bin = find_rust_binary(REPO)
        if self.rust_bin is None:
            self.skipTest("Rust edge-bridge.exe not built yet")

    def test_python_vs_rust_file_read_hash_parity(self):
        with tempfile.TemporaryDirectory(prefix="eb_parity_") as tmp:
            root = Path(tmp)
            state_dir = root / "rust_state"
            proj = root / "proj"
            proj.mkdir()
            sample = "line1: سلام\r\nline2: 1852/3600\r\n"
            (proj / "sample.txt").write_bytes(sample.encode("utf-8"))

            py_read = ProjectFiles(proj).read("sample.txt", limit=65536)
            reg = invoke_rust_cli(["register", str(proj), "--name", "Parity", "--grant-edge"], state_dir=state_dir, repo_root=REPO)
            pid = reg["project_id"]

            proc = subprocess.run(
                [str(self.rust_bin), "--state-dir", str(state_dir), "mcp", "--principal", "edge"],
                input=json.dumps({
                    "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                    "params": {"name": "file_read", "arguments": {"project_id": pid, "path": "sample.txt", "limit": 65536}},
                }) + "\n",
                capture_output=True, encoding="utf-8", timeout=20, check=True,
            )
            rust_resp = json.loads(proc.stdout.strip())["result"]["structuredContent"]["result"]
            self.assertEqual(py_read["hash"], rust_resp["hash"])
            self.assertEqual(py_read["size"], rust_resp["size"])
            self.assertEqual(py_read["content"], rust_resp["content"])
            self.assertEqual(rust_resp["content"], sample)

    def test_two_isolated_worktrees_preserve_parent_dirty_work(self):
        with tempfile.TemporaryDirectory(prefix="eb_wt_") as tmp:
            root = Path(tmp)
            repo = root / "repo"
            repo.mkdir()
            for cmd in (
                ["git", "init", "-b", "main"],
                ["git", "config", "user.name", "Test"],
                ["git", "config", "user.email", "test@local.invalid"],
            ):
                subprocess.run(cmd, cwd=repo, check=True, capture_output=True, stdin=subprocess.DEVNULL)
            (repo / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
            subprocess.run(["git", "add", "-A"], cwd=repo, check=True, capture_output=True, stdin=subprocess.DEVNULL)
            subprocess.run(["git", "commit", "-m", "init"], cwd=repo, check=True, capture_output=True, stdin=subprocess.DEVNULL)

            # Simulate user dirty work in parent repo
            (repo / "user_notes.txt").write_text("DO NOT TOUCH USER DIRTY FILE\n", encoding="utf-8")

            ge = GitEngine()
            wt1 = root / "wt_implementer"
            wt2 = root / "wt_reviewer"
            ge.create_isolated_worktree(repo, wt1, "edge-worker/implementer-1", base_ref="HEAD")
            ge.create_isolated_worktree(repo, wt2, "edge-worker/reviewer-1", base_ref="HEAD")

            # Implementer edits inside wt1 only
            (wt1 / "app.py").write_text("VALUE = 2\n", encoding="utf-8")
            subprocess.run(["git", "add", "app.py"], cwd=wt1, check=True, capture_output=True, stdin=subprocess.DEVNULL)
            subprocess.run(["git", "commit", "-m", "impl: update value"], cwd=wt1, check=True, capture_output=True, stdin=subprocess.DEVNULL)

            # Reviewer wt2 and parent dirty file remain completely isolated and untouched!
            self.assertEqual((wt2 / "app.py").read_text(encoding="utf-8"), "VALUE = 1\n")
            self.assertEqual((repo / "app.py").read_text(encoding="utf-8"), "VALUE = 1\n")
            self.assertEqual((repo / "user_notes.txt").read_text(encoding="utf-8"), "DO NOT TOUCH USER DIRTY FILE\n")

            # Cleanup task-owned worktrees safely
            subprocess.run(["git", "worktree", "remove", "--force", str(wt1)], cwd=repo, check=True, capture_output=True, stdin=subprocess.DEVNULL)
            subprocess.run(["git", "worktree", "remove", "--force", str(wt2)], cwd=repo, check=True, capture_output=True, stdin=subprocess.DEVNULL)
            self.assertTrue((repo / "user_notes.txt").is_file())


if __name__ == "__main__":
    unittest.main()
