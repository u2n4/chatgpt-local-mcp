import subprocess
import tempfile
import unittest
from pathlib import Path

from edge_bridge.git_engine import GitEngine, GitEngineError
from edge_bridge.runner import git_path


def _git(cwd: Path, *args: str) -> str:
    proc = subprocess.run(
        [str(git_path()), "-C", str(cwd), "-c", "user.name=Test", "-c", "user.email=test@localhost", *args],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=True,
    )
    return proc.stdout.strip()


class GitEngineTests(unittest.TestCase):
    def test_status_diff_non_destructive_checkpoint_and_worktree_integrate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            (root / "sub").mkdir()
            _git(root, "init")
            (root / "app.py").write_text("def add(a, b):\n    return a - b\n", encoding="utf-8")
            (root / "sub" / "note.txt").write_text("initial\n", encoding="utf-8")
            _git(root, "add", ".")
            _git(root, "commit", "-m", "init")
            orig_head = _git(root, "rev-parse", "HEAD")

            engine = GitEngine()
            with self.assertRaises(GitEngineError) as sub_err:
                engine.assert_repo_root(root / "sub")
            self.assertEqual(sub_err.exception.code, "GIT_NOT_A_REPOSITORY")

            # Make one staged edit and one untracked file
            (root / "staged.txt").write_text("staged v1\n", encoding="utf-8")
            _git(root, "add", "staged.txt")
            (root / "app.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
            (root / "scratch.txt").write_text("untracked\n", encoding="utf-8")

            st = engine.status(root)
            self.assertFalse(st["clean"])
            self.assertEqual(st["head"], orig_head)
            paths = {entry["path"]: entry["xy"] for entry in st["entries"]}
            self.assertEqual(paths["app.py"], " M")
            self.assertEqual(paths["staged.txt"], "A ")
            self.assertEqual(paths["scratch.txt"], "??")

            with self.assertRaises(GitEngineError) as flag_err:
                engine.diff(root, base_ref="--ext-diff")
            self.assertEqual(flag_err.exception.code, "INVALID_ARGUMENT")

            with self.assertRaises(GitEngineError) as dot_err:
                engine.diff(root, paths=["../secret.txt"])
            self.assertEqual(dot_err.exception.code, "INVALID_ARGUMENT")

            with self.assertRaises(GitEngineError) as env_err:
                engine.diff(root, paths=[".env"])
            self.assertEqual(env_err.exception.code, "INVALID_ARGUMENT")

            with self.assertRaises(GitEngineError) as sec_err:
                engine.diff(root, paths=["config/secrets.js"])
            self.assertEqual(sec_err.exception.code, "INVALID_ARGUMENT")

            diff_res = engine.diff(root, base_ref="HEAD", paths=["app.py"])
            self.assertIn("-    return a - b", diff_res["content"])
            self.assertIn("+    return a + b", diff_res["content"])

            # Default diff excludes tracked secret files automatically
            (root / "secrets.js").write_text("SECRET_CANARY_V1\n", encoding="utf-8")
            _git(root, "add", "secrets.js")
            _git(root, "commit", "-m", "track dummy secret file")
            (root / "secrets.js").write_text("SECRET_CANARY_V2\n", encoding="utf-8")
            all_diff = engine.diff(root)
            self.assertNotIn("SECRET_CANARY", all_diff["content"])
            self.assertIn("+    return a + b", all_diff["content"])
            _git(root, "reset", "--hard", orig_head)
            (root / "staged.txt").write_text("staged v1\n", encoding="utf-8")
            _git(root, "add", "staged.txt")
            (root / "app.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
            (root / "scratch.txt").write_text("untracked\n", encoding="utf-8")

            # Non-destructive checkpoint must NOT move HEAD or change real staged index
            ckpt = engine.checkpoint(root, "task-1", "cp-01", "before fix")
            self.assertTrue(ckpt["non_destructive"])
            self.assertEqual(_git(root, "rev-parse", "HEAD"), orig_head)
            st_after = engine.status(root)
            self.assertEqual({e["path"]: e["xy"] for e in st_after["entries"]}, paths)

            # Verify commit content inside refs/edge-bridge/checkpoints/task-1/cp-01 captured untracked file
            ckpt_tree = _git(root, "ls-tree", "-r", "--name-only", ckpt["ref"])
            self.assertIn("scratch.txt", ckpt_tree)

            # Clean main working tree, then test isolated worktree + dry_run/ff-only integration
            (root / "scratch.txt").unlink()
            _git(root, "reset", "--hard", "HEAD")

            wt_path = Path(tmp) / "worktrees" / "w1"
            wt_info = engine.create_isolated_worktree(root, wt_path, "edge-worker/w1", base_ref="HEAD")
            self.assertTrue(Path(wt_info["worktree"]).is_dir())
            (wt_path / "feature.txt").write_text("from worker\n", encoding="utf-8")
            _git(wt_path, "add", "feature.txt")
            _git(wt_path, "commit", "-m", "worker feature")

            preview = engine.integrate_ref(root, "edge-worker/w1", dry_run=True, expected_head=orig_head)
            self.assertTrue(preview["fast_forward_possible"])
            self.assertFalse(preview["applied"])
            self.assertEqual(_git(root, "rev-parse", "HEAD"), orig_head)

            applied = engine.integrate_ref(root, "edge-worker/w1", dry_run=False, expected_head=orig_head)
            self.assertTrue(applied["applied"])
            self.assertTrue((root / "feature.txt").is_file())

            with self.assertRaises(GitEngineError) as stale_err:
                engine.integrate_ref(root, "edge-worker/w1", dry_run=False, expected_head=orig_head)
            self.assertEqual(stale_err.exception.code, "VERSION_CONFLICT")
