"""NTFS canaries exercise actual handles and keep all mutations disposable."""

import base64
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from edge_bridge import files
from edge_bridge.files import FileBoundaryError, ProjectFiles


@unittest.skipUnless(os.name == "nt", "Windows NTFS containment tests")
class ProjectFilesTests(unittest.TestCase):
    def setUp(self):
        fixture = self.enterContext(tempfile.TemporaryDirectory(prefix="edge-files-"))
        self.base = Path(fixture)
        self.root = self.base / "selected"
        self.root.mkdir()
        self.outside = self.base / "outside"
        self.outside.mkdir()
        (self.outside / "canary.txt").write_bytes(b"outside-only")
        (self.root / "hello.txt").write_bytes(b"first\r\nsecond\r\n")
        self.files = ProjectFiles(self.root)

    def assert_code(self, operation, code):
        with self.assertRaises(FileBoundaryError) as caught:
            operation()
        self.assertEqual(caught.exception.code, code)

    def test_list_read_search_view_and_hash(self):
        (self.root / "second.txt").write_bytes(b"")
        self.assertEqual(self.files.list(limit=1)["next_cursor"], 1)
        self.assertEqual(self.files.list(cursor=1)["entries"][0]["name"], "second.txt")
        result = self.files.read("HELLO.txt", offset=7, limit=6)
        self.assertEqual(result["content"], "second")
        self.assertEqual(result["hash"], hashlib.sha256(b"first\r\nsecond\r\n").hexdigest())
        self.assertEqual(self.files.search("SECOND")["matches"], [
            {"path": "hello.txt", "line": 2, "text": "second"},
        ])
        self.assertEqual(self.files.view("second.txt")["content"], "")
        raw = base64.b64decode(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/"
            "XFcAAAAASUVORK5CYII="
        )
        (self.root / "pixel.png").write_bytes(raw)
        picture = self.files.view("pixel.png")
        self.assertEqual(picture["content_type"], "image/png")
        self.assertEqual(base64.b64decode(picture["content"]), raw)

    def test_reject_ambiguous_or_outside_spellings(self):
        inputs = (
            "../outside/canary.txt", "..\\outside\\canary.txt", str(self.outside / "canary.txt"),
            "C:canary.txt", "\\canary.txt", "\\\\server\\share\\canary.txt", "hello.txt:hidden",
            "hello.txt.", "hello.txt ", "NUL.txt", "com¹.txt", "dir//hello.txt",
            ".git/config", ".ENV.local", ".edge-project-bridge/journal.json",
            "config/secrets.js", "credentials.yaml", ".install-token",
            "Cookies", "Login Data For Account", "vault.kdbx", "service.token",
        )
        for path in inputs:
            with self.subTest(path=path), self.assertRaises(FileBoundaryError):
                self.files.read(path)
        self.assertEqual((self.outside / "canary.txt").read_text(), "outside-only")
        # Binary files and oversized assets never abort text search
        (self.root / "aaa_audio.wav").write_bytes(b"RIFF\x00\x00\x00\x00WAVE" + b"\x00" * 4096)
        (self.root / "aaa_unknown.blob").write_bytes(b"\x00\x01\x02BINARY_DATA\x00")
        (self.root / "zzz_code.py").write_text("needle_token = 42\n", encoding="utf-8")
        found = self.files.search("needle_token")
        self.assertEqual(found["matches"], [{"path": "zzz_code.py", "line": 1, "text": "needle_token = 42"}])

    def test_hard_link_and_junction_denied_by_handle(self):
        import _winapi

        os.link(self.outside / "canary.txt", self.root / "hardlink.txt")
        _winapi.CreateJunction(str(self.outside), str(self.root / "junction"))
        self.assert_code(lambda: self.files.read("hardlink.txt"), "UNSUPPORTED_PATH_TYPE")
        self.assert_code(lambda: self.files.read("junction/canary.txt"), "UNSUPPORTED_PATH_TYPE")
        self.assert_code(lambda: self.files.write("junction/new.txt", "new", None), "UNSUPPORTED_PATH_TYPE")
        self.assertEqual([item["name"] for item in self.files.list()["entries"]], ["hello.txt"])
        self.assertFalse((self.outside / "new.txt").exists())

    def test_root_identity_and_live_parent_pin(self):
        old = self.base / "old-root"
        with self.files._directory([]):
            with self.assertRaises(OSError):
                self.root.rename(old)
        self.root.rename(old)
        self.root.mkdir()
        (self.root / "hello.txt").write_bytes(b"replacement-root")
        self.assert_code(lambda: self.files.read("hello.txt"), "PROJECT_ROOT_CHANGED")

    def test_stale_write_and_existing_create_are_rejected(self):
        prior = self.files.read("hello.txt")["hash"]
        (self.root / "hello.txt").write_bytes(b"user's changes")
        self.assert_code(lambda: self.files.write("hello.txt", "new", prior), "VERSION_CONFLICT")
        self.assert_code(lambda: self.files.write("hello.txt", "new", None), "VERSION_CONFLICT")
        self.assertEqual((self.root / "hello.txt").read_bytes(), b"user's changes")

    def test_replacement_leaves_alternate_streams_intact(self):
        previous = self.files.read("hello.txt")["hash"]
        stream = Path(str(self.root / "hello.txt") + ":canary")
        stream.write_bytes(b"original alternate stream")
        self.assert_code(lambda: self.files.write("hello.txt", "new", previous), "UNSUPPORTED_PATH_TYPE")
        self.assertEqual(self.files.read("hello.txt")["hash"], previous)
        self.assertEqual(stream.read_bytes(), b"original alternate stream")

    def test_patch_and_reversible_delete(self):
        before = self.files.read("hello.txt")["hash"]
        result = self.files.patch([
            {"path": "hello.txt", "content": "after", "expected_hash": before},
            {"path": "created.txt", "content": "created", "expected_hash": None},
        ])
        private = self.root / ".edge-project-bridge"
        read = self.files.read("hello.txt")
        self.assertEqual(read["content"], "after")
        self.assertEqual((private / result["applied"][0]["backup"]).read_bytes(), b"first\r\nsecond\r\n")
        self.assertEqual(self.files.move("hello.txt", "moved.txt", read["hash"])["hash"], read["hash"])
        self.assert_code(lambda: self.files.read("hello.txt"), "FILE_NOT_FOUND")
        receipt = self.files.delete("moved.txt", read["hash"])
        trash = json.loads((private / f'{receipt["trash_id"]}.trash.json').read_text())
        self.assertEqual(trash["original"], "moved.txt")
        self.assertEqual((private / trash["stored_file"]).read_bytes(), b"after")
        self.assertNotIn(".edge-project-bridge", [item["name"] for item in self.files.list()["entries"]])

    def test_intervening_creator_is_never_overwritten(self):
        prior = self.files.read("hello.txt")["hash"]
        rename = files._rename
        raced = False

        def new_owner_during_publication(handle, parent, name):
            nonlocal raced
            if name == "hello.txt" and not raced:
                raced = True
                (self.root / name).write_bytes(b"new owner")
            return rename(handle, parent, name)

        with patch.object(files, "_rename", side_effect=new_owner_during_publication):
            self.assert_code(lambda: self.files.write("hello.txt", "agent", prior), "VERSION_CONFLICT")
        self.assertTrue(raced)
        self.assertEqual(self.files.read("hello.txt")["content"], "new owner")
        private = self.root / ".edge-project-bridge"
        self.assertEqual(next(private.glob("*.previous")).read_bytes(), b"first\r\nsecond\r\n")
        receipt = json.loads(next(private.glob("*.result.json")).read_bytes())
        self.assertEqual(receipt["status"], "needs_review")

    def test_recovery_after_process_exits_between_original_and_new_name(self):
        import subprocess
        import sys

        # The subprocess exits while holding the original rename. Windows
        # closes its handles, leaving a real incomplete patch journal.
        crash_script = """
import os, sys
from edge_bridge import files
from edge_bridge.files import ProjectFiles
target = ProjectFiles(sys.argv[1])
original_rename = files._rename
def stop_after_displacement(handle, parent, name):
    original_rename(handle, parent, name)
    if name.endswith(".previous"):
        os._exit(79)
files._rename = stop_after_displacement
target.patch([{"path":"hello.txt","content":"new content","expected_hash":target.read("hello.txt")["hash"]}])
"""
        run = subprocess.run([sys.executable, "-c", crash_script, str(self.root)],
                             capture_output=True, timeout=10)
        self.assertEqual(run.returncode, 79, run.stderr)
        private = self.root / ".edge-project-bridge"
        receipt = next(private.glob("*.plan.json")).name.removesuffix(".plan.json")
        self.assertFalse((self.root / "hello.txt").exists())
        review = self.files.patch_recovery(receipt)
        self.assertEqual(review["journal_status"], "result_missing")
        self.assertEqual(review["entries"][0]["status"], "restore_available")
        (self.root / "hello.txt").write_bytes(b"operator's newer file")
        preserved = self.files.patch_recovery(receipt, restore=True)
        self.assertEqual(preserved["entries"][0]["status"], "destination_preserved")
        self.assertEqual((self.root / "hello.txt").read_bytes(), b"operator's newer file")
        backup = next(private.glob("*.previous"))
        self.assertEqual(backup.read_bytes(), b"first\r\nsecond\r\n")
        (self.root / "hello.txt").rename(self.root / "operator-original.txt")
        restored = self.files.patch_recovery(receipt, restore=True)
        self.assertEqual(restored["entries"][0]["status"], "restored")
        self.assertEqual((self.root / "hello.txt").read_bytes(), b"first\r\nsecond\r\n")
        self.assertEqual((self.root / "operator-original.txt").read_bytes(), b"operator's newer file")


if __name__ == "__main__":
    unittest.main()
