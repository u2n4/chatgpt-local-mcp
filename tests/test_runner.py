from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

from edge_bridge import runner
from edge_bridge.files import FileBoundaryError, ProjectFiles
from edge_bridge.jobs import (
    ActiveJob,
    COMMAND,
    JobError,
    Jobs,
    _read_project_test_files,
    _recipe_details,
    _seal_snapshot,
    validate_project_test_files,
)


class RunnerGateTests(unittest.TestCase):
    def test_diagnostics_distinguish_recipes_and_workers(self):
        report = runner.diagnose()
        self.assertEqual(report["execution"]["scope"], "local_bundled_recipes_and_owner_granted_project_tests")
        self.assertFalse(report["execution"]["automatic_weaker_fallback"])
        self.assertFalse(report["workers"]["enabled"])
        self.assertTrue(all(value is False for value in report["billing"].values()))
        with self.assertRaises(runner.RunnerBlocked) as error:
            runner.require_workers()
        self.assertEqual(error.exception.code, report["workers"]["code"])

    def test_missing_backend_is_rejected_before_startup(self):
        with patch.object(runner, "_codex_path", return_value=Path("missing-codex.exe")):
            with self.assertRaises(runner.RunnerBlocked) as blocked:
                runner.require_execution()
        self.assertEqual(blocked.exception.code, "ISOLATION_NOT_VERIFIED")

    def test_cancel_after_assignment_before_resume_never_runs_payload(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            work, control = root / "workspace", root / "control"
            work.mkdir()
            control.mkdir()
            signal = threading.Event()
            create = runner._create_contained_process

            def cancel_after_assign(*args):
                handles = create(*args)
                signal.set()
                return handles

            command = [str(runner._python_path()), "-I", "-S", "-B", "-c",
                       "from pathlib import Path; Path('unexpected-start').touch()"]
            with patch.object(runner, "_create_contained_process", side_effect=cancel_after_assign):
                with self.assertRaises(runner.RunnerBlocked) as cancelled:
                    runner._launch(command, work, control, control / "cancel.log", signal)
            self.assertEqual(cancelled.exception.code, "START_CANCELLED")
            self.assertFalse((work / "unexpected-start").exists())

    def test_pinned_file_cannot_be_replaced_and_locked_writer_is_rejected(self):
        import win32con
        import win32file

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable, replacement = root / "fixture.exe", root / "replacement.exe"
            executable.write_bytes(b"expected pinned bytes")
            replacement.write_bytes(b"replacement bytes")
            digest = hashlib.sha256(executable.read_bytes()).hexdigest()
            with runner._locked_pinned_binary(executable, digest) as resolved:
                self.assertEqual(Path(resolved), executable.resolve())
                with self.assertRaises(PermissionError):
                    replacement.replace(executable)
                with self.assertRaises(PermissionError):
                    executable.write_bytes(b"changed")
            writer = win32file.CreateFile(str(executable), win32con.GENERIC_WRITE,
                                          win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE, None,
                                          win32con.OPEN_EXISTING, 0, None)
            try:
                with self.assertRaises(runner.RunnerBlocked) as blocked:
                    with runner._locked_pinned_binary(executable, digest):
                        self.fail("A pinned binary with an open writer must never be launched.")
                self.assertEqual(blocked.exception.code, "ISOLATION_NOT_VERIFIED")
            finally:
                writer.Close()
            replacement.replace(executable)
            with self.assertRaisesRegex(runner.RunnerBlocked, "hash changed"):
                with runner._locked_pinned_binary(executable, digest):
                    self.fail("A replaced binary must never be launched.")

    def test_pinned_image_locks_prevent_rename_of_an_ancestor(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ancestor = root / "ancestor"
            executable = ancestor / "child" / "fixture.exe"
            executable.parent.mkdir(parents=True)
            executable.write_bytes(b"fixture image")
            digest = hashlib.sha256(executable.read_bytes()).hexdigest()
            renamed = root / "renamed"

            with runner._locked_pinned_binary(executable, digest):
                with self.assertRaises(PermissionError):
                    ancestor.rename(renamed)
            ancestor.rename(renamed)
            self.assertTrue((renamed / "child" / "fixture.exe").is_file())

    def test_powershell_lock_stays_with_owned_process_until_close(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            work, control, runtime = root / "work", root / "control", root / "runtime"
            work.mkdir()
            (control / "codex-home").mkdir(parents=True)
            runtime.mkdir()
            (work / "check.ps1").touch()
            executable = runtime / "pwsh.exe"
            executable.write_bytes(b"fixture image")
            pin = hashlib.sha256(executable.read_bytes()).hexdigest()
            config = b"fixture policy"
            (control / "codex-home" / "config.toml").write_bytes(config)
            # A mock launcher owns the fixture locks after launch_recipe returns.
            owned = Mock()
            with (patch.object(runner, "_powershell_path", return_value=executable),
                  patch.object(runner, "POWERSHELL_SHA256", pin),
                  patch.object(runner, "_launch", return_value=owned) as launch):
                argv = runner._payload_command(work, "powershell_script", "check.ps1")
                receipt = {"command": argv, "entry_script": "check.ps1",
                           "profile_sha256": hashlib.sha256(config).hexdigest()}
                (control / "verified-policy.json").write_text(json.dumps(receipt), encoding="utf-8")
                process = runner.launch_recipe(work, control, control / "job.log", "powershell_script")
                try:
                    launch.assert_called_once()
                    with self.assertRaises(PermissionError):
                        executable.write_bytes(b"attempted replacement")
                finally:
                    process.image_locks.close()
            executable.write_bytes(b"replacement after close")

    def test_snapshot_refuses_path_outside_rust_allowlist_before_open(self):
        source = Mock()
        for path in ("credentials.py", ".env"):
            with self.subTest(path=path), self.assertRaises(JobError) as blocked:
                _read_project_test_files(source, [path], source_allowlist=frozenset({"allowed.py"}))
            self.assertEqual(blocked.exception.code, "BRIDGE_POLICY_DENIED")
        source.read.assert_not_called()

    def test_forced_containment_preflight_failure_never_creates_either_workload(self):
        for recipe, script in (("project_tests", None), ("powershell_script", "check.ps1")):
            with self.subTest(recipe=recipe), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                work, control = root / "workspace", root / "control"
                work.mkdir()
                control.mkdir()
                if script:
                    (work / script).touch()
                state, gate = Mock(), Mock()
                jobs = Jobs(state, root, Mock(), before_create=gate)

                def failed_probe(argv, workspace, controller, log, cancelled, **kwargs):
                    self.assertIn("EDGE_BRIDGE_CONTAINMENT_OK", " ".join(argv))
                    log.write_text("synthetic preflight failure", encoding="utf-8")
                    return Mock(poll=Mock(return_value=1), wait=Mock(return_value=1))

                with (patch.object(jobs, "_dirs", return_value=(work, control)),
                      patch.object(jobs, "_snapshot", return_value=[]),
                      patch.object(runner, "require_execution"),
                      patch.object(runner, "_verify_pinned_binary"),
                      patch.object(runner, "_launch", side_effect=failed_probe) as launch):
                    jobs._run(ActiveJob("fixture", "fixture", recipe), {}, 5, None, entry_script=script)
                launch.assert_called_once()
                gate.assert_not_called()
                result = state.update_job.call_args.kwargs
                self.assertEqual(result["status"], "failed")
                self.assertEqual(result["evidence"]["failure_code"], "ISOLATION_NOT_VERIFIED")
                self.assertIn("synthetic preflight failure", result["evidence"]["diagnostic_hint"])

    def test_codex_pin_is_checked_during_probe_and_payload_creation(self):
        examples = Path(__file__).resolve().parents[1] / "examples" / "calculator"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            work, control = root / "workspace", root / "control"
            work.mkdir()
            control.mkdir()
            shutil.copyfile(examples / "calculator.py", work / "calculator.py")
            locked = runner._locked_pinned_binary
            create = runner._create_contained_process
            active_locks = []
            observed = []

            @contextmanager
            def observe_lock(path, pin):
                with locked(path, pin) as executable:
                    active_locks.append((path, pin))
                    try:
                        yield executable
                    finally:
                        active_locks.pop()

            def observe_create(argv, workspace, controller, job, stdin, output, before_create):
                def check_image_then_create():
                    self.assertEqual(active_locks, [(runner._codex_path(), runner.CODEX_SHA256)])
                    observed.append("probe" if "EDGE_BRIDGE_CONTAINMENT_OK" in " ".join(argv) else "payload")
                    before_create()
                return create(argv, workspace, controller, job, stdin, output, check_image_then_create)

            with (patch.object(runner, "_locked_pinned_binary", side_effect=observe_lock),
                  patch.object(runner, "_create_contained_process", side_effect=observe_create)):
                runner.prepare_python_unittest(work, control)
                command = runner._command(work, ("-I", "-S", "-B", "-c", "print('fixture')"))
                owned = runner._launch(command, work, control, control / "payload.log", None)
                try:
                    self.assertEqual(owned.wait(10), 0)
                finally:
                    owned.close()
            self.assertEqual(observed, ["probe", "payload"])
            self.assertEqual(active_locks, [])

    def test_real_mxc_parent_child_grandchild_terminate_together(self):
        examples = Path(__file__).resolve().parents[1] / "examples" / "calculator"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            work, control = root / "workspace", root / "control"
            work.mkdir()
            control.mkdir()
            shutil.copyfile(examples / "calculator.py", work / "calculator.py")
            runner.prepare_python_unittest(work, control)
            grandchild = """from pathlib import Path
import time
while True:
    with Path("heartbeat").open("a") as output:
        output.write("tick\\n")
    time.sleep(0.05)
"""
            child = f"import subprocess, sys; subprocess.Popen([sys.executable, '-I','-S','-B','-c',{grandchild!r}]).wait()"
            parent = f"import subprocess, sys; subprocess.Popen([sys.executable, '-I','-S','-B','-c',{child!r}]).wait()"
            command = runner._command(work, ("-I", "-S", "-B", "-c", parent))
            process = runner._launch(command, work, control, control / "tree.log", None)
            heartbeat = work / "heartbeat"
            try:
                deadline = time.monotonic() + 12
                while not heartbeat.exists() and process.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.05)
                self.assertTrue(heartbeat.exists(), (control / "tree.log").read_text(errors="replace"))
                with self.assertRaises(TimeoutError):
                    process.wait(0.1)
                process.cancel()
                self.assertNotEqual(process.wait(5), 0)
            finally:
                process.close()
            size = heartbeat.stat().st_size
            time.sleep(0.2)
            self.assertEqual(heartbeat.stat().st_size, size)

    def test_resolve_job_limits_cpu_percent_bounds_and_omission(self):
        default_limits = runner.resolve_job_limits({})
        self.assertNotIn("cpu_percent", default_limits)
        self.assertEqual(runner.resolve_job_limits({"cpu_percent": 1})["cpu_percent"], 1)
        self.assertEqual(runner.resolve_job_limits({"cpu_percent": 50})["cpu_percent"], 50)
        for bad in (0, -1, 51, True, False, "50", 25.5):
            with self.subTest(cpu_percent=bad), self.assertRaises(runner.RunnerBlocked) as err:
                runner.resolve_job_limits({"cpu_percent": bad})
            self.assertEqual(err.exception.code, "INVALID_GRANT_LIMITS")

    def test_job_object_cpu_hard_cap_applied_and_failure_refuses_launch(self):
        import ctypes
        import win32job

        job = win32job.CreateJobObject(None, "")
        try:
            runner._apply_job_cpu_hard_cap(job, 35)
            queried = runner._JobObjectCpuRateControl()
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            ok = kernel32.QueryInformationJobObject(
                ctypes.c_void_p(int(job)),
                runner._JOB_OBJECT_CPU_RATE_CONTROL_INFORMATION,
                ctypes.byref(queried),
                ctypes.sizeof(queried),
                None,
            )
            self.assertNotEqual(ok, 0)
            self.assertEqual(
                queried.ControlFlags,
                runner._JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | runner._JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP,
            )
            self.assertEqual(queried.CpuRate, 3500)
            for bad in (0, 51, True):
                with self.subTest(bad=bad), self.assertRaises(runner.RunnerBlocked) as err:
                    runner._apply_job_cpu_hard_cap(job, bad)
                self.assertEqual(err.exception.code, "INVALID_GRANT_LIMITS")
        finally:
            job.Close()

        # If setting the hard CPU cap fails, _launch refuses before creating any process.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            work, control = root / "workspace", root / "control"
            work.mkdir()
            control.mkdir()
            create_mock = Mock()
            command = [str(runner._python_path()), "-I", "-S", "-B", "-c", "print('should-not-run')"]
            with (
                patch.object(
                    runner,
                    "_apply_job_cpu_hard_cap",
                    side_effect=runner.RunnerBlocked("INVALID_GRANT_LIMITS", "synthetic cpu cap failure"),
                ) as cap_mock,
                patch.object(runner, "_create_contained_process", create_mock),
            ):
                with self.assertRaises(runner.RunnerBlocked) as blocked:
                    runner._launch(
                        command,
                        work,
                        control,
                        control / "cpu-cap.log",
                        None,
                        limited=True,
                        job_limits={
                            "memory_bytes": 128 * 1024 * 1024,
                            "processes": 4,
                            "log_bytes": 4096,
                            "cpu_percent": 35,
                        },
                    )
            self.assertEqual(blocked.exception.code, "INVALID_GRANT_LIMITS")
            cap_mock.assert_called_once()
            self.assertEqual(cap_mock.call_args.args[1], 35)
            create_mock.assert_not_called()

    def test_payload_command_and_recipe_details_validate_test_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            work_with_init = root / "with_init"
            (work_with_init / "tests").mkdir(parents=True)
            (work_with_init / "tests" / "__init__.py").write_text("", encoding="utf-8")
            work_no_init = root / "no_init"
            (work_no_init / "tests").mkdir(parents=True)

            # Discovery command matches PROJECT_TEST_ARGS when tests/__init__.py exists,
            # and uses the no-init discovery shim (keeping -I -S -B) when absent.
            cmd_with_init = runner._payload_command(work_with_init, "project_tests")
            self.assertEqual(cmd_with_init[-len(runner.PROJECT_TEST_ARGS):], list(runner.PROJECT_TEST_ARGS))
            cmd_no_init = runner._payload_command(work_no_init, "project_tests")
            self.assertEqual(
                cmd_no_init[-9:],
                ["-I", "-S", "-B", "-c", runner._PROJECT_TEST_NO_INIT_DISCOVER_SHIM, "discover", "-s", "tests", "-v"],
            )

            for target in ("tests.test_calc", "tests.test_calc.CalcTests", "tests.test_calc.CalcTests.test_add"):
                with self.subTest(valid_target=target):
                    cmd_init = runner._payload_command(work_with_init, "project_tests", test_target=target)
                    self.assertEqual(cmd_init[-3:], [runner._PROJECT_TEST_TARGET_SHIM, target, "-v"])
                    cmd_plain = runner._payload_command(work_no_init, "project_tests", test_target=target)
                    self.assertEqual(
                        cmd_plain[-3:],
                        [runner._PROJECT_TEST_NO_INIT_TARGET_SHIM, target.removeprefix("tests."), "-v"],
                    )
                    self.assertEqual(
                        _recipe_details("python", [*COMMAND, target], "."),
                        ("project_tests", None, target),
                    )
            for bad in (
                "-c",
                "-v",
                "--failfast",
                "tests/test_calc.py",
                "tests..test_calc",
                "tests.calc",
                "..tests.test_calc",
                "os.system",
                "tests.test_a;id",
                "tests.test_a.B.c.d",
                "",
            ):
                with self.subTest(bad_target=bad):
                    with self.assertRaises(runner.RunnerBlocked) as err:
                        runner._payload_command(work_with_init, "project_tests", test_target=bad)
                    self.assertEqual(err.exception.code, "INVALID_ARGUMENT")
                    with self.assertRaises(JobError) as jerr:
                        _recipe_details("python", [*COMMAND, bad], ".")
                    self.assertEqual(jerr.exception.code, "EXECUTION_REQUEST_UNSUPPORTED")

    def test_python_discovery_and_selector_execute_in_both_layouts_with_isolated_flags(self):
        import subprocess

        def run_payload(work: Path, test_target: str | None = None):
            full = runner._payload_command(work, "project_tests", test_target=test_target)
            py_cmd = full[full.index("--") + 1:]
            self.assertEqual(py_cmd[1:4], ["-I", "-S", "-B"])
            return subprocess.run(py_cmd, cwd=work, capture_output=True, encoding="utf-8", timeout=20)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            # Layout 1: NO tests/__init__.py, 79 files including a 136 KiB module and 89 tests.
            no_init = root / "no_init"
            (no_init / "pkg").mkdir(parents=True)
            (no_init / "tests").mkdir(parents=True)
            big_text = "VALUE = 42\n# " + ("a" * (136 * 1024 - 20)) + "\n"
            (no_init / "pkg" / "big_mod.py").write_text(big_text, encoding="utf-8")
            (no_init / "pkg" / "__init__.py").write_text("", encoding="utf-8")
            for idx in range(74):
                (no_init / "pkg" / f"m_{idx:02d}.py").write_text(f"N = {idx}\n", encoding="utf-8")
            (no_init / "tests" / "helper.py").write_text("OFFSET = 8\n", encoding="utf-8")
            methods = "\n".join(
                f"    def test_case_{idx:02d}(self): self.assertEqual(big_mod.VALUE + helper.OFFSET, 50)"
                for idx in range(88)
            )
            (no_init / "tests" / "test_suite.py").write_text(
                "import unittest\nfrom pkg import big_mod\nimport helper\n"
                f"class SuiteTests(unittest.TestCase):\n{methods}\n",
                encoding="utf-8",
            )
            (no_init / "tests" / "test_extra.py").write_text(
                "import unittest\nfrom pkg import big_mod\n"
                "class ExtraTests(unittest.TestCase):\n"
                "    def test_one(self): self.assertEqual(big_mod.VALUE, 42)\n",
                encoding="utf-8",
            )
            # Validate all 79 files with default python snapshot limits (no tests/__init__.py).
            pf = ProjectFiles(str(no_init))
            rel_files = sorted(p.relative_to(no_init).as_posix() for p in no_init.rglob("*.py"))
            self.assertEqual(len(rel_files), 79)
            validated = validate_project_test_files(
                {"root": str(no_init), "root_identity": pf.root_identity}, "python", rel_files,
            )
            self.assertEqual(validated, rel_files)

            proc_all = run_payload(no_init)
            self.assertEqual(proc_all.returncode, 0, proc_all.stdout + proc_all.stderr)
            self.assertIn("Ran 89 tests", proc_all.stdout + proc_all.stderr)
            self.assertFalse((no_init / "tests" / "__init__.py").exists())

            proc_mod = run_payload(no_init, test_target="tests.test_extra")
            self.assertEqual(proc_mod.returncode, 0, proc_mod.stdout + proc_mod.stderr)
            self.assertIn("Ran 1 test", proc_mod.stdout + proc_mod.stderr)

            proc_method = run_payload(no_init, test_target="tests.test_suite.SuiteTests.test_case_00")
            self.assertEqual(proc_method.returncode, 0, proc_method.stdout + proc_method.stderr)
            self.assertIn("Ran 1 test", proc_method.stdout + proc_method.stderr)
            self.assertFalse((no_init / "tests" / "__init__.py").exists())

            # Layout 2: WITH tests/__init__.py keeps exact existing discovery and selector behavior.
            with_init = root / "with_init"
            (with_init / "tests").mkdir(parents=True)
            (with_init / "app.py").write_text("X = 7\n", encoding="utf-8")
            (with_init / "tests" / "__init__.py").write_text("", encoding="utf-8")
            (with_init / "tests" / "test_app.py").write_text(
                "import unittest\nfrom app import X\n"
                "class AppTests(unittest.TestCase):\n"
                "    def test_a(self): self.assertEqual(X, 7)\n"
                "    def test_b(self): self.assertEqual(X + 1, 8)\n",
                encoding="utf-8",
            )
            p_all = run_payload(with_init)
            self.assertEqual(p_all.returncode, 0, p_all.stdout + p_all.stderr)
            self.assertIn("Ran 2 tests", p_all.stdout + p_all.stderr)
            p_one = run_payload(with_init, test_target="tests.test_app.AppTests.test_a")
            self.assertEqual(p_one.returncode, 0, p_one.stdout + p_one.stderr)
            self.assertIn("Ran 1 test", p_one.stdout + p_one.stderr)

    def test_work_snapshot_limits_and_hardlink_refusal(self):
        import os

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            work = root / "work"
            (work / "tests").mkdir(parents=True)
            (work / "tests" / "__init__.py").write_text("", encoding="utf-8")
            (work / "tests" / "test_ok.py").write_text("assert True\n", encoding="utf-8")
            big_ok = "a" * (100 * 1024)
            (work / "big_ok.py").write_text(big_ok, encoding="utf-8")

            pf = ProjectFiles(str(work))
            project = {"root": str(work), "root_identity": pf.root_identity}
            files = ["big_ok.py", "tests/__init__.py", "tests/test_ok.py"]
            validated = validate_project_test_files(
                project,
                "python",
                files,
                max_files=128,
                max_total_bytes=4 * 1024 * 1024,
                max_file_bytes=256 * 1024,
                source_allowlist=frozenset(files),
            )
            self.assertEqual(validated, sorted(files))

            baseline = [{"path": p} for p in validated]
            sealed = _seal_snapshot(work, project["root_identity"], baseline, max_file_bytes=256 * 1024)
            self.assertEqual(len(sealed), 3)
            self.assertEqual(sealed[0]["sha256"], hashlib.sha256(big_ok.encode("utf-8")).hexdigest())

            # Single file > 256 KiB is refused with filename, measured size, and limit.
            (work / "too_big.py").write_text("b" * (256 * 1024 + 1), encoding="utf-8")
            with self.assertRaises(JobError) as err:
                validate_project_test_files(
                    project,
                    "python",
                    ["too_big.py", "tests/__init__.py", "tests/test_ok.py"],
                    max_files=128,
                    max_total_bytes=4 * 1024 * 1024,
                    max_file_bytes=256 * 1024,
                )
            self.assertEqual(err.exception.code, "RESOURCE_BUDGET_EXCEEDED")
            self.assertIn("too_big.py", str(err.exception))
            self.assertIn("262145", str(err.exception))
            self.assertIn("262144", str(err.exception))
            (work / "too_big.py").unlink()

            # > 128 files is refused with measured count and limit.
            with self.assertRaises(JobError) as err:
                validate_project_test_files(
                    project,
                    "python",
                    ["tests/__init__.py", "tests/test_ok.py", *[f"f_{i}.py" for i in range(127)]],
                    max_files=128,
                    max_total_bytes=4 * 1024 * 1024,
                    max_file_bytes=256 * 1024,
                )
            self.assertEqual(err.exception.code, "INVALID_TEST_SCOPE")
            self.assertIn("129", str(err.exception))
            self.assertIn("128", str(err.exception))

            # Total bytes > 4 MiB is refused with measured total and limit.
            bulk = "c" * (250 * 1024)
            bulk_files = []
            for idx in range(17):
                name = f"bulk_{idx:02d}.py"
                (work / name).write_text(bulk, encoding="utf-8")
                bulk_files.append(name)
            try:
                with self.assertRaises(JobError) as total_err:
                    validate_project_test_files(
                        project,
                        "python",
                        ["tests/test_ok.py", *bulk_files],
                    )
                self.assertEqual(total_err.exception.code, "RESOURCE_BUDGET_EXCEEDED")
                self.assertIn("total size", str(total_err.exception))
                self.assertIn("4194304", str(total_err.exception))
            finally:
                for name in bulk_files:
                    (work / name).unlink()

            # PowerShell script limit stays at 64 KiB and reports measured size on refusal.
            (work / "big.ps1").write_text("#" * (65_536 + 1), encoding="utf-8")
            try:
                with self.assertRaises(JobError) as ps_err:
                    validate_project_test_files(project, "powershell", ["big.ps1"])
                self.assertEqual(ps_err.exception.code, "RESOURCE_BUDGET_EXCEEDED")
                self.assertIn("big.ps1", str(ps_err.exception))
                self.assertIn("65537", str(ps_err.exception))
                self.assertIn("65536", str(ps_err.exception))
            finally:
                (work / "big.ps1").unlink()

            # Hardlink inside workspace is refused with UNSUPPORTED_PATH_TYPE.
            outside_target = root / "outside.py"
            outside_target.write_text("X = 1\n", encoding="utf-8")
            hardlinked = work / "hard.py"
            os.link(outside_target, hardlinked)
            with self.assertRaises(FileBoundaryError) as ferr:
                pf.read_snapshot_file("hard.py", max_bytes=256 * 1024)
            self.assertEqual(ferr.exception.code, "UNSUPPORTED_PATH_TYPE")
            with self.assertRaises(FileBoundaryError) as ferr2:
                validate_project_test_files(
                    project,
                    "python",
                    ["hard.py", "tests/__init__.py", "tests/test_ok.py"],
                    max_files=128,
                    max_total_bytes=4 * 1024 * 1024,
                    max_file_bytes=256 * 1024,
                )
            self.assertEqual(ferr2.exception.code, "UNSUPPORTED_PATH_TYPE")

    def test_queued_mxc_py_refuses_powershell_work_and_invalid_work_cpu_cap(self):
        import subprocess
        import sys

        repo_root = Path(__file__).resolve().parents[1]
        script = repo_root / "crates" / "bridge-cli" / "src" / "queued_mxc.py"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            proj = root / "proj"
            (proj / "tests").mkdir(parents=True)
            (proj / "tests" / "__init__.py").write_text("", encoding="utf-8")
            (proj / "tests" / "test_ok.py").write_text("assert True\n", encoding="utf-8")
            pf = ProjectFiles(str(proj))

            def invoke(req: dict):
                run_dir = root / f"run_{req['run_id']}"
                run_dir.mkdir(parents=True)
                ready_path = run_dir / "ready.pid"
                proc = subprocess.run(
                    [sys.executable, str(script), str(repo_root), str(ready_path)],
                    cwd=str(repo_root),
                    input=json.dumps(req) + "\n",
                    capture_output=True,
                    encoding="utf-8",
                    timeout=20,
                )
                return proc.returncode, json.loads(proc.stdout.strip().splitlines()[-1])

            base_req = {
                "state": str(root / "mxc-state"),
                "root": str(proj),
                "root_identity": pf.root_identity,
                "files": ["tests/__init__.py", "tests/test_ok.py"],
                "cancel": str(root / "cancel"),
                "launch_ready": str(root / "launch-ready"),
                "delegated": True,
                "timeout_seconds": 15,
                "max_memory_bytes": 256 * 1024 * 1024,
                "max_processes": 8,
                "max_output_bytes": 65536,
            }

            rc, rec = invoke({**base_req, "run_id": "ps_work", "recipe": "powershell_script_work"})
            self.assertEqual(rc, 0)
            self.assertEqual(rec["status"], "failed")
            self.assertEqual(rec["failure_code"], "POWERSHELL_SCRIPT_WORK_UNSUPPORTED")

            for label, cpu_val in (("missing", None), ("zero", 0), ("too_high", 51), ("bool", True)):
                with self.subTest(cpu_case=label):
                    req = {**base_req, "run_id": f"cpu_{label}", "recipe": "python_tests_work"}
                    if cpu_val is not None:
                        req["max_cpu_percent"] = cpu_val
                    rc, rec = invoke(req)
                    self.assertEqual(rc, 0)
                    self.assertEqual(rec["status"], "failed")
                    self.assertEqual(rec["failure_code"], "INVALID_GRANT_LIMITS")

            # queued_mxc.py keeps powershell_script capped at 64 KiB and reports measured size in failure_code.
            (proj / "oversize.ps1").write_text("#" * (65_536 + 1), encoding="utf-8")
            rc, rec = invoke({
                **base_req,
                "run_id": "ps_over_64k",
                "recipe": "powershell_script",
                "files": ["oversize.ps1"],
            })
            self.assertEqual(rc, 0)
            self.assertEqual(rec["status"], "failed")
            self.assertTrue(rec["failure_code"].startswith("RESOURCE_BUDGET_EXCEEDED:"), rec)
            self.assertIn("oversize.ps1", rec["failure_code"])
            self.assertIn("65537", rec["failure_code"])
            self.assertIn("65536", rec["failure_code"])

            # queued_mxc.py reports measured size for python_tests file > 256 KiB.
            (proj / "oversize.py").write_text("x" * (256 * 1024 + 1), encoding="utf-8")
            rc, rec = invoke({
                **base_req,
                "run_id": "py_over_256k",
                "recipe": "python_tests",
                "files": ["oversize.py", "tests/test_ok.py"],
            })
            self.assertEqual(rc, 0)
            self.assertEqual(rec["status"], "failed")
            self.assertTrue(rec["failure_code"].startswith("RESOURCE_BUDGET_EXCEEDED:"), rec)
            self.assertIn("oversize.py", rec["failure_code"])
            self.assertIn("262145", rec["failure_code"])
            self.assertIn("262144", rec["failure_code"])

