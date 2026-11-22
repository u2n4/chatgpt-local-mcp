"""Exercise the official app-server's local bootstrap inside independent MXC jobs."""
from contextlib import ExitStack
import hashlib
from pathlib import Path
import json
import tempfile
import unittest

from edge_bridge import runner


OFFLINE_APP_SERVER = """
from contextlib import contextmanager
import json, os, queue, subprocess, sys, threading, time
from pathlib import Path

@contextmanager
def app_server(codex, home, cwd):
    isolated = dict(os.environ, CODEX_HOME=str(home))
    server = subprocess.Popen([codex, "app-server", "--listen", "stdio://"],
        cwd=cwd, env=isolated, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
    messages = queue.Queue()
    serial = 0

    def receive():
        for line in server.stdout:
            item = json.loads(line)
            if "id" in item and ("result" in item or "error" in item):
                messages.put(item)
        messages.put(None)

    def call(method, params=None, *, notification=False):
        nonlocal serial
        message = {"method": method}
        if params is not None:
            message["params"] = params
        if not notification:
            serial += 1
            message["id"] = serial
        server.stdin.write(json.dumps(message).encode() + b"\\n")
        server.stdin.flush()
        if notification:
            return None
        end = time.monotonic() + 9
        while time.monotonic() < end:
            response = messages.get(timeout=max(0, end - time.monotonic()))
            if response is None:
                raise RuntimeError("Isolated app server exited")
            if response["id"] == serial:
                if not isinstance(response.get("result"), dict):
                    raise RuntimeError(method + " rejected: " + str(response.get("error")))
                return response["result"]
        raise TimeoutError(method)

    threading.Thread(target=receive, daemon=True).start()
    try:
        call("initialize", {"clientInfo": {"name": "worker_boundary_fixture", "version": "0.1.0"},
                            "capabilities": {"experimentalApi": True}})
        call("initialized", notification=True)
        yield call
    finally:
        server.stdin.close()
        try:
            server.wait(4)
        except subprocess.TimeoutExpired:
            server.terminate()
            server.wait(3)
"""


WORKER_BOOTSTRAP = OFFLINE_APP_SERVER + """
codex, peer_canary, pinned_model = sys.argv[1:4]
assert Path("owned.txt").is_file()
try:
    Path(peer_canary).read_bytes()
except PermissionError:
    pass
else:
    raise RuntimeError("Peer workspace readable")
assert not any(key in os.environ for key in ("OPENAI_API_KEY", "CONTROL_PLANE_API_KEY", "CODEX_API_KEY"))

with app_server(codex, Path("agent-home").absolute(), Path.cwd()) as call:
    result = call("account/read", {"refreshToken": False})
    assert result.get("account") is None
    cwd = str(Path.cwd())
    worker = call("thread/start", {
        "cwd": cwd, "runtimeWorkspaceRoots": [cwd], "permissions": ":workspace",
        "approvalPolicy": "never", "ephemeral": True, "model": pinned_model,
        "modelProvider": "openai", "allowProviderModelFallback": False,
    })
    assert worker["model"] == pinned_model and worker["modelProvider"] == "openai"
    assert Path(worker["cwd"]) == Path(cwd)
    assert [Path(item) for item in worker["runtimeWorkspaceRoots"]] == [Path(cwd)]
    print(json.dumps({"startup": "passed", "peer_read": "denied", "account": "absent",
                      "model": worker["model"], "thread_id": worker["thread"]["id"],
                      "model_request_sent": False}), flush=True)
"""


THREAD_CONTINUITY = OFFLINE_APP_SERVER + """
codex, project = sys.argv[1], Path(sys.argv[2])
home = project / "agent-home"
note = "Synthetic offline continuity note: 4a88a409"

def logged_note_exists(thread_id):
    for rollout in home.rglob("rollout-*.jsonl"):
        if thread_id not in rollout.name:
            continue
        for line in rollout.read_text(encoding="utf-8").splitlines():
            try:
                event = json.loads(line)
            except ValueError:
                continue
            body = event.get("payload", {})
            if event.get("type") == "response_item" and body.get("role") == "user":
                if any(item.get("text") == note for item in body.get("content", [])):
                    return True
    return False

with app_server(codex, home, project) as first:
    thread = first("thread/start", {"cwd": str(project), "runtimeWorkspaceRoots": [str(project)],
        "approvalPolicy": "never", "permissions": ":workspace", "ephemeral": False,
        "model": "gpt-6.2-sol", "modelProvider": "openai", "allowProviderModelFallback": False})
    identity = thread["thread"]["id"]
    assert thread["model"] == "gpt-6.2-sol"
    first("thread/inject_items", {"threadId": identity, "items": [
        {"type": "message", "role": "user", "content": [{"type": "input_text", "text": note}]}
    ]})

end = time.monotonic() + 4
while not logged_note_exists(identity) and time.monotonic() < end:
    time.sleep(0.05)
assert logged_note_exists(identity), "The synthetic user item was not committed."

with app_server(codex, home, project / "resume-launch") as second:
    resumed = second("thread/resume", {"threadId": identity, "model": "gpt-6.2-astra",
        "modelProvider": "openai", "approvalPolicy": "never", "permissions": ":workspace",
        "excludeTurns": True})
    assert resumed["model"] == "gpt-6.2-astra"
    assert resumed["thread"]["id"] == identity
    assert Path(resumed["cwd"]) == project
    assert [Path(item) for item in resumed["runtimeWorkspaceRoots"]] == [project]
    assert logged_note_exists(identity)
    print(json.dumps({"thread_preserved": True, "workspace_preserved": True,
        "persistent_note_verified": True, "before": thread["model"], "after": resumed["model"],
        "model_request_sent": False}), flush=True)
"""


class WorkerBoundaryTests(unittest.TestCase):
    def test_persistent_thread_reopens_with_new_model_and_original_workspace(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            codex = runner._codex_path()
            with codex.open("rb") as executable:
                self.assertEqual(hashlib.file_digest(executable, "sha256").hexdigest(), runner.CODEX_SHA256)
            work, control = root / "workspace", root / "control"
            (work / "agent-home").mkdir(parents=True)
            (work / "resume-launch").mkdir()
            (control / "codex-home").mkdir(parents=True)
            (control / "tmp").mkdir()
            profile = runner._profile(work, runner._python_path(), codex.parent)
            (control / "codex-home" / "config.toml").write_text(profile, encoding="utf-8")
            command = runner._command(work, ("-I", "-S", "-B", "-c", THREAD_CONTINUITY, str(codex), str(work)))
            log = control / "continuity.log"
            owned = runner._launch(command, work, control, log, None, limited=True)
            try:
                code = owned.wait(28)
            finally:
                owned.close()
            output = log.read_text(encoding="utf-8", errors="replace")
            self.assertEqual(code, 0, output)
            self.assertEqual(json.loads(output), {"thread_preserved": True, "workspace_preserved": True,
                "persistent_note_verified": True, "before": "gpt-6.2-sol", "after": "gpt-6.2-astra",
                "model_request_sent": False})

    def test_two_codex_app_servers_have_separate_offline_workspaces_and_pinned_threads(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            codex = runner._codex_path()
            with codex.open("rb") as executable:
                self.assertEqual(hashlib.file_digest(executable, "sha256").hexdigest(), runner.CODEX_SHA256)
            workspaces = []
            for label in ("first", "second"):
                base = root / label
                work, control = base / "workspace", base / "control"
                (work / "agent-home").mkdir(parents=True)
                (control / "codex-home").mkdir(parents=True)
                (control / "tmp").mkdir()
                (work / "owned.txt").write_text(label, encoding="utf-8")
                profile = runner._profile(work, runner._python_path(), codex.parent)
                (control / "codex-home" / "config.toml").write_text(profile, encoding="utf-8")
                workspaces.append((work, control))
            launched = []
            models = ("gpt-6.2-sol", "gpt-6.2-astra")
            with ExitStack() as cleanup:
                for index, (work, control) in enumerate(workspaces):
                    peer = workspaces[1 - index][0] / "owned.txt"
                    command = runner._command(work, ("-I", "-S", "-B", "-c", WORKER_BOOTSTRAP,
                                                     str(codex), str(peer), models[index]))
                    log = control / "result.log"
                    owned = runner._launch(command, work, control, log, None, limited=True)
                    cleanup.callback(owned.close)
                    launched.append((owned, log))
                codes = [owned.wait(25) for owned, _ in launched]
            thread_ids = set()
            for code, (_, log), model in zip(codes, launched, models, strict=True):
                output = log.read_text(encoding="utf-8", errors="replace")
                self.assertEqual(code, 0, output)
                result = json.loads(output)
                thread_ids.add(result.pop("thread_id"))
                self.assertEqual(result, {"startup": "passed", "peer_read": "denied",
                                          "account": "absent", "model": model, "model_request_sent": False})
            self.assertEqual(len(thread_ids), 2)
