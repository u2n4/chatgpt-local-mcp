import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path
ALLOWED_MODELS = ("muse-spark-1.3-contributor", "muse-wonder-1.0",
                  "muse-wonder-full-1.0", "muse-ember-1.0")
ALLOWED_EFFORTS = ("medium", "high", "max")
EXPECTED_VERSION = "Muse Code 1.4.24 (1.4.24-R9131.1)"
CLI_VERSION = "1.4.24-R9131.1"
MIN_TIMEOUT = 10
MAX_TIMEOUT = 3600
MAX_BYTES = 8 * 1024 * 1024
def log(msg):
    print(msg, flush=True)
def die(msg):
    print("error: " + msg, file=sys.stderr, flush=True)
    raise SystemExit(2)
def contributor_mode(model):
    return "off" if model == "muse-ember-1.0" else "on"

def check_env_gate():
    if "META_API_KEY" in os.environ:
        die("blocked environment override")
    for k in os.environ:
        if k.startswith("MUSE_") or k == "XDG_CONFIG_HOME":
            die("blocked environment override")
def check_auth():
    p = Path.home() / ".config" / "muse" / "auth.json"
    try:
        raw = p.read_bytes()
    except OSError:
        die("auth gate failed")
    try:
        data = json.loads(raw)
        meta = data["providers"]["meta"]
        if meta["mechanism"] != "oauth":
            die("auth gate failed")
        if meta.get("obtained_via") != "device_code":
            die("auth gate failed")
        if meta.get("subs_active") is not True:
            die("auth gate failed")
        base = meta.get("api_base_url", "")
        if not (base == "https://api.meta.ai" or base.startswith("https://api.meta.ai/")):
            die("auth gate failed")
    except (KeyError, TypeError, ValueError):
        die("auth gate failed")
def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()
def run_capture(args, timeout=60):
    return subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout, shell=False)
def check_version(muse):
    try:
        r = run_capture([muse, "--version"])
    except (OSError, subprocess.SubprocessError):
        die("version check failed")
    if r.returncode != 0 or r.stdout.strip() != EXPECTED_VERSION:
        die("version check failed")
def pct_ok(v):
    return type(v) in (int, float) and 0 <= float(v) <= 99
def check_usage(muse):
    try:
        r = run_capture([muse, "usage", "--json"])
    except (OSError, subprocess.SubprocessError):
        die("usage gate failed")
    if r.returncode != 0:
        die("usage gate failed")
    try:
        data = json.loads(r.stdout)
    except ValueError:
        die("usage gate failed")
    if data.get("reason") is not None:
        die("usage gate failed")
    try:
        al = data["allowance"]
        if al.get("source") != "mint":
            die("usage gate failed")
        if not pct_ok(al["window"]["usedPercent"]):
            die("usage gate failed")
        if not pct_ok(al["weekly"]["usedPercent"]):
            die("usage gate failed")
    except (KeyError, TypeError):
        die("usage gate failed")
def parse_args(argv=None):
    ap = argparse.ArgumentParser(description="Owner-only supervisor for one bounded Muse proposal.")
    ap.add_argument("--muse", required=True, help="absolute path to muse exe")
    ap.add_argument("--muse-sha256", required=True, help="expected hex sha256 of muse exe")
    ap.add_argument("--bridge", required=True, help="absolute path to built edge-bridge")
    ap.add_argument("--workspace", required=True, help="explicit local worker workspace path")
    ap.add_argument("--prompt-file", required=True, help="prompt file path")
    ap.add_argument("--output-dir", required=True, help="new output directory outside workspace")
    ap.add_argument("--model", required=True, choices=ALLOWED_MODELS, help="exact supported Muse ID")
    ap.add_argument("--effort", required=True, choices=ALLOWED_EFFORTS, help="reasoning effort")
    ap.add_argument("--timeout-seconds", required=True, type=int, help="positive bounded timeout")
    return ap.parse_args(argv)
def main(argv=None):
    a = parse_args(argv)
    muse = str(a.muse)
    bridge = str(a.bridge)
    if not os.path.isabs(muse) or not Path(muse).is_file():
        die("muse must be an absolute exe path")
    if not os.path.isabs(bridge) or not Path(bridge).is_file():
        die("bridge must be an absolute built path")
    exp = a.muse_sha256.lower()
    if len(exp) != 64 or any(c not in "0123456789abcdef" for c in exp):
        die("muse-sha256 must be hex")
    if sha256_file(muse).lower() != exp:
        die("muse sha256 mismatch")
    ws = Path(a.workspace).resolve()
    pf = Path(a.prompt_file).resolve()
    out = Path(a.output_dir).resolve()
    if not ws.is_dir():
        die("workspace must exist")
    if not pf.is_file():
        die("prompt-file must exist")
    if not (MIN_TIMEOUT <= int(a.timeout_seconds) <= MAX_TIMEOUT):
        die("timeout-seconds out of bounds")
    if out.exists():
        die("output-dir exists; inspect existing run")
    if out == ws or ws in out.parents:
        die("output-dir must be outside workspace")
    check_env_gate()
    check_auth()
    check_version(muse)
    check_usage(muse)
    out.mkdir(parents=False, exist_ok=False)
    sid = str(uuid.uuid4())
    mode = contributor_mode(a.model)
    events = out / "events.jsonl"
    raw_err = out / "stderr.log"
    cancel = out / "cancel.request"
    cmd = [muse, "exec", "--provider", "meta", "--model", a.model, "--reasoning-effort", a.effort, "--contributor-mode", mode, "--json", "--preset", "empty", "--no-foreign-personal-context", "--disable-write", "--disable-shell", "--disable-web-tools", "--disable-reminders", "--disable-request-user-input", "--max-model-steps", "2", "--config", "hooks={}", "--workspace", str(ws), "--session-id", sid, "--prompt-file", str(pf)]
    (out / "launch.json").write_text(json.dumps({
        "session_id": sid, "model": a.model, "requested_effort": a.effort,
        "contributor_mode": mode, "cli_version": CLI_VERSION,
        "executable_sha256": exp, "prompt_sha256": sha256_file(pf),
    }, indent=2), encoding="utf-8")
    log("launch session " + sid)
    start = time.monotonic()
    deadline = start + int(a.timeout_seconds)
    status = "error"
    code = None
    with events.open("xb") as stdout, raw_err.open("xb") as stderr:
        try:
            child = subprocess.Popen(cmd, cwd=ws, stdin=subprocess.DEVNULL,
                                     stdout=stdout, stderr=stderr)
        except OSError:
            status = "spawn-error"
        else:
            try:
                while True:
                    if any(os.fstat(f.fileno()).st_size > MAX_BYTES for f in (stdout, stderr)):
                        status = "output-cap"
                        break
                    code = child.poll()
                    if code is not None:
                        status = "completed" if code == 0 else "nonzero-exit"
                        break
                    if cancel.exists():
                        status = "cancelled"
                        break
                    if time.monotonic() >= deadline:
                        status = "timeout"
                        break
                    time.sleep(0.15)
            except KeyboardInterrupt:
                status = "cancelled"
            finally:
                if child.poll() is None:
                    child.kill()
                code = child.wait(timeout=10)
    elapsed = time.monotonic() - start
    exit_doc = {"status": status, "session_id": sid, "model": a.model, "elapsed_seconds": round(elapsed, 3), "exit_code": code}
    (out / "exit.json").write_text(json.dumps(exit_doc, indent=2), encoding="utf-8")
    log("child " + status + " code=" + str(code))
    if status != "completed":
        raise SystemExit(1)
    bcmd = [bridge, "inspect-muse-events", str(events), "--cli-version", CLI_VERSION, "--session-id", sid, "--model", a.model, "--exit-code", "0"]
    try:
        r = run_capture(bcmd, timeout=120)
    except (OSError, subprocess.SubprocessError):
        die("provider evidence failed")
    if r.returncode != 0:
        die("provider evidence failed")
    try:
        obj = json.loads(r.stdout)
    except ValueError:
        die("provider evidence invalid")
    (out / "provider-evidence.json").write_text(json.dumps(obj, indent=2), encoding="utf-8")
    log("provider artifact complete")
    return 0
if __name__ == "__main__":
    main()
