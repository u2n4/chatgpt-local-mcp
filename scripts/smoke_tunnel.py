"""Exercise the real Windows tunnel client against a disposable local control plane."""
from __future__ import annotations

import argparse
import asyncio
from contextlib import asynccontextmanager
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Callable
from urllib.parse import urlsplit

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from edge_bridge import runner
from edge_bridge.broker import call_broker, setup_state

APP = Path(__file__).resolve().parents[1]
EXPECTED_CLIENT_SHA256 = "e0b2f25d08f24a4ddb7a04f3d43b62f88d4b18a5b20f2e478295cd8f353f21e5"
FIXTURE = "Edge bridge local relay verification\n"
DUMMY_TUNNEL = "tunnel_0123456789abcdef0123456789abcdef"


def verify_client(binary: Path) -> None:
    with binary.open("rb") as executable:
        actual = hashlib.file_digest(executable, "sha256").hexdigest()
    if actual != EXPECTED_CLIENT_SHA256:
        raise RuntimeError("Expected the previously verified Windows tunnel-client v0.0.21.")


def generate_profile(binary: Path, root: Path, state: Path) -> Path:
    powershell = shutil.which("pwsh.exe")
    if powershell is None:
        raise RuntimeError("PowerShell 7 was not found.")
    profile_dir = root / "profile"
    subprocess.run(
        [powershell, "-NoProfile", "-File", str(APP / "scripts" / "tunnel-profile.ps1"),
         "-TunnelClient", str(binary), "-TunnelId", DUMMY_TUNNEL,
         "-ProfileDir", str(profile_dir), "-StateDir", str(state)],
        cwd=APP, capture_output=True, text=True, check=True, timeout=20,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    profile = profile_dir / "edge-project-bridge.yaml"
    original = profile.read_text(encoding="utf-8")
    hosted_default = 'base_url: "https://api.openai.com"'
    if original.count(hosted_default) != 1:
        raise RuntimeError("The generated profile differs from the verified template.")
    local_profile = profile_dir / "local-relay-only.yaml"
    local_profile.write_text(original.replace(hosted_default, 'base_url: "http://127.0.0.1:1"'), encoding="utf-8")
    (state / "tunnel-runtime.key").write_text("synthetic-local-smoke", encoding="utf-8")
    return local_profile


def wait_for_file(path: Path, poll, seconds: float, description: str) -> None:
    deadline = time.monotonic() + seconds
    while not path.is_file() and time.monotonic() < deadline:
        if poll() is not None:
            raise RuntimeError(f"{description} exited before creating {path.name}.")
        time.sleep(0.05)
    if not path.is_file():
        raise TimeoutError(description)


@asynccontextmanager
async def session_at(url: str):
    async with httpx.AsyncClient(trust_env=False, follow_redirects=False, timeout=15) as http:
        async with streamable_http_client(url, http_client=http) as (reader, writer, _):
            async with ClientSession(reader, writer) as session:
                await session.initialize()
                yield session


async def relay_result(session: ClientSession, tool: str, payload: dict) -> dict:
    reply = await session.call_tool(tool, payload)
    if reply.isError:
        raise RuntimeError(f"{tool}: {reply.structuredContent}")
    return reply.structuredContent["result"]


async def expect_denial(session: ClientSession, tool: str, payload: dict, expected: str) -> str:
    reply = await session.call_tool(tool, payload)
    code = (reply.structuredContent or {}).get("code")
    if not reply.isError or code != expected:
        raise RuntimeError(f"{tool} returned {code!r}, expected {expected}.")
    return code


async def check_relay(url: str, state: Path, project_id: str, restart_broker: Callable[[], None]) -> dict:
    project = {"project_id": project_id}
    query = {**project, "path": "fixture.txt"}
    task = {**project, "task_id": "relay-regression"}
    async with session_at(url) as first:
        ungranted = await expect_denial(first, "file_read", query, "PROJECT_NOT_GRANTED")
        call_broker(state, "local", "owner_grant_edge", project)
        tools = {tool.name for tool in (await first.list_tools()).tools}
        if not {"bridge_info", "file_read", "project_resume", "file_write"} <= tools:
            raise RuntimeError("Relay catalog is missing expected bridge tools.")
        file = await relay_result(first, "file_read", query)
        if file["content"] != FIXTURE or file["hash"] != hashlib.sha256(FIXTURE.encode()).hexdigest():
            raise RuntimeError("The relayed fixture content and digest did not match.")
        denied = await expect_denial(
            first, "file_write", {**query, "operation_id": "must-not-write", "content": "unsafe-write-attempt",
                                  "expected_hash": file["hash"]}, "BRIDGE_POLICY_DENIED",
        )
        identity = (await relay_result(first, "bridge_info", {}))["instance_id"]
        checkpoint = await relay_result(first, "project_resume", task)
        if checkpoint["next_action"] != "Continue the local relay smoke test":
            raise RuntimeError("Unexpected checkpoint returned over the relay.")
    restart_broker()
    async with session_at(url) as second:
        if (await relay_result(second, "bridge_info", {}))["instance_id"] != identity:
            raise RuntimeError("The bridge identity changed across transport sessions.")
        if await relay_result(second, "project_resume", task) != checkpoint:
            raise RuntimeError("The new transport session did not restore the same checkpoint.")
        if await relay_result(second, "file_read", query) != file:
            raise RuntimeError("The relayed file changed after broker restart.")
        call_broker(state, "local", "owner_revoke_edge", project)
        revoked = await expect_denial(second, "file_read", query, "PROJECT_NOT_GRANTED")
    return {"catalog_tools": len(tools), "file_sha256": file["hash"], "read_before_grant": ungranted,
            "write_via_edge": denied, "new_transport_session_same_checkpoint": True,
            "survived_broker_restart_under_same_relay": True, "read_after_revoke": revoked}


def start_broker(state: Path) -> subprocess.Popen:
    return subprocess.Popen(
        [sys.executable, "-m", "edge_bridge.cli", "--state-dir", str(state), "start"],
        cwd=APP, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )


def stop_broker(broker: subprocess.Popen, state: Path) -> None:
    if broker.poll() is None:
        try:
            call_broker(state, "local", "owner_stop")
            broker.wait(8)
        finally:
            if broker.poll() is None:
                broker.terminate()
                broker.wait(5)


def run_smoke(binary: Path, root: Path) -> dict:
    verify_client(binary)
    project, state = root / "fixture", root / "broker-state"
    project.mkdir()
    fixture = project / "fixture.txt"
    fixture.write_bytes(FIXTURE.encode())
    setup_state(state)
    profile = generate_profile(binary, root, state)
    broker = start_broker(state)

    def restart_broker():
        nonlocal broker
        stop_broker(broker, state)
        broker = start_broker(state)
        wait_for_file(state / "broker.json", broker.poll, 12, "restarted MCP broker")

    try:
        wait_for_file(state / "broker.json", broker.poll, 12, "MCP broker")
        project_id = call_broker(state, "local", "owner_register", {
            "root": str(project), "name": "Official local relay smoke fixture",
        })["project_id"]
        call_broker(state, "local", "task_checkpoint", {
            "project_id": project_id, "task_id": "relay-regression", "operation_id": "save-relay-checkpoint",
            "summary": "Verify a checkpoint over the local loopback relay.",
            "next_action": "Continue the local relay smoke test",
        })
        relay, control = root / "relay", root / "relay-control"
        for directory in (relay, control, control / "tmp", control / "codex-home"):
            directory.mkdir()
        url_file = control / "connection.json"
        owned = runner._launch(
            [str(binary), "dev", "proxy", "--backend", "go", "--listen", "127.0.0.1:0",
             "--profile-file", str(profile), "--response-timeout", "10s", "--duration", "65s",
             "--url-file", str(url_file)],
            relay, control, control / "relay.log", None,
        )
        try:
            wait_for_file(url_file, owned.poll, 16, "local tunnel-client dev proxy")
            link = json.loads(url_file.read_text(encoding="utf-8"))["mcp_url"]
            url = urlsplit(link)
            if url.scheme != "http" or url.hostname != "127.0.0.1" or url.username or not url.port:
                raise RuntimeError("Refusing a non-loopback relay URL.")
            result = asyncio.run(check_relay(link, state, project_id, restart_broker))
        finally:
            owned.close()
        if fixture.read_bytes() != FIXTURE.encode():
            raise RuntimeError("Read-only grant changed the source fixture.")
        return {**result, "transport": "official tunnel-client dev proxy", "loopback_only": True,
                "hosted_tunnel_started": False, "model_request_sent": False, "fixture_unchanged": True}
    finally:
        stop_broker(broker, state)


def main() -> int:
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--tunnel-client", required=True, type=Path)
    cli.add_argument("--output-dir", required=True, type=Path, help="Existing parent for a new disposable fixture.")
    args = cli.parse_args()
    root = Path(tempfile.mkdtemp(prefix="official-relay-", dir=args.output_dir.resolve(strict=True)))
    print(root, flush=True)
    evidence = run_smoke(args.tunnel_client.resolve(strict=True), root)
    (root / "relay-evidence.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    print(json.dumps(evidence))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
