from __future__ import annotations

from dataclasses import dataclass
from io import TextIOWrapper
from pathlib import Path
import sys
from typing import Annotated

import anyio
from mcp import types
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.shared.message import SessionMessage
from mcp.shared.version import SUPPORTED_PROTOCOL_VERSIONS
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from . import __version__
from .broker import BridgeError, READ_TOOLS, call_broker

Identifier = Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9_.:-]+$")]
RelativePath = Annotated[str, Field(min_length=1, max_length=768)]
Digest = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
Text = Annotated[str, Field(max_length=262144)]
Cursor = Annotated[int, Field(ge=0, le=1000000)]


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Page(Input):
    cursor: Cursor = 0
    limit: Annotated[int, Field(ge=1, le=100)] = 50


class DiagnosticsInput(Input):
    include_incidents: bool = True
    symptom: Annotated[str, Field(max_length=1000)] | None = None


class Project(Input):
    project_id: Identifier


class Resume(Project):
    task_id: Identifier | None = None


class TaskGet(Project):
    task_id: Identifier


class _BaseDirectory(Project, Page):
    path: RelativePath = "."


class Directory(_BaseDirectory):
    recursive: bool = False
    max_depth: Annotated[int, Field(ge=1, le=8)] = 3
    exclude_generated: bool = True


class File(Project):
    path: RelativePath


class Read(File):
    offset: Cursor = 0
    limit: Annotated[int, Field(ge=1, le=65536)] = 32768
    lossy_utf8: bool = False


class Search(_BaseDirectory):
    query: Annotated[str, Field(min_length=1, max_length=200)]
    limit: Annotated[int, Field(ge=1, le=100)] = 40
    exclude_generated: bool = True
    case_sensitive: bool = False


class Operation(Project):
    operation_id: Identifier


class Edit(Input):
    path: RelativePath
    content: Text
    expected_hash: Digest | None


class Write(Edit, Operation):
    pass


class Patch(Operation):
    edits: Annotated[list[Edit], Field(min_length=1, max_length=8)]


class Move(Operation):
    source: RelativePath
    destination: RelativePath
    expected_hash: Digest


class Delete(File, Operation):
    expected_hash: Digest


class Checkpoint(Operation):
    task_id: Identifier
    summary: Annotated[str, Field(min_length=1, max_length=4096)]
    objective: Annotated[str, Field(max_length=4096)] = ""
    next_action: Annotated[str, Field(max_length=4096)] = ""
    changed_files: list[dict] = Field(default_factory=list, max_length=50)
    test_evidence: list[dict] = Field(default_factory=list, max_length=50)
    accepted_decisions: list[str] = Field(default_factory=list, max_length=30)


class Job(Project):
    job_id: Identifier


class ArtifactRead(Project):
    artifact_id: Identifier
    offset: Cursor = 0
    limit: Annotated[int, Field(ge=1, le=65536)] = 32768


class JobOutput(Job):
    cursor: Cursor = 0
    limit: Annotated[int, Field(ge=1, le=65536)] = 32768


class JobMutation(Job, Operation):
    pass


class JobSelection(Input):
    path: RelativePath
    output_sha256: Digest


class JobApply(JobMutation):
    selection: Annotated[list[JobSelection], Field(min_length=1, max_length=20)]


class ProcessInput(JobMutation):
    content: Annotated[str, Field(max_length=8192)]


class ProcessStart(Operation):
    task_id: Identifier
    executable: Identifier
    argv: list[Annotated[str, Field(max_length=4096)]] = Field(max_length=48)
    cwd_relative: RelativePath = "."
    timeout_seconds: Annotated[int, Field(ge=1, le=900)] = 60


class WorkerStart(Operation):
    task_id: Identifier
    role: Identifier
    objective: Annotated[str, Field(min_length=1, max_length=8192)]
    scope: list[RelativePath] = Field(max_length=30)


class WorkerSteer(JobMutation):
    instruction: Annotated[str, Field(min_length=1, max_length=8192)]


class WorkerCancel(Project):
    worker_id: Identifier


class GitStatus(Project):
    max_entries: Annotated[int, Field(ge=1, le=1000)] = 200


class GitDiff(Project):
    base_ref: Annotated[str, Field(min_length=1, max_length=128)] | None = None
    staged: bool = False
    paths: list[RelativePath] | None = Field(default=None, max_length=100)
    offset: Cursor = 0
    limit: Annotated[int, Field(ge=1, le=65536)] = 32768


class GitCheckpoint(Operation):
    task_id: Identifier
    checkpoint_id: Identifier
    message: Annotated[str, Field(max_length=2000)] = ""


class GitIntegrate(Operation):
    source_ref: Annotated[str, Field(min_length=1, max_length=128)]
    dry_run: bool = True
    expected_head: Annotated[str, Field(min_length=4, max_length=64)] | None = None


@dataclass(frozen=True)
class ToolSpec:
    model: type[Input]
    description: str

    def schema(self, name: str) -> types.Tool:
        read_only = name in READ_TOOLS
        return types.Tool(
            name=name, description=self.description, inputSchema=self.model.model_json_schema(),
            annotations=types.ToolAnnotations(
                readOnlyHint=read_only, destructiveHint=not read_only,
                idempotentHint=read_only, openWorldHint=False,
            ),
        )


TOOL_SPECS = {
    "bridge_info": ToolSpec(Input, "Report bridge identity and which capabilities are enabled."),
    "bridge_health": ToolSpec(Input, "Report live SQLite health, host RAM/CPU telemetry, and desktop status."),
    "connection_diagnostics": ToolSpec(DiagnosticsInput, "Return redacted per-layer diagnostics and host-error classification."),
    "project_list": ToolSpec(Page, "List projects granted to this authenticated adapter."),
    "project_status": ToolSpec(Project, "Return current project policy and job records."),
    "project_resume": ToolSpec(Resume, "Read the model-independent checkpoint and pending work."),
    "task_get": ToolSpec(TaskGet, "Read a durable task record, dependencies, latest checkpoint, and recent jobs."),
    "policy_view": ToolSpec(Project, "Read sanitized project policy, grants, and test scope status."),
    "file_list": ToolSpec(Directory, "List a scoped project directory without following links."),
    "file_read": ToolSpec(Read, "Read one scoped text file (up to 32 MiB) and return its SHA-256 hash."),
    "file_search": ToolSpec(Search, "Search approved text files for a literal string."),
    "file_view": ToolSpec(File, "Get file information, text slice, image preview, or safe binary metadata."),
    "file_write": ToolSpec(Write, "Create or replace a file with an expected hash and operation ID."),
    "file_patch": ToolSpec(Patch, "Apply hash-checked whole-text replacements with a recovery journal."),
    "file_move": ToolSpec(Move, "Move a file within its project after checking the original hash."),
    "file_delete": ToolSpec(Delete, "Move a hash-checked project file into reversible quarantine."),
    "artifact_list": ToolSpec(Resume, "List registered text artifacts for the project or task."),
    "artifact_read": ToolSpec(ArtifactRead, "Read a registered text artifact after verifying its recorded hash."),
    "task_checkpoint": ToolSpec(Checkpoint, "Record visible decisions and next actions for a task."),
    "process_start": ToolSpec(ProcessStart, "Submit an approved Calculator, Blender, Python, Node, or PowerShell job recipe."),
    "process_input": ToolSpec(ProcessInput, "Bundled jobs use closed stdin."),
    "job_get": ToolSpec(Job, "Read a durable authorized job record."),
    "job_output": ToolSpec(JobOutput, "Read a bounded authorized job log page."),
    "job_changes": ToolSpec(Job, "Preview sealed changes from a local successful job without modifying project files."),
    "job_cancel": ToolSpec(JobMutation, "Request cancellation of a local job and its owned Windows process tree."),
    "git_status": ToolSpec(GitStatus, "Read repository branch, HEAD commit, and working tree status within project root."),
    "git_diff": ToolSpec(GitDiff, "Read bounded git diff output within the approved project root."),
    "git_checkpoint": ToolSpec(GitCheckpoint, "Create a non-destructive git checkpoint ref without altering HEAD or index."),
    "git_integrate": ToolSpec(GitIntegrate, "Preview or apply fast-forward branch integration in an owner-approved repository."),
    "worker_start": ToolSpec(WorkerStart, "Launch a worker. Disabled until isolation and included-only use are verified."),
    "worker_steer": ToolSpec(WorkerSteer, "Steer an owned worker job. Disabled until workers are verified."),
    "worker_list": ToolSpec(Resume, "Report worker profiles, records, host resource admission, and worker readiness."),
    "worker_cancel": ToolSpec(WorkerCancel, "Cancel a queued or running worker record (when workers exist)."),
}


def create_server(state: Path, principal: str) -> Server:
    # The Edge adapter advertises mutations truthfully so the host can apply its
    # own capability filters. The broker independently enforces per-project policy.
    server = Server("edge_project_bridge", version=__version__)
    # Dedicated worker limiter prevents heavy multi-subagent bursts from starving one another.
    call_limiter = anyio.CapacityLimiter(32)

    @server.list_tools()
    async def list_tools():
        return [spec.schema(name) for name, spec in TOOL_SPECS.items()]

    @server.call_tool(validate_input=False)
    async def run_tool(name: str, arguments: dict):
        try:
            spec = TOOL_SPECS.get(name)
            if spec is None:
                raise BridgeError("METHOD_NOT_FOUND", "Unknown bridge tool.")
            values = spec.model.model_validate(arguments).model_dump()
            result = await anyio.to_thread.run_sync(
                call_broker, state, principal, name, values, limiter=call_limiter,
            )
            return {"result": result}
        except ValidationError:
            error = {"code": "INVALID_ARGUMENT", "message": "Tool input did not match its closed schema."}
        except BridgeError as failure:
            error = {"code": failure.code, "message": str(failure), **failure.details}
        return types.CallToolResult(
            isError=True,
            content=[types.TextContent(type="text", text=f"{error['code']}: {error['message']}")],
            structuredContent=error,
        )

    return server


class _CleanStdioInput:
    """Async line iterator that skips blank/whitespace-only stdio lines."""

    def __init__(self, stream: anyio.AsyncFile[str]) -> None:
        self._stream = stream

    async def __aiter__(self):
        async for line in self._stream:
            if line.strip():
                yield line


async def serve_stdio(state: Path, principal: str) -> None:
    server = create_server(state, principal)
    init_options = server.create_initialization_options()
    # Use utf-8-sig so a leading UTF-8 BOM (e.g. emitted by .NET Framework 4.x /
    # Windows PowerShell 5.1 Process.Start under console code page 65001) does not
    # corrupt the first JSON-RPC frame, and skip empty lines before JSON validation.
    stdin = _CleanStdioInput(
        anyio.wrap_file(TextIOWrapper(sys.stdin.buffer, encoding="utf-8-sig", errors="replace"))
    )
    async with stdio_server(stdin=stdin) as (raw_reader, raw_writer):
        clean_writer, clean_reader = anyio.create_memory_object_stream(256)
        out_writer, out_reader = anyio.create_memory_object_stream(256)
        write_lock = anyio.Lock()
        pending_ids: set[str | int] = set()
        eof_seen = False
        all_done = anyio.Event()

        def _maybe_done() -> None:
            if eof_seen and not pending_ids:
                all_done.set()

        def _build_init_response(req_id: str | int, params: dict | None) -> types.JSONRPCResponse:
            requested = (params or {}).get("protocolVersion") if isinstance(params, dict) else None
            negotiated = (
                requested
                if isinstance(requested, str) and requested in SUPPORTED_PROTOCOL_VERSIONS
                else types.LATEST_PROTOCOL_VERSION
            )
            init_result = types.InitializeResult(
                protocolVersion=negotiated,
                capabilities=init_options.capabilities,
                serverInfo=types.Implementation(
                    name=init_options.server_name,
                    version=init_options.server_version,
                    websiteUrl=init_options.website_url,
                    icons=init_options.icons,
                ),
                instructions=init_options.instructions,
            )
            return types.JSONRPCResponse(
                jsonrpc="2.0",
                id=req_id,
                result=init_result.model_dump(by_alias=True, exclude_none=True),
            )

        async def _filter_incoming():
            nonlocal eof_seen
            async with clean_writer:
                async for item in raw_reader:
                    if isinstance(item, SessionMessage):
                        root = getattr(item.message, "root", None)
                        if isinstance(root, types.JSONRPCRequest):
                            if root.method == "server/discover":
                                err = types.JSONRPCError(
                                    jsonrpc="2.0",
                                    id=root.id,
                                    error=types.ErrorData(
                                        code=types.METHOD_NOT_FOUND,
                                        message="Method not found: server/discover",
                                    ),
                                )
                                async with write_lock:
                                    await raw_writer.send(SessionMessage(types.JSONRPCMessage(err)))
                                continue
                            if root.method == "initialize":
                                # Answer initialize idempotently at the transport layer so stateless
                                # ServerSession never transitions back to Initializing mid-burst.
                                resp = _build_init_response(root.id, root.params)
                                async with write_lock:
                                    await raw_writer.send(SessionMessage(types.JSONRPCMessage(resp)))
                                continue
                            pending_ids.add(root.id)
                        elif isinstance(root, types.JSONRPCNotification):
                            if root.method == "notifications/initialized":
                                continue
                    await clean_writer.send(item)
                eof_seen = True
                _maybe_done()
                if not all_done.is_set():
                    with anyio.move_on_after(30):
                        await all_done.wait()

        async def _forward_outgoing():
            try:
                async for msg in out_reader:
                    async with write_lock:
                        await raw_writer.send(msg)
                    root = getattr(msg.message, "root", None)
                    if isinstance(root, (types.JSONRPCResponse, types.JSONRPCError)):
                        pending_ids.discard(root.id)
                        _maybe_done()
            except anyio.ClosedResourceError:
                pass
            finally:
                with anyio.CancelScope(shield=True):
                    try:
                        await raw_writer.aclose()
                    except Exception:
                        pass

        async with anyio.create_task_group() as tg:
            tg.start_soon(_filter_incoming)
            tg.start_soon(_forward_outgoing)
            try:
                await server.run(
                    clean_reader,
                    out_writer,
                    init_options,
                    stateless=True,
                )
            finally:
                all_done.set()
                tg.cancel_scope.cancel()
        with anyio.CancelScope(shield=True):
            try:
                await raw_writer.aclose()
            except Exception:
                pass

