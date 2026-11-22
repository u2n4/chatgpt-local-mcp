import asyncio
import os
import subprocess
import tempfile
import unittest
from contextlib import asynccontextmanager
from pathlib import Path

import jsonschema
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

MARKER = "MCP-CONTRACT-MARKER-7f3a9c1e"


def _binary_path() -> Path:
    override = os.environ.get("EPB_MCP_TEST_BINARY")
    if override:
        return Path(override)
    repo_root = Path(__file__).resolve().parents[2]
    return repo_root / "target" / "x86_64-pc-windows-gnullvm" / "release" / "edge-bridge.exe"


@asynccontextmanager
async def _stdio_session(binary: Path, state_dir: Path):
    params = StdioServerParameters(
        command=str(binary),
        args=[
            "--state-dir",
            str(state_dir),
            "--environment-kind",
            "canary",
            "mcp",
            "--principal",
            "edge",
        ],
    )
    async with stdio_client(params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            session.epb_initialize_result = await session.initialize()
            yield session


class McpWireSchemasTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.binary = _binary_path()
        if os.environ.get("EPB_MCP_TEST_BINARY"):
            self.assertTrue(self.binary.is_file(), f"explicit worker binary missing: {self.binary}")
        if not self.binary.is_file():
            self.skipTest(f"local worker binary not found: {self.binary}")
        self.state_dir = self.tmp / "state"
        self.fixture = self.tmp / "fixture"
        self.fixture.mkdir(parents=True)
        self.hello = self.fixture / "hello.txt"
        self.hello.write_text(f"hello {MARKER}\n", encoding="utf-8")
        self.original_hello = self.hello.read_bytes()
        subprocess.run(
            [
                str(self.binary),
                "--state-dir",
                str(self.state_dir),
                "--environment-kind",
                "canary",
                "register",
                str(self.fixture),
                "--name",
                "MCP contract fixture",
                "--grant-edge",
            ],
            check=True,
            timeout=15,
            capture_output=True,
            text=True,
        )

    async def test_wire_schemas_and_contract(self):
        async with _stdio_session(self.binary, self.state_dir) as session:
            listed = await session.list_tools()
            tools = list(listed.tools)
            names = [tool.name for tool in tools]
            self.assertEqual(len(names), 39)
            self.assertEqual(len(set(names)), 39)

            for tool in tools:
                jsonschema.Draft202012Validator.check_schema(tool.inputSchema)
                if tool.outputSchema is not None:
                    jsonschema.Draft202012Validator.check_schema(tool.outputSchema)

            by_name = {tool.name: tool for tool in tools}
            expected_required = {
                "file_read": ["project_id", "path"],
                "file_view": ["project_id", "path"],
                "file_search": ["project_id", "query"],
                "file_read_batch": ["project_id", "items"],
                "task_get": ["project_id", "task_id"],
                "task_submit": ["project_id", "task_id", "operation_id"],
                "job_get": ["project_id", "job_id"],
                "artifact_read": ["project_id", "artifact_id"],
            }
            for tool_name, required in expected_required.items():
                self.assertIn(tool_name, by_name)
                actual_required = by_name[tool_name].inputSchema.get("required", [])
                self.assertEqual(set(actual_required), set(required))

            for tool_name in ("bridge_info", "project_list", "file_read", "file_search"):
                self.assertIn(tool_name, by_name)
                output_schema = by_name[tool_name].outputSchema
                self.assertIsNotNone(output_schema)
                properties = output_schema.get("properties", {})
                self.assertIn("result", properties)
                self.assertIn("result", output_schema.get("required", []))
                result_schema = properties["result"]
                self.assertIsInstance(result_schema, dict)
                self.assertIn(result_schema.get("type"), ("object", None))

            project_result = await session.call_tool("project_list", {})
            self.assertFalse(getattr(project_result, "isError", False))
            project_structured = project_result.structuredContent
            project_id = project_structured["result"]["projects"][0]["project_id"]
            self.assertTrue(project_id)

            read_result = await session.call_tool(
                "file_read", {"project_id": project_id, "path": "hello.txt"}
            )
            self.assertFalse(getattr(read_result, "isError", False))
            payload = read_result.structuredContent["result"]
            self.assertEqual(payload["path"], "hello.txt")
            self.assertEqual(payload["content"], self.original_hello.decode("utf-8"))

            search_result = await session.call_tool(
                "file_search", {"project_id": project_id, "query": MARKER}
            )
            self.assertFalse(getattr(search_result, "isError", False))
            hits = search_result.structuredContent["result"]["hits"]
            self.assertEqual(len(hits), 1)
            self.assertEqual((hits[0]["path"], hits[0]["line"]), ("hello.txt", 1))
            self.assertIn(MARKER, hits[0]["preview"])

            instructions = session.epb_initialize_result.instructions or ""
            self.assertIn("read-only", instructions[:512])
            self.assertIn("parallel", instructions)
            for tool in tools:
                self.assertNotIn("principal_hint", tool.description)
            self.assertTrue(
                by_name["file_write"].description.startswith("Not callable from this read-only connection")
            )

            # Several agents share one connection: every concurrent call gets its own answer.
            burst = await asyncio.gather(
                *(
                    session.call_tool(name, arguments)
                    for _ in range(8)
                    for name, arguments in (
                        ("file_read", {"project_id": project_id, "path": "hello.txt"}),
                        ("file_search", {"project_id": project_id, "query": MARKER}),
                        ("project_status", {"project_id": project_id}),
                    )
                )
            )
            self.assertEqual(len(burst), 24)
            for index, result in enumerate(burst):
                self.assertFalse(getattr(result, "isError", False))
                structured = result.structuredContent["result"]
                if index % 3 == 0:
                    self.assertEqual(structured["content"], self.original_hello.decode("utf-8"))
                elif index % 3 == 1:
                    self.assertEqual(len(structured["hits"]), 1)
                else:
                    self.assertEqual(structured["project"]["project_id"], project_id)

            write_result = await session.call_tool(
                "file_write",
                {
                    "project_id": project_id,
                    "path": "hello.txt",
                    "content": "overwritten by denied write\n",
                },
            )
            self.assertTrue(write_result.isError)
            self.assertEqual(write_result.structuredContent["code"], "BRIDGE_POLICY_DENIED")
            self.assertEqual(self.hello.read_bytes(), self.original_hello)

        async with _stdio_session(self.binary, self.state_dir) as fresh_session:
            repeated = await fresh_session.call_tool("project_list", {})
            self.assertFalse(getattr(repeated, "isError", False))
            repeated_structured = repeated.structuredContent
            repeated_project_id = repeated_structured["result"]["projects"][0]["project_id"]
            self.assertEqual(repeated_project_id, project_id)


if __name__ == "__main__":
    unittest.main()
