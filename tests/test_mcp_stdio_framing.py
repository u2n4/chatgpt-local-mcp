"""Regression tests for stdio MCP framing (UTF-8 BOM and blank lines)."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from edge_bridge.broker import setup_state


def _five_line_requests() -> list[dict]:
    return [
        {"jsonrpc": "2.0", "id": "openai-mcp-discover", "method": "server/discover"},
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "framing_test", "version": "1.0"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "bridge_info", "arguments": {}}},
    ]


class McpStdioFramingTests(unittest.TestCase):
    def _run_mcp_bytes(self, state: Path, payload: bytes) -> tuple[int, list[dict], str]:
        proc = subprocess.run(
            [sys.executable, "-m", "edge_bridge.cli", "--state-dir", str(state), "mcp", "--principal", "edge"],
            input=payload,
            capture_output=True,
            timeout=25,
        )
        stdout_text = proc.stdout.decode("utf-8", errors="replace")
        stderr_text = proc.stderr.decode("utf-8", errors="replace")
        messages = [json.loads(line) for line in stdout_text.splitlines() if line.strip()]
        return proc.returncode, messages, stderr_text

    def test_leading_utf8_bom_preserves_pre_initialize_server_discover_32601(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            state = Path(tmp) / "state"
            setup_state(state)
            body = "\n".join(json.dumps(r) for r in _five_line_requests()) + "\n"
            payload = b"\xef\xbb\xbf" + body.encode("utf-8")

            rc, messages, stderr = self._run_mcp_bytes(state, payload)
            self.assertEqual(rc, 0, stderr)
            self.assertEqual(stderr, "")
            by_id = {m["id"]: m for m in messages if "id" in m}
            self.assertEqual(by_id["openai-mcp-discover"]["error"]["code"], -32601)
            self.assertIn("result", by_id[1])
            self.assertEqual(len(by_id[2]["result"]["tools"]), 33)
            self.assertIn(3, by_id)
            self.assertFalse(any(m.get("method") == "notifications/message" for m in messages))

    def test_blank_and_crlf_lines_do_not_emit_validation_errors_or_crash_on_eof(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            state = Path(tmp) / "state"
            setup_state(state)
            lines = [json.dumps(r) for r in _five_line_requests()]
            # Leading BOM + blank lines between frames + trailing \n\r\n (as PS 5.1 emits)
            raw = "\r\n".join(["", lines[0], "   ", lines[1], lines[2], "", lines[3], lines[4], "", ""])
            payload = b"\xef\xbb\xbf" + raw.encode("utf-8")

            for _ in range(10):
                rc, messages, stderr = self._run_mcp_bytes(state, payload)
                self.assertEqual(rc, 0, stderr)
                self.assertEqual(stderr, "")
                by_id = {m["id"]: m for m in messages if "id" in m}
                self.assertEqual(by_id["openai-mcp-discover"]["error"]["code"], -32601)
                self.assertEqual(len(by_id[2]["result"]["tools"]), 33)
                self.assertIn(3, by_id)
                self.assertFalse(any(m.get("method") == "notifications/message" for m in messages))


if __name__ == "__main__":
    unittest.main()
