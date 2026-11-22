from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import tempfile
import threading
import unittest

from edge_bridge.browser import BrowserError, EdgeBrowserEngine, personal_edge_profile_dir
from edge_bridge.desktop import DesktopEngine, DesktopError, verify_codex_mcp_computer_use


class _LocalTestAppHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        return

    def do_GET(self):
        if self.path == "/next":
            body = b"<html><head><title>Next Page</title></head><body><div id='status'>DONE</div></body></html>"
        else:
            body = (
                b"<html><head><title>Local Bridge Test App</title></head>"
                b"<body>"
                b"<input id='query-box' name='q' type='text' value='initial'/>"
                b"<button id='submit-btn' class='primary'>Run</button>"
                b"<a id='next-link' href='/next'>Next</a>"
                b"</body></html>"
            )
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class DesktopAndBrowserTests(unittest.TestCase):
    def test_desktop_session_lock_permissions_and_notepad_workflow(self):
        cu = verify_codex_mcp_computer_use()
        self.assertFalse(cu["computer_use_in_mcp_catalog"])
        self.assertFalse(cu["assumed_available"])

        with tempfile.TemporaryDirectory() as tmp:
            engine = DesktopEngine(Path(tmp))
            win = engine.register_test_window(hwnd=1001, title="Untitled - Notepad", process_name="notepad.exe")
            self.assertEqual(win["hwnd"], 1001)
            self.assertEqual(len(engine.list_windows()), 1)

            # Sensitive windows are blocked at registration and approval
            with self.assertRaises(DesktopError) as sens_err:
                engine.register_test_window(hwnd=1002, title="Windows Security - Password Required", process_name="CredUIBroker.exe")
            self.assertEqual(sens_err.exception.code, "SENSITIVE_WINDOW_DENIED")

            # Unapproved window cannot be controlled even when holding lock
            engine.session_lock.acquire("agent-1")
            try:
                # Concurrent second agent lock acquisition is denied
                with self.assertRaises(DesktopError) as lock_err:
                    engine.session_lock.acquire("agent-2")
                self.assertEqual(lock_err.exception.code, "DESKTOP_SESSION_LOCKED")

                with self.assertRaises(DesktopError) as unapp_err:
                    engine.focus_window(1001, agent_id="agent-1")
                self.assertEqual(unapp_err.exception.code, "WINDOW_NOT_APPROVED")

                # Approve Notepad and execute full UIA control sequence with post-action verification
                engine.approve_window(1001)
                tree = engine.read_accessibility_tree(1001)
                self.assertEqual(tree["provider"], "windows_ui_automation")
                self.assertEqual(len(tree["root"]["children"]), 2)

                foc = engine.focus_window(1001, agent_id="agent-1")
                self.assertTrue(foc["verified"])

                clk = engine.click_control(1001, "edit_1", agent_id="agent-1")
                self.assertTrue(clk["verified"])

                typed = engine.type_text(1001, "edit_1", "Hello Edge Bridge 2.0", agent_id="agent-1")
                self.assertTrue(typed["verified"])
                self.assertEqual(typed["after"]["controls"]["edit_1"]["value"], "Hello Edge Bridge 2.0")

                keys = engine.send_keys(1001, "Ctrl+S", agent_id="agent-1")
                self.assertTrue(keys["verified"])

                with self.assertRaises(DesktopError) as bad_key:
                    engine.send_keys(1001, "Ctrl+Alt+Del", agent_id="agent-1")
                self.assertEqual(bad_key.exception.code, "FORBIDDEN_KEY_SEQUENCE")

                cap = engine.capture_window(1001)
                self.assertEqual(cap["content_type"], "image/png")
            finally:
                stopped = engine.stop_session()
                self.assertTrue(stopped["stopped"])
                self.assertIsNone(engine.session_lock.owner)

    def test_edge_browser_isolated_contexts_and_local_app_workflow(self):
        server = HTTPServer(("127.0.0.1", 0), _LocalTestAppHandler)
        port = server.server_port
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                browser = EdgeBrowserEngine(Path(tmp) / "browser-contexts")

                # Personal Edge User Data directory is strictly forbidden
                with self.assertRaises(BrowserError) as prof_err:
                    browser.start_session("worker-1", custom_user_data_dir=personal_edge_profile_dir())
                self.assertEqual(prof_err.exception.code, "PERSONAL_PROFILE_FORBIDDEN")

                s1 = browser.start_session("worker-1")
                s2 = browser.start_session("worker-2")
                self.assertNotEqual(s1["user_data_dir"], s2["user_data_dir"])
                self.assertFalse(s1["personal_profile_used"])

                # Cross-worker session access is denied
                with self.assertRaises(BrowserError) as cross_err:
                    browser.read_page_state(s1["session_id"], worker_id="worker-2")
                self.assertEqual(cross_err.exception.code, "CROSS_WORKER_SESSION_DENIED")

                # Automating ChatGPT UI is forbidden
                with self.assertRaises(BrowserError) as cgpt_err:
                    browser.navigate(s1["session_id"], "https://chatgpt.com/c/123", worker_id="worker-1")
                self.assertEqual(cgpt_err.exception.code, "CHATGPT_UI_AUTOMATION_FORBIDDEN")

                # Navigate to local test app, inspect DOM, fill, click, wait, screenshot, and clean teardown
                nav = browser.navigate(s1["session_id"], f"http://127.0.0.1:{port}/", worker_id="worker-1")
                self.assertEqual(nav["status_code"], 200)
                self.assertEqual(nav["title"], "Local Bridge Test App")

                dom = browser.inspect_dom(s1["session_id"], "#query-box", worker_id="worker-1")
                self.assertEqual(dom["match_count"], 1)

                filled = browser.fill(s1["session_id"], "#query-box", "isolated edge test", worker_id="worker-1")
                self.assertTrue(filled["verified"])

                waited = browser.wait_for(s1["session_id"], selector="#submit-btn", text="Run", worker_id="worker-1")
                self.assertTrue(waited["matched"])

                shot = browser.capture_screenshot(s1["session_id"], worker_id="worker-1")
                self.assertEqual(shot["content_type"], "image/png")

                clicked = browser.click(s1["session_id"], "#next-link", worker_id="worker-1")
                self.assertTrue(clicked["verified"])
                state = browser.read_page_state(s1["session_id"], worker_id="worker-1")
                self.assertEqual(state["title"], "Next Page")
                self.assertEqual(browser.observe_errors(s1["session_id"])["error_count"], 0)

                ended = browser.end_session(s1["session_id"], worker_id="worker-1")
                self.assertTrue(ended["closed"])
                self.assertTrue(ended["user_data_dir_cleaned"])
                browser.stop_all_sessions()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(2)
