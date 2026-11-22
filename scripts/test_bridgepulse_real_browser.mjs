/**
 * Real Headless Microsoft Edge (CDP) Browser Verification for BridgePulse V0.4.0 Svelte UI.
 * Uses an isolated temporary --user-data-dir (ZERO personal profile access) and isolated temp edge-bridge serve.
 * Verifies:
 *  1. Arabic RTL layout (<html lang="ar" dir="rtl">) and unauthenticated state
 *  2. Actionable Arabic error banners on empty token & invalid token (401)
 *  3. Real login with owner.token -> Projects view renders real project_id + local badge
 *  4. Keyboard shortcuts 2..7 & 1 render Tasks, Changes, Tests, Evidence (signed Ed25519), Diagnostics, Approvals
 *  5. Server disconnect -> actionable Arabic error banner (no crash) -> server restart -> full UI recovery
 *  6. Zero JS console errors or uncaught page exceptions across the entire run
 */
import { spawn, execFileSync } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(__dirname, "..");
const RUST_BIN = path.join(REPO, "target", "x86_64-pc-windows-gnullvm", "release", "edge-bridge.exe");
const UI_DIST = path.join(REPO, "apps", "bridgepulse", "dist");
const PYTHON_BIN = path.join(REPO, ".venv", "Scripts", "python.exe");
const EDGE_BIN = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
const OUT_PATH = path.join(REPO, "audit-v0.4.0-20261119", "evidence-bundle", "bridgepulse-real-browser-test.json");

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function getFreePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, "127.0.0.1", () => {
      const addr = srv.address();
      const port = addr.port;
      srv.close(() => resolve(port));
    });
    srv.on("error", reject);
  });
}

class CdpClient {
  constructor(wsUrl) {
    this.wsUrl = wsUrl;
    this.nextId = 1;
    this.pending = new Map();
    this.consoleErrors = [];
    this.pageExceptions = [];
  }

  async connect() {
    this.ws = new WebSocket(this.wsUrl);
    await new Promise((resolve, reject) => {
      this.ws.addEventListener("open", resolve, { once: true });
      this.ws.addEventListener("error", reject, { once: true });
    });
    this.ws.addEventListener("message", (ev) => {
      const msg = JSON.parse(String(ev.data));
      if (msg.id && this.pending.has(msg.id)) {
        const { resolve, reject } = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        if (msg.error) reject(new Error(JSON.stringify(msg.error)));
        else resolve(msg.result);
      } else if (msg.method === "Runtime.exceptionThrown") {
        this.pageExceptions.push(msg.params?.exceptionDetails?.text || "unknown exception");
      } else if (msg.method === "Runtime.consoleAPICalled" && msg.params?.type === "error") {
        const txt = (msg.params.args || []).map((a) => a.value ?? a.description ?? "").join(" ");
        this.consoleErrors.push(txt);
      }
    });
  }

  send(method, params = {}) {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.ws.send(JSON.stringify({ id, method, params }));
    });
  }

  async evalJs(expression) {
    const res = await this.send("Runtime.evaluate", {
      expression,
      awaitPromise: true,
      returnByValue: true,
    });
    if (res.exceptionDetails) {
      throw new Error("Eval exception: " + JSON.stringify(res.exceptionDetails));
    }
    return res.result?.value;
  }

  close() {
    try { this.ws?.close(); } catch {}
  }
}

async function waitForFile(filePath, timeoutMs = 10000) {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    if (fs.existsSync(filePath)) return;
    await sleep(50);
  }
  throw new Error(`Timed out waiting for ${filePath}`);
}

async function waitForHttp(url, timeoutMs = 15000) {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    try {
      const r = await fetch(url);
      if (r.ok) return await r.json();
    } catch {}
    await sleep(100);
  }
  throw new Error(`Timed out waiting for HTTP ${url}`);
}

async function waitForCondition(cdp, jsExpr, timeoutMs = 8000) {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    const val = await cdp.evalJs(jsExpr);
    if (val) return val;
    await sleep(100);
  }
  throw new Error(`Condition timed out: ${jsExpr}`);
}

async function main() {
  if (!fs.existsSync(EDGE_BIN)) throw new Error(`Microsoft Edge not found at ${EDGE_BIN}`);
  if (!fs.existsSync(RUST_BIN)) throw new Error(`Rust binary not found at ${RUST_BIN}`);
  if (!fs.existsSync(path.join(UI_DIST, "index.html"))) throw new Error(`BridgePulse dist missing at ${UI_DIST}`);

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "eb_browser_test_"));
  const stateDir = path.join(tmpDir, "state");
  const projDir = path.join(tmpDir, "proj");
  const edgeProfile = path.join(tmpDir, "edge_profile");
  fs.mkdirSync(path.join(projDir, "tests"), { recursive: true });
  fs.writeFileSync(path.join(projDir, "tests", "__init__.py"), "");
  fs.writeFileSync(
    path.join(projDir, "tests", "test_ui_probe.py"),
    "import unittest\nclass T(unittest.TestCase):\n    def test_math(self): self.assertEqual(3*3, 9)\n"
  );

  let srvProc = null;
  let edgeProc = null;
  let cdp = null;

  try {
    // 1. Seed isolated state with 1 project, 1 grant, and 1 real verified test run
    const reg = JSON.parse(
      execFileSync(RUST_BIN, ["--state-dir", stateDir, "register", projDir, "--name", "BridgePulse UI Audit Project", "--grant-edge"], { encoding: "utf8" })
    );
    const pid = reg.project_id;
    const grant = JSON.parse(
      execFileSync(RUST_BIN, ["--state-dir", stateDir, "grant-create", pid, "--requester", "executor:codex_primary", "--writable-path", "src/**", "--recipe", "python_tests"], { encoding: "utf8" })
    );
    const runRes = JSON.parse(
      execFileSync(RUST_BIN, [
        "--state-dir", stateDir, "run-job",
        "--project-id", pid, "--task-id", "ui_audit_task", "--operation-id", "op-ui-audit-1",
        "--cwd", projDir, "--executable", PYTHON_BIN,
        "--arg", "-B", "--arg", "-m", "--arg", "unittest", "--arg", "discover", "--arg", "-s", "--arg", "tests", "--arg", "-t", "--arg", ".", "--arg", "-v",
      ], { encoding: "utf8" })
    );

    const brokerPort = await getFreePort();
    const startServer = async () => {
      const discPath = path.join(stateDir, "rust-broker.json");
      if (fs.existsSync(discPath)) fs.unlinkSync(discPath);
      const p = spawn(RUST_BIN, ["--state-dir", stateDir, "serve", "--port", String(brokerPort), "--ui-dist", UI_DIST], {
        stdio: ["ignore", "pipe", "pipe"],
      });
      await waitForFile(discPath, 10000);
      return p;
    };

    srvProc = await startServer();
    const ownerToken = fs.readFileSync(path.join(stateDir, "owner.token"), "utf8").trim();

    // 2. Launch headless Microsoft Edge with isolated empty profile
    const cdpPort = await getFreePort();
    edgeProc = spawn(EDGE_BIN, [
      "--headless=new",
      "--disable-gpu",
      "--no-first-run",
      "--no-default-browser-check",
      `--remote-debugging-port=${cdpPort}`,
      `--user-data-dir=${edgeProfile}`,
      "about:blank",
    ], { stdio: ["ignore", "pipe", "pipe"] });

    const targets = await waitForHttp(`http://127.0.0.1:${cdpPort}/json/list`, 15000);
    const pageTarget = targets.find((t) => t.type === "page") || targets[0];
    if (!pageTarget?.webSocketDebuggerUrl) throw new Error("No CDP page target found");

    cdp = new CdpClient(pageTarget.webSocketDebuggerUrl);
    await cdp.connect();
    await cdp.send("Page.enable");
    await cdp.send("Runtime.enable");

    const uiUrl = `http://127.0.0.1:${brokerPort}/`;
    await cdp.send("Page.navigate", { url: uiUrl });
    await waitForCondition(cdp, `document.querySelector('h1')?.textContent?.includes('BridgePulse V0.4.0')`);

    const initialCheck = await cdp.evalJs(`({
      lang: document.documentElement.lang,
      dir: document.documentElement.dir,
      title: document.title,
      h1: document.querySelector('h1')?.textContent?.trim(),
      unauthBadge: document.querySelector('.topbar')?.textContent?.includes('غير متصل')
    })`);

    // 3. Test empty token error banner
    await cdp.evalJs(`document.querySelector('.auth-bar button').click()`);
    await waitForCondition(cdp, `document.querySelector('.alert.error') !== null`);
    const emptyErrText = await cdp.evalJs(`document.querySelector('.alert.error').textContent.trim()`);

    // 4. Test invalid token -> 401 actionable error banner
    await cdp.evalJs(`(() => {
      const inp = document.querySelector('.auth-bar input');
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
      setter.call(inp, '0000000000000000000000000000000000000000000000000000000000000000');
      inp.dispatchEvent(new Event('input', { bubbles: true }));
      document.querySelector('.auth-bar button').click();
    })()`);
    await waitForCondition(cdp, `document.querySelector('.alert.error')?.textContent?.includes('AUTH_REQUIRED')`);
    const badTokErr = await cdp.evalJs(`document.querySelector('.alert.error').textContent.trim()`);

    // 5. Authenticate with real owner token (injected transiently, never printed)
    await cdp.evalJs(`(() => {
      const inp = document.querySelector('.auth-bar input');
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
      setter.call(inp, ${JSON.stringify(ownerToken)});
      inp.dispatchEvent(new Event('input', { bubbles: true }));
      inp.blur();
      document.querySelector('.auth-bar button').click();
    })()`);
    await waitForCondition(cdp, `document.body.textContent.includes(${JSON.stringify(pid)})`);
    const projectsView = await cdp.evalJs(`({
      principalBadge: document.querySelector('.topbar .badge')?.textContent?.trim(),
      hasProjectName: document.body.textContent.includes('BridgePulse UI Audit Project'),
      hasProjectId: document.body.textContent.includes(${JSON.stringify(pid)}),
      errorBannerGone: document.querySelector('.alert.error') === null
    })`);

    // 6. Test keyboard shortcuts 2..7 & 1 and inspect every rendered view
    const pressKey = async (key) => {
      await cdp.evalJs(`window.dispatchEvent(new KeyboardEvent('keydown', { key: ${JSON.stringify(key)}, bubbles: true }))`);
      await sleep(120);
    };

    await pressKey("2");
    const tasksView = await cdp.evalJs(`({
      heading: document.querySelector('h2')?.textContent?.trim(),
      hasRunId: document.body.textContent.includes(${JSON.stringify(runRes.job.run_id)}),
      hasTaskId: document.body.textContent.includes('ui_audit_task'),
      hasOutcomeTriad: document.body.textContent.includes('verify=')
    })`);

    await pressKey("3");
    const changesView = await cdp.evalJs(`({
      heading: document.querySelector('h2')?.textContent?.trim(),
      isStaticExplanatoryOnly: !document.querySelector('main table') && document.body.textContent.includes('edge-bridge apply-patch')
    })`);

    await pressKey("4");
    const testsView = await cdp.evalJs(`({
      heading: document.querySelector('h2')?.textContent?.trim(),
      hasPassVerdict: document.body.textContent.includes('PASS'),
      hasParserName: document.body.textContent.includes('python_unittest')
    })`);

    await pressKey("5");
    const evidenceView = await cdp.evalJs(`({
      hasManifestId: document.body.textContent.includes(${JSON.stringify(runRes.manifest.identity.manifest_id)}),
      hasEd25519Sig: document.body.textContent.includes('ed25519:'),
      hasSha256: document.body.textContent.includes('sha256:')
    })`);

    await pressKey("6");
    const diagnosticsView = await cdp.evalJs(`({
      hasCodexRow: document.body.textContent.includes('codex'),
      hasSqliteVersion: document.body.textContent.includes('sqlite_runtime_version'),
      hasIncludedOnly: document.body.textContent.includes('INCLUDED_ONLY')
    })`);

    await pressKey("7");
    const approvalsView = await cdp.evalJs(`({
      heading: document.querySelector('h2')?.textContent?.trim(),
      hasGrantId: document.body.textContent.includes(${JSON.stringify(grant.grant_id)}),
      hasRequester: document.body.textContent.includes('executor:codex_primary')
    })`);

    // 7. Disconnect -> actionable error banner -> restart -> recovery!
    srvProc.kill();
    await new Promise((r) => srvProc.once("exit", r));
    srvProc = null;
    await sleep(200);

    await cdp.evalJs(`document.querySelector('.auth-bar button').click()`);
    await waitForCondition(cdp, `document.querySelector('.alert.error')?.textContent?.includes('الاتصال بخادم Bridge المحلي')`);
    const disconnectErr = await cdp.evalJs(`document.querySelector('.alert.error').textContent.trim()`);

    // Restart server on exact same port -> click refresh -> verify recovery
    srvProc = await startServer();
    await pressKey("1");
    await cdp.evalJs(`document.querySelector('.auth-bar button').click()`);
    await waitForCondition(cdp, `document.querySelector('.alert.error') === null && document.body.textContent.includes(${JSON.stringify(pid)})`);
    const recoveredOk = await cdp.evalJs(`({
      errorCleared: document.querySelector('.alert.error') === null,
      projectRenderedAgain: document.body.textContent.includes(${JSON.stringify(pid)})
    })`);

    // Filter out expected browser network console error during simulated disconnect + 401 test
    const unexpectedConsoleErrors = cdp.consoleErrors.filter(
      (e) => !e.includes("401") && !e.includes("Failed to fetch") && !e.includes("ERR_CONNECTION_REFUSED")
    );

    const report = {
      captured_at_utc: new Date().toISOString(),
      browser: "Microsoft Edge (headless CDP, isolated temporary profile)",
      status:
        initialCheck.dir === "rtl" &&
        projectsView.hasProjectId &&
        tasksView.hasRunId &&
        testsView.hasPassVerdict &&
        evidenceView.hasManifestId &&
        diagnosticsView.hasCodexRow &&
        approvalsView.hasGrantId &&
        recoveredOk.errorCleared &&
        cdp.pageExceptions.length === 0 &&
        unexpectedConsoleErrors.length === 0
          ? "PASS"
          : "FAIL",
      initial_rtl_and_unauth: initialCheck,
      empty_token_error_banner_present: emptyErrText.includes("المصادقة مطلوبة"),
      invalid_token_401_error_banner_present: badTokErr.includes("AUTH_REQUIRED"),
      authenticated_projects_view: projectsView,
      keyboard_shortcut_views: {
        tasks_key_2: tasksView,
        changes_key_3: changesView,
        tests_key_4: testsView,
        evidence_key_5: evidenceView,
        diagnostics_key_6: diagnosticsView,
        approvals_key_7: approvalsView,
      },
      disconnect_and_recovery: {
        disconnect_error_banner_present: disconnectErr.includes("edge-bridge serve"),
        recovered_after_server_restart: recoveredOk,
      },
      ui_gaps_observed_honestly: [
        "View 3 (changes / التغييرات والفرق) currently renders static guidance text only; it does not yet fetch or render live patch_journals/diffs from /api/overview.",
        "BridgePulse UI is currently an authenticated inspection/dashboard workbench; interactive task submission or grant approval buttons are not yet wired into the Svelte UI.",
      ],
      uncaught_page_exceptions: cdp.pageExceptions,
      unexpected_console_errors: unexpectedConsoleErrors,
    };

    fs.mkdirSync(path.dirname(OUT_PATH), { recursive: true });
    fs.writeFileSync(OUT_PATH, JSON.stringify(report, null, 2) + "\n", "utf8");
    console.log(JSON.stringify(report, null, 2));
    if (report.status !== "PASS") process.exitCode = 1;
  } finally {
    cdp?.close();
    try { edgeProc?.kill(); } catch {}
    try { srvProc?.kill(); } catch {}
    await sleep(300);
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
