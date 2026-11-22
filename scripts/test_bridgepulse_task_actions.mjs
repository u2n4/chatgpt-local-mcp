import assert from 'node:assert/strict';
import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import net from 'node:net';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const { chromium } = require(process.env.EPB_PLAYWRIGHT_MODULE || 'playwright');
const execFileP = promisify(execFile);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const root = path.resolve(process.cwd());
const exe = process.env.EPB_BRIDGE_BINARY || path.join(root, 'target/x86_64-pc-windows-gnullvm/release/edge-bridge.exe');
const dist = process.env.EPB_UI_DIST || path.join(root, 'apps/bridgepulse/dist');
const edgePath = ['C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe', 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe', process.env.EPB_EDGE_PATH].filter(Boolean).find((p) => fs.existsSync(p));
assert(edgePath, 'installed Edge msedge.exe must exist');
assert(fs.existsSync(exe), 'edge-bridge.exe must exist');
assert(fs.existsSync(dist), 'bridgepulse dist must exist');
const base = fs.mkdtempSync(path.join(os.tmpdir(), 'epb-ui-'));
const state = path.join(base, 'state');
const project = path.join(base, 'project');
fs.mkdirSync(state, { recursive: true });
fs.mkdirSync(project, { recursive: true });
const reg = await execFileP(exe, ['--state-dir', state, '--environment-kind', 'canary', 'register', project, '--name', 'Fixture', '--grant-edge']);
const projectId = JSON.parse(reg.stdout).project_id;
assert(typeof projectId === 'string' && projectId.length > 0);
const probe = net.createServer();
await new Promise((r, j) => { probe.on('error', j); probe.listen(0, '127.0.0.1', r); });
const { port } = probe.address();
await new Promise((r) => probe.close(r));
const child = spawn(exe, ['--state-dir', state, '--environment-kind', 'canary', 'serve', '--port', String(port), '--ui-dist', dist], { stdio: ['ignore', 'pipe', 'pipe'] });
async function getRoot() {
  return new Promise((resolve, reject) => {
    http.get(`http://127.0.0.1:${port}/`, (res) => { res.resume(); resolve(res.statusCode); }).on('error', reject);
  });
}
async function waitReady() {
  for (let i = 0; i < 100; i++) { try { if ((await getRoot()) === 200) return; } catch {} await sleep(100); }
  throw new Error('serve did not return 200 on /');
}
let browser;
try {
await waitReady();
const ownerToken = fs.readFileSync(path.join(state, 'owner.token'), 'utf8').trim();
const edgeToken = fs.readFileSync(path.join(state, 'edge.token'), 'utf8').trim();
assert(ownerToken.length > 0 && edgeToken.length > 0);
async function api(token, method, params) {
  const res = await fetch(`http://127.0.0.1:${port}/api/v1/call`, { method: 'POST', headers: { 'content-type': 'application/json', 'X-Bridge-Token': token }, body: JSON.stringify({ method, params }), signal: AbortSignal.timeout(5000) });
  return { status: res.status, body: await res.json() };
}
function isCall(resp, method) {
  if (!resp.url().includes('/api/v1/call') || resp.request().method() !== 'POST') return false;
  try { return JSON.parse(resp.request().postData()).method === method; } catch { return false; }
}
  const seed = await api(ownerToken, 'task_submit', { project_id: projectId, task_id: 'fixture-task', operation_id: 'ui-fixture-1', recipe: 'python_tests', args: [] });
  assert.equal(seed.status, 200);
  assert.equal(seed.body.ok, true);
  assert.equal(seed.body.result.state, 'queued');
  const runId = seed.body.result.run_id;
  assert(typeof runId === 'string' && runId.length > 0);
  browser = await chromium.launch({ executablePath: edgePath, headless: true, chromiumSandbox: true });
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  page.setDefaultTimeout(10000);
  await page.goto(`http://127.0.0.1:${port}/`);
  await page.getByLabel('رمز المصادقة المحلي').fill(ownerToken);
  await page.getByRole('button', { name: 'تحديث' }).click();
  await page.getByText('local').waitFor({ state: 'visible' });
  assert((await page.getByText('local').first().textContent()).includes('local'));
  await page.locator('button:has-text("مساحة المهام")').click();
  const row = page.locator(`tr:has-text("${runId}"), li:has-text("${runId}"), [data-run-id="${runId}"]`).first();
  await row.scrollIntoViewIfNeeded();
  const [logsResp] = await Promise.all([page.waitForResponse((r) => isCall(r, 'job_output')), row.getByRole('button', { name: 'عرض السجل' }).click()]);
  const logsBody = await logsResp.json();
  assert.equal(logsBody.ok, true);
  assert.deepEqual(logsBody.result.chunks, []);
  const [cancelResp] = await Promise.all([page.waitForResponse((r) => isCall(r, 'job_cancel')), row.getByRole('button', { name: 'إلغاء المهمة' }).click()]);
  const cancelBody = await cancelResp.json();
  assert.equal(cancelBody.ok, true);
  assert.equal(cancelBody.result.state, 'cancelled');
  await row.locator('text=cancelled').waitFor({ state: 'visible' });
  const got = await api(ownerToken, 'job_get', { project_id: projectId, job_id: runId });
  assert.equal(got.status, 200);
  assert.equal(got.body.ok, true);
  assert.equal(got.body.result.run_id, runId);
  assert.equal(got.body.result.state, 'cancelled');
  const edgeCtx = await browser.newContext();
  const edgePage = await edgeCtx.newPage();
  edgePage.setDefaultTimeout(10000);
  await edgePage.goto(`http://127.0.0.1:${port}/`);
  await edgePage.getByLabel('رمز المصادقة المحلي').fill(edgeToken);
  const [edgeOverview] = await Promise.all([
    edgePage.waitForResponse((response) => new URL(response.url()).pathname === '/api/overview'),
    edgePage.getByRole('button', { name: 'تحديث' }).click(),
  ]);
  assert.equal(edgeOverview.status(), 403);
  await edgePage.locator('button:has-text("مساحة المهام")').click();
  assert.equal(await edgePage.getByRole('button', { name: 'عرض السجل' }).count(), 0);
  assert.equal(await edgePage.getByRole('button', { name: 'إلغاء المهمة' }).count(), 0);
  await edgeCtx.close();
  await ctx.close();
  const denied = await api(edgeToken, 'job_cancel', { project_id: projectId, job_id: runId });
  assert.equal(denied.status, 400);
  assert.equal(denied.body.code, 'BRIDGE_POLICY_DENIED');
  console.log(`ok project=${projectId} run=${runId} state=${cancelBody.result.state} logs_chunks=0 edge_deny=BRIDGE_POLICY_DENIED base=${base}`);
} finally {
  if (browser) await browser.close();
  if (child.pid && !child.killed) child.kill();
}
