<script lang="ts">
  import { onMount } from 'svelte';

  type ViewId =
    | 'projects'
    | 'tasks'
    | 'changes'
    | 'tests'
    | 'evidence'
    | 'diagnostics'
    | 'approvals';

  interface CapabilityStatus {
    implemented: boolean;
    authorized: boolean;
    available: 'true' | 'false' | 'unknown';
    verified: boolean;
    last_verified_at?: string | null;
    reason: string;
  }

  interface OverviewData {
    bridge_version: string;
    principal: string;
    host_id: string;
    versions: Record<string, unknown>;
    health: Record<string, unknown> | null;
    resources: {
      ram_total_mb: number;
      ram_available_mb: number;
      ram_used_percent: number;
      process_working_set_bytes?: number;
      gpu_probe: CapabilityStatus;
      desktop_name?: string | null;
      mxc_default_desktop: boolean;
    };
    containment: {
      backend: string;
      binary_hash_verified?: boolean;
      interactive_default_desktop?: boolean;
      automatic_weaker_fallback?: boolean;
      status?: CapabilityStatus;
    };
    providers: Array<{
      provider: string;
      installed: boolean;
      detected_version?: string | null;
      auth_mode: string;
      billing_policy: string;
      included_only_compatible: boolean;
      disabled_reasons: string[];
      capability: CapabilityStatus;
    }>;
    projects: Array<{
      project_id: string;
      display_name: string;
      policy_revision: number;
      policy_hash: string;
      capabilities: string[];
    }>;
    grants: Array<{
      grant_id: string;
      requester_principal: string;
      project_id: string;
      writable_paths: string[];
      allowed_recipes: string[];
      expires_at: string;
      revoked: boolean;
    }>;
    runs: Array<{
      run_id: string;
      task_id: string;
      project_id: string;
      host_id: string;
      state: string;
      exit_code?: number | null;
      outcome?: {
        agent_outcome: string;
        execution_outcome: string;
        verification_outcome: string;
      } | null;
      updated_at: string;
    }>;
    evidence_manifests: Array<{
      identity: {
        manifest_id: string;
        run_id: string;
        host_id: string;
        project_id: string;
        evidence_class: string;
      };
      command: { executable: string; argv: string[] };
      time: { monotonic_duration_ms: number; finished_at_utc: string };
      tests: {
        parser_name: string;
        discovered: number;
        executed: number;
        passed: number;
        failed: number;
        skipped: number;
        fresh_for_run: boolean;
      };
      conclusions: {
        overall_verdict: string;
        untested_areas: string[];
        reproduction_command: string;
        provenance_disclaimer: string;
      };
      manifest_sha256?: string;
      signature_ed25519_hex?: string;
    }>;
    paired_devices: Array<{
      host_id: string;
      display_name: string;
      status: string;
      approved_scopes: string[];
      last_heartbeat_at?: string | null;
      revoked: boolean;
    }>;
  }

  const navItems: Array<{ id: ViewId; label: string; key: string }> = [
    { id: 'projects', label: 'المشاريع والأجهزة', key: '1' },
    { id: 'tasks', label: 'مساحة المهام', key: '2' },
    { id: 'changes', label: 'التغييرات والفرق', key: '3' },
    { id: 'tests', label: 'نتائج الاختبارات', key: '4' },
    { id: 'evidence', label: 'الأدلة والتوقيعات', key: '5' },
    { id: 'diagnostics', label: 'التشخيص والأداء', key: '6' },
    { id: 'approvals', label: 'الموافقات والصلاحيات', key: '7' },
  ];

  let activeView = $state<ViewId>('projects');
  let token = $state<string>('');
  let overview = $state<OverviewData | null>(null);
  let loading = $state<boolean>(false);
  let errorState = $state<{ action: string; reason: string; nextStep: string } | null>(null);
  let loadedToken = $state('');
  let refreshSequence = 0;
  let isOwner = $derived(overview?.principal === 'local' && loadedToken !== '' && token.trim() === loadedToken);
  let jobRunId = $state<string | null>(null);
  let jobChunks = $state<Array<{ content: string; stream: string; seq: number }>>([]);
  let jobTruncated = $state<boolean>(false);
  let jobLoading = $state<boolean>(false);
  let jobCancellingId = $state<string | null>(null);
  let jobFeedback = $state<string | null>(null);
  let jobError = $state<{ action: string; reason: string; nextStep: string } | null>(null);
  let jobSeq = 0;

  async function refreshOverview() {
    const requestToken = token.trim();
    if (!requestToken) {
      errorState = {
        action: 'تحميل حالة النواة المحلية',
        reason: 'المصادقة مطلوبة: عنوان loopback وحده لا يكفي للوصول.',
        nextStep: 'أدخل رمز المالك (owner.token) أو رمز edge.token في شريط المصادقة أعلى الصفحة ثم اضغط تحديث.',
      };
      return;
    }
    const sequence = ++refreshSequence;
    loading = true;
    errorState = null;
    try {
      sessionStorage.setItem('bridgepulse_token', requestToken);
      const res = await fetch('/api/overview', {
        headers: { 'X-Bridge-Token': requestToken },
      });
      const data = await res.json();
      if (sequence !== refreshSequence || requestToken !== token.trim()) return;
      if (!res.ok || !data.ok) {
        errorState = {
          action: 'استعلام /api/overview',
          reason: `${data.code ?? res.status}: ${data.message ?? 'فشل غير محدد'}`,
          nextStep: data.next_action ?? 'تأكد من صحة الرمز ومن أن الطلب من نفس الأصل المحلي.',
        };
        overview = null;
        loadedToken = '';
      } else {
        overview = data as OverviewData;
        loadedToken = requestToken;
      }
    } catch (err) {
      if (sequence !== refreshSequence) return;
      errorState = {
        action: 'الاتصال بخادم Bridge المحلي',
        reason: String(err),
        nextStep: 'تأكد من تشغيل `edge-bridge serve` على 127.0.0.1 ثم أعد المحاولة.',
      };
    } finally {
      if (sequence === refreshSequence) loading = false;
    }
  }

  function invalidateAuthentication() {
    ++refreshSequence;
    ++jobSeq;
    loadedToken = '';
    overview = null;
    loading = false;
    jobLoading = false;
    jobCancellingId = null;
    jobRunId = null;
    jobChunks = [];
    jobTruncated = false;
    jobError = null;
    jobFeedback = null;
  }

  async function callJobApi(method: 'job_output' | 'job_cancel', run: { project_id: string; run_id: string }) {
    const requestToken = token.trim();
    const res = await fetch('/api/v1/call', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Bridge-Token': requestToken },
      body: JSON.stringify({ method, params: { project_id: run.project_id, job_id: run.run_id, limit: 100 } }),
    });
    const data = await res.json();
    return { res, data };
  }

  function isJobCancellable(state: string) {
    return state === 'queued' || state === 'running';
  }

  async function viewJobLog(run: { project_id: string; run_id: string }) {
    if (!isOwner) return;
    const requestToken = token.trim();
    if (!requestToken) return;
    const requestRunId = run.run_id;
    const seq = ++jobSeq;
    jobLoading = true;
    jobFeedback = null;
    jobError = null;
    jobRunId = requestRunId;
    jobChunks = [];
    jobTruncated = false;
    try {
      const { res, data } = await callJobApi('job_output', run);
      if (seq !== jobSeq) return;
      if (token.trim() !== requestToken || jobRunId !== requestRunId) return;
      if (!res.ok || !data.ok) {
        jobError = {
          action: 'عرض سجل المهمة',
          reason: `${data.code ?? res.status}: ${data.message ?? 'فشل غير محدد'}`,
          nextStep: data.next_action ?? 'تأكد من أن الرمز الحالي للمالك ثم أعد المحاولة.',
        };
        return;
      }
      const result = data.result as { chunks?: Array<{ content: string; stream: string; seq: number }>; truncated?: boolean };
      jobChunks = Array.isArray(result.chunks) ? result.chunks.slice(0, 100) : [];
      jobTruncated = result.truncated === true;
      jobFeedback = jobChunks.length === 0 ? 'لا يوجد إخراج متاح لهذه المهمة بعد.' : `تم تحميل ${jobChunks.length} مقطعًا من السجل.`;
    } catch (err) {
      if (seq !== jobSeq) return;
      if (token.trim() !== requestToken || jobRunId !== requestRunId) return;
      jobError = {
        action: 'عرض سجل المهمة',
        reason: String(err),
        nextStep: 'تأكد من تشغيل الخادم المحلي ثم أعد المحاولة.',
      };
    } finally {
      if (seq === jobSeq && token.trim() === requestToken && jobRunId === requestRunId) {
        jobLoading = false;
      }
    }
  }

  async function cancelJob(run: { project_id: string; run_id: string; state: string }) {
    if (!isOwner) return;
    if (!isJobCancellable(run.state) || jobCancellingId !== null) return;
    const requestToken = token.trim();
    if (!requestToken) return;
    const requestRunId = run.run_id;
    jobCancellingId = requestRunId;
    jobFeedback = null;
    jobError = null;
    try {
      const { res, data } = await callJobApi('job_cancel', run);
      if (token.trim() !== requestToken) return;
      if (!res.ok || !data.ok) {
        jobError = {
          action: 'إلغاء المهمة',
          reason: `${data.code ?? res.status}: ${data.message ?? 'فشل غير محدد'}`,
          nextStep: data.next_action ?? 'تأكد من أن المهمة ما زالت قابلة للإلغاء ثم أعد المحاولة.',
        };
        return;
      }
      jobFeedback = data.result?.state === 'cancelled'
        ? 'تم إلغاء المهمة.'
        : 'تم طلب إلغاء المهمة.';
      await refreshOverview();
    } catch (err) {
      if (token.trim() !== requestToken) return;
      jobError = {
        action: 'إلغاء المهمة',
        reason: String(err),
        nextStep: 'تأكد من تشغيل الخادم المحلي ثم أعد المحاولة.',
      };
    } finally {
      if (token.trim() === requestToken) {
        jobCancellingId = null;
      }
    }
  }

  function handleKeydown(e: KeyboardEvent) {
    if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) return;
    const found = navItems.find((n) => n.key === e.key);
    if (found) activeView = found.id;
  }

  onMount(() => {
    const saved = sessionStorage.getItem('bridgepulse_token');
    if (saved) {
      token = saved;
      void refreshOverview();
    }
  });
</script>

<svelte:window onkeydown={handleKeydown} />

<div class="shell">
  <aside class="sidebar" aria-label="التنقل الرئيسي">
    <div class="brand">
      <h1>BridgePulse V0.4.0</h1>
      <p>منصة تطوير وأدلة محلية بنواة Rust</p>
    </div>

    {#each navItems as item}
      <button
        class="nav-btn {activeView === item.id ? 'active' : ''}"
        onclick={() => (activeView = item.id)}
      >
        <span>{item.label}</span>
        <span class="kbd ltr">{item.key}</span>
      </button>
    {/each}

    <div style="margin-top: auto;" class="muted">
      <div>الاختصارات: مفاتيح <span class="ltr">1-7</span></div>
      <div>لا تخزّن الواجهة أسرار المزودين ولا تنفذ shell مباشرة.</div>
    </div>
  </aside>

  <main class="main">
    <header class="topbar">
      <div>
        <strong>الحالة الحقيقية:</strong>
        {#if overview}
          <span class="badge PASS ltr">{overview.principal}</span>
          <span class="muted ltr">host={overview.host_id}</span>
          {#if overview.containment?.status && !overview.containment.status.verified}
            <span class="badge BLOCKED">العزل MXC غير متحقق على هذا السطح</span>
          {/if}
        {:else}
          <span class="badge NOT_TESTED">غير متصل / بانتظار المصادقة</span>
        {/if}
      </div>

      <div class="auth-bar">
        <input
          class="input ltr"
          type="password"
          placeholder="X-Bridge-Token (owner / edge)"
          bind:value={token}
          oninput={invalidateAuthentication}
          aria-label="رمز المصادقة المحلي"
        />
        <button class="btn" onclick={refreshOverview} disabled={loading}>
          {loading ? 'جاري التحديث...' : 'تحديث'}
        </button>
      </div>
    </header>

    {#if errorState}
      <div class="alert error" role="alert">
        <div><strong>الإجراء:</strong> {errorState.action}</div>
        <div><strong>السبب:</strong> {errorState.reason}</div>
        <div><strong>الخطوة التالية:</strong> {errorState.nextStep}</div>
      </div>
    {/if}

    {#if overview}
      {#if activeView === 'projects'}
        <div class="grid">
          <section class="card">
            <h2>المشاريع المعتمدة ({overview.projects.length})</h2>
            <table>
              <thead>
                <tr><th>المشروع</th><th>المعرّف</th><th>الصلاحيات</th><th>مراجعة السياسة</th></tr>
              </thead>
              <tbody>
                {#each overview.projects as p}
                  <tr>
                    <td>{p.display_name}</td>
                    <td class="ltr">{p.project_id}</td>
                    <td class="ltr">{p.capabilities.join(', ')}</td>
                    <td class="ltr">rev {p.policy_revision}</td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </section>

          <section class="card">
            <h2>الأجهزة المقترنة ({overview.paired_devices.length})</h2>
            {#if overview.paired_devices.length === 0}
              <p class="muted">لا توجد أجهزة خارجية مقترنة حاليًا. جهاز الوالد يبقى <span class="badge BLOCKED">BLOCKED</span> حتى يتم الإقران الصريح على الجهاز المستهدف.</p>
            {:else}
              <table>
                <thead><tr><th>الجهاز</th><th>المعرّف</th><th>الحالة</th><th>النطاقات</th></tr></thead>
                <tbody>
                  {#each overview.paired_devices as d}
                    <tr>
                      <td>{d.display_name}</td>
                      <td class="ltr">{d.host_id}</td>
                      <td><span class="badge {d.revoked ? 'FAIL' : 'PASS'}">{d.status}</span></td>
                      <td class="ltr">{d.approved_scopes.join(', ')}</td>
                    </tr>
                  {/each}
                </tbody>
              </table>
            {/if}
          </section>
        </div>

      {:else if activeView === 'tasks'}
        <section class="card">
          <h2>المهام والتشغيلات المستمرة ({overview.runs.length})</h2>
          <table>
            <thead>
              <tr><th>Run ID</th><th>المهمة</th><th>الحالة</th><th>نتيجة الوكيل / التنفيذ / التحقق</th><th>رمز الخروج</th><th>إجراءات</th></tr>
            </thead>
            <tbody>
              {#each overview.runs as r}
                <tr>
                  <td class="ltr">{r.run_id}</td>
                  <td class="ltr">{r.task_id}</td>
                  <td><span class="badge {r.state === 'succeeded' ? 'PASS' : r.state === 'failed' ? 'FAIL' : 'PARTIAL'} ltr">{r.state}</span></td>
                  <td class="ltr">
                    {#if r.outcome}
                      agent={r.outcome.agent_outcome} | exec={r.outcome.execution_outcome} | verify={r.outcome.verification_outcome}
                    {:else}
                      NOT_TESTED
                    {/if}
                  </td>
                  <td class="ltr">{r.exit_code ?? '-'}</td>
                  <td>
                    {#if isOwner}
                      <button class="btn" onclick={() => viewJobLog(r)} disabled={jobLoading && jobRunId === r.run_id}>{jobLoading && jobRunId === r.run_id ? 'جاري تحميل السجل...' : 'عرض السجل'}</button>
                      {#if isJobCancellable(r.state)}
                        <button class="btn" onclick={() => cancelJob(r)} disabled={jobCancellingId !== null}>{jobCancellingId === r.run_id ? 'جاري الإلغاء...' : 'إلغاء المهمة'}</button>
                      {/if}
                    {/if}
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
          {#if isOwner && jobError}
            <div class="alert error" role="alert">
              <div><strong>الإجراء:</strong> {jobError.action}</div>
              <div><strong>السبب:</strong> {jobError.reason}</div>
              <div><strong>الخطوة التالية:</strong> {jobError.nextStep}</div>
            </div>
          {/if}
          {#if isOwner && jobFeedback}
            <p class="muted" role="status">{jobFeedback}</p>
          {/if}
          {#if isOwner && jobRunId}
            <div class="card" aria-live="polite">
              <h3><span class="ltr">{jobRunId}</span> — سجل المهمة (بحد أقصى 100 مقطع)</h3>
              {#if jobLoading}
                <p class="muted">جاري تحميل السجل...</p>
              {:else if jobChunks.length === 0}
                <p class="muted">لا يوجد إخراج متاح لهذه المهمة بعد.</p>
              {:else}
                {#if jobTruncated}
                  <p class="muted">الإخراج مقتطع؛ يعرض أول 100 مقطع.</p>
                {/if}
                <div>
                  {#each jobChunks as chunk}
                    <pre class="ltr">[{chunk.stream} #{chunk.seq}] {chunk.content}</pre>
                  {/each}
                </div>
              {/if}
            </div>
          {/if}
        </section>

      {:else if activeView === 'changes'}
        <section class="card">
          <h2>التغييرات وخطط الرقع (Hash-Checked Patch Plans)</h2>
          <p class="muted">كل تعديل يمر عبر فحص preimage SHA-256 وسجل استرداد journal، ويرفض التراجع الكتابة فوق تعديلات المستخدم اللاحقة.</p>
          <p class="muted">استخدم <span class="ltr">edge-bridge apply-patch</span> أو <span class="ltr">edge_bridge.cli apply-patch-plan</span> مع مسار ملف الخطة الفعلي.</p>
        </section>

      {:else if activeView === 'tests'}
        <section class="card">
          <h2>نتائج الاختبارات الحقيقية ({overview.evidence_manifests.length})</h2>
          <table>
            <thead>
              <tr><th>الحكم</th><th>الفئة</th><th>المحلل</th><th>مكتشف / منفذ / ناجح / فاشل / متخطى</th><th>المدة</th></tr>
            </thead>
            <tbody>
              {#each overview.evidence_manifests as ev}
                <tr>
                  <td><span class="badge {ev.conclusions.overall_verdict} ltr">{ev.conclusions.overall_verdict}</span></td>
                  <td class="ltr">{ev.identity.evidence_class}</td>
                  <td class="ltr">{ev.tests.parser_name}</td>
                  <td class="ltr">{ev.tests.discovered} / {ev.tests.executed} / {ev.tests.passed} / {ev.tests.failed} / {ev.tests.skipped}</td>
                  <td class="ltr">{ev.time.monotonic_duration_ms} ms</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </section>

      {:else if activeView === 'evidence'}
        <div class="grid">
          {#each overview.evidence_manifests as ev}
            <article class="card">
              <h3>
                <span class="badge {ev.conclusions.overall_verdict} ltr">{ev.conclusions.overall_verdict}</span>
                <span class="ltr">{ev.identity.manifest_id}</span>
              </h3>
              <div class="muted ltr">run={ev.identity.run_id} | host={ev.identity.host_id}</div>
              <div class="muted ltr">cmd: {ev.command.executable} {ev.command.argv.join(' ')}</div>
              <div class="muted ltr">sha256: {ev.manifest_sha256 ?? 'unsigned'}</div>
              <div class="muted ltr">ed25519: {ev.signature_ed25519_hex ? ev.signature_ed25519_hex.slice(0, 24) + '...' : 'unsigned'}</div>
              <p class="muted">{ev.conclusions.provenance_disclaimer}</p>
            </article>
          {/each}
        </div>

      {:else if activeView === 'diagnostics'}
        <div class="grid">
          <section class="card">
            <h2>العقود والإصدارات والذاكرة</h2>
            <pre class="ltr">{JSON.stringify({ versions: overview.versions, resources: overview.resources }, null, 2)}</pre>
          </section>
          <section class="card">
            <h2>موصلات أدوات البرمجة والعزل</h2>
            <table>
              <thead><tr><th>المزود</th><th>الإصدار</th><th>الفوترة</th><th>متاح</th><th>متحقق</th><th>السبب</th></tr></thead>
              <tbody>
                {#each overview.providers as pr}
                  <tr>
                    <td class="ltr">{pr.provider}</td>
                    <td class="ltr">{pr.detected_version ?? 'غير مثبت'}</td>
                    <td class="ltr">{pr.billing_policy}</td>
                    <td><span class="badge {pr.capability.available} ltr">{pr.capability.available}</span></td>
                    <td><span class="badge {pr.capability.verified ? 'PASS' : 'BLOCKED'}">{pr.capability.verified ? 'نعم' : 'مقيد'}</span></td>
                    <td>{pr.capability.reason}</td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </section>
        </div>

      {:else if activeView === 'approvals'}
        <section class="card">
          <h2>مظاريف التفويض المقيّدة ({overview.grants.length})</h2>
          <p class="muted">يظل اعتماد <span class="ltr">edge</span> مقتصرًا على القراءة فقط؛ أي تنفيذ مفوض يتطلب مظروف <span class="ltr">TaskGrantEnvelope</span> محدد الصلاحية والمشروع والمسارات والمدة.</p>
          <table>
            <thead><tr><th>Grant ID</th><th>الطالب</th><th>المشروع</th><th>المسارات المسموحة</th><th>الانتهاء</th><th>الحالة</th></tr></thead>
            <tbody>
              {#each overview.grants as g}
                <tr>
                  <td class="ltr">{g.grant_id}</td>
                  <td class="ltr">{g.requester_principal}</td>
                  <td class="ltr">{g.project_id}</td>
                  <td class="ltr">{g.writable_paths.join(', ')}</td>
                  <td class="ltr">{g.expires_at}</td>
                  <td><span class="badge {g.revoked ? 'FAIL' : 'PASS'}">{g.revoked ? 'ملغى' : 'نشط'}</span></td>
                </tr>
              {/each}
            </tbody>
          </table>
        </section>
      {/if}
    {/if}
  </main>
</div>
