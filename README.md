# ChatGPT Local MCP (Edge Project Bridge)

[English](#english) | [العربية](#العربية)

## English

ChatGPT Local MCP connects ChatGPT web, or any MCP client, to one project folder on your Windows PC. The model works like a coding agent: it reads your project, works on a copy of it, runs tests in a sandbox, and hands you a diff. It cannot change, move or delete your project files. You apply the diff yourself with one command.

### What the model can and cannot do

| The model can | The model cannot |
| --- | --- |
| Read the project files and the Git status and diff | Change, move, rename or delete a project file |
| Copy files into its own work area, `_pro\work\<workspace>\`, and edit them there | Write anywhere outside `_pro\` |
| Run the project's tests in a sandbox, as background jobs | Read credential-style files (`.env`, keys, `.git\config` and similar) |
| Write a diff to `_pro\outbox\` and a report to `_pro\reports\` | Reach the network or other folders from inside the sandbox |
| Read requests that you leave in `_pro\inbox\` | Write to `_pro\inbox\` |

### What you need

| For | You need |
| --- | --- |
| Install, read, copy, edit, diff | Windows 10 or 11 (x64) and [PowerShell 7](https://learn.microsoft.com/powershell/scripting/install/installing-powershell-on-windows) |
| Git tools | Git for Windows |
| Test runs | `uv`, Python 3.13, PowerShell `7.6.10` x64 (MSI install) and `@openai/codex@0.171.0`. The installer lists what is missing and does not stop. |
| ChatGPT web | An OpenAI Platform organization with Tunnels access, and OpenAI's `tunnel-client` |

### Install

Open **PowerShell 7** and run this block. It downloads `install.ps1` and `SHA256SUMS.txt`, compares the SHA-256 hash, stops if they differ, and then runs the installer:

```powershell
$ErrorActionPreference = 'Stop'
$version = '0.6.0-pre3'
$base = "https://github.com/u2n4/chatgpt-local-mcp/releases/download/v$version"
Invoke-WebRequest -Uri "$base/install.ps1" -OutFile '.\install.ps1'
Invoke-WebRequest -Uri "$base/SHA256SUMS.txt" -OutFile '.\SHA256SUMS.txt'
$lines = @(Get-Content -LiteralPath '.\SHA256SUMS.txt' | Where-Object { $_ -match '^[0-9a-fA-F]{64}\s+\*?install\.ps1$' })
if ($lines.Count -ne 1) { throw 'Expected one install.ps1 entry in SHA256SUMS.txt' }
$expected = ($lines[0] -split '\s+')[0].ToLowerInvariant()
$actual = (Get-FileHash -LiteralPath '.\install.ps1' -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $expected) { throw "SHA-256 mismatch for install.ps1: expected $expected, got $actual" }
pwsh -ExecutionPolicy Bypass -File .\install.ps1 -Version $version
```

The installer asks two questions: where to install, and which project folder to work on. It shows both paths and asks `y/N` before it writes anything. It installs only into a new or empty folder. It does not change `PATH`, the registry or the execution policy, and it installs no other software.

### First use

Open PowerShell 7 in the install folder and run:

```powershell
.\start.ps1
```

`start.ps1` runs the environment check (stopping if persistent environment variables look like credentials), creates a 4-hour `pro-agent` grant (override with `-Profile pro-review` or `-Minutes <1..1440>`), prints the grant id and expiry, and starts the local worker in the same window. If the worker runtime is not built yet, it still creates the grant (reading, copying, editing and diffing work without the worker) and tells you to run `.\setup-worker.ps1` after installing missing test-run prerequisites.

Run `.\status.ps1` at any time to see the binary version, project path and id, worker status, missing prerequisites, and `_pro\` workspaces and outputs. Individual helpers (`environment-check.ps1`, `new-grant.ps1`, `setup-worker.ps1`, `start-worker.ps1`) are also in the install folder; see [docs/INSTALL.md](docs/INSTALL.md).

### Connect an MCP client that starts a local program

For a client such as Claude Code or Codex CLI, add a stdio MCP server with the values the installer printed:

| Field | Value |
| --- | --- |
| Program | `<InstallDir>\bin\edge-bridge.exe` |
| Arguments | `--state-dir=<InstallDir>\state` `mcp` `--principal=executor:default` |

### Connect ChatGPT web

ChatGPT web cannot start a program on your PC. It reaches the bridge through OpenAI's `tunnel-client` (tested with `tunnel-client` 0.0.21 on one PC). After installing `tunnel-client`, run from the install folder:

1. Create a tunnel at <https://platform.openai.com/settings/organization/tunnels> and a runtime API key at <https://platform.openai.com/settings/organization/api-keys>.
2. Configure and check the tunnel profile (prompts for the tunnel id and hidden runtime API key, stores the key in `<InstallDir>\state\tunnel-runtime.key` without putting it on the command line, and runs `tunnel-client doctor`):

   ```powershell
   .\setup-tunnel.ps1
   ```

   If `tunnel-client` is not on `PATH`, pass `-TunnelClientPath <path-to-tunnel-client.exe>`.
3. Start the tunnel in a second PowerShell 7 window and leave it open:

   ```powershell
   .\start-tunnel.ps1
   ```

4. While the tunnel is running, open <https://chatgpt.com/#settings/Connectors>, add the tunnel as a connector, and refresh it. The connector must show 46 tools.

### Give the model a job

With a `pro-agent` grant, a prompt like this is enough:

```text
Use the connector. Call project_list, then policy_view. Work alone until done:
copy what you need into a workspace named "fix1", make the change with work_edit,
run the tests, repeat until they pass, then work_export_diff to _pro/outbox/fix1.diff
and write a short report to _pro/reports/fix1.md.
```

When it finishes, preview and apply the change from the install folder:

```powershell
.\apply.ps1 fix1
```

`apply.ps1` runs a dry-run preview of what would change, asks `y/N`, and applies all files or none. It refuses when a project file changed after the model copied it, and prints the `journal_id` and exact rollback command:

```powershell
.\rollback.ps1 <journal_id>
```

### Limits you should know

- A run lasts at most 60 seconds, and only standard-library `unittest` runs. A project that needs `pytest`, `numpy` or other packages cannot be tested yet.
- A test run works on a snapshot of at most 128 files, 256 KiB per file and 4 MiB in total. A larger project is refused with `RESOURCE_BUDGET_EXCEEDED`, and the refusal names the limit and the measured value. The tests folder needs no `__init__.py`.
- The model cannot test its own change by default. `.\start.ps1 -AllowWorkExec` (which prints a warning and asks `y/N` first) or `.\start-worker.ps1 --allow-work-exec` turns that on. Code written by the model then runs in the sandbox on your PC. Measured on one PC: no network and no folder outside the copy, but the code can read your user name, profile paths and the registry keys `HKCU\Software`, `HKLM\Software` and `HKCU\Environment`. Turn it on only when you accept that.
- Test runs need the exact pinned builds of PowerShell `7.6.10` and `@openai/codex@0.171.0`. The Codex package is used only as the sandbox engine; it needs no OpenAI account and no model. If either build updates, test runs fail until the pins are updated.
- This is a prerelease, tested on one PC. `SHA256SUMS.txt` from the same release detects a damaged download only; it does not prove who published the release.

### More

- [Full installation guide](docs/INSTALL.md): unattended install, uninstall, troubleshooting
- [What a remote model can do, tool by tool](docs/TOOL_CAPABILITIES.md)
- [Remote executor and grants](docs/REMOTE_EXECUTOR.md)
- [Known limitations](docs/KNOWN_LIMITATIONS.md)
- [Security boundaries and test references](SECURITY_BOUNDARIES.md)
- [Build, run and test from source](docs/BUILD_AND_TEST.md)
- [Rust design decisions](docs/adr/0001-rust-core-and-incremental-migration.md), [legacy Python architecture](docs/ARCHITECTURE.md), [source export scope](docs/RELEASE_SCOPE.md)

For contributors: the bridge is a Windows-local MCP broker with three connection identities. `edge` reads owner-approved projects and nothing else. `local` is the owner. `executor` holds a separate credential and a project grant. The Rust HTTP listener binds to `127.0.0.1`. Legacy stdio and modern HTTP MCP use separate entry points and expose 46 tools. `task_submit` returns a durable background run; collect it with `job_wait`, or query it with `job_get` and the returned `run_id`.

## العربية

ChatGPT Local MCP يربط ChatGPT web، أو أي MCP client، بمجلد مشروع واحد على جهازك (Windows). الـ model يشتغل مثل coding agent: يقرأ مشروعك، يشتغل على نسخة منه، يشغّل الاختبارات داخل sandbox، ويعطيك diff. لا يقدر يعدّل أو ينقل أو يحذف ملفات مشروعك. أنت تطبّق الـ diff بأمر واحد.

### ماذا يقدر الـ model وماذا لا يقدر

| يقدر | لا يقدر |
| --- | --- |
| يقرأ ملفات المشروع وحالة Git والـ diff | يعدّل أو ينقل أو يعيد تسمية أو يحذف ملفًا من المشروع |
| ينسخ ملفات إلى منطقة عمله `_pro\work\<workspace>\` ويعدّلها هناك | يكتب في أي مكان خارج `_pro\` |
| يشغّل اختبارات المشروع داخل sandbox كمهام في الخلفية | يقرأ ملفات الأسرار (`.env`، المفاتيح، `.git\config` وما يشبهها) |
| يكتب diff في `_pro\outbox\` وتقريرًا في `_pro\reports\` | يصل إلى الشبكة أو إلى مجلدات أخرى من داخل الـ sandbox |
| يقرأ الطلبات التي تتركها له في `_pro\inbox\` | يكتب في `_pro\inbox\` |

### ما تحتاجه

| من أجل | تحتاج |
| --- | --- |
| التثبيت، القراءة، النسخ، التعديل، الـ diff | Windows 10 أو 11 (x64) و [PowerShell 7](https://learn.microsoft.com/powershell/scripting/install/installing-powershell-on-windows) |
| أدوات Git | Git for Windows |
| تشغيل الاختبارات | `uv` و Python 3.13 و PowerShell `7.6.10` x64 (تثبيت MSI) و `@openai/codex@0.171.0`. المثبّت يذكر الناقص ولا يتوقف. |
| ChatGPT web | حساب OpenAI Platform (organization) فيه صلاحية Tunnels، وبرنامج `tunnel-client` من OpenAI |

### التثبيت

افتح **PowerShell 7** وشغّل هذا المقطع. ينزّل `install.ps1` و `SHA256SUMS.txt`، يقارن تجزئة SHA-256، يتوقف إذا اختلفتا، ثم يشغّل المثبّت:

```powershell
$ErrorActionPreference = 'Stop'
$version = '0.6.0-pre3'
$base = "https://github.com/u2n4/chatgpt-local-mcp/releases/download/v$version"
Invoke-WebRequest -Uri "$base/install.ps1" -OutFile '.\install.ps1'
Invoke-WebRequest -Uri "$base/SHA256SUMS.txt" -OutFile '.\SHA256SUMS.txt'
$lines = @(Get-Content -LiteralPath '.\SHA256SUMS.txt' | Where-Object { $_ -match '^[0-9a-fA-F]{64}\s+\*?install\.ps1$' })
if ($lines.Count -ne 1) { throw 'Expected one install.ps1 entry in SHA256SUMS.txt' }
$expected = ($lines[0] -split '\s+')[0].ToLowerInvariant()
$actual = (Get-FileHash -LiteralPath '.\install.ps1' -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $expected) { throw "SHA-256 mismatch for install.ps1: expected $expected, got $actual" }
pwsh -ExecutionPolicy Bypass -File .\install.ps1 -Version $version
```

المثبّت يسأل سؤالين: أين يثبّت، وأي مجلد مشروع يشتغل عليه. يعرض المسارين ويسأل `y/N` قبل أن يكتب أي شيء. يثبّت فقط في مجلد جديد أو فارغ. لا يغيّر `PATH` ولا سجل Windows ولا سياسة التنفيذ، ولا يثبّت برامج أخرى.

### أول استخدام

افتح PowerShell 7 في مجلد التثبيت وشغّل:

```powershell
.\start.ps1
```

الأمر `start.ps1` يفحص متغيرات البيئة الدائمة (ويتوقف إذا وجد متغيرات تشبه الأسرار)، وينشئ منحة `pro-agent` صالحة 4 ساعات (تقدر تغيّرها بـ `-Profile pro-review` أو `-Minutes <1..1440>`)، ويطبع `grant_id` ووقت الانتهاء، ثم يشغّل الـ worker المحلي في النافذة نفسها. إذا لم تكن بيئة الـ worker مبنية بعد، يبقى ينشئ المنحة (القراءة والنسخ والتعديل والـ diff تشتغل بدون الـ worker) ويطلب منك تشغيل `.\setup-worker.ps1` بعد تثبيت المتطلبات الناقصة.

شغّل `.\status.ps1` في أي وقت لمعرفة إصدار البرنامج، مسار المشروع ورمزه، حالة الـ worker، المتطلبات الناقصة، ومناطق العمل والملفات داخل `_pro\`. السكربتات الفردية (`environment-check.ps1` و `new-grant.ps1` و `setup-worker.ps1` و `start-worker.ps1`) لا تزال موجودة في مجلد التثبيت؛ راجع [docs/INSTALL.md](docs/INSTALL.md).

### الربط مع MCP client يشغّل برنامجًا محليًا

مع client مثل Claude Code أو Codex CLI، أضف stdio MCP server بالقيم التي طبعها المثبّت:

| الحقل | القيمة |
| --- | --- |
| Program | `<InstallDir>\bin\edge-bridge.exe` |
| Arguments | `--state-dir=<InstallDir>\state` `mcp` `--principal=executor:default` |

### الربط مع ChatGPT web

ChatGPT web لا يقدر يشغّل برنامجًا على جهازك. يصل إلى الـ bridge عن طريق `tunnel-client` من OpenAI (جُرّب مع `tunnel-client` 0.0.21 على جهاز واحد). بعد تثبيت `tunnel-client`، نفّذ من مجلد التثبيت:

1. أنشئ tunnel من <https://platform.openai.com/settings/organization/tunnels> و runtime API key من <https://platform.openai.com/settings/organization/api-keys>.
2. جهّز الـ profile وافحصه (يسألك عن الـ tunnel id و الـ runtime API key بإدخال مخفي، يحفظ المفتاح في `<InstallDir>\state\tunnel-runtime.key` بدون وضعه على سطر الأوامر، ويشغّل `tunnel-client doctor`):

   ```powershell
   .\setup-tunnel.ps1
   ```

   إذا لم يكن `tunnel-client` في `PATH`، مرّر `-TunnelClientPath <مسار-tunnel-client.exe>`.
3. شغّل الـ tunnel في نافذة PowerShell 7 ثانية واتركها مفتوحة:

   ```powershell
   .\start-tunnel.ps1
   ```

4. بينما الـ tunnel يعمل، افتح <https://chatgpt.com/#settings/Connectors>، أضف الـ tunnel كـ connector، ثم حدّثه (Refresh). يجب أن يعرض 46 أداة.

### أعطِ الـ model مهمة

مع منحة `pro-agent` يكفي prompt مثل هذا:

```text
Use the connector. Call project_list, then policy_view. Work alone until done:
copy what you need into a workspace named "fix1", make the change with work_edit,
run the tests, repeat until they pass, then work_export_diff to _pro/outbox/fix1.diff
and write a short report to _pro/reports/fix1.md.
```

بعد أن ينتهي، راجع التغيير وطبّقه من مجلد التثبيت:

```powershell
.\apply.ps1 fix1
```

الأمر `apply.ps1` يعرض ما سيتغير أولًا (dry run)، يسأل `y/N`، ويطبّق كل الملفات أو لا شيء. يرفض إذا تغيّر ملف في المشروع بعد أن نسخه الـ model، ويطبع `journal_id` وأمر التراجع الدقيق:

```powershell
.\rollback.ps1 <journal_id>
```

### حدود لازم تعرفها

- التشغيل الواحد أقصاه 60 ثانية، ويشتغل `unittest` من المكتبة القياسية فقط. مشروع يحتاج `pytest` أو `numpy` أو مكتبات أخرى لا يُختبر حاليًا.
- تشغيل الاختبارات يعمل على لقطة (snapshot) أقصاها 128 ملفًا و256 KiB للملف و4 MiB بالمجموع. المشروع الأكبر يُرفض بالرمز `RESOURCE_BUDGET_EXCEEDED`، والرفض يذكر الحد والقيمة المقاسة. مجلد الاختبارات لا يحتاج `__init__.py`.
- الـ model لا يقدر يختبر تعديله هو افتراضيًا. الأمر `.\start.ps1 -AllowWorkExec` (يعرض تحذيرًا ويسأل `y/N` أولًا) أو `.\start-worker.ps1 --allow-work-exec` يفتح ذلك، وعندها يشتغل كود كتبه الـ model داخل الـ sandbox على جهازك. القياس على جهاز واحد: لا شبكة ولا مجلدات خارج النسخة، لكن الكود يقدر يقرأ اسم المستخدم ومسارات الـ profile ومفاتيح السجل `HKCU\Software` و `HKLM\Software` و `HKCU\Environment`. افتحه فقط إذا قبلت هذا.
- تشغيل الاختبارات يحتاج الإصدارين المثبّتين بالضبط: PowerShell `7.6.10` و `@openai/codex@0.171.0`. حزمة Codex تُستخدم كمحرك sandbox فقط؛ لا تحتاج حساب OpenAI ولا model. إذا تحدّث أحدهما تفشل الاختبارات حتى يُحدَّث التثبيت في المشروع.
- هذا إصدار تجريبي (prerelease) جُرّب على جهاز واحد. ملف `SHA256SUMS.txt` من الإصدار نفسه يكشف تلف التنزيل فقط، ولا يثبت من نشر الإصدار.

### المزيد

- [دليل التثبيت الكامل](docs/INSTALL.md): التثبيت بدون أسئلة، الإزالة، حل المشاكل
- [ماذا يقدر الـ model البعيد، أداة أداة](docs/TOOL_CAPABILITIES.md)
- [المنفّذ البعيد والمنح](docs/REMOTE_EXECUTOR.md)
- [الحدود المعروفة](docs/KNOWN_LIMITATIONS.md)
- [حدود الأمان ومراجع الاختبارات](SECURITY_BOUNDARIES.md)
- [البناء والتشغيل والاختبار من المصدر](docs/BUILD_AND_TEST.md)
- [قرارات تصميم Rust](docs/adr/0001-rust-core-and-incremental-migration.md)، [معمارية Python القديمة](docs/ARCHITECTURE.md)، [نطاق تصدير المصدر](docs/RELEASE_SCOPE.md)

للمساهمين: الـ bridge وسيط MCP محلي على Windows بثلاث هويات اتصال. `edge` يقرأ المشاريع التي وافق عليها المالك فقط. `local` هو المالك. `executor` له اعتماد مستقل ومنحة على المشروع. مستمع HTTP في Rust يرتبط بـ `127.0.0.1`. مسار stdio القديم ومسار HTTP الحديث لهما نقطتا دخول منفصلتان ويعرضان 46 أداة. `task_submit` يرجّع تشغيلًا دائمًا في الخلفية؛ اجمع نتيجته بـ `job_wait` أو استعلم عنه بـ `job_get` مع `run_id`.
