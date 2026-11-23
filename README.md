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
| Test runs | `uv`, Python 3.13, PowerShell `7.7.0` x64 (MSI install) and `@openai/codex@0.171.0`. The installer lists what is missing and does not stop. |
| ChatGPT web | An OpenAI Platform organization with Tunnels access, and OpenAI's `tunnel-client` |

### Install

Open **PowerShell 7** and run:

```powershell
$version = '0.6.0-pre1'
$base = "https://github.com/u2n4/chatgpt-local-mcp/releases/download/v$version"
Invoke-WebRequest -Uri "$base/install.ps1" -OutFile '.\install.ps1'
Invoke-WebRequest -Uri "$base/SHA256SUMS.txt" -OutFile '.\SHA256SUMS.txt'
```

Check that the two hashes are the same:

```powershell
(Get-FileHash -LiteralPath '.\install.ps1' -Algorithm SHA256).Hash.ToLowerInvariant()
Select-String -Path '.\SHA256SUMS.txt' -Pattern 'install\.ps1$'
```

Run the installer:

```powershell
pwsh -ExecutionPolicy Bypass -File .\install.ps1 -Version $version
```

The installer asks two questions: where to install, and which project folder to work on. It shows both paths and asks `y/N` before it writes anything. It installs only into a new or empty folder. It does not change `PATH`, the registry or the execution policy, and it installs no other software.

### First use

Open PowerShell 7 in the install folder and run the helper scripts in this order:

| Step | Command | What it does |
| --- | --- | --- |
| 1 | `.\environment-check.ps1` | Lists entries in your persistent environment that look like credentials. A test run is refused while any exist. |
| 2 | `.\new-grant.ps1 -Profile pro-agent` | Creates a grant, valid for 60 minutes, and prints its `grant_id`. Without `-Profile` the grant is `pro-review`: read, and create reports only. |
| 3 | `.\setup-worker.ps1` | Only when the installer listed missing items for test runs: run it after you install them. |
| 4 | `.\start-worker.ps1` | Starts the local worker that runs the queued tests. Leave the window open. |

### Connect an MCP client that starts a local program

For a client such as Claude Code or Codex CLI, add a stdio MCP server with the values the installer printed:

| Field | Value |
| --- | --- |
| Program | `<InstallDir>\bin\edge-bridge.exe` |
| Arguments | `--state-dir=<InstallDir>\state` `mcp` `--principal=executor:default` |

### Connect ChatGPT web

ChatGPT web cannot start a program on your PC. It reaches the bridge through OpenAI's `tunnel-client`. The installer does not set this up. These steps were tested with `tunnel-client` 0.0.21 on one PC:

1. Create a tunnel at <https://platform.openai.com/settings/organization/tunnels> and copy its tunnel id.
2. Create a runtime API key at <https://platform.openai.com/settings/organization/api-keys>.
3. Create a tunnel profile that starts the bridge (one line):

   ```powershell
   tunnel-client init --sample sample_mcp_stdio_local --profile chatgpt-local-mcp --tunnel-id <tunnel id> --mcp-command "'<InstallDir>/bin/edge-bridge.exe' --state-dir '<InstallDir>/state' mcp --principal executor:default"
   ```

4. Check the profile with `tunnel-client doctor`, then start it with `tunnel-client run`. `tunnel-client help quickstart` gives the exact options for your version.
5. In ChatGPT, open <https://chatgpt.com/#settings/Connectors>, add the tunnel as a connector, and refresh it. It must show 46 tools.

### Give the model a job

With a `pro-agent` grant, a prompt like this is enough:

```text
Use the connector. Call project_list, then policy_view. Work alone until done:
copy what you need into a workspace named "fix1", make the change with work_edit,
run the tests, repeat until they pass, then work_export_diff to _pro/outbox/fix1.diff
and write a short report to _pro/reports/fix1.md.
```

When it finishes, look at the change and apply it. The project id is in `<InstallDir>\install.json`:

```powershell
cd <InstallDir>
.\bin\edge-bridge.exe --state-dir .\state work-apply <project_id> fix1            # shows what would change
.\bin\edge-bridge.exe --state-dir .\state work-apply <project_id> fix1 --confirm  # applies it
```

`work-apply` changes all files or none. It refuses when a project file changed after the model copied it, and it prints a journal id that `rollback-patch` restores:

```powershell
.\bin\edge-bridge.exe --state-dir .\state rollback-patch --project-root <project folder> --journal-id <journal id>
```

### Limits you should know

- A run lasts at most 60 seconds, and only standard-library `unittest` runs. A project that needs `pytest`, `numpy` or other packages cannot be tested yet.
- The project's own tests run only when the project is small: at most 32 files, 64 KiB per file. Larger projects are refused with `RESOURCE_BUDGET_EXCEEDED`.
- The model cannot test its own change by default. `start-worker.ps1 --allow-work-exec` turns that on. Code written by the model then runs in the sandbox on your PC. Measured on one PC: no network and no folder outside the copy, but the code can read your user name, profile paths and the registry keys `HKCU\Software`, `HKLM\Software` and `HKCU\Environment`. Turn it on only when you accept that.
- Test runs need the exact pinned builds of PowerShell `7.7.0` and `@openai/codex@0.171.0`. The Codex package is used only as the sandbox engine; it needs no OpenAI account and no model. If either build updates, test runs fail until the pins are updated.
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
| تشغيل الاختبارات | `uv` و Python 3.13 و PowerShell `7.7.0` x64 (تثبيت MSI) و `@openai/codex@0.171.0`. المثبّت يذكر الناقص ولا يتوقف. |
| ChatGPT web | حساب OpenAI Platform (organization) فيه صلاحية Tunnels، وبرنامج `tunnel-client` من OpenAI |

### التثبيت

افتح **PowerShell 7** وشغّل:

```powershell
$version = '0.6.0-pre1'
$base = "https://github.com/u2n4/chatgpt-local-mcp/releases/download/v$version"
Invoke-WebRequest -Uri "$base/install.ps1" -OutFile '.\install.ps1'
Invoke-WebRequest -Uri "$base/SHA256SUMS.txt" -OutFile '.\SHA256SUMS.txt'
```

تأكد أن التجزئتين متطابقتان:

```powershell
(Get-FileHash -LiteralPath '.\install.ps1' -Algorithm SHA256).Hash.ToLowerInvariant()
Select-String -Path '.\SHA256SUMS.txt' -Pattern 'install\.ps1$'
```

شغّل المثبّت:

```powershell
pwsh -ExecutionPolicy Bypass -File .\install.ps1 -Version $version
```

المثبّت يسأل سؤالين: أين يثبّت، وأي مجلد مشروع يشتغل عليه. يعرض المسارين ويسأل `y/N` قبل أن يكتب أي شيء. يثبّت فقط في مجلد جديد أو فارغ. لا يغيّر `PATH` ولا سجل Windows ولا سياسة التنفيذ، ولا يثبّت برامج أخرى.

### أول استخدام

افتح PowerShell 7 في مجلد التثبيت وشغّل السكربتات المساعدة بهذا الترتيب:

| الخطوة | الأمر | ماذا يفعل |
| --- | --- | --- |
| 1 | `.\environment-check.ps1` | يعرض متغيرات البيئة الدائمة التي تشبه الأسرار. تشغيل الاختبارات يُرفض ما دامت موجودة. |
| 2 | `.\new-grant.ps1 -Profile pro-agent` | ينشئ منحة (grant) صالحة 60 دقيقة ويطبع `grant_id`. بدون `-Profile` تكون المنحة `pro-review`: قراءة وإنشاء تقارير فقط. |
| 3 | `.\setup-worker.ps1` | فقط إذا ذكر المثبّت أشياء ناقصة لتشغيل الاختبارات: شغّله بعد تثبيتها. |
| 4 | `.\start-worker.ps1` | يشغّل الـ worker المحلي الذي ينفّذ الاختبارات. اترك النافذة مفتوحة. |

### الربط مع MCP client يشغّل برنامجًا محليًا

مع client مثل Claude Code أو Codex CLI، أضف stdio MCP server بالقيم التي طبعها المثبّت:

| الحقل | القيمة |
| --- | --- |
| Program | `<InstallDir>\bin\edge-bridge.exe` |
| Arguments | `--state-dir=<InstallDir>\state` `mcp` `--principal=executor:default` |

### الربط مع ChatGPT web

ChatGPT web لا يقدر يشغّل برنامجًا على جهازك. يصل إلى الـ bridge عن طريق `tunnel-client` من OpenAI. المثبّت لا يجهّز هذا. هذه الخطوات جُرّبت مع `tunnel-client` 0.0.21 على جهاز واحد:

1. أنشئ tunnel من <https://platform.openai.com/settings/organization/tunnels> وانسخ الـ tunnel id.
2. أنشئ runtime API key من <https://platform.openai.com/settings/organization/api-keys>.
3. أنشئ profile للـ tunnel يشغّل الـ bridge (سطر واحد):

   ```powershell
   tunnel-client init --sample sample_mcp_stdio_local --profile chatgpt-local-mcp --tunnel-id <tunnel id> --mcp-command "'<InstallDir>/bin/edge-bridge.exe' --state-dir '<InstallDir>/state' mcp --principal executor:default"
   ```

4. افحص الـ profile بالأمر `tunnel-client doctor` ثم شغّله بالأمر `tunnel-client run`. الأمر `tunnel-client help quickstart` يعطيك الخيارات الدقيقة لنسختك.
5. في ChatGPT افتح <https://chatgpt.com/#settings/Connectors>، أضف الـ tunnel كـ connector، ثم حدّثه (Refresh). يجب أن يعرض 46 أداة.

### أعطِ الـ model مهمة

مع منحة `pro-agent` يكفي prompt مثل هذا:

```text
Use the connector. Call project_list, then policy_view. Work alone until done:
copy what you need into a workspace named "fix1", make the change with work_edit,
run the tests, repeat until they pass, then work_export_diff to _pro/outbox/fix1.diff
and write a short report to _pro/reports/fix1.md.
```

بعد أن ينتهي، راجع التغيير وطبّقه. الـ project id موجود في `<InstallDir>\install.json`:

```powershell
cd <InstallDir>
.\bin\edge-bridge.exe --state-dir .\state work-apply <project_id> fix1            # يعرض ما سيتغير فقط
.\bin\edge-bridge.exe --state-dir .\state work-apply <project_id> fix1 --confirm  # يطبّق
```

`work-apply` يغيّر كل الملفات أو لا شيء. يرفض إذا تغيّر ملف في المشروع بعد أن نسخه الـ model، ويطبع journal id يرجّع به `rollback-patch` كل شيء:

```powershell
.\bin\edge-bridge.exe --state-dir .\state rollback-patch --project-root <مجلد المشروع> --journal-id <journal id>
```

### حدود لازم تعرفها

- التشغيل الواحد أقصاه 60 ثانية، ويشتغل `unittest` من المكتبة القياسية فقط. مشروع يحتاج `pytest` أو `numpy` أو مكتبات أخرى لا يُختبر حاليًا.
- اختبارات المشروع نفسه تشتغل فقط إذا كان المشروع صغيرًا: 32 ملفًا كحد أقصى و64 KiB للملف. المشاريع الأكبر تُرفض بالرمز `RESOURCE_BUDGET_EXCEEDED`.
- الـ model لا يقدر يختبر تعديله هو افتراضيًا. الأمر `start-worker.ps1 --allow-work-exec` يفتح ذلك، وعندها يشتغل كود كتبه الـ model داخل الـ sandbox على جهازك. القياس على جهاز واحد: لا شبكة ولا مجلدات خارج النسخة، لكن الكود يقدر يقرأ اسم المستخدم ومسارات الـ profile ومفاتيح السجل `HKCU\Software` و `HKLM\Software` و `HKCU\Environment`. افتحه فقط إذا قبلت هذا.
- تشغيل الاختبارات يحتاج الإصدارين المثبّتين بالضبط: PowerShell `7.7.0` و `@openai/codex@0.171.0`. حزمة Codex تُستخدم كمحرك sandbox فقط؛ لا تحتاج حساب OpenAI ولا model. إذا تحدّث أحدهما تفشل الاختبارات حتى يُحدَّث التثبيت في المشروع.
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
