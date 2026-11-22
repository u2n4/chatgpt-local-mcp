# Edge Project Bridge

Edge Project Bridge is a Windows-local MCP broker for project-scoped reads, file edits, Git operations, durable jobs, and evidence. The repository contains the Rust canary, the BridgePulse Svelte/TypeScript UI, and the legacy Python bridge.

## العربية

Edge Project Bridge وسيط MCP محلي على ويندوز. يربط كل مشروع وصلاحية باتصال واضح، ويحفظ طلبات المهام ونتائجها في SQLite. تفتح BridgePulse لوحة المالك على loopback. الحالة ومفاتيح التشغيل تعتمد على مجلد حالة مستقل تختاره محليًا.

| المسار | الاستخدام | الحكم في نسخة الـCanary |
| --- | --- | --- |
| `edge` / `edge_read` | قراءة المشاريع الممنوحة للاتصال | صلاحية قراءة فقط |
| `local` | إدارة الجذور والمنح وتجارب محلية معتمدة | صلاحية مالك |
| `executor` | هوية مستقلة للتقديم ضمن منحة مشروع | قبول دائم للطلب بحسب المنحة؛ تتطلب مرحلة التشغيل تحققًا محليًا مستقلاً |
| وكيل برمجي بعيد | تنفيذ نموذج عبر موصل العميل المستهدف | يحتاج اختبار عزل العامل ومسار الاستخدام المشمول |

شغّل أول تجربة في مجلد حالة معزول ومشروع تجريبي. دليل البناء فيه أوامر Rust وBridgePulse واختبار عملاء MCP. ملفات الاختبار والأمثلة الاصطناعية موجودة في المستودع. [دليل البناء والاختبار](docs/BUILD_AND_TEST.md)

### التثبيت

يُثبَّت Edge Project Bridge على ويندوز من إصدار GitHub باستخدام PowerShell 7 في ثلاث خطوات (نزّل `install.ps1` و`SHA256SUMS.txt`، تحقّق من تجزئة SHA-256 للملف `install.ps1`، ثم فكّ حظره عند تنزيله بالمتصفح عبر `Unblock-File -LiteralPath .\install.ps1` وشغّله عبر `pwsh -ExecutionPolicy Bypass -File .\install.ps1 -Version '<VERSION>'`).

- **مستويان للتثبيت:** يُثبَّت المستوى الأساسي دائمًا (يقرأ النموذج البعيد المشروع وينشئ ملفات جديدة تحت `_pro\` فقط، ولا يكتب تحت `_pro\inbox\` أبدًا، ولا يستطيع تعديل أو نقل أو حذف أي ملف موجود في المشروع) ويحتاج PowerShell 7 فقط (وGit اختياريًا لأدوات قراءة Git). وتحتاج تشغيلات الاختبارات أيضًا `uv` وPython 3.13 والإصدارين المثبّتين أدناه؛ إن نقص شيء يذكره المثبّت ولا يتوقف، وبعد تثبيته افتح نافذة PowerShell 7 جديدة وشغّل `setup-worker.ps1`.
- **تنبيه الإصدارات المثبّتة:** يتحقّق العامل من تجزئة SHA-256 لإصدار PowerShell `7.7.0` x64 المثبّت بملف MSI في `%ProgramFiles%\PowerShell\7\pwsh.exe` وإصدار `@openai/codex@0.171.0`؛ أي تحديث تلقائي لأحدهما إلى بناء أحدث يجعل تشغيلات الاختبارات تفشل حتى يُحدَّث التثبيت في المنتج (ولا يتأثر المستوى الأساسي).
- **حدود التحقّق والضمانات:** ملف `SHA256SUMS.txt` من الإصدار نفسه يكشف تلف التنزيل أو استبداله فقط ولا يحمي من اختراق الإصدار أو الحساب؛ للثقة بالسكربت قارن تجزئته بقيمة من قناة أخرى أو اقرأه قبل تشغيله. المعامل `-Sha256` يتحقّق من ملف الأرشيف `.zip` فقط لا من `install.ps1`، واستخدام `-ZipPath` يتخطّى تنزيل الأرشيف فقط بينما يظل `uv sync` ينزّل حزم Python من PyPI ما لم تكن مخبّأة محليًا. يتطلّب المثبّت مجلدًا جديدًا أو فارغًا ولا يستبدل تثبيتًا قائمًا (لإصدار أحدث أو مشروع ثانٍ استخدم مجلدًا آخر)، ولا يعدّل `PATH` أو سجل ويندوز أو سياسة التنفيذ، ولا يثبّت برامج نيابةً عنك، ولا يُعِدّ نفقًا أو موصّل ChatGPT web.

[دليل التثبيت الكامل](docs/INSTALL.md)

## English

| Principal | Scope | Canary behavior |
| --- | --- | --- |
| `edge` | Owner-approved project reads | Read only |
| `local` | Owner administration and controlled local operations | Owner credential |
| `executor` | Separate credential and a project grant | Durable submission within the grant; runtime approval remains separate |
| Remote coding provider | End-to-end execution through a target connector | Requires verified worker isolation and an included-only provider route |

The Rust HTTP listener binds to `127.0.0.1`. Legacy stdio and modern HTTP MCP use separate entry points. A successful `task_submit` receipt identifies a durable run. Query its state using the returned `run_id`.

### Install

Install Edge Project Bridge on Windows from a GitHub Release using PowerShell 7 in three steps (download `install.ps1` and `SHA256SUMS.txt`, verify the SHA-256 hash of `install.ps1`, then unblock it if downloaded in a browser with `Unblock-File -LiteralPath .\install.ps1` and run `pwsh -ExecutionPolicy Bypass -File .\install.ps1 -Version '<VERSION>'`).

- **Two install levels:** The core level is always installed (the remote model reads the project and creates new files only under `_pro\`, never under `_pro\inbox\`, and cannot change, move, or delete any existing project file) and needs only PowerShell 7 (plus Git optionally for Git read tools). Test runs also need `uv`, Python 3.13, and the two pinned builds below; if anything is missing, the installer lists it and does not stop—after installing it, open a new PowerShell 7 window and run `setup-worker.ps1`.
- **Pinned-build warning:** The worker verifies the exact SHA-256 hash of PowerShell `7.7.0` x64 installed via MSI at `%ProgramFiles%\PowerShell\7\pwsh.exe` and `@openai/codex@0.171.0`; if either auto-updates to a newer build, test runs fail until the pins in Edge Project Bridge are updated (the core level is unaffected).
- **Verification limits and boundaries:** `SHA256SUMS.txt` from the same release only detects a corrupted or swapped download and does not protect against a compromised release or account; to trust the script, compare its hash with another channel or read it first. `-Sha256` checks the release `.zip` only, not `install.ps1`, and `-ZipPath` skips downloading the archive only (`uv sync` still downloads Python packages from PyPI unless already cached). The installer requires a new or empty folder and never replaces an existing install (use another folder for a newer version or a second project); it does not change `PATH`, the registry, or execution policy, does not install software for you, and does not set up a tunnel or ChatGPT web connector.

[Full installation guide](docs/INSTALL.md)

- [Build, run and test](docs/BUILD_AND_TEST.md)
- [Source export scope and canary limitations](docs/RELEASE_SCOPE.md)
- [Rust design decisions](docs/adr/0001-rust-core-and-incremental-migration.md)
- [Legacy Python architecture](docs/ARCHITECTURE.md)
- [Security boundaries and test references](SECURITY_BOUNDARIES.md)
