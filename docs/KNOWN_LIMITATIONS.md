# Canary acceptance limits

| Area | Status |
| --- | --- |
| Local HTTP multi-client workload | Covered by the 3/8/16-process benchmark and 30-minute scenario |
| HTTP ownership and recovery | Synthetic fixtures cover current grant checks, queue persistence, retransmission and explicit cancellation where the supported runner is available |
| Existing read-only connector | Uses legacy stdio. The HTTP scheduler covers the loopback HTTP entry point |
| Remote coding provider from the intended web client | BLOCKED at the provider containment and included-only proof boundary |
| Modern MCP feature coverage | Discovery, version metadata and tool calls are available. Complete contracts for all legacy tools and universal request cancellation remain open |
| Windows containment | Evidence is specific to a verified runner, job recipe, host and desktop. The owner-approved test supervisor is a distinct scope from an interactive coding worker |
| Restart reconciliation | Queued records survive; externally started operations may require reconciliation as unknown |
| Physical devices and flight | Device and telemetry parsing tests use synthetic inputs. Second-host, SITL and HITL acceptance require separate target evidence |
| Production | Promotion follows account, connector, migration, containment and rollback validation |

## Read budgets on the read-only stdio connection

Read-only tool calls run in parallel on that connection: 8 single-file reads, 4 heavy calls and 4 control calls at once. Each budget below applies to one call, so the worst case is the budget times the number of calls of that kind running together.

| Tool | Budget per call | Over the budget |
| --- | --- | --- |
| `file_read`, `file_view`, each `file_read_batch` item | 32 MiB file, 65536 characters per page | `RESOURCE_BUDGET_EXCEEDED` |
| `file_search` | 2 MiB per file | The file is skipped |
| `git_status`, `git_diff`, `git_diff_summary` | 64 MiB of output per Git process. `git_diff_summary` runs two, so it can hold up to 128 MiB | `RESOURCE_BUDGET_EXCEEDED` |
| `file_list`, `file_search`, `project_context`, `project_resume` | 200000 entries read from disk, counting directories and skipped entries | `RESOURCE_BUDGET_EXCEEDED` |
| `artifact_list`, `artifact_read`, recent evidence in `project_context` | No byte budget. A sealed evidence manifest is loaded whole | Open |

`git_diff` and `git_diff_summary` hold the diff they return a page or a digest of. `file_list` collects the walked entries before it returns one page. A streaming implementation of both is open.

## Git reads and content filters

`git_status`, `git_diff` and `git_diff_summary` are refused for a repository whose configuration sets `filter.<name>.clean`, `filter.<name>.smudge` or `filter.<name>.process`, or names another configuration file with `include.path` or `includeIf`. Git runs such a command while it compares changed files, so a read would execute a command taken from the repository. This includes a repository where Git LFS was installed with `git lfs install --local`. A filter set only in the user or system configuration is not loaded by the bridge and does not cause a refusal; files with that filter are then compared unfiltered.

`base_ref` must name a commit (a branch, a tag, a commit id, or a form such as `HEAD~1`). A tree, written as `HEAD:dir` or by its object id, is refused.

A changed file whose name the file service refuses to read is left out of `git_diff`, `git_diff_summary` and the entries of `git_status`. `git_status` still reports the repository as dirty.

Git reads do not look inside nested repositories or submodules. A change inside a submodule does not appear in `git_status` or `git_diff` of the outer repository.

## Open after the fourth review

These were reported by review and are not fixed.

| Area | What is open | Effect |
| --- | --- | --- |
| Git reads | A Git process has an output cap but no time limit | A repository that makes Git wait (for example an unreachable object store) holds one of the four heavy read slots until the connection ends |
| Git reads | Git still reads the repository's own attributes, exclude files and object alternates | A hostile repository can make Git open files outside the approved root. No content from them is returned by the tools reviewed |
| Git reads | `base_ref` accepts any commit Git can resolve, including stash, reflog and unreachable commits | A reviewer can diff against content that was removed from the published history, except for paths the file service refuses |
| Queue worker | The manifest records that the sandbox launcher started, not that the test or script process inside it started | A launcher that exits before it creates the payload is recorded as a workload that ran and produced no result |
| Queue worker | The workspace size scan checks for links by path and then opens by path | Not shown to be reachable: creating a junction inside the sandbox was denied in testing. If a workload could create one between the two steps, the scan would read outside the workspace |
| Evidence | A task id or artifact path chosen by the owner is returned to remote readers as stored, without the secret scan | An owner who names a run after a credential exposes that name to `edge` |
| Delegated writes | `file_patch` checks the 64-edit limit after authorizing each edit | A delegate whose grant includes patch rights (not the `pro-review` profile) can make the server do a few thousand grant lookups in one call |
| Queue worker | The workspace limit is a sample, not a quota; queue length per grant, CPU share and retention of stored output have no bound. `grant.limits.max_cpu_percent` is stored on the grant and shown by `policy_view` but is not applied by the worker (only `0` is refused with `INVALID_GRANT_LIMITS`); `max_duration_seconds`, `max_memory_mb`, `max_processes`, `max_output_bytes` and `max_storage_bytes` are applied as `min(recipe_cap, grant_limit)` | See `docs/REMOTE_EXECUTOR.md` |
| Queue worker | A run can read the persistent environment in the registry (`HKCU\Environment` and the machine environment key), although its own process environment is cleared. Measured on Windows 11 build 26300.9974 with the pinned `codex.exe` 0.171.0 sandbox and with `mxc-sdk` 1.1.0; neither offers a setting that closes it | Project code that reads those keys and prints them returns the values in `job_output`, apart from what the secret scan recognises. The worker therefore refuses every delegated run with `PERSISTENT_ENVIRONMENT_HOLDS_CREDENTIALS` while an entry in either key looks like a credential, by a word in its name (`KEY`, `TOKEN`, `SECRET`, `PASSWORD`, `AUTH`, `PAT` and similar) or by a value the secret scan recognises. `edge-bridge environment-check` lists the names for the owner. An entry whose value is not text or is longer than 1 MiB counts as well, and a key that cannot be read, or that changes while it is read, stops the run with `PERSISTENT_ENVIRONMENT_UNREADABLE`. The check is a guess from names and values: a credential under a plain name with a value the scan does not know passes it, other registry keys are not checked, and it is made once when the worker takes the request, so a variable added after that is not seen. `worker --allow-environment-credentials` turns the check off |
| Queue worker | `python_tests` passes over a folder whose project-relative path is not valid for the bridge: longer than 768 bytes, or with a component that ends in a dot or space or is a reserved device name | Tests below such a folder are not run and the run does not say so. The copy step already limits source paths to 180 characters |
| Queue worker | Delegated queued runs are refused when the state directory holds more than one project | One bridge instance cannot offer a reviewer test runs on several projects. Each needs its own state directory, worker and connection, until inputs are approved by content instead of by folder |
| Queue worker | A state directory knows only its own grants | Two instances that register the same files, directly, nested or through another name, do not see each other's grants. A file a reviewer wrote through one can run in the other. Keep the project folders of separate instances apart |
| Queue worker | Files are kept out of a run by folder (every folder a grant for the project has made writable), not by who wrote them | A file a reviewer wrote that the owner later moves elsewhere in the project can run. An owner file placed in such a folder cannot |
| Queue worker | Delegated `python_tests` discovery skips credential-style files and folders (the paths hidden from remote principals) without reporting it | A test that needs such a file fails inside the run because the file is absent |
