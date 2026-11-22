# Source Release Scope

The canary source includes the Rust workspace, its Python compatibility layer and legacy broker, the BridgePulse frontend source, pinned lockfiles, schemas and migrations, build and verification scripts, synthetic fixtures, and a lockfile-derived dependency summary. This checkout targets an isolated canary. Promotion requires separate evidence from the intended target.

| Area | Release handling |
| --- | --- |
| State, tokens, tunnel profiles, sessions, and private projects | Keep in their protected runtime locations |
| Old reports, evidence bundles, and benchmark measurements | Keep the originals in their local evidence directories |
| Rust binary, Python environment, and generated UI | Build from this source |
| Remote worker activation and account routing | Validate on an authorized target with independently verified isolation and included-only usage |

## Export refresh

Run `python -B scripts/source_export.py refresh <development-worktree>` from the staging tree, with the actual source root as the argument. Refresh reads Git's tracked and unignored candidate names, copies allowlisted source files, and preserves the export-specific files named in `OVERRIDES`. Reconcile any changes to those files in both trees before preparing a new publication. Use a fresh staging directory when upstream files have been deleted or renamed.

Run `manifest` again after changes. Review the exact staged Git tree, compare its paths to the manifest, and scan it with a local Gitleaks release using full redaction. The Git history exported for a new source repository can start at the reviewed snapshot.
