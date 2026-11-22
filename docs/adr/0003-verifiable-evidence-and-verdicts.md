# ADR-0003: Verifiable Evidence Manifests & Truthful Verdicts

- **Status:** Accepted (V0.4.0)
- **Date:** 2026-11-19
- **Context:** Treating an agent exit or `exit_code == 0` as proof of verification hides soft-denied tool calls (e.g., AGY headless denials), zero-test runs, stale result files, and weakened test suites.
- **Decision:**
  1. Separate `agent_outcome`, `execution_outcome`, and `verification_outcome` in every `DurableJobRecord` and `EvidenceManifest`.
  2. Create process start/exit records and raw logs outside the job's writable scope, hash the test suite before and after execution, and parse machine-readable outputs (`python_unittest`, `junit_xml`, `cargo_test`, `node_test`, `playwright_json`).
  3. Enforce fail-closed verdict rules: `executed == 0` -> `NOT_TESTED` (never `PASS`), stale result file -> `STALE` (never `PASS`), unauthorized test-suite edit -> `FAIL`, soft-denied provider action -> `agent_outcome = BLOCKED`.
  4. Sign every `EvidenceManifest` with a per-device Ed25519 keypair and scan actual payload bytes for secrets before export (`scan_and_redact_secrets`), explicitly noting that SHA-256 proves byte consistency and Ed25519 proves key attribution — not physical-world calibration or host compromise absence.
  5. Classify every evidence artifact explicitly (`software_unit`, `software_integration`, `recorded_log`, `sitl`, `hitl`, `sih`, `hardware_bench`, `flight_observation`).
- **Consequences:** Every green `PASS` verdict is cryptographically and mechanically traceable to fresh, real, non-zero test execution on a named host and exact source revision.
