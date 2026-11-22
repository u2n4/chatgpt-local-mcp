//! Verifiable test evidence engine (§12):
//! - Per-device Ed25519 signing & verification with explicit provenance disclaimers.
//! - Content-level secret scanner & redactor (never trusts `redacted: true` blindly).
//! - Real machine-readable parsers for Python unittest, JUnit XML, Cargo test, Node test, Playwright JSON.
//! - Strict truthfulness verdicts: zero tests, missing reports, or stale reports NEVER become PASS.

use bridge_platform::sha256_bytes;
use bridge_types::*;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use quick_xml::Reader;
use quick_xml::events::Event;
use rand::rngs::OsRng;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::sync::OnceLock;

use crate::files::ScopedFiles;

pub const DELEGATED_WORKLOAD_REPORT_EXECUTOR: &str = "local-owner-mxc-queue-worker";
pub const DELEGATED_WORKLOAD_REPORT_NOTE: &str =
    "The exit code and parsed test counts are reported by the workload. The signature authenticates the capture, and the device makes no independent test verdict.";

pub const PROVENANCE_DISCLAIMER: &str =
    "SHA-256 proves byte consistency and Ed25519 signatures establish attribution to the signing device key; neither proves physical-world calibration or an uncompromised host by itself.";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretScanReport {
    pub clean: bool,
    pub findings_count: usize,
    pub finding_categories: Vec<String>,
    pub redacted_text: String,
}

fn secret_patterns() -> &'static Vec<(&'static str, Regex)> {
    static PATTERNS: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        vec![
            ("pem_private_key", Regex::new(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----").unwrap()),
            ("openai_or_sk_key", Regex::new(r"\bsk-[A-Za-z0-9_-]{20,}\b").unwrap()),
            ("github_pat", Regex::new(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b").unwrap()),
            ("aws_access_key", Regex::new(r"\bAKIA[0-9A-Z]{16}\b").unwrap()),
            ("bearer_token", Regex::new(r"(?i)Bearer\s+[A-Za-z0-9._\-]{20,}").unwrap()),
            ("jwt_token", Regex::new(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b").unwrap()),
            ("inline_secret_kv", Regex::new(r"(?i)\b(?:api_key|secret_key|password|passwd|private_key|control_plane_api_key|access_token)\s*[:=]\s*['\x22]?[A-Za-z0-9_\-./+]{8,}['\x22]?").unwrap()),
            ("email_address", Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b").unwrap()),
        ]
    })
}

/// Names of environment entries that look like credentials. An entry counts when its name
/// holds one of a few words (`API_KEY`, `GithubToken`, `DB_PASSWORD`, `MY_PAT`), when the secret
/// scanner recognises its value, or when its value could not be read as text (`None`), since
/// nothing can then be said about it. An entry with an empty value is not counted, and an email
/// address alone is not a credential. The names are for the owner, not for a remote reader.
pub fn credential_like_environment_names(entries: &[(String, Option<String>)]) -> Vec<String> {
    const WORDS: [&str; 12] = ["KEY", "APIKEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "PWD", "CREDENTIAL",
        "CREDENTIALS", "AUTH", "PAT", "COOKIE"];
    const ANYWHERE: [&str; 6] = ["TOKEN", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL", "APIKEY"];
    let mut names: Vec<String> = entries.iter().filter(|(name, value)| {
        let Some(value) = value else { return true };
        let upper = name.to_ascii_uppercase();
        !value.trim().is_empty() && (upper.split(|c: char| !c.is_ascii_alphanumeric()).any(|word| WORDS.contains(&word))
            || WORDS.iter().any(|word| upper.ends_with(word))
            || ANYWHERE.iter().any(|word| upper.contains(word))
            || scan_and_redact_secrets(value).finding_categories.iter().any(|category| category != "email_address"))
    }).map(|(name, _)| name.clone()).collect();
    names.sort();
    names.dedup();
    names
}

/// Content-level secret scanner & redactor: scans actual payload text before any export.
pub fn scan_and_redact_secrets(input: &str) -> SecretScanReport {
    let mut out = input.to_string();
    let mut categories = Vec::new();
    let mut count = 0usize;

    for (cat, re) in secret_patterns() {
        let hits = re.find_iter(&out).count();
        if hits > 0 {
            count += hits;
            categories.push((*cat).to_string());
            out = re
                .replace_all(&out, format!("[REDACTED:{cat}]"))
                .into_owned();
        }
    }
    SecretScanReport {
        clean: count == 0,
        findings_count: count,
        finding_categories: categories,
        redacted_text: out,
    }
}

/// Sanitize arbitrary log strings before embedding into Markdown/HTML reports to prevent active content injection.
pub fn sanitize_report_text(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace("javascript:", "[blocked-scheme]:")
}

/// Load or generate a protected per-device Ed25519 signing keypair inside the state directory.
pub fn load_or_create_device_signing_key(state_dir: &Path) -> Result<(SigningKey, String), BridgeError> {
    let key_file = state_dir.join("device-signing-ed25519.key");
    if key_file.is_file() {
        let hex_str = fs::read_to_string(&key_file).map_err(|e| {
            BridgeError::new(ErrorCode::StateAclUnsafe, format!("Read device key failed: {e}"), OriginLayer::Evidence)
        })?;
        let bytes = hex::decode(hex_str.trim()).map_err(|e| {
            BridgeError::new(ErrorCode::InternalError, format!("Corrupt device key hex: {e}"), OriginLayer::Evidence)
        })?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| {
            BridgeError::new(ErrorCode::InternalError, "Device key must be 32 bytes.", OriginLayer::Evidence)
        })?;
        let sk = SigningKey::from_bytes(&arr);
        let pk_hex = hex::encode(sk.verifying_key().to_bytes());
        return Ok((sk, pk_hex));
    }
    fs::create_dir_all(state_dir).map_err(|e| {
        BridgeError::new(ErrorCode::StateAclUnsafe, format!("Cannot create state dir: {e}"), OriginLayer::Evidence)
    })?;
    let mut csprng = OsRng;
    let sk = SigningKey::generate(&mut csprng);
    fs::write(&key_file, hex::encode(sk.to_bytes())).map_err(|e| {
        BridgeError::new(ErrorCode::StateAclUnsafe, format!("Write device key failed: {e}"), OriginLayer::Evidence)
    })?;
    let pk_hex = hex::encode(sk.verifying_key().to_bytes());
    Ok((sk, pk_hex))
}

/// Canonical manifest payload bytes (with signature fields cleared) for deterministic hashing & Ed25519 signing.
fn canonical_manifest_bytes(manifest: &EvidenceManifest) -> Vec<u8> {
    let mut copy = manifest.clone();
    copy.manifest_sha256 = None;
    copy.signature_ed25519_hex = None;
    copy.signer_public_key_hex = None;
    serde_json::to_vec(&copy).expect("manifest serializable")
}

pub fn seal_and_sign_manifest(manifest: &mut EvidenceManifest, signing_key: &SigningKey) {
    let canonical = canonical_manifest_bytes(manifest);
    let digest = sha256_bytes(&canonical);
    let sig: Signature = signing_key.sign(&canonical);
    manifest.manifest_sha256 = Some(digest);
    manifest.signature_ed25519_hex = Some(hex::encode(sig.to_bytes()));
    manifest.signer_public_key_hex = Some(hex::encode(signing_key.verifying_key().to_bytes()));
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceVerificationReport {
    pub manifest_id: String,
    pub overall_verified: bool,
    /// 1. Cryptographic Ed25519 signature valid against the manifest's embedded key & canonical SHA-256.
    pub signature_cryptographically_valid: bool,
    /// 2. Embedded signing key matches an explicitly supplied trusted device public key (blocks rogue key substitution!).
    pub device_key_trusted: bool,
    /// 3. Referenced artifacts match their digests and sizes. None means inspection was not performed.
    pub artifacts_hashes_verified: Option<bool>,
    /// 4. Manifest includes all required fields, provenance disclaimer, and non-empty command/time/environment metadata.
    pub manifest_complete: bool,
    /// 5. Recorded `overall_verdict` matches recomputed truthful verdict (never PASS on 0 tests, stale, failed, or tampered suite).
    pub tests_verdict_truthful: bool,
    pub reported_verdict: Verdict,
    pub recomputed_verdict: Verdict,
    pub failures: Vec<String>,
}

/// Strictly separated 5-dimension evidence verification (§7 of Audit).
pub fn verify_evidence_full(
    manifest: &EvidenceManifest,
    expected_trusted_pubkey_hex: Option<&str>,
    artifacts_dir: Option<&Path>,
) -> Result<EvidenceVerificationReport, BridgeError> {
    let mut failures = Vec::new();
    let sig_valid = verify_manifest_signature(manifest).unwrap_or(false);
    if !sig_valid {
        failures.push("Manifest SHA-256 digest or Ed25519 signature verification failed.".into());
    }

    let device_key_trusted = match (expected_trusted_pubkey_hex, manifest.signer_public_key_hex.as_deref()) {
        (Some(expected), Some(actual)) => {
            let ok = expected.eq_ignore_ascii_case(actual);
            if !ok {
                failures.push(format!(
                    "Untrusted signer key substitution detected: expected device key '{expected}', manifest signed by '{actual}'."
                ));
            }
            ok
        }
        (Some(_), None) => {
            failures.push("Manifest is unsigned (missing signer_public_key_hex).".into());
            false
        }
        (None, _) => {
            failures.push("No trusted device public key provided; cryptographic signature alone does not establish device trust.".into());
            false
        }
    };

    let artifacts_hashes_verified = match artifacts_dir {
        Some(_) if !sig_valid || !device_key_trusted => {
            failures.push("Artifact inspection skipped because the manifest signature or signing key is untrusted.".into());
            None
        }
        Some(base_dir) => Some(verify_artifacts(base_dir, &manifest.artifacts, &mut failures)),
        None => None,
    };

    let manifest_complete = !manifest.identity.run_id.0.is_empty()
        && !manifest.identity.host_id.0.is_empty()
        && !manifest.command.executable.is_empty()
        && !manifest.environment.host_name.is_empty()
        && !manifest.source.source_hash_before.is_empty()
        && !manifest.source.source_hash_after.is_empty()
        && !manifest.conclusions.provenance_disclaimer.is_empty();
    if !manifest_complete {
        failures.push("Manifest is missing required identity, source, command, environment, or provenance fields.".into());
    }

    let recomputed = if manifest.authorization.executor_identity == DELEGATED_WORKLOAD_REPORT_EXECUTOR {
        delegated_workload_verdict(manifest.execution.timed_out, manifest.execution.cancelled)
    } else {
        compute_verification_verdict(
            &manifest.tests,
            manifest.execution.exit_code,
            manifest.execution.timed_out,
            manifest.execution.cancelled,
            manifest.execution.policy_denied,
            manifest.source.test_suite_modified,
        )
    };
    let tests_verdict_truthful = manifest.conclusions.overall_verdict == recomputed
        && !(manifest.conclusions.overall_verdict == Verdict::Pass
            && (manifest.tests.executed == 0
                || !manifest.tests.fresh_for_run
                || manifest.tests.failed > 0
                || manifest.source.test_suite_modified));
    if !tests_verdict_truthful {
        failures.push(format!(
            "Reported verdict '{:?}' conflicts with recomputed truthful verdict '{:?}'.",
            manifest.conclusions.overall_verdict, recomputed
        ));
    }

    let overall = sig_valid
        && device_key_trusted
        && artifacts_hashes_verified.unwrap_or(true)
        && manifest_complete
        && tests_verdict_truthful;

    Ok(EvidenceVerificationReport {
        manifest_id: manifest.identity.manifest_id.0.clone(),
        overall_verified: overall,
        signature_cryptographically_valid: sig_valid,
        device_key_trusted,
        artifacts_hashes_verified,
        manifest_complete,
        tests_verdict_truthful,
        reported_verdict: manifest.conclusions.overall_verdict,
        recomputed_verdict: recomputed,
        failures,
    })
}

fn verify_artifacts(base_dir: &Path, artifacts: &[SealedArtifactRef], failures: &mut Vec<String>) -> bool {
    if artifacts.is_empty() {
        failures.push("Manifest references zero artifacts.".into());
        return false;
    }
    let scope = (|| -> Result<ScopedFiles, BridgeError> {
        let base = std::path::absolute(base_dir).map_err(|error| BridgeError::new(
            ErrorCode::InvalidArgument, format!("Invalid artifact directory: {error}"), OriginLayer::Evidence,
        ))?;
        let identity = ScopedFiles::new(&base, None)?.current_root_identity()?;
        ScopedFiles::new(base, Some(identity))
    })();
    let Ok(scope) = scope else {
        failures.push("The approved artifact directory is unavailable or unsafe.".into());
        return false;
    };
    let mut all_ok = true;
    for (index, artifact) in artifacts.iter().enumerate() {
        match scope.verify_artifact_digest(&artifact.relative_path, artifact.size_bytes, &artifact.sha256) {
            Ok(true) => {}
            Ok(false) => {
                failures.push(format!("Artifact {} does not match its signed digest or byte count.", index + 1));
                all_ok = false;
            }
            Err(_) => {
                failures.push(format!("Artifact {} could not be inspected within the approved directory.", index + 1));
                all_ok = false;
            }
        }
    }
    all_ok
}

pub fn verify_manifest_signature(manifest: &EvidenceManifest) -> Result<bool, BridgeError> {
    let Some(ref expected_sha) = manifest.manifest_sha256 else {
        return Ok(false);
    };
    let Some(ref sig_hex) = manifest.signature_ed25519_hex else {
        return Ok(false);
    };
    let Some(ref pk_hex) = manifest.signer_public_key_hex else {
        return Ok(false);
    };
    let canonical = canonical_manifest_bytes(manifest);
    let actual_sha = sha256_bytes(&canonical);
    if !actual_sha.eq_ignore_ascii_case(expected_sha) {
        return Ok(false);
    }
    let pk_bytes: [u8; 32] = hex::decode(pk_hex)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| BridgeError::new(ErrorCode::InvalidArgument, "Invalid public key hex.", OriginLayer::Evidence))?;
    let sig_bytes: [u8; 64] = hex::decode(sig_hex)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| BridgeError::new(ErrorCode::InvalidArgument, "Invalid signature hex.", OriginLayer::Evidence))?;
    let vk = VerifyingKey::from_bytes(&pk_bytes).map_err(|_| {
        BridgeError::new(ErrorCode::InvalidArgument, "Invalid Ed25519 verifying key.", OriginLayer::Evidence)
    })?;
    let sig = Signature::from_bytes(&sig_bytes);
    Ok(vk.verify(&canonical, &sig).is_ok())
}

/// Delegated workloads supply their own observations. Only the controller can attest stop events.
pub fn delegated_workload_verdict(timed_out: bool, cancelled: bool) -> Verdict {
    if cancelled {
        Verdict::Cancelled
    } else if timed_out {
        Verdict::Fail
    } else {
        Verdict::NotTested
    }
}

/// Compute truthful verification verdict from parsed test counts, exit code, freshness, and tampering checks.
/// INVARIANT (§12): Zero executed tests, stale reports, missing parsers, or test-suite tampering NEVER become PASS!
pub fn compute_verification_verdict(
    tests: &EvidenceTestsGroup,
    exit_code: Option<i32>,
    timed_out: bool,
    cancelled: bool,
    policy_denied: bool,
    test_suite_modified_unauthorized: bool,
) -> Verdict {
    if policy_denied {
        return Verdict::Blocked;
    }
    if cancelled {
        return Verdict::Cancelled;
    }
    if timed_out {
        return Verdict::Fail;
    }
    if !tests.fresh_for_run {
        return Verdict::Stale;
    }
    if test_suite_modified_unauthorized {
        return Verdict::Fail;
    }
    if tests.executed == 0 {
        return Verdict::NotTested;
    }
    if tests.failed > 0 || exit_code != Some(0) {
        return Verdict::Fail;
    }
    if tests.skipped > 0 {
        return Verdict::Partial;
    }
    if tests.passed == tests.executed && tests.executed > 0 && exit_code == Some(0) {
        return Verdict::Pass;
    }
    Verdict::Fail
}

// Limit case allocations even when a caller has no capture size limit.
const MAX_PARSED_CASES: usize = 16_384;

fn case_counts(cases: &[TestCaseOutcome]) -> (u32, u32, u32) {
    let count = |status| {
        u32::try_from(cases.iter().filter(|c| c.status == status).count()).unwrap_or(u32::MAX)
    };
    (count(Verdict::Pass), count(Verdict::Fail), count(Verdict::NotTested))
}

fn unittest_summary(total: u32, status: &str, details: Option<&str>) -> Option<(u32, u32, u32)> {
    if status == "NO TESTS RAN" {
        return (total == 0 && details.is_none()).then_some((0, 0, 0));
    }
    let mut counts = [None; 5];
    if let Some(details) = details {
        for item in details.split(',') {
            let (name, value) = item.trim().split_once('=')?;
            let index = match name {
                "failures" => 0,
                "errors" => 1,
                "unexpected successes" => 2,
                "skipped" => 3,
                "expected failures" => 4,
                _ => return None,
            };
            if counts[index].is_some() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            counts[index] = Some(value.parse::<u32>().ok()?);
        }
    }
    let [failures, errors, unexpected, skipped, expected] = counts.map(|n| n.unwrap_or(0));
    let failed = failures.checked_add(errors)?.checked_add(unexpected)?;
    let skipped = skipped.checked_add(expected)?;
    if (status == "OK") != (failed == 0) {
        return None;
    }
    let passed = total.checked_sub(failed.checked_add(skipped)?)?;
    Some((passed, failed, skipped))
}

/// Parse Python unittest output. Inconsistent summaries yield no parsed counts.
pub fn parse_python_unittest(output: &str, fresh_for_run: bool) -> EvidenceTestsGroup {
    let case_re = Regex::new(
        r"^(\S+\s+\([^)]+\))\s+\.\.\.\s+(ok|FAIL|ERROR|skipped.*|expected failure|unexpected success)$",
    ).unwrap();
    let ran_re = Regex::new(r"^Ran\s+(\S+)\s+tests?(?:\s+in\s+\S+)?$").unwrap();
    let status_re = Regex::new(r"^(OK|FAILED|NO TESTS RAN)(?: \((.*)\))?$").unwrap();

    let parse = || {
        let mut cases = Vec::new();
        let mut ran = None;
        let mut summary = None;
        for line in output.lines().map(str::trim) {
            if let Some(cap) = case_re.captures(line) {
                if cases.len() == MAX_PARSED_CASES {
                    return None;
                }
                let raw_status = &cap[2];
                let status = match raw_status {
                    "ok" => Verdict::Pass,
                    _ if raw_status.starts_with("skipped") || raw_status == "expected failure" => Verdict::NotTested,
                    _ => Verdict::Fail,
                };
                cases.push(TestCaseOutcome {
                    name: cap[1].to_string(), status, duration_ms: None,
                    message: (status != Verdict::Pass).then(|| raw_status.to_string()),
                });
            } else if let Some(cap) = ran_re.captures(line) {
                if ran.is_some() || !cap[1].bytes().all(|b| b.is_ascii_digit()) {
                    return None;
                }
                ran = Some(cap[1].parse::<u32>().ok()?);
            } else if let Some(cap) = status_re.captures(line) && let Some(total) = ran {
                if summary.is_some() {
                    return None;
                }
                summary = Some(unittest_summary(total, &cap[1], cap.get(2).map(|m| m.as_str()))?);
            }
        }
        let total = ran?;
        let counts = summary?;
        if !cases.is_empty() && counts != case_counts(&cases) {
            return None;
        }
        Some((total, counts, cases))
    };
    let parsed = parse();
    let valid = parsed.is_some();
    let (total, (passed, failed, skipped), cases) = parsed.unwrap_or_default();
    EvidenceTestsGroup {
        parser_name: if valid { "python_unittest" } else { "none" }.into(),
        parser_version: if valid { "1.0.0" } else { "none" }.into(),
        discovered: total,
        executed: total,
        passed,
        failed,
        skipped,
        results_artifact_sha256: sha256_bytes(output.as_bytes()),
        fresh_for_run,
        cases,
    }
}

/// Parse JUnit XML reports (pytest --junitxml, nextest, ctest, etc.).
pub fn parse_junit_xml(xml: &str, fresh_for_run: bool) -> Result<EvidenceTestsGroup, BridgeError> {
    let mut cases = Vec::new();
    let mut reader = Reader::from_str(xml);
    let mut buf = Vec::new();
    let mut cur: Option<TestCaseOutcome> = None;
    let too_many_cases = || BridgeError::new(
        ErrorCode::ResourceBudgetExceeded, "Too many test cases in the JUnit report.", OriginLayer::Evidence,
    );
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Empty(ref e)) => {
                let tag = e.name();
                if tag.as_ref() == b"testcase" {
                    if cases.len() == MAX_PARSED_CASES {
                        return Err(too_many_cases());
                    }
                    let mut name = String::new();
                    let mut time_ms = None;
                    for attr in e.attributes().flatten() {
                        if attr.key.as_ref() == b"name" {
                            name = String::from_utf8_lossy(&attr.value).to_string();
                        } else if attr.key.as_ref() == b"time" {
                            time_ms = String::from_utf8_lossy(&attr.value).parse::<f64>().ok().map(|s| s * 1000.0).filter(|ms| ms.is_finite() && *ms >= 0.0);
                        }
                    }
                    cases.push(TestCaseOutcome {
                        name,
                        status: Verdict::Pass,
                        duration_ms: time_ms,
                        message: None,
                    });
                } else if tag.as_ref() == b"skipped" {
                    if let Some(ref mut tc) = cur {
                        tc.status = Verdict::NotTested;
                    }
                } else if tag.as_ref() == b"failure" || tag.as_ref() == b"error" {
                    if let Some(ref mut tc) = cur {
                        tc.status = Verdict::Fail;
                    }
                }
            }
            Ok(Event::Start(ref e)) => {
                let tag = e.name();
                if tag.as_ref() == b"testcase" {
                    if cases.len() == MAX_PARSED_CASES {
                        return Err(too_many_cases());
                    }
                    let mut name = String::new();
                    let mut time_ms = None;
                    for attr in e.attributes().flatten() {
                        if attr.key.as_ref() == b"name" {
                            name = String::from_utf8_lossy(&attr.value).to_string();
                        } else if attr.key.as_ref() == b"time" {
                            time_ms = String::from_utf8_lossy(&attr.value).parse::<f64>().ok().map(|s| s * 1000.0).filter(|ms| ms.is_finite() && *ms >= 0.0);
                        }
                    }
                    cur = Some(TestCaseOutcome {
                        name,
                        status: Verdict::Pass,
                        duration_ms: time_ms,
                        message: None,
                    });
                } else if tag.as_ref() == b"failure" || tag.as_ref() == b"error" {
                    if let Some(ref mut tc) = cur {
                        tc.status = Verdict::Fail;
                        for attr in e.attributes().flatten() {
                            if attr.key.as_ref() == b"message" {
                                tc.message = Some(String::from_utf8_lossy(&attr.value).to_string());
                            }
                        }
                    }
                } else if tag.as_ref() == b"skipped" {
                    if let Some(ref mut tc) = cur {
                        tc.status = Verdict::NotTested;
                    }
                }
            }
            Ok(Event::End(ref e)) => {
                if e.name().as_ref() == b"testcase" {
                    if let Some(tc) = cur.take() {
                        cases.push(tc);
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(BridgeError::new(
                    ErrorCode::InvalidArgument,
                    format!("Malformed JUnit XML: {e}"),
                    OriginLayer::Evidence,
                ));
            }
            _ => {}
        }
        buf.clear();
    }

    let (passed, failed, skipped) = case_counts(&cases);
    let total = u32::try_from(cases.len()).unwrap_or(u32::MAX);
    Ok(EvidenceTestsGroup {
        parser_name: "junit_xml".to_string(),
        parser_version: "1.0.0".to_string(),
        discovered: total,
        executed: passed.saturating_add(failed),
        passed,
        failed,
        skipped,
        results_artifact_sha256: sha256_bytes(xml.as_bytes()),
        fresh_for_run,
        cases,
    })
}

/// Parse `cargo test` standard stdout output.
pub fn parse_cargo_test(output: &str, fresh_for_run: bool) -> EvidenceTestsGroup {
    let re = Regex::new(r"^test\s+(\S+)\s+\.\.\.\s+(ok|FAILED|ignored)$").unwrap();
    let mut cases = Vec::new();
    for line in output.lines() {
        if let Some(cap) = re.captures(line.trim()) {
            let status = match &cap[2] {
                "ok" => Verdict::Pass,
                "FAILED" => Verdict::Fail,
                _ => Verdict::NotTested,
            };
            if cases.len() == MAX_PARSED_CASES {
                cases.clear();
                break;
            }
            cases.push(TestCaseOutcome {
                name: cap[1].to_string(),
                status,
                duration_ms: None,
                message: None,
            });
        }
    }
    let (passed, failed, skipped) = case_counts(&cases);
    EvidenceTestsGroup {
        parser_name: "cargo_test".to_string(),
        parser_version: "1.0.0".to_string(),
        discovered: u32::try_from(cases.len()).unwrap_or(u32::MAX),
        executed: passed.saturating_add(failed),
        passed,
        failed,
        skipped,
        results_artifact_sha256: sha256_bytes(output.as_bytes()),
        fresh_for_run,
        cases,
    }
}

/// Parse Node.js `--test` TAP output.
pub fn parse_node_test_tap(output: &str, fresh_for_run: bool) -> EvidenceTestsGroup {
    let mut cases = Vec::new();
    let ok_re = Regex::new(r"^(ok|not ok)\s+\d+\s+-\s+(.+)$").unwrap();
    for line in output.lines() {
        let t = line.trim();
        if let Some(cap) = ok_re.captures(t) {
            let is_ok = &cap[1] == "ok";
            let label = cap[2].to_string();
            let skipped = label.contains("# SKIP") || label.contains("# TODO");
            let status = if skipped {
                Verdict::NotTested
            } else if is_ok {
                Verdict::Pass
            } else {
                Verdict::Fail
            };
            if cases.len() == MAX_PARSED_CASES {
                cases.clear();
                break;
            }
            cases.push(TestCaseOutcome {
                name: label,
                status,
                duration_ms: None,
                message: None,
            });
        }
    }
    let (passed, failed, skipped) = case_counts(&cases);
    EvidenceTestsGroup {
        parser_name: "node_test_tap".to_string(),
        parser_version: "1.0.0".to_string(),
        discovered: u32::try_from(cases.len()).unwrap_or(u32::MAX),
        executed: passed.saturating_add(failed),
        passed,
        failed,
        skipped,
        results_artifact_sha256: sha256_bytes(output.as_bytes()),
        fresh_for_run,
        cases,
    }
}

/// Render a human-readable sanitized Markdown report strictly derived from the trusted `EvidenceManifest`.
pub fn render_evidence_markdown(manifest: &EvidenceManifest) -> String {
    let safe_cmd = sanitize_report_text(&format!(
        "{} {}",
        manifest.command.executable,
        manifest.command.argv.join(" ")
    ));
    let mut md = format!(
        "# Verification Evidence Report — `{}`\n\n\
        - **Verdict:** `{:?}`\n\
        - **Evidence Class:** `{:?}`\n\
        - **Run ID:** `{}` | **Task ID:** `{}`\n\
        - **Host:** `{}` (`{}` / `{}`)\n\
        - **Project:** `{}` | **Workspace:** `{}`\n\
        - **Isolation Backend:** `{}` (`{}`)\n\
        - **Command:** `{}`\n\
        - **Duration:** `{} ms` ({} -> {})\n\
        - **Outcomes:** agent=`{:?}`, execution=`{:?}`, verification=`{:?}`\n\
        - **Source SHA-256 Before -> After:** `{}` -> `{}`\n\
        - **Test Suite Modified:** `{}` (suite SHA-256: `{}`)\n\
        - **Manifest SHA-256:** `{}`\n\
        - **Ed25519 Signature:** `{}`\n\n\
        ## {} (`{}` v{})\n\n\
        | Discovered | Executed | Passed | Failed | Skipped | Fresh |\n\
        | ---: | ---: | ---: | ---: | ---: | --- |\n\
        | {} | {} | {} | {} | {} | {} |\n\n",
        manifest.identity.manifest_id,
        manifest.conclusions.overall_verdict,
        manifest.identity.evidence_class,
        manifest.identity.run_id,
        manifest.identity.task_id,
        sanitize_report_text(&manifest.environment.host_name),
        sanitize_report_text(&manifest.environment.os_build),
        sanitize_report_text(&manifest.environment.architecture),
        manifest.identity.project_id,
        manifest.identity.workspace_id,
        sanitize_report_text(&manifest.environment.isolation_backend),
        sanitize_report_text(&manifest.authorization.containment_probe_result),
        safe_cmd,
        manifest.time.monotonic_duration_ms,
        manifest.time.started_at_utc.to_rfc3339(),
        manifest.time.finished_at_utc.to_rfc3339(),
        manifest.execution.outcome_triad.agent_outcome,
        manifest.execution.outcome_triad.execution_outcome,
        manifest.execution.outcome_triad.verification_outcome,
        manifest.source.source_hash_before,
        manifest.source.source_hash_after,
        manifest.source.test_suite_modified,
        manifest.source.test_suite_manifest_sha256,
        manifest.manifest_sha256.as_deref().unwrap_or("unsigned"),
        manifest.signature_ed25519_hex.as_deref().unwrap_or("unsigned"),
        if manifest.authorization.executor_identity == DELEGATED_WORKLOAD_REPORT_EXECUTOR {
            "Workload-Reported Test Counts"
        } else {
            "Test Results"
        },
        manifest.tests.parser_name,
        manifest.tests.parser_version,
        manifest.tests.discovered,
        manifest.tests.executed,
        manifest.tests.passed,
        manifest.tests.failed,
        manifest.tests.skipped,
        manifest.tests.fresh_for_run,
    );

    if !manifest.tests.cases.is_empty() {
        md.push_str("| Test Case | Status | Note |\n| --- | --- | --- |\n");
        for c in &manifest.tests.cases {
            md.push_str(&format!(
                "| `{}` | `{:?}` | {} |\n",
                sanitize_report_text(&c.name),
                c.status,
                sanitize_report_text(c.message.as_deref().unwrap_or(""))
            ));
        }
        md.push('\n');
    }

    md.push_str("## Artifacts\n\n| Artifact ID | Path | SHA-256 | Bytes | Secret Scan |\n| --- | --- | --- | ---: | --- |\n");
    for a in &manifest.artifacts {
        md.push_str(&format!(
            "| `{}` | `{}` | `{}` | {} | {} |\n",
            a.artifact_id,
            sanitize_report_text(&a.relative_path),
            a.sha256,
            a.size_bytes,
            if a.secret_scan_passed { "CLEAN" } else { "REDACTED" }
        ));
    }
    md.push_str("\n## Untested Boundaries & Provenance Note\n\n");
    for u in &manifest.conclusions.untested_areas {
        md.push_str(&format!("- {}\n", sanitize_report_text(u)));
    }
    md.push_str(&format!(
        "\n> {}\n",
        sanitize_report_text(&manifest.conclusions.provenance_disclaimer)
    ));
    md
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn environment_entries_that_look_like_credentials_are_named() {
        let entry = |name: &str, value: &str| (name.to_string(), Some(value.to_string()));
        let entries = [entry("OPENAI_API_KEY", "x"), entry("GithubToken", "x"), entry("DB_PASSWORD", "x"),
            entry("MY_PAT", "x"), entry("APIKEY", "x"), entry("GITHUBPAT", "x"), entry("TOKENFILE", "x"),
            entry("BASICAUTH", "x"), ("OPAQUE".to_string(), None),
            entry("SERVICE", "sk-"), entry("Path", "C:/Windows;C:/Users/someone@example.com/bin"),
            entry("TEMP", "C:/Temp"), entry("KEYBOARD_LAYOUT", "us"), entry("PATHEXT", ".exe"), entry("OS", "Windows_NT"),
            entry("PROCESSOR_IDENTIFIER", "x"), entry("PSModulePath", "x"), entry("ComSpec", "x"), entry("windir", "x"),
            entry("MONKEY_MODE", "on"), entry("EMPTY_TOKEN", "  "), entry("AUTHOR", "someone")];
        assert_eq!(credential_like_environment_names(&entries),
            ["APIKEY", "BASICAUTH", "DB_PASSWORD", "GITHUBPAT", "GithubToken", "MY_PAT", "OPAQUE", "OPENAI_API_KEY",
                "TOKENFILE"]);
        let recognised = [entry("SERVICE", &format!("sk-{}", "A1b2".repeat(12)))];
        assert_eq!(credential_like_environment_names(&recognised), ["SERVICE"]);
    }

    #[test]
    fn secret_scanner_catches_real_patterns_and_redacts() {
        let fixture_bearer = "B".repeat(24);
        let fixture_api_key = "K".repeat(16);
        let sample = format!("Authorization: Bearer {fixture_bearer}\napi_key={fixture_api_key}\nuser@example.com");
        let rep = scan_and_redact_secrets(&sample);
        assert!(!rep.clean);
        assert!(rep.findings_count >= 3);
        assert!(!rep.redacted_text.contains(&fixture_bearer));
        assert!(!rep.redacted_text.contains(&fixture_api_key));
        assert!(!rep.redacted_text.contains("user@example.com"));
    }

    #[test]
    fn zero_tests_and_stale_reports_never_produce_pass() {
        for (footer, exit_code) in [("OK", 0), ("NO TESTS RAN", 5)] {
            let zero = parse_python_unittest(&format!("Ran 0 tests in 0.000s\n\n{footer}\n"), true);
            assert_eq!(zero.parser_name, "python_unittest");
            assert_eq!(zero.executed, 0);
            assert_eq!(
                compute_verification_verdict(&zero, Some(exit_code), false, false, false, false),
                Verdict::NotTested
            );
        }

        let stale = parse_python_unittest("test_a (t.T) ... ok\n\nRan 1 test in 0.001s\n\nOK\n", false);
        assert_eq!(
            compute_verification_verdict(&stale, Some(0), false, false, false, false),
            Verdict::Stale
        );

        let tampered = parse_python_unittest("test_a (t.T) ... ok\n\nRan 1 test in 0.001s\n\nOK\n", true);
        assert_eq!(
            compute_verification_verdict(&tampered, Some(0), false, false, false, true),
            Verdict::Fail
        );

        let good = parse_python_unittest("test_a (t.T) ... ok\n\nRan 1 test in 0.001s\n\nOK\n", true);
        assert_eq!(
            compute_verification_verdict(&good, Some(0), false, false, false, false),
            Verdict::Pass
        );
    }

    #[test]
    fn unittest_rejects_overflow_and_inconsistent_summaries() {
        for output in [
            "Ran 1 test\nFAILED (failures=4294967295, errors=1)",
            "Ran 1 test\nFAILED (failures=4294967296)",
            "Ran 4294967296 tests\nOK",
            "Ran 1 test\nFAILED (failures=1, skipped=1)",
            "Ran 1 test\nFAILED (failures=1, failures=0)",
            "Ran 1 test\nFAILED",
            "Ran 1 test",
            "Ran 1 test\nOK (errors=1)",
            "Ran 1 test\nNO TESTS RAN",
            "test_a (t.T) ... ok\nRan 2 tests\nOK",
            "test_a (t.T) ... ok\nRan 1 test\nFAILED (errors=1)",
        ] {
            let parsed = parse_python_unittest(output, true);
            assert_eq!(parsed.parser_name, "none", "{output}");
            assert_eq!((parsed.executed, parsed.passed, parsed.failed, parsed.skipped), (0, 0, 0, 0), "{output}");
            assert_eq!(compute_verification_verdict(&parsed, Some(0), false, false, false, false),
                Verdict::NotTested, "{output}");
        }
    }

    #[test]
    fn unittest_keeps_valid_nonverbose_failure_and_skip_counts() {
        let parsed = parse_python_unittest("Ran 5 tests\nFAILED (failures=1, errors=1, skipped=2)", true);
        assert_eq!((parsed.executed, parsed.passed, parsed.failed, parsed.skipped), (5, 1, 2, 2));
        let parsed = parse_python_unittest("Ran 2 tests\nOK (expected failures=1)", true);
        assert_eq!((parsed.executed, parsed.passed, parsed.failed, parsed.skipped), (2, 1, 0, 1));
    }

    #[test]
    fn junit_xml_parses_pass_fail_skipped() {
        let xml = r#"<testsuite tests="3" failures="1" skipped="1">
            <testcase name="test_ok" time="0.012"/>
            <testcase name="test_bad" time="0.005"><failure message="expected 5 got 4"/></testcase>
            <testcase name="test_skip" time="0.001"><skipped/></testcase>
        </testsuite>"#;
        let g = parse_junit_xml(xml, true).unwrap();
        assert_eq!(g.discovered, 3);
        assert_eq!(g.passed, 1);
        assert_eq!(g.failed, 1);
        assert_eq!(g.skipped, 1);
        assert_eq!(
            compute_verification_verdict(&g, Some(1), false, false, false, false),
            Verdict::Fail
        );
    }

    fn manifest_fixture(log_bytes: &[u8]) -> EvidenceManifest {
        EvidenceManifest {
            identity: EvidenceIdentityGroup {
                manifest_id: ManifestId::new_random(),
                report_format_version: "1.0.0".into(),
                run_id: RunId::new_random(),
                task_id: TaskId("t1".into()),
                host_id: HostId("host_trusted".into()),
                project_id: ProjectId("project_1".into()),
                workspace_id: WorkspaceId("ws_1".into()),
                broker_version: "0.4.0".into(),
                runner_version: "0.4.0".into(),
                adapter_version: "1.0.0".into(),
                evidence_class: EvidenceClass::SoftwareUnit,
            },
            authorization: EvidenceAuthorizationGroup {
                grant_id: None,
                requester_principal: "local".into(),
                executor_identity: "runner".into(),
                policy_revision: 1,
                effective_scope: vec![".".into()],
                containment_probe_result: "ok".into(),
            },
            source: EvidenceSourceGroup {
                base_commit: None,
                dirty_input_manifest_sha256: "a".repeat(64),
                source_hash_before: "a".repeat(64),
                source_hash_after: "a".repeat(64),
                patch_digest: None,
                test_suite_manifest_sha256: "b".repeat(64),
                test_suite_modified: false,
            },
            inputs: EvidenceInputsGroup {
                config_hashes: Default::default(),
                declared_units: Default::default(),
                random_seed: None,
                synthetic_data: true,
            },
            environment: EvidenceEnvironmentGroup {
                os_build: "windows".into(),
                architecture: "x86_64".into(),
                host_name: "HOST-TEST".into(),
                toolchain_versions: Default::default(),
                resolved_executable: "python.exe".into(),
                resolved_executable_sha256: "c".repeat(64),
                isolation_backend: "win32-job-object".into(),
            },
            command: EvidenceCommandGroup {
                executable: "python.exe".into(),
                argv: vec!["-m".into(), "unittest".into()],
                cwd: ".".into(),
                redacted_env_keys: vec![],
                supervisor_pid: Some(1234),
                process_start_recorded_outside_job: true,
            },
            time: EvidenceTimeGroup {
                started_at_utc: chrono::Utc::now(),
                finished_at_utc: chrono::Utc::now(),
                monotonic_duration_ms: 10,
                clock_uncertainty_note: "monotonic".into(),
            },
            execution: EvidenceExecutionGroup {
                exit_code: Some(0),
                timed_out: false,
                cancelled: false,
                policy_denied: false,
                partial_output: false,
                cleanup_confirmed: true,
                outcome_triad: OutcomeTriad {
                    agent_outcome: Verdict::NotTested,
                    execution_outcome: Verdict::Pass,
                    verification_outcome: Verdict::Pass,
                    soft_denied_tools: vec![],
                },
            },
            tests: parse_python_unittest(std::str::from_utf8(log_bytes).unwrap(), true),
            artifacts: vec![SealedArtifactRef {
                artifact_id: ArtifactId::new_random(),
                relative_path: "run.log".into(),
                sha256: sha256_bytes(log_bytes),
                size_bytes: log_bytes.len() as u64,
                media_type: "text/plain".into(),
                capture_origin: "supervisor".into(),
                export_policy: "redacted".into(),
                secret_scan_passed: true,
            }],
            conclusions: EvidenceConclusionsGroup {
                overall_verdict: Verdict::Pass,
                claims: vec![],
                untested_areas: vec![],
                reproduction_command: "python -m unittest".into(),
                provenance_disclaimer: PROVENANCE_DISCLAIMER.into(),
            },
            manifest_sha256: None,
            signature_ed25519_hex: None,
            signer_public_key_hex: None,
        }
    }

    fn running_evidence_fixture(
        dir: &Path,
    ) -> (crate::state::StateStore, EvidenceManifest) {
        let store = crate::state::StateStore::open(dir.join("state.sqlite3")).unwrap();
        let mut manifest = manifest_fixture(b"Ran 1 test\nOK");
        let project = store.register_project(dir, "Evidence fixture", "ev-fixture-root").unwrap();
        manifest.identity.project_id = ProjectId(project.project_id);
        let now = chrono::Utc::now();
        let run = DurableJobRecord {
            run_id: manifest.identity.run_id.clone(),
            task_id: manifest.identity.task_id.clone(),
            host_id: manifest.identity.host_id.clone(),
            project_id: manifest.identity.project_id.clone(),
            workspace_id: manifest.identity.workspace_id.clone(),
            grant_id: None,
            requester_principal: "local".into(),
            executor_identity: "fixture".into(),
            operation_id: OperationId("evidence-fixture".into()),
            dedup_key: sha256_bytes(b"evidence-fixture"),
            payload_digest: sha256_bytes(b"{}"),
            state: JobState::Running,
            pid: None,
            process_start_time_100ns: None,
            exit_code: None,
            outcome: None,
            evidence_manifest_id: None,
            output_seq: 0,
            output_truncated: false,
            output_dir: dir.display().to_string(),
            created_at: now,
            updated_at: now,
        };
        store.claim_durable_run(&run, "{}").unwrap();
        (store, manifest)
    }

    #[test]
    fn busy_evidence_transaction_cannot_sign_or_commit() {
        let dir = tempfile::tempdir().unwrap();
        let (store, manifest) = running_evidence_fixture(dir.path());
        let lock = rusqlite::Connection::open(store.db_path()).unwrap();
        lock.execute_batch("BEGIN IMMEDIATE").unwrap();
        let run_id = &manifest.identity.run_id.0;
        let result = store.finalize_queued_run_with_evidence::<()>(run_id, JobState::Succeeded, Some(0), |_| {
            panic!("Signing must wait for the terminal decision");
        });
        assert_eq!(result.unwrap_err().code, ErrorCode::ResourceBusy);
        assert_eq!(store.get_durable_run(run_id).unwrap().unwrap().state, JobState::Running);
        assert!(store.get_evidence_manifest(&manifest.identity.manifest_id.0).unwrap().is_none());
        lock.execute_batch("ROLLBACK").unwrap();
    }

    #[test]
    fn failed_terminal_write_rolls_back_the_signed_manifest_row() {
        let dir = tempfile::tempdir().unwrap();
        let (store, mut manifest) = running_evidence_fixture(dir.path());
        let db = rusqlite::Connection::open(store.db_path()).unwrap();
        db.execute_batch(
            "CREATE TRIGGER reject_run_finalization BEFORE UPDATE OF evidence_manifest_id ON durable_runs
             BEGIN SELECT RAISE(ABORT, 'fixture final state write fault'); END;",
        ).unwrap();
        let run_id = manifest.identity.run_id.0.clone();
        let manifest_id = manifest.identity.manifest_id.0.clone();
        let result = store.finalize_queued_run_with_evidence(&run_id, JobState::Succeeded, Some(0), |_| {
            seal_and_sign_manifest(&mut manifest, &SigningKey::generate(&mut OsRng));
            let json = serde_json::to_string_pretty(&manifest).unwrap();
            Ok::<_, ()>((manifest, json))
        });
        assert!(result.is_err());
        assert!(store.get_evidence_manifest(&manifest_id).unwrap().is_none());
        let run = store.get_durable_run(&run_id).unwrap().unwrap();
        assert_eq!(run.state, JobState::Running);
        assert!(run.evidence_manifest_id.is_none());
    }

    #[test]
    fn cancellation_between_signing_and_commit_cannot_change_the_decision() {
        let dir = tempfile::tempdir().unwrap();
        let (store, mut manifest) = running_evidence_fixture(dir.path());
        let canceller = crate::state::StateStore::open_current(store.db_path()).unwrap();
        let run_id = manifest.identity.run_id.0.clone();
        let manifest_id = manifest.identity.manifest_id.clone();
        let key = SigningKey::generate(&mut OsRng);
        let (run, _, _) = store.finalize_queued_run_with_evidence(
            &run_id, JobState::Succeeded, Some(0),
            |terminal| {
                assert_eq!(terminal, JobState::Succeeded);
                seal_and_sign_manifest(&mut manifest, &key);
                let json = serde_json::to_string_pretty(&manifest).unwrap();
                // The workload is signed. The final run row has yet to be committed.
                assert_eq!(canceller.request_run_cancel(&run_id).unwrap_err().code, ErrorCode::ResourceBusy);
                assert!(canceller.get_evidence_manifest(&manifest_id.0).unwrap().is_none());
                Ok::<_, ()>((manifest, json))
            },
        ).unwrap().unwrap();
        assert_eq!(run.state, JobState::Succeeded);
        assert_eq!(run.evidence_manifest_id, Some(manifest_id.clone()));
        assert_eq!(canceller.request_run_cancel(&run_id).unwrap().state, JobState::Succeeded);
        let saved = canceller.get_evidence_manifest(&manifest_id.0).unwrap().unwrap();
        assert!(!saved.execution.cancelled);
        assert!(verify_manifest_signature(&saved).unwrap());
    }

    #[test]
    fn negative_attacks_signed_field_tamper_artifact_tamper_and_rogue_key_substitution() {
        let dir = tempfile::tempdir().unwrap();
        let art_dir = dir.path().join("arts");
        fs::create_dir_all(&art_dir).unwrap();
        let log_bytes = b"test_a (t.T) ... ok\n\nRan 1 test in 0.001s\n\nOK\n";
        fs::write(art_dir.join("run.log"), log_bytes).unwrap();

        let (trusted_sk, trusted_pk_hex) = load_or_create_device_signing_key(dir.path()).unwrap();
        let mut m = manifest_fixture(log_bytes);
        seal_and_sign_manifest(&mut m, &trusted_sk);

        // 0. Baseline valid passes all 5 dimensions
        let ok_rep = verify_evidence_full(&m, Some(&trusted_pk_hex), Some(&art_dir)).unwrap();
        assert!(ok_rep.overall_verified);
        assert!(ok_rep.device_key_trusted);
        assert_eq!(ok_rep.artifacts_hashes_verified, Some(true));

        // 1. Tamper signed field -> cryptographic verification FAILS
        let mut tampered_field = m.clone();
        tampered_field.tests.passed = 999;
        let rep1 = verify_evidence_full(&tampered_field, Some(&trusted_pk_hex), Some(&art_dir)).unwrap();
        assert!(!rep1.overall_verified);
        assert!(!rep1.signature_cryptographically_valid);
        assert_eq!(rep1.artifacts_hashes_verified, None);

        // 2. Rogue attacker key substitution (valid self-signature, UNTRUSTED device key!) -> FAILS device_key_trusted!
        let mut rogue_csprng = OsRng;
        let rogue_sk = SigningKey::generate(&mut rogue_csprng);
        let mut rogue_signed = m.clone();
        rogue_signed.conclusions.overall_verdict = Verdict::Pass;
        seal_and_sign_manifest(&mut rogue_signed, &rogue_sk);
        let rep2 = verify_evidence_full(&rogue_signed, Some(&trusted_pk_hex), Some(&art_dir)).unwrap();
        assert!(rep2.signature_cryptographically_valid);
        assert!(!rep2.device_key_trusted);
        assert_eq!(rep2.artifacts_hashes_verified, None);
        assert!(!rep2.overall_verified);

        // A trusted manifest still has to identify artifacts by relative paths.
        let mut absolute_name = m.clone();
        absolute_name.artifacts[0].relative_path = art_dir.join("run.log").display().to_string();
        seal_and_sign_manifest(&mut absolute_name, &trusted_sk);
        let refused = verify_evidence_full(&absolute_name, Some(&trusted_pk_hex), Some(&art_dir)).unwrap();
        assert!(refused.signature_cryptographically_valid && refused.device_key_trusted);
        assert_eq!(refused.artifacts_hashes_verified, Some(false));
        assert!(!refused.overall_verified);

        // 3. Tamper artifact on disk after signing -> FAILS artifacts_hashes_verified!
        fs::write(art_dir.join("run.log"), b"TAMPERED LOG CONTENT").unwrap();
        let rep3 = verify_evidence_full(&m, Some(&trusted_pk_hex), Some(&art_dir)).unwrap();
        assert!(rep3.signature_cryptographically_valid);
        assert!(rep3.device_key_trusted);
        assert_eq!(rep3.artifacts_hashes_verified, Some(false));
        assert!(!rep3.overall_verified);
    }
}
