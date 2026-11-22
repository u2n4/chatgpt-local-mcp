"""Compare two BridgePulse/Bridge evidence manifests and source baselines reproducibly."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def compare_baselines(before_manifest: dict[str, Any], after_manifest: dict[str, Any]) -> dict[str, Any]:
    b_tests = before_manifest.get("tests", {})
    a_tests = after_manifest.get("tests", {})
    b_time = before_manifest.get("time", {})
    a_time = after_manifest.get("time", {})
    b_env = before_manifest.get("environment", {})
    a_env = after_manifest.get("environment", {})
    b_src = before_manifest.get("source", {})
    a_src = after_manifest.get("source", {})

    b_verdict = before_manifest.get("conclusions", {}).get("overall_verdict", "UNKNOWN")
    a_verdict = after_manifest.get("conclusions", {}).get("overall_verdict", "UNKNOWN")

    return {
        "before_manifest_id": before_manifest.get("identity", {}).get("manifest_id"),
        "after_manifest_id": after_manifest.get("identity", {}).get("manifest_id"),
        "verdict_transition": f"{b_verdict} -> {a_verdict}",
        "host_comparison": {
            "before_host": b_env.get("host_name"),
            "after_host": a_env.get("host_name"),
            "same_host": b_env.get("host_name") == a_env.get("host_name"),
        },
        "source_hash_changed": b_src.get("source_hash_after") != a_src.get("source_hash_after"),
        "source_hash_before": b_src.get("source_hash_after"),
        "source_hash_after": a_src.get("source_hash_after"),
        "test_delta": {
            "executed_before": b_tests.get("executed", 0),
            "executed_after": a_tests.get("executed", 0),
            "passed_before": b_tests.get("passed", 0),
            "passed_after": a_tests.get("passed", 0),
            "failed_before": b_tests.get("failed", 0),
            "failed_after": a_tests.get("failed", 0),
            "duration_ms_before": b_time.get("monotonic_duration_ms"),
            "duration_ms_after": a_time.get("monotonic_duration_ms"),
        },
    }


def export_comparison_report(
    comparison: dict[str, Any],
    measurement_summary: dict[str, Any] | None,
    out_dir: Path,
) -> dict[str, str]:
    out_dir.mkdir(parents=True, exist_ok=True)
    bundle = {
        "report_format_version": "1.0.0",
        "comparison": comparison,
        "measurement_summary": measurement_summary,
    }
    json_text = json.dumps(bundle, indent=2, sort_keys=True) + "\n"
    json_path = out_dir / "bridgepulse-lab-report.json"
    json_path.write_text(json_text, encoding="utf-8")
    digest = hashlib.sha256(json_text.encode("utf-8")).hexdigest()

    td = comparison["test_delta"]
    md = [
        "# BridgePulse Lab — Baseline & Measurement Comparison Report",
        "",
        f"- **Verdict Transition:** `{comparison['verdict_transition']}`",
        f"- **Before Manifest:** `{comparison['before_manifest_id']}`",
        f"- **After Manifest:** `{comparison['after_manifest_id']}`",
        f"- **Host:** `{comparison['host_comparison']['before_host']}` -> `{comparison['host_comparison']['after_host']}`",
        f"- **Source Hash:** `{comparison['source_hash_before']}` -> `{comparison['source_hash_after']}`",
        f"- **Tests Passed / Failed:** `{td['passed_before']}/{td['failed_before']}` -> `{td['passed_after']}/{td['failed_after']}`",
        f"- **Report JSON SHA-256:** `{digest}`",
        "",
    ]
    if measurement_summary:
        md.extend([
            "## Measurement Summary",
            "",
            f"- **Dataset Label:** `{measurement_summary['dataset_label']}` (synthetic=`{measurement_summary['synthetic_data']}`)",
            f"- **Evidence Class:** `{measurement_summary['evidence_class']}`",
            f"- **Source SHA-256:** `{measurement_summary['source_sha256']}`",
            f"- **Valid / Stale / Out-of-Range / Missing:** `{measurement_summary['counts']['valid_rows']}` / `{measurement_summary['counts']['stale_rows']}` / `{measurement_summary['counts']['out_of_range_rows']}` / `{measurement_summary['counts']['missing_rows']}`",
            f"- **Mean (SI):** `{measurement_summary['metrics']['mean']} {measurement_summary['metrics']['si_unit']}`",
            "",
        ])
    md_path = out_dir / "bridgepulse-lab-report.md"
    md_path.write_text("\n".join(md), encoding="utf-8")
    return {
        "json_path": str(json_path),
        "markdown_path": str(md_path),
        "json_sha256": digest,
    }
