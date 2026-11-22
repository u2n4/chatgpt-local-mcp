"""Deterministic measurement ingestion, unit conversion, staleness/range validation, and reproducible stats.
NEVER relabels synthetic fixtures as real flight or hardware telemetry.
"""
from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import statistics
from typing import Any

# Exact international knot definition: 1852 m / 3600 s = 0.5144444444444445 m/s
KNOTS_TO_MPS = 1852.0 / 3600.0
FEET_TO_METERS = 0.3048


@dataclass(frozen=True)
class ValidationLimits:
    min_value: float
    max_value: float
    max_stale_seconds: float


def convert_to_si(value: float, unit: str) -> tuple[float, str]:
    """Convert declared physical units into SI deterministically."""
    u = unit.strip()
    if u == "m/s":
        return float(value), "m/s"
    if u in {"kt", "kn", "knots"}:
        return float(value) * KNOTS_TO_MPS, "m/s"
    if u == "m":
        return float(value), "m"
    if u == "ft":
        return float(value) * FEET_TO_METERS, "m"
    if u == "K":
        return float(value), "K"
    if u == "C":
        return float(value) + 273.15, "K"
    raise ValueError(f"Unsupported declared unit: {unit!r}")


def parse_utc(ts: str) -> datetime:
    cleaned = ts.strip()
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"
    dt = datetime.fromisoformat(cleaned)
    if dt.tzinfo is None:
        raise ValueError(f"Timestamp must include explicit UTC/timezone offset: {ts!r}")
    return dt.astimezone(timezone.utc)


def analyze_csv_dataset(
    csv_path: Path,
    *,
    limits: ValidationLimits,
    reference_time_utc: datetime,
    dataset_label: str = "synthetic_fixture",
    evidence_class: str = "software_unit",
) -> dict[str, Any]:
    raw_bytes = csv_path.read_bytes()
    raw_sha256 = hashlib.sha256(raw_bytes).hexdigest()
    text = raw_bytes.decode("utf-8")

    valid_si: list[float] = []
    si_unit: str | None = None
    missing_rows = 0
    stale_rows = 0
    out_of_range_rows = 0
    invalid_rows = 0
    total_rows = 0

    reader = csv.DictReader(text.splitlines())
    for row in reader:
        total_rows += 1
        raw_ts = (row.get("timestamp_utc") or "").strip()
        raw_val = (row.get("value") or "").strip()
        raw_unit = (row.get("unit") or "").strip()

        if not raw_ts or not raw_val or not raw_unit:
            missing_rows += 1
            continue
        try:
            dt = parse_utc(raw_ts)
            num = float(raw_val)
            if not math.isfinite(num):
                invalid_rows += 1
                continue
            si_val, unit_out = convert_to_si(num, raw_unit)
        except ValueError:
            invalid_rows += 1
            continue

        age_s = (reference_time_utc - dt).total_seconds()
        if age_s > limits.max_stale_seconds or age_s < -limits.max_stale_seconds:
            stale_rows += 1
            continue
        if si_val < limits.min_value or si_val > limits.max_value:
            out_of_range_rows += 1
            continue

        si_unit = unit_out
        valid_si.append(si_val)

    metrics = {
        "valid_count": len(valid_si),
        "si_unit": si_unit,
        "min": round(min(valid_si), 6) if valid_si else None,
        "max": round(max(valid_si), 6) if valid_si else None,
        "mean": round(statistics.fmean(valid_si), 6) if valid_si else None,
        "median": round(statistics.median(valid_si), 6) if valid_si else None,
        "stdev": round(statistics.pstdev(valid_si), 6) if len(valid_si) >= 2 else 0.0 if valid_si else None,
    }
    return {
        "dataset_label": dataset_label,
        "synthetic_data": dataset_label.startswith("synthetic"),
        "evidence_class": evidence_class,
        "source_file": csv_path.name,
        "source_sha256": raw_sha256,
        "reference_time_utc": reference_time_utc.isoformat(),
        "counts": {
            "total_rows": total_rows,
            "valid_rows": len(valid_si),
            "missing_rows": missing_rows,
            "stale_rows": stale_rows,
            "out_of_range_rows": out_of_range_rows,
            "invalid_rows": invalid_rows,
        },
        "metrics": metrics,
    }


def analyze_json_dataset(
    json_path: Path,
    *,
    limits: ValidationLimits,
    reference_time_utc: datetime,
    dataset_label: str = "synthetic_fixture",
    evidence_class: str = "software_unit",
) -> dict[str, Any]:
    raw_bytes = json_path.read_bytes()
    payload = json.loads(raw_bytes.decode("utf-8"))
    rows = payload.get("samples", []) if isinstance(payload, dict) else payload
    valid_si: list[float] = []
    si_unit: str | None = None
    missing_rows = stale_rows = out_of_range_rows = invalid_rows = 0

    for row in rows:
        raw_ts = row.get("timestamp_utc")
        raw_val = row.get("value")
        raw_unit = row.get("unit")
        if raw_ts is None or raw_val is None or not raw_unit:
            missing_rows += 1
            continue
        try:
            dt = parse_utc(str(raw_ts))
            num = float(raw_val)
            if not math.isfinite(num):
                invalid_rows += 1
                continue
            si_val, u_out = convert_to_si(num, str(raw_unit))
        except (ValueError, TypeError):
            invalid_rows += 1
            continue
        age_s = (reference_time_utc - dt).total_seconds()
        if age_s > limits.max_stale_seconds or age_s < -limits.max_stale_seconds:
            stale_rows += 1
            continue
        if si_val < limits.min_value or si_val > limits.max_value:
            out_of_range_rows += 1
            continue
        si_unit = u_out
        valid_si.append(si_val)

    return {
        "dataset_label": dataset_label,
        "synthetic_data": dataset_label.startswith("synthetic"),
        "evidence_class": evidence_class,
        "source_file": json_path.name,
        "source_sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "counts": {
            "total_rows": len(rows),
            "valid_rows": len(valid_si),
            "missing_rows": missing_rows,
            "stale_rows": stale_rows,
            "out_of_range_rows": out_of_range_rows,
            "invalid_rows": invalid_rows,
        },
        "metrics": {
            "valid_count": len(valid_si),
            "si_unit": si_unit,
            "mean": round(statistics.fmean(valid_si), 6) if valid_si else None,
        },
    }
