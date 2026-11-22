"""Stage 8 Conditional Hardware, Telemetry, and Aviation Profile (§13):
- Strictly separates software_unit, recorded_log, sitl, hitl/sih, hardware_bench, flight_observation.
- Never auto-discovers/connects to serial/UDP autopilots or sends actuation commands.
- Explicitly probes optional SDKs (pyulog, pymavlink, mavsdk) without installing flight stacks unsolicited.
"""
from __future__ import annotations

import importlib.util
import json
from typing import Any

EVIDENCE_CLASSES = (
    "software_unit",
    "software_integration",
    "recorded_log",
    "sitl",
    "hitl",
    "sih",
    "hardware_bench",
    "flight_observation",
)

READ_ONLY_OUTGOING_ALLOWLIST = (
    "HEARTBEAT",
    "REQUEST_DATA_STREAM",
    "MESSAGE_INTERVAL_REQUEST",
    "PARAM_REQUEST_LIST",
    "AUTOPILOT_VERSION_REQUEST",
)

DENIED_ACTUATION_ACTIONS = (
    "arm",
    "disarm",
    "motor_test",
    "takeoff",
    "land",
    "live_control",
    "param_write",
    "firmware_flash",
)


def probe_hardware_profiles() -> dict[str, Any]:
    pyulog = importlib.util.find_spec("pyulog") is not None
    pymavlink = importlib.util.find_spec("pymavlink") is not None
    mavsdk = importlib.util.find_spec("mavsdk") is not None
    return {
        "evidence_classes": list(EVIDENCE_CLASSES),
        "rust_native_ulog_parser": {
            "implemented": True,
            "verified": True,
            "parser_version": "ulog-binary-1.0.0",
            "handles_dropouts_and_truncation": True,
        },
        "optional_python_sdks": {
            "pyulog_installed": pyulog,
            "pymavlink_installed": pymavlink,
            "mavsdk_installed": mavsdk,
        },
        "telemetry_policy": {
            "default_mode": "log_import_and_readonly_allowlist",
            "allowed_outgoing_messages": list(READ_ONLY_OUTGOING_ALLOWLIST),
            "passive_disclosure": "SDK sessions may emit heartbeats or stream/parameter requests; never described as strictly zero-byte passive.",
            "denied_physical_actions": list(DENIED_ACTUATION_ACTIONS),
            "auto_serial_udp_discovery_disabled": True,
            "mavlink_signing_note": "MAVLink v2 signing is message authentication, NOT encryption; channel protection must be separate.",
        },
        "hardware_status": {
            "sitl": {"status": "NOT_TESTED", "reason": "No PX4/ArduPilot flight stack was verified in the test environment."},
            "hitl_sih": {"status": "BLOCKED", "reason": "No physical autopilot attached; PX4 HITL compatibility is community-maintained and version-sensitive."},
            "hardware_bench": {"status": "BLOCKED", "reason": "No supervised physical bench hardware was available for testing."},
            "flight_observation": {"status": "NOT_TESTED", "reason": "No real flight logs imported yet; synthetic fixtures are strictly labelled synthetic."},
        },
    }


if __name__ == "__main__":
    print(json.dumps(probe_hardware_profiles(), indent=2))
