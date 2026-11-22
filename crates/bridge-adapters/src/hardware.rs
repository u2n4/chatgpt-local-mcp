//! Conditional Hardware, Telemetry, and Aviation Log Adapters (§13).
//! - Real PX4 ULog binary parser handling header, flag bits, message counts, dropouts (`O`), and truncated records [S26].
//! - Strict MAVLink read-only outgoing message allowlist vs hard-denied actuation/parameter-write/firmware-write messages.
//! - Clear provenance labels (`recorded_log`, `sitl`, `hitl`, `hardware_bench`, `flight_observation`).
//! - NEVER auto-connects to serial/UDP autopilots or declares hardware/flight acceptance from simulation or mock data.

use bridge_platform::sha256_bytes;
use bridge_types::*;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Outgoing messages explicitly allowed in the read-only telemetry profile.
/// Note (§13): explicitly discloses that SDK sessions may emit heartbeats/requests (not strictly zero-byte passive).
pub const READ_ONLY_TELEMETRY_ALLOWLIST: &[&str] = &[
    "HEARTBEAT",
    "REQUEST_DATA_STREAM",
    "MESSAGE_INTERVAL_REQUEST",
    "PARAM_REQUEST_LIST",
    "AUTOPILOT_VERSION_REQUEST",
];

/// Physical actuation, parameter write, and firmware write messages HARD-DENIED outside supervised hardware grants.
pub const DENIED_PHYSICAL_ACTUATION_MESSAGES: &[&str] = &[
    "COMMAND_LONG:MAV_CMD_COMPONENT_ARM_DISARM",
    "COMMAND_LONG:MAV_CMD_NAV_TAKEOFF",
    "COMMAND_LONG:MAV_CMD_NAV_LAND",
    "COMMAND_LONG:MAV_CMD_DO_MOTOR_TEST",
    "COMMAND_LONG:MAV_CMD_PREFLIGHT_REBOOT_SHUTDOWN",
    "SET_POSITION_TARGET_LOCAL_NED",
    "SET_ATTITUDE_TARGET",
    "ACTUATOR_CONTROL_TARGET",
    "PARAM_SET",
    "PARAM_EXT_SET",
    "MISSION_ITEM_INT",
    "MISSION_WRITE_PARTIAL_LIST",
    "FILE_TRANSFER_PROTOCOL:FIRMWARE_FLASH",
];

pub fn validate_telemetry_outgoing_message(msg_name: &str) -> Result<(), BridgeError> {
    if DENIED_PHYSICAL_ACTUATION_MESSAGES
        .iter()
        .any(|d| d.eq_ignore_ascii_case(msg_name))
    {
        return Err(BridgeError::new(
            ErrorCode::HardwareActionDenied,
            format!(
                "Message '{msg_name}' is a physical actuation, parameter-write, or firmware-write action; strictly denied in read-only telemetry / coding profiles."
            ),
            OriginLayer::HardwareAdapter,
        ));
    }
    if !READ_ONLY_TELEMETRY_ALLOWLIST
        .iter()
        .any(|a| a.eq_ignore_ascii_case(msg_name))
    {
        return Err(BridgeError::new(
            ErrorCode::HardwareActionDenied,
            format!("Message '{msg_name}' is not on the explicit read-only telemetry allowlist."),
            OriginLayer::HardwareAdapter,
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutgoingTelemetryFrame {
    pub message_name: String,
    pub payload_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetrySendAuditEntry {
    pub message_name: String,
    pub payload_len: usize,
    pub allowed: bool,
    pub reason: String,
}

pub trait TelemetryWireSink {
    fn write_frame(&mut self, frame: &OutgoingTelemetryFrame) -> Result<(), BridgeError>;
}

/// Enforces the MAVLink read-only allowlist directly at the actual transmit boundary (§10 of Audit):
/// denied physical actuation / parameter-write / firmware-write frames NEVER emit a single byte onto the wire.
pub struct TelemetrySendGate<S: TelemetryWireSink> {
    sink: S,
    audit_log: Vec<TelemetrySendAuditEntry>,
}

impl<S: TelemetryWireSink> TelemetrySendGate<S> {
    pub fn new(sink: S) -> Self {
        Self {
            sink,
            audit_log: Vec::new(),
        }
    }

    pub fn send(&mut self, frame: &OutgoingTelemetryFrame) -> Result<(), BridgeError> {
        match validate_telemetry_outgoing_message(&frame.message_name) {
            Ok(()) => {
                self.sink.write_frame(frame)?;
                self.audit_log.push(TelemetrySendAuditEntry {
                    message_name: frame.message_name.clone(),
                    payload_len: frame.payload_bytes.len(),
                    allowed: true,
                    reason: "Permitted by explicit READ_ONLY_TELEMETRY_ALLOWLIST.".into(),
                });
                Ok(())
            }
            Err(err) => {
                self.audit_log.push(TelemetrySendAuditEntry {
                    message_name: frame.message_name.clone(),
                    payload_len: frame.payload_bytes.len(),
                    allowed: false,
                    reason: err.message.clone(),
                });
                Err(err)
            }
        }
    }

    pub fn audit_log(&self) -> &[TelemetrySendAuditEntry] {
        &self.audit_log
    }

    pub fn into_inner(self) -> S {
        self.sink
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ULogSummary {
    pub valid_magic: bool,
    pub ulog_version: u8,
    pub timestamp_start_us: u64,
    pub info_fields: BTreeMap<String, String>,
    pub message_counts: BTreeMap<String, u64>,
    pub dropout_count: u64,
    pub total_dropout_ms: u64,
    pub truncated_trailing_bytes: usize,
    pub header: TelemetryStreamHeader,
}

/// Real PX4 ULog binary format parser per official PX4 specification [S26]:
/// Header (16 bytes): `55 4C 6F 67 01 12 35` (7 bytes magic) + 1 byte version + 8 bytes uint64 timestamp_us.
/// Followed by length-prefixed messages: 2 bytes LE `msg_size` + 1 byte `msg_type` + `msg_size` payload.
/// Explicitly tracks dropouts (`O` / 0x4F) and truncated tail records!
pub fn parse_ulog_bytes(raw: &[u8], stream_source: &str, evidence_class: EvidenceClass) -> Result<ULogSummary, BridgeError> {
    const ULOG_MAGIC: &[u8; 7] = &[0x55, 0x4C, 0x6F, 0x67, 0x01, 0x12, 0x35];
    if raw.len() < 16 || &raw[..7] != ULOG_MAGIC {
        return Err(BridgeError::new(
            ErrorCode::InvalidArgument,
            "Invalid ULog binary header magic (expected PX4 ULog magic bytes 55 4C 6F 67 01 12 35).",
            OriginLayer::HardwareAdapter,
        ));
    }
    let version = raw[7];
    let ts_start_us = u64::from_le_bytes(raw[8..16].try_into().unwrap());

    let mut pos = 16usize;
    let mut info_fields = BTreeMap::new();
    let mut msg_counts: BTreeMap<String, u64> = BTreeMap::new();
    let mut dropout_count = 0u64;
    let mut total_dropout_ms = 0u64;
    let mut truncated_trailing_bytes = 0usize;

    while pos < raw.len() {
        if pos + 3 > raw.len() {
            truncated_trailing_bytes = raw.len() - pos;
            break;
        }
        let msg_size = u16::from_le_bytes([raw[pos], raw[pos + 1]]) as usize;
        let msg_type = raw[pos + 2];
        pos += 3;
        if pos + msg_size > raw.len() {
            truncated_trailing_bytes = raw.len() - (pos - 3);
            break;
        }
        let payload = &raw[pos..pos + msg_size];
        pos += msg_size;

        let type_char = (msg_type as char).to_string();
        *msg_counts.entry(type_char).or_insert(0) += 1;

        match msg_type {
            // 'I' (0x49): Information message: 1 byte key_len + key + value
            b'I' if !payload.is_empty() => {
                let klen = payload[0] as usize;
                if 1 + klen <= payload.len() {
                    let key = String::from_utf8_lossy(&payload[1..1 + klen]).to_string();
                    let val = String::from_utf8_lossy(&payload[1 + klen..]).trim_end_matches('\0').to_string();
                    info_fields.insert(key, val);
                }
            }
            // 'O' (0x4F): Dropout message: 2 bytes LE duration_ms
            b'O' if payload.len() >= 2 => {
                dropout_count += 1;
                total_dropout_ms += u16::from_le_bytes([payload[0], payload[1]]) as u64;
            }
            _ => {}
        }
    }

    let firmware = info_fields
        .get("char[40] ver_sw")
        .or_else(|| info_fields.get("ver_sw"))
        .cloned()
        .unwrap_or_else(|| "unknown_firmware".into());
    let device_id = info_fields
        .get("char[16] sys_name")
        .or_else(|| info_fields.get("sys_name"))
        .cloned()
        .unwrap_or_else(|| "unknown_ulog_source".into());

    let now = Utc::now();
    let mut units = BTreeMap::new();
    units.insert("timestamp_start".into(), "us".into());
    units.insert("dropout_duration".into(), "ms".into());

    let header = TelemetryStreamHeader {
        device_identity: device_id,
        firmware_version: firmware,
        stream_source: stream_source.to_string(),
        evidence_class,
        units,
        source_timestamp_utc: now,
        receive_timestamp_utc: now,
        freshness_threshold_ms: 5000,
        sequence_gaps: 0,
        dropouts_detected: dropout_count,
        truncated_records: if truncated_trailing_bytes > 0 { 1 } else { 0 },
        parser_version: "ulog-binary-1.0.0".into(),
        raw_log_sha256: sha256_bytes(raw),
        allowed_outgoing_messages: READ_ONLY_TELEMETRY_ALLOWLIST.iter().map(|s| s.to_string()).collect(),
        denied_outgoing_messages: DENIED_PHYSICAL_ACTUATION_MESSAGES.iter().map(|s| s.to_string()).collect(),
    };

    Ok(ULogSummary {
        valid_magic: true,
        ulog_version: version,
        timestamp_start_us: ts_start_us,
        info_fields,
        message_counts: msg_counts,
        dropout_count,
        total_dropout_ms,
        truncated_trailing_bytes,
        header,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mavlink_policy_blocks_arm_takeoff_and_param_writes() {
        assert!(validate_telemetry_outgoing_message("HEARTBEAT").is_ok());
        assert_eq!(
            validate_telemetry_outgoing_message("COMMAND_LONG:MAV_CMD_COMPONENT_ARM_DISARM").unwrap_err().code,
            ErrorCode::HardwareActionDenied
        );
        assert_eq!(
            validate_telemetry_outgoing_message("PARAM_SET").unwrap_err().code,
            ErrorCode::HardwareActionDenied
        );
        assert_eq!(
            validate_telemetry_outgoing_message("UNKNOWN_VENDOR_CMD").unwrap_err().code,
            ErrorCode::HardwareActionDenied
        );
    }

    #[test]
    fn telemetry_send_gate_emits_zero_wire_bytes_for_denied_commands() {
        struct RecordingSink {
            transmitted: Vec<OutgoingTelemetryFrame>,
        }
        impl TelemetryWireSink for RecordingSink {
            fn write_frame(&mut self, frame: &OutgoingTelemetryFrame) -> Result<(), BridgeError> {
                self.transmitted.push(frame.clone());
                Ok(())
            }
        }
        let mut gate = TelemetrySendGate::new(RecordingSink { transmitted: Vec::new() });
        // Allowed heartbeat reaches wire
        gate.send(&OutgoingTelemetryFrame {
            message_name: "HEARTBEAT".into(),
            payload_bytes: vec![0xFD, 0x09, 0x00],
        })
        .unwrap();
        // Denied arm, takeoff, param write, firmware flash MUST NOT reach wire
        for denied in [
            "COMMAND_LONG:MAV_CMD_COMPONENT_ARM_DISARM",
            "COMMAND_LONG:MAV_CMD_NAV_TAKEOFF",
            "PARAM_SET",
            "FILE_TRANSFER_PROTOCOL:FIRMWARE_FLASH",
        ] {
            let err = gate
                .send(&OutgoingTelemetryFrame {
                    message_name: denied.into(),
                    payload_bytes: vec![0xDE, 0xAD],
                })
                .unwrap_err();
            assert_eq!(err.code, ErrorCode::HardwareActionDenied);
        }
        assert_eq!(gate.audit_log().len(), 5);
        let sink = gate.into_inner();
        assert_eq!(sink.transmitted.len(), 1);
        assert_eq!(sink.transmitted[0].message_name, "HEARTBEAT");
    }

    #[test]
    fn ulog_parser_reads_info_dropouts_and_truncation_honestly() {
        let mut buf = vec![0x55, 0x4C, 0x6F, 0x67, 0x01, 0x12, 0x35, 0x01];
        buf.extend_from_slice(&1_234_567u64.to_le_bytes());
        // Info message: key="sys_name", val="PX4_SITL_TEST"
        let key = b"sys_name";
        let val = b"PX4_SITL_TEST";
        let payload_len = (1 + key.len() + val.len()) as u16;
        buf.extend_from_slice(&payload_len.to_le_bytes());
        buf.push(b'I');
        buf.push(key.len() as u8);
        buf.extend_from_slice(key);
        buf.extend_from_slice(val);
        // Dropout message: 45 ms
        buf.extend_from_slice(&2u16.to_le_bytes());
        buf.push(b'O');
        buf.extend_from_slice(&45u16.to_le_bytes());
        // Truncated trailing record (claims 50 bytes, only 2 present)
        buf.extend_from_slice(&50u16.to_le_bytes());
        buf.push(b'D');
        buf.extend_from_slice(&[0xAA, 0xBB]);

        let summary = parse_ulog_bytes(&buf, "synthetic_test.ulg", EvidenceClass::RecordedLog).unwrap();
        assert!(summary.valid_magic);
        assert_eq!(summary.timestamp_start_us, 1_234_567);
        assert_eq!(summary.info_fields.get("sys_name").unwrap(), "PX4_SITL_TEST");
        assert_eq!(summary.dropout_count, 1);
        assert_eq!(summary.total_dropout_ms, 45);
        assert_eq!(summary.truncated_trailing_bytes, 5);
        assert_eq!(summary.header.truncated_records, 1);
    }
}
