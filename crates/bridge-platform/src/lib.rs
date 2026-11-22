//! OS-specific security boundaries, path identity verification, Win32 Job Objects,
//! MXC containment probes, resource telemetry, and WSL/Linux runner probes.

pub mod linux;
#[cfg(windows)]
pub mod windows;

#[cfg(windows)]
pub use windows::{host_resources, host_resources_with_gpu};

/// Whether the peer has closed the reading end of our stdout. Only Windows pipes are probed.
#[cfg(windows)]
pub use windows::stdout_peer_closed;
#[cfg(not(windows))]
pub fn stdout_peer_closed() -> bool {
    false
}

#[cfg(not(windows))]
pub fn host_resources() -> HostResources {
    host_resources_with_gpu(true)
}

#[cfg(not(windows))]
pub fn host_resources_with_gpu(probe_gpu: bool) -> HostResources {
    HostResources {
        ram_total_mb: 0,
        ram_available_mb: 0,
        ram_used_percent: 0,
        process_working_set_bytes: None,
        gpu_probe: optional_gpu_probe(probe_gpu),
        desktop_name: None,
        mxc_default_desktop: false,
    }
}

use bridge_types::{AvailableState, BridgeError, CapabilityStatus, ErrorCode, OriginLayer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileIdentity {
    pub volume_serial: u32,
    pub file_index_high: u32,
    pub file_index_low: u32,
    pub is_reparse_point: bool,
    pub is_directory: bool,
    pub n_links: u32,
    pub size_bytes: u64,
}

impl FileIdentity {
    pub fn canonical_id(&self) -> String {
        format!(
            "ntfs:{:08x}:{:08x}{:08x}",
            self.volume_serial, self.file_index_high, self.file_index_low
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostResources {
    pub ram_total_mb: u64,
    pub ram_available_mb: u64,
    pub ram_used_percent: u32,
    pub process_working_set_bytes: Option<u64>,
    pub gpu_probe: CapabilityStatus,
    pub desktop_name: Option<String>,
    pub mxc_default_desktop: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainmentProbe {
    pub backend: String,
    pub pinned_version: String,
    pub binary_path: Option<String>,
    pub binary_sha256: Option<String>,
    pub binary_hash_verified: bool,
    pub desktop_name: Option<String>,
    pub interactive_default_desktop: bool,
    pub automatic_weaker_fallback: bool,
    pub status: CapabilityStatus,
}

pub fn sha256_file(path: &Path) -> Result<String, BridgeError> {
    sha256_file_with_len(path).map(|(digest, _)| digest)
}

/// SHA-256 of a file and the number of bytes hashed, read through a fixed buffer
/// so the cost in memory does not depend on the file size.
pub fn sha256_file_with_len(path: &Path) -> Result<(String, u64), BridgeError> {
    let file = File::open(path).map_err(|e| {
        BridgeError::new(
            ErrorCode::FileNotFound,
            format!("Cannot open file for SHA-256: {e}"),
            OriginLayer::FileService,
        )
    })?;
    sha256_handle_with_len(file)
}

pub fn sha256_handle_with_len(mut f: File) -> Result<(String, u64), BridgeError> {
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    let mut len = 0u64;
    loop {
        let n = f.read(&mut buf).map_err(|e| {
            BridgeError::new(
                ErrorCode::InternalError,
                format!("Read error during SHA-256: {e}"),
                OriginLayer::FileService,
            )
        })?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        len += n as u64;
    }
    Ok((hex::encode(hasher.finalize()), len))
}

pub fn sha256_bytes(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// Strictly validate a relative POSIX-style project path against Windows and POSIX hazards:
/// rejects UNC paths, device namespaces (`\\?\`, `\\.\`), drive-relative paths (`C:foo`),
/// Alternate Data Streams (`:`), Windows reserved device names (`CON`, `NUL`, `AUX`, `PRN`,
/// `COM1..9`, `LPT1..9` and their superscript digits), NUL bytes, trailing dots/spaces,
/// backslashes, and `..` traversal.
pub fn validate_relative_path(raw: &str) -> Result<Vec<String>, BridgeError> {
    if raw.is_empty() || raw.len() > 768 {
        return Err(BridgeError::new(
            ErrorCode::InvalidArgument,
            "Relative path length must be between 1 and 768 bytes.",
            OriginLayer::FileService,
        ));
    }
    if raw.contains('\0')
        || raw.contains('\\')
        || raw.contains(':')
        || raw.starts_with('/')
        || raw.starts_with("//")
    {
        return Err(BridgeError::new(
            ErrorCode::PathOutsideRoot,
            "Path contains forbidden drive, UNC, ADS, backslash, NUL, or absolute prefix.",
            OriginLayer::FileService,
        ));
    }
    if raw == "." {
        return Ok(Vec::new());
    }
    let mut parts = Vec::new();
    for seg in raw.split('/') {
        if seg.is_empty() || seg == "." || seg == ".." {
            return Err(BridgeError::new(
                ErrorCode::PathOutsideRoot,
                "Path contains empty, '.', or '..' traversal segment.",
                OriginLayer::FileService,
            ));
        }
        if seg.encode_utf16().count() > 255 {
            return Err(BridgeError::new(
                ErrorCode::InvalidArgument,
                "Each path component must fit within 255 UTF-16 code units.",
                OriginLayer::FileService,
            ));
        }
        if seg.ends_with('.') || seg.ends_with(' ') {
            return Err(BridgeError::new(
                ErrorCode::UnsupportedPathType,
                "Path segment cannot end with a trailing dot or space on Windows.",
                OriginLayer::FileService,
            ));
        }
        if seg.bytes().any(|b| b < 0x20 || matches!(b, b'<' | b'>' | b'"' | b'|' | b'?' | b'*')) {
            return Err(BridgeError::new(
                ErrorCode::UnsupportedPathType,
                "Path segment contains disallowed Windows control or wildcard characters.",
                OriginLayer::FileService,
            ));
        }
        let stem = seg.split('.').next().unwrap_or(seg).to_ascii_uppercase();
        let is_reserved = matches!(
            stem.as_str(),
            "CON"
                | "PRN"
                | "AUX"
                | "NUL"
                | "COM1"
                | "COM2"
                | "COM3"
                | "COM4"
                | "COM5"
                | "COM6"
                | "COM7"
                | "COM8"
                | "COM9"
                | "COM¹"
                | "COM²"
                | "COM³"
                | "LPT1"
                | "LPT2"
                | "LPT3"
                | "LPT4"
                | "LPT5"
                | "LPT6"
                | "LPT7"
                | "LPT8"
                | "LPT9"
                | "LPT¹"
                | "LPT²"
                | "LPT³"
        );
        if is_reserved {
            return Err(BridgeError::new(
                ErrorCode::UnsupportedPathType,
                format!("Reserved Windows device name '{seg}' is forbidden."),
                OriginLayer::FileService,
            ));
        }
        parts.push(seg.to_string());
    }
    Ok(parts)
}

fn optional_gpu_probe(probe: bool) -> CapabilityStatus {
    if probe {
        return probe_gpu_honest();
    }
    CapabilityStatus {
        implemented: true,
        authorized: true,
        available: AvailableState::Unknown,
        verified: false,
        last_verified_at: None,
        reason: "GPU sampling is available in the local doctor and owner overview.".into(),
    }
}

pub fn probe_gpu_honest() -> CapabilityStatus {
    let now = chrono::Utc::now();
    let probe = std::process::Command::new("nvidia-smi")
        .args([
            "--query-gpu=name,utilization.gpu,memory.used,memory.total",
            "--format=csv,noheader,nounits",
        ])
        .stdin(std::process::Stdio::null())
        .output();
    match probe {
        Ok(out) if out.status.success() => {
            let line = String::from_utf8_lossy(&out.stdout)
                .lines()
                .next()
                .unwrap_or("")
                .trim()
                .to_string();
            if !line.is_empty() {
                return CapabilityStatus {
                    implemented: true,
                    authorized: true,
                    available: AvailableState::True,
                    verified: true,
                    last_verified_at: Some(now),
                    reason: format!("nvidia-smi reported GPU: {line}"),
                };
            }
            CapabilityStatus {
                implemented: true,
                authorized: true,
                available: AvailableState::Unknown,
                verified: false,
                last_verified_at: Some(now),
                reason: "nvidia-smi returned empty output; GPU presence is unknown to this probe."
                    .to_string(),
            }
        }
        Ok(out) => CapabilityStatus {
            implemented: true,
            authorized: true,
            available: AvailableState::Unknown,
            verified: false,
            last_verified_at: Some(now),
            reason: format!(
                "nvidia-smi exited with code {:?}; GPU presence is unknown/unavailable to this probe (not proof of absence).",
                out.status.code()
            ),
        },
        Err(e) => CapabilityStatus {
            implemented: true,
            authorized: true,
            available: AvailableState::Unknown,
            verified: false,
            last_verified_at: Some(now),
            reason: format!(
                "nvidia-smi unavailable ({e}); GPU presence is unknown/unavailable to this probe (not proof of absence)."
            ),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_path_counts_each_component_in_utf16_code_units() {
        let at_limit = format!("{}x", "\u{1f642}".repeat(127));
        let over_limit = format!("{at_limit}x");
        assert_eq!(validate_relative_path(&format!("dir/{at_limit}")).unwrap()[1], at_limit);
        assert_eq!(validate_relative_path(&format!("dir/{over_limit}")).unwrap_err().code, ErrorCode::InvalidArgument);
        assert_eq!(validate_relative_path(&format!("dir/{}", "a".repeat(256))).unwrap_err().code, ErrorCode::InvalidArgument);
    }

    #[test]
    fn path_validator_blocks_windows_hazards() {
        assert_eq!(
            validate_relative_path("src/main.rs").unwrap(),
            vec!["src", "main.rs"]
        );
        assert!(validate_relative_path(".").unwrap().is_empty());
        // Traversal & absolute
        assert!(validate_relative_path("../secret.txt").is_err());
        assert!(validate_relative_path("/etc/passwd").is_err());
        assert!(validate_relative_path("a\\b").is_err());
        // UNC & ADS & Drive-relative
        assert!(validate_relative_path("//server/share/file").is_err());
        assert!(validate_relative_path("foo.txt:stream").is_err());
        assert!(validate_relative_path("C:relative.txt").is_err());
        // Reserved Windows device names
        assert!(validate_relative_path("CON").is_err());
        assert!(validate_relative_path("dir/nul.txt").is_err());
        assert!(validate_relative_path("com1.log").is_err());
        assert!(validate_relative_path("lpt9").is_err());
        // Trailing dot/space
        assert!(validate_relative_path("file.").is_err());
        assert!(validate_relative_path("file ").is_err());
    }

    #[test]
    fn rejects_windows_device_names_with_superscript_digits() {
        for prefix in ["com", "LpT"] {
            for digit in ['¹', '²', '³'] {
                for extension in ["", ".log"] {
                    let path = format!("dir/{prefix}{digit}{extension}");
                    assert_eq!(validate_relative_path(&path).unwrap_err().code, ErrorCode::UnsupportedPathType);
                }
            }
        }
        assert!(validate_relative_path("dir/report³.txt").is_ok());
    }
}
