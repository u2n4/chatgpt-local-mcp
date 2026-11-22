//! Supported Linux/WSL capability probes.
//! Never mutates the owner's global `.wslconfig` or WSL settings.

use bridge_types::{AvailableState, CapabilityStatus};
use chrono::Utc;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WslProbeResult {
    pub wsl_installed: bool,
    pub distros_detected: Vec<String>,
    pub isolation_verified: bool,
    pub capability: CapabilityStatus,
}

/// Read-only probe of WSL availability without starting stopped distros or changing settings.
pub fn probe_wsl_readonly() -> WslProbeResult {
    let now = Utc::now();
    let out = std::process::Command::new("wsl.exe")
        .args(["-l", "-q"])
        .stdin(std::process::Stdio::null())
        .output();
    match out {
        Ok(output) if output.status.success() => {
            // wsl.exe outputs UTF-16LE on Windows
            let raw = output.stdout;
            let text = if raw.len() >= 2 && raw.iter().skip(1).step_by(2).filter(|&&b| b == 0).count() > raw.len() / 4 {
                let u16s: Vec<u16> = raw
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                String::from_utf16_lossy(&u16s)
            } else {
                String::from_utf8_lossy(&raw).into_owned()
            };
            let distros: Vec<String> = text
                .lines()
                .map(|l| l.trim().trim_start_matches('\u{feff}').to_string())
                .filter(|l| !l.is_empty())
                .collect();
            let avail = if distros.is_empty() {
                AvailableState::False
            } else {
                AvailableState::True
            };
            WslProbeResult {
                wsl_installed: true,
                distros_detected: distros.clone(),
                isolation_verified: false,
                capability: CapabilityStatus {
                    implemented: true,
                    authorized: false,
                    available: avail,
                    verified: false,
                    last_verified_at: Some(now),
                    reason: format!(
                        "WSL distros detected ({:?}), but WSL presence alone is NOT proof of network/filesystem isolation; requires dedicated unprivileged container/namespace policy.",
                        distros
                    ),
                },
            }
        }
        _ => WslProbeResult {
            wsl_installed: false,
            distros_detected: Vec::new(),
            isolation_verified: false,
            capability: CapabilityStatus {
                implemented: true,
                authorized: false,
                available: AvailableState::False,
                verified: false,
                last_verified_at: Some(now),
                reason: "wsl.exe unavailable on this host.".to_string(),
            },
        },
    }
}
