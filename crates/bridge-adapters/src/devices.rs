//! Authenticated Multi-Device Pairing & Host-Agent Channel (§10).
//! - Per-device Ed25519 identity keypair + explicit `host_id` (friendly hostname is NEVER trusted identity).
//! - Short-lived one-time pairing token displaying explicit scopes on the target computer.
//! - Mutual Ed25519 signed request verification + nonce replay protection + target-host policy check.
//! - Each host keeps its own local SQLite database (NEVER shared WAL over SMB/NFS).

use bridge_core::evidence::load_or_create_device_signing_key;
use bridge_core::state::StateStore;
use bridge_platform::sha256_bytes;
use bridge_types::*;
use chrono::{Duration, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::path::Path;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalHostIdentity {
    pub host_id: HostId,
    pub display_name: String,
    pub public_key_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingOffer {
    pub token_id: String,
    pub one_time_secret: String,
    pub target_host_id: HostId,
    pub scopes: Vec<String>,
    pub expires_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedHostEnvelope {
    pub sender_host_id: String,
    pub nonce: String,
    pub timestamp_unix: i64,
    pub payload_json: String,
    pub signature_ed25519_hex: String,
}

pub struct DeviceChannel {
    store: StateStore,
    signing_key: SigningKey,
    local_identity: LocalHostIdentity,
    seen_nonces: Arc<Mutex<HashSet<String>>>,
}

impl DeviceChannel {
    pub fn init(store: StateStore, state_dir: &Path, display_name: &str) -> Result<Self, BridgeError> {
        let (sk, pk_hex) = load_or_create_device_signing_key(state_dir)?;
        let host_id = HostId(format!("host_{}", &pk_hex[..16]));
        Ok(Self {
            store,
            signing_key: sk,
            local_identity: LocalHostIdentity {
                host_id,
                display_name: display_name.to_string(),
                public_key_hex: pk_hex,
            },
            seen_nonces: Arc::new(Mutex::new(HashSet::new())),
        })
    }

    pub fn local_identity(&self) -> &LocalHostIdentity {
        &self.local_identity
    }

    /// Create a short-lived one-time pairing token bound to an explicit target `host_id` and scopes.
    pub fn create_pairing_offer(
        &self,
        target_host_id: HostId,
        scopes: Vec<String>,
        ttl_seconds: i64,
    ) -> Result<PairingOffer, BridgeError> {
        let token_id = format!("pair_{}", uuid::Uuid::new_v4().simple());
        let secret = format!("{}{}", uuid::Uuid::new_v4().simple(), uuid::Uuid::new_v4().simple());
        let token_hash = sha256_bytes(secret.as_bytes());
        let expires_at = Utc::now() + Duration::seconds(ttl_seconds.clamp(30, 900));
        self.store
            .create_pairing_token(&token_id, &token_hash, &target_host_id.0, &scopes, expires_at)?;
        Ok(PairingOffer {
            token_id,
            one_time_secret: secret,
            target_host_id,
            scopes,
            expires_at,
        })
    }

    /// Complete pairing on the owner/broker side by validating the one-time token and binding
    /// the peer's Ed25519 public key and approved scopes.
    pub fn complete_pairing(
        &self,
        one_time_secret: &str,
        peer_identity: &LocalHostIdentity,
        endpoint_url: &str,
        peer_capabilities: BTreeMap<String, CapabilityStatus>,
    ) -> Result<DeviceRecord, BridgeError> {
        // Verify host_id matches peer public key fingerprint (prevents hostname spoofing!)
        let expected_hid = format!("host_{}", &peer_identity.public_key_hex[..16.min(peer_identity.public_key_hex.len())]);
        if peer_identity.host_id.0 != expected_hid {
            return Err(BridgeError::new(
                ErrorCode::AuthRequired,
                "Peer host_id does not match Ed25519 public key fingerprint.",
                OriginLayer::DeviceChannel,
            ));
        }
        let token_hash = sha256_bytes(one_time_secret.as_bytes());
        let approved_scopes = self
            .store
            .consume_pairing_token(&token_hash, &peer_identity.host_id.0)?;

        let record = DeviceRecord {
            host_id: peer_identity.host_id.clone(),
            display_name: peer_identity.display_name.clone(),
            public_key_hex: peer_identity.public_key_hex.clone(),
            endpoint_url: endpoint_url.to_string(),
            approved_scopes,
            capabilities: peer_capabilities,
            status: "paired_verified".to_string(),
            last_heartbeat_at: Some(Utc::now()),
            paired_at: Utc::now(),
            revoked: false,
        };
        self.store.upsert_paired_device(&record)?;
        Ok(record)
    }

    pub fn sign_envelope(&self, payload_json: String) -> SignedHostEnvelope {
        let nonce = uuid::Uuid::new_v4().simple().to_string();
        let ts = Utc::now().timestamp();
        let signing_input = format!(
            "edge-bridge-host/v0.4|{}|{}|{}|{}",
            self.local_identity.host_id.0, nonce, ts, payload_json
        );
        let sig: Signature = self.signing_key.sign(signing_input.as_bytes());
        SignedHostEnvelope {
            sender_host_id: self.local_identity.host_id.0.clone(),
            nonce,
            timestamp_unix: ts,
            payload_json,
            signature_ed25519_hex: hex::encode(sig.to_bytes()),
        }
    }

    /// Authenticate an incoming signed envelope from a paired peer host, verifying:
    /// 1) Sender is paired and NOT revoked
    /// 2) Timestamp is within +/- 30 seconds
    /// 3) Nonce has never been replayed
    /// 4) Ed25519 signature matches paired device's pinned public key
    pub fn verify_incoming_envelope(&self, env: &SignedHostEnvelope) -> Result<DeviceRecord, BridgeError> {
        let now_ts = Utc::now().timestamp();
        if (now_ts - env.timestamp_unix).abs() > 30 {
            return Err(BridgeError::new(
                ErrorCode::AuthRequired,
                "Signed host envelope timestamp outside 30-second freshness window.",
                OriginLayer::DeviceChannel,
            ));
        }
        let devices = self.store.list_paired_devices()?;
        let peer = devices
            .into_iter()
            .find(|d| d.host_id.0 == env.sender_host_id && !d.revoked)
            .ok_or_else(|| {
                BridgeError::new(
                    ErrorCode::DeviceNotPaired,
                    format!("Host '{}' is not paired or has been revoked.", env.sender_host_id),
                    OriginLayer::DeviceChannel,
                )
            })?;

        let pk_bytes: [u8; 32] = hex::decode(&peer.public_key_hex)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| BridgeError::new(ErrorCode::AuthRequired, "Invalid stored peer public key.", OriginLayer::DeviceChannel))?;
        let sig_bytes: [u8; 64] = hex::decode(&env.signature_ed25519_hex)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| BridgeError::new(ErrorCode::AuthRequired, "Invalid envelope signature format.", OriginLayer::DeviceChannel))?;

        let vk = VerifyingKey::from_bytes(&pk_bytes).map_err(|_| {
            BridgeError::new(ErrorCode::AuthRequired, "Corrupt peer Ed25519 key.", OriginLayer::DeviceChannel)
        })?;
        let sig = Signature::from_bytes(&sig_bytes);
        let signing_input = format!(
            "edge-bridge-host/v0.4|{}|{}|{}|{}",
            env.sender_host_id, env.nonce, env.timestamp_unix, env.payload_json
        );
        vk.verify(signing_input.as_bytes(), &sig).map_err(|_| {
            BridgeError::new(
                ErrorCode::AuthRequired,
                "Peer Ed25519 signature verification failed.",
                OriginLayer::DeviceChannel,
            )
        })?;

        let mut nonces = self.seen_nonces.lock().unwrap();
        if nonces.len() > 16_384 {
            nonces.clear();
        }
        if !nonces.insert(format!("{}:{}", env.sender_host_id, env.nonce)) {
            return Err(BridgeError::new(
                ErrorCode::AuthRequired,
                "Replayed host envelope nonce rejected.",
                OriginLayer::DeviceChannel,
            ));
        }

        Ok(peer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutual_ed25519_pairing_verification_and_replay_rejection() {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let store_a = StateStore::open(dir_a.path().join("state.sqlite3")).unwrap();
        let store_b = StateStore::open(dir_b.path().join("state.sqlite3")).unwrap();

        let host_a = DeviceChannel::init(store_a, dir_a.path(), "Host-A-Owner").unwrap();
        let host_b = DeviceChannel::init(store_b, dir_b.path(), "Host-B-Rehearsal").unwrap();

        // Host A issues one-time token explicitly bound to Host B's cryptographic host_id
        let offer = host_a
            .create_pairing_offer(
                host_b.local_identity().host_id.clone(),
                vec!["project:bridgepulse-lab:read".into(), "project:bridgepulse-lab:test".into()],
                300,
            )
            .unwrap();

        // Complete pairing
        let paired = host_a
            .complete_pairing(
                &offer.one_time_secret,
                host_b.local_identity(),
                "https://127.0.0.1:18443",
                BTreeMap::new(),
            )
            .unwrap();
        assert_eq!(paired.host_id, host_b.local_identity().host_id);

        // One-time token cannot be reused
        assert!(host_a
            .complete_pairing(&offer.one_time_secret, host_b.local_identity(), "https://127.0.0.1:18443", BTreeMap::new())
            .is_err());

        // Host B signs a scoped message -> Host A verifies it
        let env = host_b.sign_envelope(r#"{"op":"status"}"#.to_string());
        let verified_peer = host_a.verify_incoming_envelope(&env).unwrap();
        assert_eq!(verified_peer.host_id, host_b.local_identity().host_id);

        // Replaying the exact signed envelope MUST fail!
        assert_eq!(
            host_a.verify_incoming_envelope(&env).unwrap_err().code,
            ErrorCode::AuthRequired
        );
    }
}
