//! Delivery manifest (spec 4.3) and minisign signatures.

use std::io::Cursor;

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

pub const MANIFEST_FORMAT: &str = "sealdrop-manifest/1";
pub const NOTES: &str = "expires is advisory and is not enforced by any software; release.window_secs is enforced by the named service for the encrypted package only";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiphertextInfo {
    pub file: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipientInfo {
    pub kind: String,
    pub fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseInfo {
    pub service: String,
    pub release_id: String,
    pub window_secs: u64,
    /// The service's minisign public key (base64), pinned at seal time for receipt checks.
    pub service_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub format: String,
    pub package_id: String,
    pub tool: String,
    pub created: String,
    pub ciphertext: CiphertextInfo,
    pub plaintext_tar_sha256: String,
    pub recipients: Vec<RecipientInfo>,
    pub signer: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classification: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release: Option<ReleaseInfo>,
    pub notes: String,
}

impl Manifest {
    pub fn to_json(&self) -> Result<Vec<u8>> {
        serde_json::to_vec_pretty(self).map_err(|e| Error::Manifest(e.to_string()))
    }

    pub fn from_json(bytes: &[u8]) -> Result<Manifest> {
        if bytes.len() > 1024 * 1024 {
            return Err(Error::Manifest("manifest too large".into()));
        }
        let m: Manifest =
            serde_json::from_slice(bytes).map_err(|e| Error::Manifest(e.to_string()))?;
        if m.format != MANIFEST_FORMAT {
            return Err(Error::Manifest(format!(
                "unknown manifest format {}",
                m.format
            )));
        }
        Ok(m)
    }
}

pub fn sign(
    bytes: &[u8],
    sk: &minisign::SecretKey,
    pk: &minisign::PublicKey,
    package_id: &str,
) -> Result<minisign::SignatureBox> {
    let comment = format!("sealdrop manifest {package_id}");
    minisign::sign(Some(pk), sk, Cursor::new(bytes), Some(&comment), None)
        .map_err(|e| Error::Manifest(format!("sign: {e}")))
}

pub fn verify(bytes: &[u8], sig: &minisign::SignatureBox, pk: &minisign::PublicKey) -> Result<()> {
    minisign::verify(pk, sig, Cursor::new(bytes), true, false, false)
        .map_err(|e| Error::Verify(format!("manifest signature invalid: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Manifest {
        Manifest {
            format: MANIFEST_FORMAT.into(),
            package_id: "11111111-2222-3333-4444-555555555555".into(),
            tool: crate::TOOL.into(),
            created: "2026-10-13T09:00:00Z".into(),
            ciphertext: CiphertextInfo {
                file: "r.sealdrop.age".into(),
                size: 10,
                sha256: "ab".into(),
            },
            plaintext_tar_sha256: "cd".into(),
            recipients: vec![RecipientInfo {
                kind: "x25519".into(),
                fingerprint: "0123456789abcdef".into(),
            }],
            signer: "RWQ...".into(),
            classification: Some("confidential".into()),
            expires: None,
            release: None,
            notes: NOTES.into(),
        }
    }

    #[test]
    fn json_round_trip_and_signature() {
        let m = sample();
        let bytes = m.to_json().unwrap();
        let back = Manifest::from_json(&bytes).unwrap();
        assert_eq!(back.package_id, m.package_id);
        let kp = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
        let sig = sign(&bytes, &kp.sk, &kp.pk, &m.package_id).unwrap();
        assert_eq!(
            sig.trusted_comment().unwrap(),
            format!("sealdrop manifest {}", m.package_id)
        );
        verify(&bytes, &sig, &kp.pk).unwrap();
        let mut tampered = bytes.clone();
        tampered[10] ^= 1;
        assert!(verify(&tampered, &sig, &kp.pk).is_err());
        let other = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
        assert!(verify(&bytes, &sig, &other.pk).is_err());
    }
}
