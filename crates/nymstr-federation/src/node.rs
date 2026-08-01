//! Node identity (spec §2), signed tree heads (spec §5.3), inclusion
//! promises (spec §7), and witness signatures (spec §12).

use super::canonical::to_canonical_json;
use super::epoch::EpochHeader;
use super::{hash_hex, labels, FederationError, SignatureVerifier};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

/// `nodeId = lowercase hex SHA256(armored node public key)` (spec §2.1).
pub fn node_id_for(node_pk_armored: &str) -> String {
    hash_hex(&Sha256::digest(node_pk_armored.as_bytes()).into())
}

/// Signed, self-contained node descriptor (spec §2.2). Soft state: newest
/// `issuedAt` wins; anyone may cache and re-serve it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeDescriptor {
    pub version: u32,
    pub node_id: String,
    pub node_pk: String,
    pub nym_address: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
    pub epoch_seconds: u64,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub policy: Value,
    pub issued_at: String,
    pub sig: String,
}

impl NodeDescriptor {
    /// `"nymstr-descriptor-v2:" || JCS(descriptor without sig)`.
    pub fn signing_payload(&self) -> Result<String, FederationError> {
        let mut json =
            serde_json::to_value(self).map_err(|_| FederationError::NonCanonicalNumber)?;
        json.as_object_mut()
            .expect("descriptor serializes to an object")
            .remove("sig");
        Ok(format!(
            "{}{}",
            labels::DESCRIPTOR,
            to_canonical_json(&json)?
        ))
    }

    /// Full verification: structural checks, fingerprint binding, signature.
    /// After this returns Ok, `node_pk` is THE key for `node_id` and every
    /// other field is authentic (spec §2.2).
    pub fn verify(&self, verifier: &dyn SignatureVerifier) -> Result<(), FederationError> {
        if self.version != 2 {
            return Err(FederationError::BadDescriptor("unsupported version"));
        }
        if self.node_pk.is_empty() || self.nym_address.is_empty() {
            return Err(FederationError::BadDescriptor("incomplete descriptor"));
        }
        if self.epoch_seconds == 0 {
            return Err(FederationError::BadDescriptor(
                "epochSeconds must be positive",
            ));
        }
        if self.node_id != node_id_for(&self.node_pk) {
            return Err(FederationError::BadDescriptor("nodeId does not match key"));
        }
        if !verifier.verify(&self.node_pk, &self.signing_payload()?, &self.sig) {
            return Err(FederationError::BadDescriptor("bad signature"));
        }
        Ok(())
    }
}

/// The string signed over an epoch hash — by the node itself (STH) with the
/// cosign label, by witnesses with the witness label (spec §5.3, §12.1).
pub fn sth_signing_payload(epoch_hash_hex: &str) -> String {
    format!("{}{epoch_hash_hex}", labels::COSIGN)
}

pub fn witness_signing_payload(epoch_hash_hex: &str) -> String {
    format!("{}{epoch_hash_hex}", labels::WITNESS)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WitnessSignature {
    /// Witness key fingerprint, computed like a nodeId.
    pub witness_id: String,
    pub sig: String,
}

/// A published epoch: header + node signature + lazily accumulated witness
/// signatures (spec §5.3). The node signature alone finalizes the epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedTreeHead {
    pub header: EpochHeader,
    pub node_sig: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub witness_sigs: Vec<WitnessSignature>,
}

impl SignedTreeHead {
    /// Verify the node's own signature against its (descriptor-verified) key,
    /// including that the header actually names that node.
    pub fn verify_node_sig(
        &self,
        node_id: &str,
        node_pk: &str,
        verifier: &dyn SignatureVerifier,
    ) -> Result<(), FederationError> {
        if self.header.node_id != node_id {
            return Err(FederationError::BadProof);
        }
        let payload = sth_signing_payload(&self.header.hash_hex()?);
        if !verifier.verify(node_pk, &payload, &self.node_sig) {
            return Err(FederationError::BadSignature);
        }
        Ok(())
    }

    /// Count valid witness signatures from a caller-trusted witness set
    /// (`(witness_id, witness_pk)` pairs) and require at least `min_witnesses`
    /// (spec §12.3). Signatures from unknown witnesses are ignored, not
    /// errors — the STH may carry endorsements the caller doesn't trust.
    pub fn verify_witnesses(
        &self,
        trusted: &[(String, String)],
        min_witnesses: usize,
        verifier: &dyn SignatureVerifier,
    ) -> Result<usize, FederationError> {
        let payload = witness_signing_payload(&self.header.hash_hex()?);
        let mut seen: HashSet<&str> = HashSet::new();
        let mut have = 0usize;
        for ws in &self.witness_sigs {
            if !seen.insert(ws.witness_id.as_str()) {
                return Err(FederationError::DuplicateSigner(ws.witness_id.clone()));
            }
            let Some((_, pk)) = trusted.iter().find(|(id, _)| *id == ws.witness_id) else {
                continue;
            };
            if verifier.verify(pk, &payload, &ws.sig) {
                have += 1;
            }
        }
        if have >= min_witnesses {
            Ok(have)
        } else {
            Err(FederationError::ThresholdNotMet {
                have,
                need: min_witnesses,
            })
        }
    }
}

/// Signed inclusion promise returned by `submitMutation` (spec §7): the node
/// commits to including the mutation in a finalized epoch no later than
/// `deadlineEpoch`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InclusionPromise {
    pub mutation_hash: String,
    pub received_epoch: u64,
    pub deadline_epoch: u64,
    pub node_id: String,
    pub sig: String,
}

pub const PROMISE_WINDOW_EPOCHS: u64 = 3;

impl InclusionPromise {
    /// `"nymstr-promise-v2:" || JCS(promise without sig)`.
    pub fn signing_payload(&self) -> Result<String, FederationError> {
        let mut json =
            serde_json::to_value(self).map_err(|_| FederationError::NonCanonicalNumber)?;
        json.as_object_mut()
            .expect("promise serializes to an object")
            .remove("sig");
        Ok(format!("{}{}", labels::PROMISE, to_canonical_json(&json)?))
    }

    pub fn verify(
        &self,
        node_id: &str,
        node_pk: &str,
        verifier: &dyn SignatureVerifier,
    ) -> Result<(), FederationError> {
        if self.node_id != node_id || self.deadline_epoch < self.received_epoch {
            return Err(FederationError::BadProof);
        }
        if !verifier.verify(node_pk, &self.signing_payload()?, &self.sig) {
            return Err(FederationError::BadSignature);
        }
        Ok(())
    }
}

/// Evidence that a node signed two different tree heads for the same epoch —
/// the split-view / fork certificate (spec §12.2). Self-verifying given the
/// node's descriptor-bound key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForkCertificate {
    pub node_id: String,
    pub first: SignedTreeHead,
    pub second: SignedTreeHead,
}

impl ForkCertificate {
    /// Valid iff both STHs carry genuine node signatures for the SAME epoch
    /// with DIFFERENT header hashes.
    pub fn verify(
        &self,
        node_pk: &str,
        verifier: &dyn SignatureVerifier,
    ) -> Result<(), FederationError> {
        self.first
            .verify_node_sig(&self.node_id, node_pk, verifier)?;
        self.second
            .verify_node_sig(&self.node_id, node_pk, verifier)?;
        if self.first.header.epoch != self.second.header.epoch {
            return Err(FederationError::BadProof);
        }
        if self.first.header.hash()? == self.second.header.hash()? {
            return Err(FederationError::BadProof);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::labeled_hash;
    use crate::testutil::{mock_sign, MockVerifier};
    use serde_json::json;

    fn descriptor(pk: &str) -> NodeDescriptor {
        let mut d = NodeDescriptor {
            version: 2,
            node_id: node_id_for(pk),
            node_pk: pk.to_string(),
            nym_address: "nym://addr".to_string(),
            aliases: vec![],
            epoch_seconds: 30,
            policy: json!({"registration": "open"}),
            issued_at: "2026-07-15T12:00:00Z".to_string(),
            sig: String::new(),
        };
        d.sig = mock_sign(pk, &d.signing_payload().unwrap());
        d
    }

    fn header(epoch: u64, node_id: &str, salt: &str) -> EpochHeader {
        EpochHeader {
            version: 2,
            epoch,
            prev_epoch_hash: hash_hex(&labeled_hash("t:", salt.as_bytes())),
            directory_root: hash_hex(&[1u8; 32]),
            log_root: hash_hex(&[2u8; 32]),
            mutations_hash: hash_hex(&[3u8; 32]),
            mutation_count: 1,
            node_id: node_id.to_string(),
            timestamp: "2026-07-15T12:00:00Z".to_string(),
        }
    }

    fn sth(h: EpochHeader, node_pk: &str) -> SignedTreeHead {
        let sig = mock_sign(node_pk, &sth_signing_payload(&h.hash_hex().unwrap()));
        SignedTreeHead {
            header: h,
            node_sig: sig,
            witness_sigs: vec![],
        }
    }

    #[test]
    fn descriptor_roundtrip_and_tamper() {
        let v = MockVerifier::default();
        let d = descriptor("pk-node");
        d.verify(&v).unwrap();

        // Fingerprint mismatch.
        let mut bad = d.clone();
        bad.node_id = "0".repeat(64);
        assert_eq!(
            bad.verify(&v).unwrap_err(),
            FederationError::BadDescriptor("nodeId does not match key")
        );

        // Any field tamper breaks the signature.
        let mut bad = d.clone();
        bad.nym_address = "nym://evil".to_string();
        assert_eq!(
            bad.verify(&v).unwrap_err(),
            FederationError::BadDescriptor("bad signature")
        );

        // A different key can't claim this nodeId.
        let mut bad = d.clone();
        bad.node_pk = "pk-mallory".to_string();
        bad.sig = mock_sign("pk-mallory", &bad.signing_payload().unwrap());
        assert_eq!(
            bad.verify(&v).unwrap_err(),
            FederationError::BadDescriptor("nodeId does not match key")
        );
    }

    #[test]
    fn sth_node_signature() {
        let v = MockVerifier::default();
        let node_id = node_id_for("pk-node");
        let s = sth(header(5, &node_id, "a"), "pk-node");
        s.verify_node_sig(&node_id, "pk-node", &v).unwrap();

        // Wrong node id in header.
        let foreign = sth(header(5, &node_id_for("pk-other"), "a"), "pk-node");
        assert_eq!(
            foreign
                .verify_node_sig(&node_id, "pk-node", &v)
                .unwrap_err(),
            FederationError::BadProof
        );

        // Signature by another key.
        let forged = sth(header(5, &node_id, "a"), "pk-mallory");
        assert_eq!(
            forged.verify_node_sig(&node_id, "pk-node", &v).unwrap_err(),
            FederationError::BadSignature
        );
    }

    #[test]
    fn witness_threshold_counting() {
        let v = MockVerifier::default();
        let node_id = node_id_for("pk-node");
        let mut s = sth(header(9, &node_id, "b"), "pk-node");
        let payload = witness_signing_payload(&s.header.hash_hex().unwrap());

        let trusted: Vec<(String, String)> = (0..3)
            .map(|i| (node_id_for(&format!("pk-w{i}")), format!("pk-w{i}")))
            .collect();

        // Two trusted witnesses + one unknown + one forged.
        s.witness_sigs = vec![
            WitnessSignature {
                witness_id: trusted[0].0.clone(),
                sig: mock_sign("pk-w0", &payload),
            },
            WitnessSignature {
                witness_id: trusted[1].0.clone(),
                sig: mock_sign("pk-w1", &payload),
            },
            WitnessSignature {
                witness_id: node_id_for("pk-unknown"),
                sig: mock_sign("pk-unknown", &payload),
            },
            WitnessSignature {
                witness_id: trusted[2].0.clone(),
                sig: mock_sign("pk-mallory", &payload),
            },
        ];
        assert_eq!(s.verify_witnesses(&trusted, 2, &v).unwrap(), 2);
        assert!(matches!(
            s.verify_witnesses(&trusted, 3, &v).unwrap_err(),
            FederationError::ThresholdNotMet { have: 2, need: 3 }
        ));

        // Duplicate witness ids are an error, not double-counted.
        s.witness_sigs.push(s.witness_sigs[0].clone());
        assert!(matches!(
            s.verify_witnesses(&trusted, 1, &v).unwrap_err(),
            FederationError::DuplicateSigner(_)
        ));
    }

    #[test]
    fn promise_roundtrip_and_tamper() {
        let v = MockVerifier::default();
        let node_id = node_id_for("pk-node");
        let mut p = InclusionPromise {
            mutation_hash: hash_hex(&[7u8; 32]),
            received_epoch: 10,
            deadline_epoch: 13,
            node_id: node_id.clone(),
            sig: String::new(),
        };
        p.sig = mock_sign("pk-node", &p.signing_payload().unwrap());
        p.verify(&node_id, "pk-node", &v).unwrap();

        let mut widened = p.clone();
        widened.deadline_epoch = 99; // node can't quietly extend its deadline
        assert_eq!(
            widened.verify(&node_id, "pk-node", &v).unwrap_err(),
            FederationError::BadSignature
        );

        let mut inverted = p.clone();
        inverted.deadline_epoch = 5;
        inverted.sig = mock_sign("pk-node", &inverted.signing_payload().unwrap());
        assert_eq!(
            inverted.verify(&node_id, "pk-node", &v).unwrap_err(),
            FederationError::BadProof
        );
    }

    #[test]
    fn fork_certificate() {
        let v = MockVerifier::default();
        let node_id = node_id_for("pk-node");

        // Two genuinely signed, different headers for the same epoch: fork.
        let cert = ForkCertificate {
            node_id: node_id.clone(),
            first: sth(header(7, &node_id, "x"), "pk-node"),
            second: sth(header(7, &node_id, "y"), "pk-node"),
        };
        cert.verify("pk-node", &v).unwrap();

        // Different epochs: not a fork.
        let not_fork = ForkCertificate {
            node_id: node_id.clone(),
            first: sth(header(7, &node_id, "x"), "pk-node"),
            second: sth(header(8, &node_id, "y"), "pk-node"),
        };
        assert_eq!(
            not_fork.verify("pk-node", &v).unwrap_err(),
            FederationError::BadProof
        );

        // Identical heads: not a fork.
        let same = ForkCertificate {
            node_id: node_id.clone(),
            first: sth(header(7, &node_id, "x"), "pk-node"),
            second: sth(header(7, &node_id, "x"), "pk-node"),
        };
        assert_eq!(
            same.verify("pk-node", &v).unwrap_err(),
            FederationError::BadProof
        );

        // A forged half can't frame an honest node.
        let framed = ForkCertificate {
            node_id: node_id.clone(),
            first: sth(header(7, &node_id, "x"), "pk-node"),
            second: sth(header(7, &node_id, "y"), "pk-mallory"),
        };
        assert_eq!(
            framed.verify("pk-node", &v).unwrap_err(),
            FederationError::BadSignature
        );
    }
}
