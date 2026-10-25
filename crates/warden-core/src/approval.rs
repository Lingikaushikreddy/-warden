//! Signed, single-use approvals.
//!
//! An [`Approval`] is an ed25519 signature over a domain-separated message
//! binding exactly one action (SHA-256 of [`Action::canonical_bytes`]), one
//! granted [`Tier`], and one random 128-bit nonce:
//!
//! ```text
//! b"warden/approval/v1\0" || action_hash (32) || tier byte (1) || nonce (16)
//! ```
//!
//! [`Approver::redeem`] accepts an approval at most once. `Blocked` actions can
//! never be approved: [`Approver::grant`] refuses them, and `redeem` rejects
//! them even when the approval carries a valid signature.
//!
//! The spent-nonce set is held in memory only. A restarted `Approver` forgets
//! which nonces were spent; persisting it across restarts is Plan 2.
//! The set grows only with legitimate redemptions: a nonce is recorded only
//! after every other check has passed, so rejected approvals never add to it.

use crate::action::Action;
use crate::policy::Tier;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt;

/// Domain-separation prefix for the signed approval message.
pub const APPROVAL_DOMAIN: &[u8] = b"warden/approval/v1\0";

/// The byte that encodes `tier` in the signed message.
///
/// Pinned by a test. Changing a value invalidates every outstanding approval.
/// The match is exhaustive, so a new `Tier` variant fails to compile here.
pub fn tier_byte(tier: Tier) -> u8 {
    match tier {
        Tier::Auto => 0,
        Tier::Yes => 1,
        Tier::YesPin => 2,
        Tier::Blocked => 3,
    }
}

/// The exact bytes an approval signature covers.
pub fn approval_message(action_hash: &[u8; 32], tier: Tier, nonce: &[u8; 16]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(APPROVAL_DOMAIN.len() + 32 + 1 + 16);
    msg.extend_from_slice(APPROVAL_DOMAIN);
    msg.extend_from_slice(action_hash);
    msg.push(tier_byte(tier));
    msg.extend_from_slice(nonce);
    msg
}

fn action_hash(action: &Action) -> [u8; 32] {
    Sha256::digest(action.canonical_bytes()).into()
}

/// Why an approval was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ApprovalError {
    #[error("blocked actions can never be approved")]
    Blocked,
    #[error("approval is for a different action")]
    WrongAction,
    #[error("approval signature is invalid")]
    BadSignature,
    #[error("approval has already been used")]
    AlreadyUsed,
    #[error("approval tier is lower than the action requires")]
    InsufficientTier,
}

/// A signed approval for one action at one tier, usable once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Approval {
    #[serde(with = "hex_bytes")]
    pub action_hash: [u8; 32],
    pub tier: Tier,
    #[serde(with = "hex_bytes")]
    pub nonce: [u8; 16],
    #[serde(with = "hex_signature")]
    pub signature: Signature,
}

/// Holds the approval signing key and the in-memory set of spent nonces.
pub struct Approver {
    key: SigningKey,
    spent: HashSet<[u8; 16]>,
}

impl fmt::Debug for Approver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Approver")
            .field(
                "verifying_key",
                &hex::encode(self.key.verifying_key().as_bytes()),
            )
            .field("spent", &self.spent.len())
            .finish_non_exhaustive()
    }
}

impl Approver {
    /// A new approver with a fresh key from the OS RNG.
    pub fn generate() -> Approver {
        Approver::from_signing_key(SigningKey::generate(&mut OsRng))
    }

    /// An approver using an existing key, with no spent nonces.
    ///
    /// # Security
    ///
    /// The returned `Approver` starts with an EMPTY spent-nonce set, and
    /// approvals carry no expiry or epoch. Reloading a key this way (for
    /// example after a restart) re-enables every approval that key ever
    /// signed, including ones already redeemed: they can be replayed once
    /// more. Until the spent-nonce set is persisted alongside the key and
    /// approvals carry an expiry (Plan 2), only use this with a fresh key or
    /// in tests. See docs/SECURITY-NOTES.md, "Approvals: expiry and persisted
    /// nonces".
    pub fn from_signing_key(key: SigningKey) -> Approver {
        Approver {
            key,
            spent: HashSet::new(),
        }
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    /// Sign an approval for `action` at `tier`. Refuses `Blocked`.
    pub fn grant(&self, action: &Action, tier: Tier) -> Result<Approval, ApprovalError> {
        if tier == Tier::Blocked {
            return Err(ApprovalError::Blocked);
        }
        let action_hash = action_hash(action);
        let mut nonce = [0u8; 16];
        OsRng.fill_bytes(&mut nonce);
        let signature = self.key.sign(&approval_message(&action_hash, tier, &nonce));
        Ok(Approval {
            action_hash,
            tier,
            nonce,
            signature,
        })
    }

    /// Accept `approval` for `action`, whose classifier-computed tier is
    /// `required`. Checks, in order: neither tier is `Blocked`; the action
    /// hash matches; the signature verifies (strict); the granted tier covers
    /// `required`; the nonce is unspent. Only after all pass is the nonce
    /// marked spent, so a failed redeem never burns it.
    pub fn redeem(
        &mut self,
        action: &Action,
        required: Tier,
        approval: &Approval,
    ) -> Result<(), ApprovalError> {
        if required == Tier::Blocked || approval.tier == Tier::Blocked {
            return Err(ApprovalError::Blocked);
        }
        let hash = action_hash(action);
        if hash != approval.action_hash {
            return Err(ApprovalError::WrongAction);
        }
        // Sign-check over the locally computed hash, never the claimed one.
        let msg = approval_message(&hash, approval.tier, &approval.nonce);
        self.key
            .verifying_key()
            .verify_strict(&msg, &approval.signature)
            .map_err(|_| ApprovalError::BadSignature)?;
        if approval.tier < required {
            return Err(ApprovalError::InsufficientTier);
        }
        // Single check-and-mark, reached only after every other check passed.
        if !self.spent.insert(approval.nonce) {
            return Err(ApprovalError::AlreadyUsed);
        }
        Ok(())
    }
}

mod hex_bytes {
    use serde::{de::Error, Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer, const N: usize>(b: &[u8; N], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(b))
    }

    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        d: D,
    ) -> Result<[u8; N], D::Error> {
        let s = String::deserialize(d)?;
        let mut out = [0u8; N];
        hex::decode_to_slice(&s, &mut out).map_err(D::Error::custom)?;
        Ok(out)
    }
}

mod hex_signature {
    use ed25519_dalek::Signature;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(sig: &Signature, s: S) -> Result<S::Ok, S::Error> {
        super::hex_bytes::serialize(&sig.to_bytes(), s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Signature, D::Error> {
        let b: [u8; 64] = super::hex_bytes::deserialize(d)?;
        Ok(Signature::from_bytes(&b))
    }
}
