//! Signed, single-use approvals.
//!
//! An [`Approval`] is an ed25519 signature over a domain-separated message
//! binding exactly one action (SHA-256 of [`Action::canonical_bytes`]), one
//! granted [`Tier`], a validity window, and one random 128-bit nonce:
//!
//! ```text
//! b"warden/approval/v2\0" || action_hash (32) || tier byte (1)
//!     || issued_at_ms (u64 BE) || expires_at_ms (u64 BE) || nonce (16)
//! ```
//!
//! The v1 domain had no expiry; v1 approvals never verify under v2.
//! [`Approver::grant`] sets `expires_at_ms = issued_at_ms + ttl_ms` with
//! `0 < ttl_ms <= MAX_TTL_MS`. [`Approver::redeem`] refuses an approval once
//! `now_ms >= expires_at_ms`. A `now_ms` before `issued_at_ms` (clock skew)
//! is allowed. Times are caller-supplied milliseconds since the Unix epoch;
//! this crate does not read the clock.
//!
//! [`Approver::redeem`] accepts an approval at most once. It classifies the
//! action itself (with [`classify`] and the caller's [`PolicyConfig`]) to get
//! the required tier; there is no caller-supplied tier to get wrong.
//! `Blocked` actions can never be approved: [`Approver::grant`] refuses them,
//! and `redeem` rejects them even when the approval carries a valid
//! signature.
//!
//! The spent-nonce set is held in memory. [`Approver::spent`] exports it and
//! [`Approver::from_signing_key_with_spent`] restores it, so a caller (the
//! agent crate) can persist it next to the key across restarts.
//! The set grows only with legitimate redemptions: a nonce is recorded only
//! after every other check has passed, so rejected approvals never add to it.

use crate::action::Action;
use crate::policy::{classify, PolicyConfig, Tier};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt;

/// Domain-separation prefix for the signed approval message.
pub const APPROVAL_DOMAIN: &[u8] = b"warden/approval/v2\0";

/// The longest lifetime [`Approver::grant`] accepts, in milliseconds (10 min).
pub const MAX_TTL_MS: u64 = 600_000;

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

/// The exact bytes an approval signature covers. Pinned by a golden test.
pub fn approval_message(
    action_hash: &[u8; 32],
    tier: Tier,
    issued_at_ms: u64,
    expires_at_ms: u64,
    nonce: &[u8; 16],
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(APPROVAL_DOMAIN.len() + 32 + 1 + 8 + 8 + 16);
    msg.extend_from_slice(APPROVAL_DOMAIN);
    msg.extend_from_slice(action_hash);
    msg.push(tier_byte(tier));
    msg.extend_from_slice(&issued_at_ms.to_be_bytes());
    msg.extend_from_slice(&expires_at_ms.to_be_bytes());
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
    #[error("approval has expired")]
    Expired,
    #[error("approval ttl must be between 1 ms and MAX_TTL_MS, without overflow")]
    BadTtl,
}

/// A signed approval for one action at one tier, usable once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Approval {
    #[serde(with = "hex_bytes")]
    pub action_hash: [u8; 32],
    pub tier: Tier,
    /// Milliseconds since the Unix epoch, as given to `grant`. Signed.
    pub issued_at_ms: u64,
    /// `issued_at_ms + ttl_ms`; redeem refuses at or after this. Signed.
    pub expires_at_ms: u64,
    #[serde(with = "hex_bytes")]
    pub nonce: [u8; 16],
    #[serde(with = "hex_signature")]
    pub signature: Signature,
}

/// Holds the approval signing key and the set of spent nonces.
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
    /// The returned `Approver` starts with an EMPTY spent-nonce set. Reloading
    /// a key this way (for example after a restart) re-enables every
    /// unexpired approval that key signed, including ones already redeemed:
    /// they can be replayed once more within their window (at most
    /// [`MAX_TTL_MS`]). For a reloaded key, use
    /// [`Approver::from_signing_key_with_spent`] with the persisted set. See
    /// docs/SECURITY-NOTES.md, "Approvals: expiry and persisted nonces".
    pub fn from_signing_key(key: SigningKey) -> Approver {
        Approver::from_signing_key_with_spent(key, [])
    }

    /// An approver using an existing key and a previously exported
    /// spent-nonce set (see [`Approver::spent`]).
    pub fn from_signing_key_with_spent(
        key: SigningKey,
        spent: impl IntoIterator<Item = [u8; 16]>,
    ) -> Approver {
        Approver {
            key,
            spent: spent.into_iter().collect(),
        }
    }

    /// The spent nonces, sorted, for the caller to persist.
    pub fn spent(&self) -> Vec<[u8; 16]> {
        let mut out: Vec<[u8; 16]> = self.spent.iter().copied().collect();
        out.sort_unstable();
        out
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    /// Sign an approval for `action` at `tier`, valid from `issued_at_ms`
    /// for `ttl_ms` milliseconds. Refuses `Blocked`, and refuses with
    /// `BadTtl` a `ttl_ms` of 0, above [`MAX_TTL_MS`], or one that overflows
    /// `issued_at_ms + ttl_ms`.
    pub fn grant(
        &self,
        action: &Action,
        tier: Tier,
        issued_at_ms: u64,
        ttl_ms: u64,
    ) -> Result<Approval, ApprovalError> {
        if tier == Tier::Blocked {
            return Err(ApprovalError::Blocked);
        }
        if ttl_ms == 0 || ttl_ms > MAX_TTL_MS {
            return Err(ApprovalError::BadTtl);
        }
        let expires_at_ms = issued_at_ms
            .checked_add(ttl_ms)
            .ok_or(ApprovalError::BadTtl)?;
        let action_hash = action_hash(action);
        let mut nonce = [0u8; 16];
        OsRng.fill_bytes(&mut nonce);
        let msg = approval_message(&action_hash, tier, issued_at_ms, expires_at_ms, &nonce);
        let signature = self.key.sign(&msg);
        Ok(Approval {
            action_hash,
            tier,
            issued_at_ms,
            expires_at_ms,
            nonce,
            signature,
        })
    }

    /// Accept `approval` for `action` under policy `cfg` at time `now_ms`.
    ///
    /// The required tier is computed here with [`classify`]; callers cannot
    /// supply it, so a stale or lower view of the action can never downgrade
    /// what the approval must cover. Checks, in order: neither the required
    /// tier nor the approval's tier is `Blocked`; the action hash matches;
    /// the signature verifies (strict); `now_ms < expires_at_ms`; the granted
    /// tier covers the required tier; the nonce is unspent. Only after all
    /// pass is the nonce marked spent, so a failed redeem never burns it.
    pub fn redeem(
        &mut self,
        action: &Action,
        cfg: &PolicyConfig,
        approval: &Approval,
        now_ms: u64,
    ) -> Result<(), ApprovalError> {
        let required = classify(action, cfg);
        if required == Tier::Blocked || approval.tier == Tier::Blocked {
            return Err(ApprovalError::Blocked);
        }
        let hash = action_hash(action);
        if hash != approval.action_hash {
            return Err(ApprovalError::WrongAction);
        }
        // Sign-check over the locally computed hash, never the claimed one.
        let msg = approval_message(
            &hash,
            approval.tier,
            approval.issued_at_ms,
            approval.expires_at_ms,
            &approval.nonce,
        );
        self.key
            .verifying_key()
            .verify_strict(&msg, &approval.signature)
            .map_err(|_| ApprovalError::BadSignature)?;
        // The window is signed, so it is trusted only after verify_strict.
        if now_ms >= approval.expires_at_ms {
            return Err(ApprovalError::Expired);
        }
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
