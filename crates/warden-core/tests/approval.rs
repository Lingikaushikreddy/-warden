use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use warden_core::{
    approval_message, tier_byte, Action, Approval, ApprovalError, Approver, Capability, Tier,
};

fn write_action(path: &str) -> Action {
    Action {
        id: "a1".into(),
        summary: "write a file".into(),
        capabilities: vec![Capability::WritePath(PathBuf::from(path))],
    }
}

fn hash(action: &Action) -> [u8; 32] {
    Sha256::digest(action.canonical_bytes()).into()
}

/// Test helper: sign an arbitrary (action, tier, nonce) with a raw key,
/// bypassing `grant` (which refuses Blocked).
fn hand_sign(key: &SigningKey, action: &Action, tier: Tier, nonce: [u8; 16]) -> Approval {
    let action_hash = hash(action);
    let msg = approval_message(&action_hash, tier, &nonce);
    Approval {
        action_hash,
        tier,
        nonce,
        signature: key.sign(&msg),
    }
}

#[test]
fn valid_approval_redeems_once() {
    let mut ap = Approver::generate();
    let a = write_action("/tmp/a");
    let approval = ap.grant(&a, Tier::Yes).unwrap();
    assert_eq!(ap.redeem(&a, Tier::Yes, &approval), Ok(()));
}

#[test]
fn second_redeem_is_already_used() {
    let mut ap = Approver::generate();
    let a = write_action("/tmp/a");
    let approval = ap.grant(&a, Tier::Yes).unwrap();
    ap.redeem(&a, Tier::Yes, &approval).unwrap();
    assert_eq!(
        ap.redeem(&a, Tier::Yes, &approval),
        Err(ApprovalError::AlreadyUsed)
    );
}

#[test]
fn approval_for_other_action_is_wrong_action() {
    let mut ap = Approver::generate();
    let a = write_action("/tmp/a");
    let b = write_action("/tmp/b");
    let approval = ap.grant(&a, Tier::Yes).unwrap();
    assert_eq!(
        ap.redeem(&b, Tier::Yes, &approval),
        Err(ApprovalError::WrongAction)
    );
}

#[test]
fn tampered_signature_is_bad_signature() {
    let mut ap = Approver::generate();
    let a = write_action("/tmp/a");
    let mut approval = ap.grant(&a, Tier::Yes).unwrap();
    let mut sig = approval.signature.to_bytes();
    sig[0] ^= 0x01;
    approval.signature = ed25519_dalek::Signature::from_bytes(&sig);
    assert_eq!(
        ap.redeem(&a, Tier::Yes, &approval),
        Err(ApprovalError::BadSignature)
    );
}

#[test]
fn tampered_tier_is_bad_signature() {
    let mut ap = Approver::generate();
    let a = write_action("/tmp/a");
    // Granted Yes, attacker bumps to YesPin to cover a YesPin action.
    let mut approval = ap.grant(&a, Tier::Yes).unwrap();
    approval.tier = Tier::YesPin;
    assert_eq!(
        ap.redeem(&a, Tier::YesPin, &approval),
        Err(ApprovalError::BadSignature)
    );
}

#[test]
fn tampered_nonce_is_bad_signature() {
    let mut ap = Approver::generate();
    let a = write_action("/tmp/a");
    let mut approval = ap.grant(&a, Tier::Yes).unwrap();
    approval.nonce[0] ^= 0x01;
    assert_eq!(
        ap.redeem(&a, Tier::Yes, &approval),
        Err(ApprovalError::BadSignature)
    );
}

#[test]
fn blocked_tier_cannot_be_granted() {
    let ap = Approver::generate();
    let a = write_action("/tmp/a");
    assert_eq!(
        ap.grant(&a, Tier::Blocked).unwrap_err(),
        ApprovalError::Blocked
    );
}

#[test]
fn blocked_cannot_be_redeemed_even_with_valid_signature() {
    let key = SigningKey::generate(&mut OsRng);
    let mut ap = Approver::from_signing_key(key.clone());
    let a = write_action("/tmp/a");

    // Approval tier Blocked, validly signed by this Approver's own key.
    let forged = hand_sign(&key, &a, Tier::Blocked, [7u8; 16]);
    for required in [Tier::Auto, Tier::Yes, Tier::YesPin, Tier::Blocked] {
        assert_eq!(
            ap.redeem(&a, required, &forged),
            Err(ApprovalError::Blocked),
            "required {required:?}"
        );
    }

    // Required tier Blocked: even a validly signed YesPin approval fails.
    let pin = hand_sign(&key, &a, Tier::YesPin, [8u8; 16]);
    assert_eq!(
        ap.redeem(&a, Tier::Blocked, &pin),
        Err(ApprovalError::Blocked)
    );
}

#[test]
fn yes_approval_cannot_cover_yespin_action() {
    let mut ap = Approver::generate();
    let a = write_action("/tmp/a");
    let approval = ap.grant(&a, Tier::Yes).unwrap();
    assert_eq!(
        ap.redeem(&a, Tier::YesPin, &approval),
        Err(ApprovalError::InsufficientTier)
    );
}

#[test]
fn higher_tier_approval_covers_lower_requirement() {
    let mut ap = Approver::generate();
    let a = write_action("/tmp/a");
    let approval = ap.grant(&a, Tier::YesPin).unwrap();
    assert_eq!(ap.redeem(&a, Tier::Yes, &approval), Ok(()));
}

#[test]
fn failed_redeem_does_not_burn_nonce() {
    let mut ap = Approver::generate();
    let a = write_action("/tmp/a");
    let b = write_action("/tmp/b");
    let approval = ap.grant(&a, Tier::Yes).unwrap();
    assert_eq!(
        ap.redeem(&b, Tier::Yes, &approval),
        Err(ApprovalError::WrongAction)
    );
    assert_eq!(
        ap.redeem(&a, Tier::YesPin, &approval),
        Err(ApprovalError::InsufficientTier)
    );
    assert_eq!(ap.redeem(&a, Tier::Yes, &approval), Ok(()));
}

#[test]
fn bad_signature_copy_does_not_burn_original_nonce() {
    let mut ap = Approver::generate();
    let a = write_action("/tmp/a");
    let original = ap.grant(&a, Tier::Yes).unwrap();
    let mut copy = original.clone();
    let mut sig = copy.signature.to_bytes();
    sig[10] ^= 0x80;
    copy.signature = ed25519_dalek::Signature::from_bytes(&sig);
    assert_eq!(
        ap.redeem(&a, Tier::Yes, &copy),
        Err(ApprovalError::BadSignature)
    );
    assert_eq!(ap.redeem(&a, Tier::Yes, &original), Ok(()));
}

#[test]
fn tampered_tier_copy_does_not_burn_original_nonce() {
    let mut ap = Approver::generate();
    let a = write_action("/tmp/a");
    let original = ap.grant(&a, Tier::YesPin).unwrap();
    let mut copy = original.clone();
    copy.tier = Tier::Yes;
    assert_eq!(
        ap.redeem(&a, Tier::Yes, &copy),
        Err(ApprovalError::BadSignature)
    );
    assert_eq!(ap.redeem(&a, Tier::Yes, &original), Ok(()));
}

#[test]
fn approval_from_other_approver_is_bad_signature() {
    let other = Approver::generate();
    let mut ap = Approver::generate();
    let a = write_action("/tmp/a");
    let approval = other.grant(&a, Tier::Yes).unwrap();
    assert_eq!(
        ap.redeem(&a, Tier::Yes, &approval),
        Err(ApprovalError::BadSignature)
    );
}

#[test]
fn grant_binds_action_hash_and_fresh_nonce() {
    let ap = Approver::generate();
    let a = write_action("/tmp/a");
    let x = ap.grant(&a, Tier::Yes).unwrap();
    let y = ap.grant(&a, Tier::Yes).unwrap();
    assert_eq!(x.action_hash, hash(&a));
    assert_eq!(x.tier, Tier::Yes);
    assert_ne!(x.nonce, y.nonce);
    assert!(ap
        .verifying_key()
        .verify_strict(
            &approval_message(&x.action_hash, x.tier, &x.nonce),
            &x.signature
        )
        .is_ok());
}

#[test]
fn tier_byte_mapping_is_pinned() {
    // Changing any byte invalidates every outstanding approval.
    let pinned = [
        (Tier::Auto, 0u8),
        (Tier::Yes, 1),
        (Tier::YesPin, 2),
        (Tier::Blocked, 3),
    ];
    for (tier, byte) in pinned {
        assert_eq!(tier_byte(tier), byte, "{tier:?}");
    }
    let bytes: Vec<u8> = pinned.iter().map(|(t, _)| tier_byte(*t)).collect();
    assert_eq!(bytes, (0..=3).collect::<Vec<u8>>());
}

#[test]
fn approval_message_layout_is_pinned() {
    let h = [0xAAu8; 32];
    let n = [0xBBu8; 16];
    let msg = approval_message(&h, Tier::YesPin, &n);
    let mut want = b"warden/approval/v1\0".to_vec();
    want.extend_from_slice(&h);
    want.push(2);
    want.extend_from_slice(&n);
    assert_eq!(msg, want);
    assert_eq!(msg.len(), 19 + 32 + 1 + 16);
}

#[test]
fn approval_serde_round_trips_with_hex() {
    let ap = Approver::generate();
    let a = write_action("/tmp/a");
    let x = ap.grant(&a, Tier::Yes).unwrap();
    let json = serde_json::to_value(&x).unwrap();
    assert_eq!(json["action_hash"], hex::encode(x.action_hash));
    assert_eq!(json["nonce"], hex::encode(x.nonce));
    assert_eq!(json["signature"], hex::encode(x.signature.to_bytes()));
    let back: Approval = serde_json::from_value(json).unwrap();
    assert_eq!(back, x);
}

#[test]
fn approval_deserialize_rejects_wrong_length_hex() {
    let json = serde_json::json!({
        "action_hash": "00",
        "tier": "Yes",
        "nonce": hex::encode([0u8; 16]),
        "signature": hex::encode([0u8; 64]),
    });
    assert!(serde_json::from_value::<Approval>(json).is_err());
}

#[test]
fn approver_debug_does_not_print_secret_key() {
    let key = SigningKey::generate(&mut OsRng);
    let secret_hex = hex::encode(key.to_bytes());
    let ap = Approver::from_signing_key(key);
    let dbg = format!("{ap:?}");
    assert!(!dbg.contains(&secret_hex));
    assert!(!dbg.to_lowercase().contains(&secret_hex[..16]));
}
