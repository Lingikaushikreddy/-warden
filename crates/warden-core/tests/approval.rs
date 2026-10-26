use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use warden_core::{
    approval_message, classify, tier_byte, Action, Approval, ApprovalError, Approver, Capability,
    PolicyConfig, Tier, APPROVAL_DOMAIN, MAX_TTL_MS,
};

/// Fixed clock for tests: approvals are issued at `T0` and live `TTL` ms.
const T0: u64 = 1_700_000_000_000;
const TTL: u64 = 60_000;
/// A redeem time inside every test approval's window.
const NOW: u64 = T0 + 1;

fn cfg() -> PolicyConfig {
    PolicyConfig {
        allowed_roots: vec![PathBuf::from("/tmp")],
    }
}

fn action_with(cap: Capability) -> Action {
    Action {
        id: "a1".into(),
        summary: "test action".into(),
        capabilities: vec![cap],
    }
}

/// Classified `YesPin`.
fn delete_action(path: &str) -> Action {
    action_with(Capability::DeletePath(PathBuf::from(path)))
}

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
    let (issued_at_ms, expires_at_ms) = (T0, T0 + TTL);
    let msg = approval_message(&action_hash, tier, issued_at_ms, expires_at_ms, &nonce);
    Approval {
        action_hash,
        tier,
        issued_at_ms,
        expires_at_ms,
        nonce,
        signature: key.sign(&msg),
    }
}

#[test]
fn valid_approval_redeems_once() {
    let mut ap = Approver::generate();
    let a = write_action("/tmp/a");
    let approval = ap.grant(&a, Tier::Yes, T0, TTL).unwrap();
    assert_eq!(ap.redeem(&a, &cfg(), &approval, NOW), Ok(()));
}

#[test]
fn second_redeem_is_already_used() {
    let mut ap = Approver::generate();
    let a = write_action("/tmp/a");
    let approval = ap.grant(&a, Tier::Yes, T0, TTL).unwrap();
    ap.redeem(&a, &cfg(), &approval, NOW).unwrap();
    assert_eq!(
        ap.redeem(&a, &cfg(), &approval, NOW),
        Err(ApprovalError::AlreadyUsed)
    );
}

#[test]
fn approval_for_other_action_is_wrong_action() {
    let mut ap = Approver::generate();
    let a = write_action("/tmp/a");
    let b = write_action("/tmp/b");
    let approval = ap.grant(&a, Tier::Yes, T0, TTL).unwrap();
    assert_eq!(
        ap.redeem(&b, &cfg(), &approval, NOW),
        Err(ApprovalError::WrongAction)
    );
}

#[test]
fn tampered_signature_is_bad_signature() {
    let mut ap = Approver::generate();
    let a = write_action("/tmp/a");
    let mut approval = ap.grant(&a, Tier::Yes, T0, TTL).unwrap();
    let mut sig = approval.signature.to_bytes();
    sig[0] ^= 0x01;
    approval.signature = ed25519_dalek::Signature::from_bytes(&sig);
    assert_eq!(
        ap.redeem(&a, &cfg(), &approval, NOW),
        Err(ApprovalError::BadSignature)
    );
}

#[test]
fn tampered_tier_is_bad_signature() {
    let mut ap = Approver::generate();
    let a = delete_action("/tmp/a");
    // Granted Yes, attacker bumps to YesPin to cover a YesPin action.
    let mut approval = ap.grant(&a, Tier::Yes, T0, TTL).unwrap();
    approval.tier = Tier::YesPin;
    assert_eq!(
        ap.redeem(&a, &cfg(), &approval, NOW),
        Err(ApprovalError::BadSignature)
    );
}

#[test]
fn tampered_nonce_is_bad_signature() {
    let mut ap = Approver::generate();
    let a = write_action("/tmp/a");
    let mut approval = ap.grant(&a, Tier::Yes, T0, TTL).unwrap();
    approval.nonce[0] ^= 0x01;
    assert_eq!(
        ap.redeem(&a, &cfg(), &approval, NOW),
        Err(ApprovalError::BadSignature)
    );
}

#[test]
fn blocked_tier_cannot_be_granted() {
    let ap = Approver::generate();
    let a = write_action("/tmp/a");
    assert_eq!(
        ap.grant(&a, Tier::Blocked, T0, TTL).unwrap_err(),
        ApprovalError::Blocked
    );
}

#[test]
fn blocked_cannot_be_redeemed_even_with_valid_signature() {
    let key = SigningKey::generate(&mut OsRng);
    let mut ap = Approver::from_signing_key(key.clone());

    // Approval tier Blocked, validly signed by this Approver's own key, for
    // actions of every non-Blocked tier.
    let actions = [
        action_with(Capability::ReadPath(PathBuf::from("/tmp/a"))),
        write_action("/tmp/a"),
        delete_action("/tmp/a"),
    ];
    for (i, a) in actions.iter().enumerate() {
        let forged = hand_sign(&key, a, Tier::Blocked, [i as u8; 16]);
        assert_eq!(
            ap.redeem(a, &cfg(), &forged, NOW),
            Err(ApprovalError::Blocked),
            "{a:?}"
        );
    }

    // A Blocked action: even a validly signed YesPin approval fails,
    // whatever the approval says.
    for cap in [Capability::FormatDisk, Capability::EditRegistry] {
        let a = action_with(cap);
        assert_eq!(classify(&a, &cfg()), Tier::Blocked);
        for (j, tier) in [Tier::Auto, Tier::Yes, Tier::YesPin]
            .into_iter()
            .enumerate()
        {
            let approval = hand_sign(&key, &a, tier, [0x40 + j as u8; 16]);
            assert_eq!(
                ap.redeem(&a, &cfg(), &approval, NOW),
                Err(ApprovalError::Blocked),
                "{tier:?}"
            );
        }
    }
}

#[test]
fn yes_approval_cannot_cover_yespin_action() {
    let mut ap = Approver::generate();
    let a = delete_action("/tmp/a");
    let approval = ap.grant(&a, Tier::Yes, T0, TTL).unwrap();
    assert_eq!(
        ap.redeem(&a, &cfg(), &approval, NOW),
        Err(ApprovalError::InsufficientTier)
    );
}

#[test]
fn caller_view_of_tier_cannot_downgrade() {
    // A caller with a stale or lower view of the action (it believes a
    // write+delete action is only Yes) grants Yes. redeem classifies the
    // action itself and still requires YesPin.
    let mut ap = Approver::generate();
    let a = Action {
        id: "a2".into(),
        summary: "write then delete".into(),
        capabilities: vec![
            Capability::WritePath(PathBuf::from("/tmp/a")),
            Capability::DeletePath(PathBuf::from("/tmp/a")),
        ],
    };
    assert_eq!(classify(&a, &cfg()), Tier::YesPin);
    let stale = ap.grant(&a, Tier::Yes, T0, TTL).unwrap();
    assert_eq!(
        ap.redeem(&a, &cfg(), &stale, NOW),
        Err(ApprovalError::InsufficientTier)
    );
    let ok = ap.grant(&a, Tier::YesPin, T0, TTL).unwrap();
    assert_eq!(ap.redeem(&a, &cfg(), &ok, NOW), Ok(()));
}

#[test]
fn higher_tier_approval_covers_lower_requirement() {
    let mut ap = Approver::generate();
    let a = write_action("/tmp/a");
    let approval = ap.grant(&a, Tier::YesPin, T0, TTL).unwrap();
    assert_eq!(ap.redeem(&a, &cfg(), &approval, NOW), Ok(()));
}

#[test]
fn failed_redeem_does_not_burn_nonce() {
    let mut ap = Approver::generate();
    // A read is Auto inside the allowed roots and Yes outside them.
    let a = action_with(Capability::ReadPath(PathBuf::from("/srv/data")));
    let b = action_with(Capability::ReadPath(PathBuf::from("/srv/other")));
    let outside = cfg();
    let inside = PolicyConfig {
        allowed_roots: vec![PathBuf::from("/srv")],
    };
    let approval = ap.grant(&a, Tier::Auto, T0, TTL).unwrap();
    assert_eq!(
        ap.redeem(&b, &inside, &approval, NOW),
        Err(ApprovalError::WrongAction)
    );
    assert_eq!(
        ap.redeem(&a, &outside, &approval, NOW),
        Err(ApprovalError::InsufficientTier)
    );
    assert_eq!(ap.redeem(&a, &inside, &approval, NOW), Ok(()));
}

#[test]
fn bad_signature_copy_does_not_burn_original_nonce() {
    let mut ap = Approver::generate();
    let a = write_action("/tmp/a");
    let original = ap.grant(&a, Tier::Yes, T0, TTL).unwrap();
    let mut copy = original.clone();
    let mut sig = copy.signature.to_bytes();
    sig[10] ^= 0x80;
    copy.signature = ed25519_dalek::Signature::from_bytes(&sig);
    assert_eq!(
        ap.redeem(&a, &cfg(), &copy, NOW),
        Err(ApprovalError::BadSignature)
    );
    assert_eq!(ap.redeem(&a, &cfg(), &original, NOW), Ok(()));
}

#[test]
fn tampered_tier_copy_does_not_burn_original_nonce() {
    let mut ap = Approver::generate();
    let a = write_action("/tmp/a");
    let original = ap.grant(&a, Tier::YesPin, T0, TTL).unwrap();
    let mut copy = original.clone();
    copy.tier = Tier::Yes;
    assert_eq!(
        ap.redeem(&a, &cfg(), &copy, NOW),
        Err(ApprovalError::BadSignature)
    );
    assert_eq!(ap.redeem(&a, &cfg(), &original, NOW), Ok(()));
}

#[test]
fn approval_from_other_approver_is_bad_signature() {
    let other = Approver::generate();
    let mut ap = Approver::generate();
    let a = write_action("/tmp/a");
    let approval = other.grant(&a, Tier::Yes, T0, TTL).unwrap();
    assert_eq!(
        ap.redeem(&a, &cfg(), &approval, NOW),
        Err(ApprovalError::BadSignature)
    );
}

#[test]
fn grant_binds_action_hash_and_fresh_nonce() {
    let ap = Approver::generate();
    let a = write_action("/tmp/a");
    let x = ap.grant(&a, Tier::Yes, T0, TTL).unwrap();
    let y = ap.grant(&a, Tier::Yes, T0, TTL).unwrap();
    assert_eq!(x.action_hash, hash(&a));
    assert_eq!(x.tier, Tier::Yes);
    assert_eq!(x.issued_at_ms, T0);
    assert_eq!(x.expires_at_ms, T0 + TTL);
    assert_ne!(x.nonce, y.nonce);
    assert!(ap
        .verifying_key()
        .verify_strict(
            &approval_message(
                &x.action_hash,
                x.tier,
                x.issued_at_ms,
                x.expires_at_ms,
                &x.nonce
            ),
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
fn approval_serde_round_trips_with_hex() {
    let ap = Approver::generate();
    let a = write_action("/tmp/a");
    let x = ap.grant(&a, Tier::Yes, T0, TTL).unwrap();
    let json = serde_json::to_value(&x).unwrap();
    assert_eq!(json["action_hash"], hex::encode(x.action_hash));
    assert_eq!(json["nonce"], hex::encode(x.nonce));
    assert_eq!(json["issued_at_ms"], T0);
    assert_eq!(json["expires_at_ms"], T0 + TTL);
    assert_eq!(json["signature"], hex::encode(x.signature.to_bytes()));
    let back: Approval = serde_json::from_value(json).unwrap();
    assert_eq!(back, x);
}

#[test]
fn approval_deserialize_rejects_wrong_length_hex() {
    let json = serde_json::json!({
        "action_hash": "00",
        "tier": "Yes",
        "issued_at_ms": T0,
        "expires_at_ms": T0 + TTL,
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

#[test]
fn expired_approval_is_refused_and_does_not_burn_nonce() {
    let mut ap = Approver::generate();
    let a = write_action("/tmp/a");
    let approval = ap.grant(&a, Tier::Yes, T0, TTL).unwrap();
    // Exactly at expiry and after it: Expired.
    for now in [T0 + TTL, T0 + TTL + 1, u64::MAX] {
        assert_eq!(
            ap.redeem(&a, &cfg(), &approval, now),
            Err(ApprovalError::Expired),
            "now={now}"
        );
    }
    assert!(ap.spent().is_empty());
    // The nonce was not burned: still redeemable inside the window.
    assert_eq!(ap.redeem(&a, &cfg(), &approval, T0 + TTL - 1), Ok(()));
}

#[test]
fn approval_valid_just_before_expiry() {
    let mut ap = Approver::generate();
    let a = write_action("/tmp/a");
    let approval = ap.grant(&a, Tier::Yes, T0, TTL).unwrap();
    assert_eq!(ap.redeem(&a, &cfg(), &approval, T0 + TTL - 1), Ok(()));

    // A clock behind issued_at (skew) is allowed.
    let early = ap.grant(&a, Tier::Yes, T0, TTL).unwrap();
    assert_eq!(ap.redeem(&a, &cfg(), &early, 0), Ok(()));
}

#[test]
fn expiry_is_checked_after_signature_and_before_tier_floor() {
    let mut ap = Approver::generate();
    let a = delete_action("/tmp/a"); // YesPin
    let approval = ap.grant(&a, Tier::Yes, T0, TTL).unwrap();
    // Expired and insufficient tier: expiry is checked first.
    assert_eq!(
        ap.redeem(&a, &cfg(), &approval, T0 + TTL),
        Err(ApprovalError::Expired)
    );
    // Expired and badly signed: the signature is checked first.
    let mut forged = approval.clone();
    forged.expires_at_ms = T0;
    assert_eq!(
        ap.redeem(&a, &cfg(), &forged, T0 + TTL),
        Err(ApprovalError::BadSignature)
    );
}

#[test]
fn ttl_zero_and_ttl_above_max_are_bad_ttl() {
    let ap = Approver::generate();
    let a = write_action("/tmp/a");
    assert_eq!(MAX_TTL_MS, 600_000);
    for ttl in [0, MAX_TTL_MS + 1, u64::MAX] {
        assert_eq!(
            ap.grant(&a, Tier::Yes, T0, ttl).unwrap_err(),
            ApprovalError::BadTtl,
            "ttl={ttl}"
        );
    }
    // issued_at + ttl overflowing u64 is BadTtl, not a wrap.
    assert_eq!(
        ap.grant(&a, Tier::Yes, u64::MAX, 1).unwrap_err(),
        ApprovalError::BadTtl
    );
    // Bounds are inclusive of 1 and MAX_TTL_MS.
    let lo = ap.grant(&a, Tier::Yes, T0, 1).unwrap();
    assert_eq!(lo.expires_at_ms, T0 + 1);
    let hi = ap.grant(&a, Tier::Yes, T0, MAX_TTL_MS).unwrap();
    assert_eq!(hi.expires_at_ms, T0 + MAX_TTL_MS);
    // Blocked is still refused as Blocked, whatever the ttl.
    assert_eq!(
        ap.grant(&a, Tier::Blocked, T0, 0).unwrap_err(),
        ApprovalError::Blocked
    );
}

#[test]
fn tampered_expiry_is_bad_signature() {
    let mut ap = Approver::generate();
    let a = write_action("/tmp/a");
    let original = ap.grant(&a, Tier::Yes, T0, TTL).unwrap();
    let mut copy = original.clone();
    copy.expires_at_ms += 1;
    assert_eq!(
        ap.redeem(&a, &cfg(), &copy, NOW),
        Err(ApprovalError::BadSignature)
    );
    let mut copy = original.clone();
    copy.issued_at_ms -= 1;
    assert_eq!(
        ap.redeem(&a, &cfg(), &copy, NOW),
        Err(ApprovalError::BadSignature)
    );
    // Neither tampered copy burned the original nonce.
    assert_eq!(ap.redeem(&a, &cfg(), &original, NOW), Ok(()));
}

#[test]
fn domain_is_v2_and_message_layout_is_pinned() {
    assert_eq!(APPROVAL_DOMAIN, b"warden/approval/v2\0");
    let h = [0xAAu8; 32];
    let n = [0xBBu8; 16];
    let msg = approval_message(
        &h,
        Tier::YesPin,
        0x0102_0304_0506_0708,
        0x1112_1314_1516_1718,
        &n,
    );
    // Golden bytes: domain || hash || tier || issued_at BE || expires_at BE || nonce.
    let want = hex::decode(concat!(
        "77617264656e2f617070726f76616c2f763200", // "warden/approval/v2\0"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "02",
        "0102030405060708",
        "1112131415161718",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    ))
    .unwrap();
    assert_eq!(msg, want);
    assert_eq!(msg.len(), 19 + 32 + 1 + 8 + 8 + 16);
}

#[test]
fn spent_nonces_survive_roundtrip_through_from_signing_key_with_spent() {
    let key = SigningKey::generate(&mut OsRng);
    let mut ap = Approver::from_signing_key(key.clone());
    let a = write_action("/tmp/a");
    let used = ap.grant(&a, Tier::Yes, T0, TTL).unwrap();
    let unused = ap.grant(&a, Tier::Yes, T0, TTL).unwrap();
    let other = ap.grant(&a, Tier::Yes, T0, TTL).unwrap();
    ap.redeem(&a, &cfg(), &used, NOW).unwrap();
    ap.redeem(&a, &cfg(), &other, NOW).unwrap();

    let spent = ap.spent();
    assert_eq!(spent.len(), 2);
    assert!(spent.windows(2).all(|w| w[0] < w[1]), "spent() is sorted");
    let mut want = vec![used.nonce, other.nonce];
    want.sort();
    assert_eq!(spent, want);

    let mut rebuilt = Approver::from_signing_key_with_spent(key, spent);
    assert_eq!(
        rebuilt.redeem(&a, &cfg(), &used, NOW),
        Err(ApprovalError::AlreadyUsed)
    );
    assert_eq!(
        rebuilt.redeem(&a, &cfg(), &other, NOW),
        Err(ApprovalError::AlreadyUsed)
    );
    assert_eq!(rebuilt.redeem(&a, &cfg(), &unused, NOW), Ok(()));
    assert_eq!(rebuilt.spent().len(), 3);
}
