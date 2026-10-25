use std::path::PathBuf;
use warden_core::{classify, Action, Capability, PolicyConfig, Tier};

fn cfg() -> PolicyConfig {
    PolicyConfig {
        allowed_roots: vec![PathBuf::from("/root")],
    }
}

fn act(caps: Vec<Capability>) -> Action {
    Action {
        id: "t".into(),
        summary: "test".into(),
        capabilities: caps,
    }
}

fn read(p: &str) -> Capability {
    Capability::ReadPath(PathBuf::from(p))
}

#[test]
fn read_inside_root_is_auto() {
    assert_eq!(
        classify(&act(vec![read("/root/a/b.txt")]), &cfg()),
        Tier::Auto
    );
}

#[test]
fn read_outside_root_needs_yes() {
    assert_eq!(classify(&act(vec![read("/etc/hosts")]), &cfg()), Tier::Yes);
}

#[test]
fn delete_needs_pin() {
    let a = act(vec![Capability::DeletePath("/root/a".into())]);
    assert_eq!(classify(&a, &cfg()), Tier::YesPin);
}

#[test]
fn message_person_needs_pin() {
    let a = act(vec![Capability::MessagePerson("mom".into())]);
    assert_eq!(classify(&a, &cfg()), Tier::YesPin);
}

#[test]
fn format_disk_is_blocked() {
    assert_eq!(
        classify(&act(vec![Capability::FormatDisk]), &cfg()),
        Tier::Blocked
    );
}

#[test]
fn highest_tier_wins() {
    let a = act(vec![
        read("/root/a"),
        Capability::DeletePath("/root/a".into()),
    ]);
    assert_eq!(classify(&a, &cfg()), Tier::YesPin);
}

#[test]
fn empty_action_is_auto() {
    assert_eq!(classify(&act(vec![]), &cfg()), Tier::Auto);
}

#[test]
fn path_traversal_does_not_count_as_inside() {
    assert_eq!(
        classify(&act(vec![read("/root/../etc/passwd")]), &cfg()),
        Tier::Yes
    );
}

#[test]
fn blocked_beats_everything() {
    let a = act(vec![read("/root/a"), Capability::FormatDisk]);
    assert_eq!(classify(&a, &cfg()), Tier::Blocked);
}

#[test]
fn relative_paths_never_count_as_inside() {
    assert_eq!(classify(&act(vec![read("a/b")]), &cfg()), Tier::Yes);
    assert_eq!(classify(&act(vec![read("../root/a")]), &cfg()), Tier::Yes);
}

#[test]
fn dotdot_at_fs_root_clamps_to_root() {
    let c = PolicyConfig {
        allowed_roots: vec![PathBuf::from("/")],
    };
    // /.. normalizes to / lexically; still absolute, so inside "/"
    assert_eq!(classify(&act(vec![read("/../etc")]), &c), Tier::Auto);
}

#[test]
fn relative_root_never_matches() {
    let c = PolicyConfig {
        allowed_roots: vec![PathBuf::from("root")],
    };
    assert_eq!(classify(&act(vec![read("root/a")]), &c), Tier::Yes);
}

#[test]
fn sibling_prefix_is_not_inside() {
    assert_eq!(classify(&act(vec![read("/rootkit/a")]), &cfg()), Tier::Yes);
}

#[test]
fn root_with_dotdot_is_normalized() {
    let c = PolicyConfig {
        allowed_roots: vec![PathBuf::from("/root/x/..")],
    };
    assert_eq!(classify(&act(vec![read("/root/a")]), &c), Tier::Auto);
}

#[test]
fn tier_ordering() {
    assert!(Tier::Auto < Tier::Yes && Tier::Yes < Tier::YesPin && Tier::YesPin < Tier::Blocked);
}

#[test]
fn every_capability_tier_is_pinned() {
    use Capability::*;
    let p = |s: &str| PathBuf::from(s);
    let table = vec![
        (ReadPath(p("/root/a")), Tier::Auto),
        (ReadPath(p("/etc/a")), Tier::Yes),
        (WritePath(p("/root/a")), Tier::Yes),
        (WritePath(p("/etc/a")), Tier::Yes),
        (DeletePath(p("/root/a")), Tier::YesPin),
        (RunNewScript("s".into()), Tier::Yes),
        (OpenApp("a".into()), Tier::Yes),
        (MessagePerson("m".into()), Tier::YesPin),
        (SendEmail("e".into()), Tier::YesPin),
        (InstallSoftware("i".into()), Tier::YesPin),
        (NetworkSend("n".into()), Tier::YesPin),
        (FormatDisk, Tier::Blocked),
        (EditRegistry, Tier::Blocked),
        (DisableSecurityTool, Tier::Blocked),
        (ReadSavedPasswords, Tier::Blocked),
    ];
    for (cap, want) in table {
        assert_eq!(classify(&act(vec![cap.clone()]), &cfg()), want, "{cap:?}");
    }
}

#[test]
fn order_independent() {
    let a = act(vec![Capability::FormatDisk, read("/root/a")]);
    assert_eq!(classify(&a, &cfg()), Tier::Blocked);
}

#[test]
fn multiple_allowed_roots() {
    let c = PolicyConfig {
        allowed_roots: vec![PathBuf::from("/root"), PathBuf::from("/data")],
    };
    assert_eq!(classify(&act(vec![read("/data/x")]), &c), Tier::Auto);
    assert_eq!(classify(&act(vec![read("/root/x")]), &c), Tier::Auto);
    assert_eq!(classify(&act(vec![read("/other/x")]), &c), Tier::Yes);
}

#[test]
fn empty_allowed_roots_means_every_read_is_yes() {
    let c = PolicyConfig {
        allowed_roots: vec![],
    };
    assert_eq!(classify(&act(vec![read("/root/a")]), &c), Tier::Yes);
}
