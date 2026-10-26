use serde_json::json;
use std::path::{Path, PathBuf};
use warden_agent::tools::*;
use warden_core::{classify, Capability, PolicyConfig, Tier};

fn call(name: &str, args: serde_json::Value) -> ToolCall {
    ToolCall {
        id: "c1".into(),
        name: name.into(),
        args,
    }
}

fn parse(name: &str, args: serde_json::Value) -> Result<Tool, ToolError> {
    parse_call(&call(name, args), Path::new("/root"))
}

#[test]
fn unknown_tool_is_refused() {
    assert!(matches!(
        parse("run_shell", json!({})),
        Err(ToolError::UnknownTool(n)) if n == "run_shell"
    ));
}

#[test]
fn extra_field_is_bad_args() {
    for (n, a) in [
        ("list_dir", json!({"path": "/root", "x": 1})),
        ("read_file", json!({"path": "/root/a", "x": 1})),
        (
            "write_file",
            json!({"path": "/root/a", "content": "", "x": 1}),
        ),
        ("delete_file", json!({"path": "/root/a", "x": 1})),
    ] {
        assert!(matches!(parse(n, a), Err(ToolError::BadArgs(_))), "{n}");
    }
}

#[test]
fn dotdot_is_normalized_not_trusted() {
    let t = parse("read_file", json!({"path": "/root/../etc/x"})).unwrap();
    assert!(matches!(t, Tool::ReadFile { ref path, .. } if path == Path::new("/etc/x")));
}

#[test]
fn relative_path_resolves_against_cwd() {
    let t = parse("delete_file", json!({"path": "sub/../a.txt"})).unwrap();
    assert!(matches!(t, Tool::DeleteFile { ref path } if path == Path::new("/root/a.txt")));
}

#[test]
fn relative_cwd_is_bad_args() {
    let c = call("list_dir", json!({"path": "a"}));
    assert!(matches!(
        parse_call(&c, Path::new("rel")),
        Err(ToolError::BadArgs(_))
    ));
}

#[test]
fn nul_and_empty_and_overlong_paths_are_bad_args() {
    let long = format!("/root/{}", "a".repeat(4096));
    for p in ["", "/root/a\u{0}b", long.as_str()] {
        assert!(
            matches!(
                parse("list_dir", json!({"path": p})),
                Err(ToolError::BadArgs(_))
            ),
            "{}",
            p.len()
        );
    }
}

#[test]
fn ten_megabyte_write_is_too_large() {
    let c = "x".repeat(10 * 1024 * 1024);
    assert!(matches!(
        parse("write_file", json!({"path": "/root/a", "content": c})),
        Err(ToolError::TooLarge)
    ));
    let ok = "x".repeat(MAX_WRITE_BYTES as usize);
    assert!(parse("write_file", json!({"path": "/root/a", "content": ok})).is_ok());
}

#[test]
fn args_that_are_not_an_object_are_bad_args() {
    for a in [json!(null), json!("s"), json!([1]), json!(3)] {
        assert!(matches!(parse("read_file", a), Err(ToolError::BadArgs(_))));
    }
}

#[test]
fn max_bytes_above_cap_is_clamped_to_max_read() {
    let t = parse(
        "read_file",
        json!({"path": "/root/a", "max_bytes": 99_999_999_999u64}),
    )
    .unwrap();
    assert!(matches!(t, Tool::ReadFile { max_bytes, .. } if max_bytes == MAX_READ_BYTES));
    let t = parse("read_file", json!({"path": "/root/a"})).unwrap();
    assert!(matches!(t, Tool::ReadFile { max_bytes, .. } if max_bytes == DEFAULT_READ_BYTES));
}

#[test]
fn zero_max_bytes_is_bad_args() {
    assert!(matches!(
        parse("read_file", json!({"path": "/root/a", "max_bytes": 0})),
        Err(ToolError::BadArgs(_))
    ));
}

#[test]
fn bad_args_message_never_contains_content() {
    let r = parse(
        "write_file",
        json!({"path": "/root/a", "content": "TOPSECRET", "extra": "TOPSECRET2"}),
    );
    let msg = match r {
        Err(ToolError::BadArgs(m)) => m,
        _ => panic!("expected BadArgs"),
    };
    assert!(!msg.contains("TOPSECRET"), "{msg}");
    assert!(msg.len() < 200);
    let r = parse("write_file", json!({"path": 5, "content": "TOPSECRET"}));
    let e = r.unwrap_err();
    assert!(!e.to_string().contains("TOPSECRET"));
    let r = parse(
        "write_file",
        json!({"path": "/root/a", "content": 7, "z": "TOPSECRET"}),
    );
    assert!(!r.unwrap_err().to_string().contains("TOPSECRET"));
}

#[test]
fn non_utf8_free_unicode_paths_work() {
    let t = parse("read_file", json!({"path": "/root/données/日本語.txt"})).unwrap();
    assert!(
        matches!(t, Tool::ReadFile { ref path, .. } if path == Path::new("/root/données/日本語.txt"))
    );
}

#[test]
fn summary_never_contains_content() {
    let t = parse(
        "write_file",
        json!({"path": "/root/a.txt", "content": "TOPSECRET"}),
    )
    .unwrap();
    let a = to_action(&t, "x");
    assert!(!a.summary.contains("TOPSECRET"));
    assert_eq!(a.summary, "write /root/a.txt (9 bytes)");
    assert_eq!(a.id, "x");
}

#[test]
fn capabilities_match_tools() {
    let p = PathBuf::from("/root/a");
    let cases = [
        (
            Tool::ListDir { path: p.clone() },
            Capability::ReadPath(p.clone()),
            "list /root/a",
        ),
        (
            Tool::ReadFile {
                path: p.clone(),
                max_bytes: 10,
            },
            Capability::ReadPath(p.clone()),
            "read /root/a (max 10 bytes)",
        ),
        (
            Tool::WriteFile {
                path: p.clone(),
                content: "abc".into(),
            },
            Capability::WritePath(p.clone()),
            "write /root/a (3 bytes)",
        ),
        (
            Tool::DeleteFile { path: p.clone() },
            Capability::DeletePath(p.clone()),
            "delete /root/a",
        ),
    ];
    for (t, cap, summary) in cases {
        let a = to_action(&t, "id1");
        assert_eq!(a.capabilities, vec![cap]);
        assert_eq!(a.summary, summary);
    }
}

#[test]
fn tool_specs_have_object_schemas_and_unique_names() {
    let specs = tool_specs();
    assert_eq!(specs.len(), 4);
    let mut names: Vec<_> = specs.iter().map(|s| s.name).collect();
    names.sort();
    names.dedup();
    assert_eq!(
        names,
        ["delete_file", "list_dir", "read_file", "write_file"]
    );
    for s in &specs {
        assert_eq!(s.schema["type"], "object");
        assert!(s.schema["properties"].is_object());
        assert!(s.schema["required"].is_array());
        assert_eq!(s.schema["additionalProperties"], false);
        assert!(!s.description.is_empty());
    }
}

#[test]
fn tool_name_matches_spec_names() {
    let p = PathBuf::from("/a");
    assert_eq!(Tool::ListDir { path: p.clone() }.name(), "list_dir");
    assert_eq!(Tool::DeleteFile { path: p }.name(), "delete_file");
}

#[test]
fn classify_round_trip() {
    let cfg = PolicyConfig {
        allowed_roots: vec![PathBuf::from("/root")],
    };
    let tier =
        |n: &str, a: serde_json::Value| classify(&to_action(&parse(n, a).unwrap(), "x"), &cfg);
    assert_eq!(tier("read_file", json!({"path": "/root/a"})), Tier::Auto);
    assert_eq!(tier("list_dir", json!({"path": "/root"})), Tier::Auto);
    assert_eq!(
        tier("write_file", json!({"path": "/root/a", "content": "x"})),
        Tier::Yes
    );
    assert_eq!(
        tier("delete_file", json!({"path": "/root/a"})),
        Tier::YesPin
    );
    assert_eq!(tier("read_file", json!({"path": "/etc/hosts"})), Tier::Yes);
    assert_eq!(
        tier("read_file", json!({"path": "/root/../etc/hosts"})),
        Tier::Yes
    );
}
