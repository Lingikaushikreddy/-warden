use serde_json::json;
use warden_agent::planner::{
    Block, MockPlanner, PlanRequest, PlanResponse, Planner, PlannerError, Role, Turn,
};
use warden_agent::redact::redact;
use warden_agent::tools::{tool_specs, ToolCall};

fn request(text: &str) -> PlanRequest {
    PlanRequest {
        system: redact("You are careful.").0,
        turns: vec![Turn {
            role: Role::User,
            blocks: vec![Block::Text(redact(text).0)],
        }],
        tools: tool_specs(),
    }
}

fn reply(text: &str) -> PlanResponse {
    PlanResponse {
        text: Some(text.to_string()),
        calls: vec![],
    }
}

#[tokio::test]
async fn scripted_responses_in_order() {
    let call = ToolCall {
        id: "t1".into(),
        name: "list_dir".into(),
        args: json!({"path": "."}),
    };
    let mock = MockPlanner::scripted(vec![
        Ok(reply("first")),
        Ok(PlanResponse {
            text: None,
            calls: vec![call],
        }),
        Err(PlannerError::Status(500)),
    ]);
    let req = request("hi");
    let a = mock.plan(&req).await.unwrap();
    assert_eq!(a.text.as_deref(), Some("first"));
    let b = mock.plan(&req).await.unwrap();
    assert_eq!(b.text, None);
    assert_eq!(b.calls.len(), 1);
    assert_eq!(b.calls[0].name, "list_dir");
    assert_eq!(
        mock.plan(&req).await.unwrap_err(),
        PlannerError::Status(500)
    );
}

#[tokio::test]
async fn requests_are_recorded_as_serialized_strings() {
    let mock = MockPlanner::scripted(vec![Ok(reply("a")), Ok(reply("b"))]);
    mock.plan(&request("first question")).await.unwrap();
    let mut second = request("second question");
    second.turns.push(Turn {
        role: Role::Assistant,
        blocks: vec![Block::tool_use("t1", "read_file", &json!({"path": "a"}))],
    });
    mock.plan(&second).await.unwrap();

    let reqs = mock.requests();
    assert_eq!(reqs.len(), 2);
    assert!(reqs[0].contains("first question"));
    assert!(!reqs[0].contains("second question"));
    assert!(reqs[1].contains("second question"));
    for name in ["list_dir", "read_file", "write_file", "delete_file"] {
        assert!(reqs[0].contains(name), "missing tool {name}");
    }
    // Each entry is valid JSON of the request.
    let v: serde_json::Value = serde_json::from_str(&reqs[1]).unwrap();
    assert_eq!(v["system"], "You are careful.");
    assert_eq!(v["turns"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn exhausted_script_is_malformed() {
    let mock = MockPlanner::scripted(vec![Ok(reply("only"))]);
    let req = request("x");
    mock.plan(&req).await.unwrap();
    assert_eq!(
        mock.plan(&req).await.unwrap_err(),
        PlannerError::Malformed("script exhausted".into())
    );
    // Still recorded, even when the script has run out.
    assert_eq!(mock.requests().len(), 2);
}

#[test]
fn tool_use_args_are_redacted_by_constructor() {
    let raw = json!({"path": "/tmp/x", "password": "hunter2hunter2hunter2"});
    let block = Block::tool_use("t1", "write_file", &raw);
    let Block::ToolUse { id, name, args } = &block else {
        panic!("not a tool_use block");
    };
    assert_eq!(id, "t1");
    assert_eq!(name, "write_file");
    assert_eq!(args.as_value()["path"], "/tmp/x");
    assert_ne!(args.as_value()["password"], "hunter2hunter2hunter2");
    let s = serde_json::to_string(&block).unwrap();
    assert!(!s.contains("hunter2"), "raw secret serialized: {s}");
    assert!(s.contains("[REDACTED"));
}

#[test]
fn raw_value_cannot_be_used_in_tool_use() {
    // The type-level guarantee is the compile_fail doctest on
    // `warden_agent::planner::RedactedJson`; here we check the only public
    // way in goes through redaction.
    let block = Block::tool_use("t1", "x", &json!({"token": "abcd1234abcd1234"}));
    let Block::ToolUse { args, .. } = block else {
        panic!()
    };
    assert_ne!(args.as_value()["token"], "abcd1234abcd1234");
}

#[cfg(feature = "test-hooks")]
#[tokio::test]
async fn from_script_file_loads() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("script.json");
    std::fs::write(
        &path,
        r#"[
            {"text": "looking", "calls": [{"id": "c1", "name": "list_dir", "args": {"path": "."}}]},
            {"error": "transport"},
            {"text": "done", "calls": []}
        ]"#,
    )
    .unwrap();
    let mock = MockPlanner::from_script_file(&path).unwrap();
    let req = request("go");
    let a = mock.plan(&req).await.unwrap();
    assert_eq!(a.text.as_deref(), Some("looking"));
    assert_eq!(a.calls[0].id, "c1");
    assert_eq!(a.calls[0].args, json!({"path": "."}));
    assert!(matches!(
        mock.plan(&req).await.unwrap_err(),
        PlannerError::Transport(_)
    ));
    assert_eq!(mock.plan(&req).await.unwrap().text.as_deref(), Some("done"));
    assert_eq!(
        mock.plan(&req).await.unwrap_err(),
        PlannerError::Malformed("script exhausted".into())
    );

    let bad = dir.path().join("bad.json");
    std::fs::write(&bad, r#"[{"error": "nonsense"}]"#).unwrap();
    assert!(MockPlanner::from_script_file(&bad).is_err());
}
