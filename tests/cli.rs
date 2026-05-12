//! Subprocess integration tests for the `acdp` CLI binary.
//!
//! Gated on the `cli` feature; the binary path is provided by Cargo via
//! the `CARGO_BIN_EXE_acdp` env var. The tests drive the binary as a
//! black box (stdin / stdout / exit code) so they catch UX regressions
//! that unit tests would miss.

#![cfg(feature = "cli")]

use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::json;
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

fn acdp_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_acdp"))
}

/// Run the CLI with the given args + stdin, return `(exit_code, stdout, stderr)`.
fn run_cli(args: &[&str], stdin_payload: Option<&str>) -> (i32, String, String) {
    let mut child = acdp_bin()
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn acdp binary");
    if let Some(payload) = stdin_payload {
        child
            .stdin
            .as_mut()
            .expect("stdin pipe")
            .write_all(payload.as_bytes())
            .expect("write stdin");
    }
    let out = child.wait_with_output().expect("wait acdp");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

// ── publish ───────────────────────────────────────────────────────────────────

/// FEAT-04 — `acdp publish` posts to `POST /contexts` and prints the
/// registry's PublishResponse. Mocks the registry with wiremock over
/// plain HTTP (reqwest's rustls TLS backend handles both schemes).
#[tokio::test]
async fn cli_publish_against_mocked_registry() {
    let registry = MockServer::start().await;
    let response_body = json!({
        "ctx_id": "acdp://r.example.com/12345678-1234-4321-8123-123456781234",
        "lineage_id": "lin:sha256:b14ccd2a8b34530309255db68c151a10689b6a82feb30aff9222d54fdd871720",
        "version": 1,
        "created_at": "2026-05-10T00:00:00.000Z",
        "status": "active",
    });

    Mock::given(method("POST"))
        .and(path("/contexts"))
        .respond_with(ResponseTemplate::new(201).set_body_json(response_body.clone()))
        .mount(&registry)
        .await;

    let seed_hex = "0".repeat(64); // all-zeros — test seed only
    let url = registry.uri();

    let (code, stdout, stderr) = run_cli(
        &[
            "publish",
            &url,
            "--key-seed",
            &seed_hex,
            "--agent-id",
            "did:web:agents.example.com:test",
            "--key-id",
            "did:web:agents.example.com:test#key-1",
            "--title",
            "cli test",
            "--type",
            "data_snapshot",
            "--visibility",
            "public",
        ],
        Some(""), // empty stdin
    );

    assert_eq!(
        code, 0,
        "publish must exit 0 on success; stderr={stderr}, stdout={stdout}"
    );
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("publish stdout must be JSON");
    assert_eq!(parsed["ctx_id"], response_body["ctx_id"]);
    assert_eq!(parsed["version"], 1);

    // Verify the request body wiremock recorded matches what we asked
    // the CLI to publish. Catches regressions where flag values fail
    // to plumb through to the producer builder.
    let requests = registry
        .received_requests()
        .await
        .expect("recorded requests");
    let last = requests
        .last()
        .expect("publish MUST have made at least one request");
    let sent: acdp::types::PublishRequest =
        serde_json::from_slice(&last.body).expect("posted body MUST deserialize as PublishRequest");
    assert_eq!(sent.title, "cli test");
    assert!(
        matches!(sent.context_type, acdp::types::ContextType::DataSnapshot),
        "type flag did not propagate"
    );
    assert_eq!(sent.agent_id.as_str(), "did:web:agents.example.com:test");
    assert_eq!(sent.signature.algorithm, "ed25519");
    assert_eq!(
        sent.signature.value.len(),
        88,
        "ed25519 signature MUST be 88 base64 chars"
    );
    // Hash matches what the producer would have computed locally for
    // exactly this ProducerContent — confirms the CLI didn't drop or
    // mangle a producer-controlled field.
    let req_value = serde_json::to_value(&sent).expect("re-serialize");
    let recomputed =
        acdp::crypto::compute_content_hash(&req_value).expect("recompute content_hash");
    assert_eq!(
        sent.content_hash, recomputed,
        "posted content_hash MUST match recomputation over the body the CLI built"
    );
}

/// FEAT-04 — `--idempotency-key` is forwarded as a request header. We
/// match the request having the header set.
#[tokio::test]
async fn cli_publish_forwards_idempotency_key() {
    let registry = MockServer::start().await;
    let response_body = json!({
        "ctx_id": "acdp://r.example.com/12345678-1234-4321-8123-123456781234",
        "lineage_id": "lin:sha256:b14ccd2a8b34530309255db68c151a10689b6a82feb30aff9222d54fdd871720",
        "version": 1,
        "created_at": "2026-05-10T00:00:00.000Z",
        "status": "active",
    });

    Mock::given(method("POST"))
        .and(path("/contexts"))
        .and(wiremock::matchers::header(
            "Idempotency-Key",
            "11111111-2222-3333-4444-555555555555",
        ))
        .respond_with(ResponseTemplate::new(201).set_body_json(response_body))
        .mount(&registry)
        .await;

    let seed_hex = "0".repeat(64);
    let url = registry.uri();
    let (code, stdout, stderr) = run_cli(
        &[
            "publish",
            &url,
            "--key-seed",
            &seed_hex,
            "--agent-id",
            "did:web:agents.example.com:test",
            "--key-id",
            "did:web:agents.example.com:test#key-1",
            "--title",
            "idem test",
            "--type",
            "data_snapshot",
            "--idempotency-key",
            "11111111-2222-3333-4444-555555555555",
        ],
        None,
    );
    assert_eq!(
        code, 0,
        "idem publish must succeed; stderr={stderr}, stdout={stdout}"
    );
}

// ── validate ──────────────────────────────────────────────────────────────────

/// FEAT-05 — `acdp validate` runs offline schema validation and
/// reports both the declared and recomputed content_hash so users can
/// see whether the body is internally consistent.
#[test]
fn cli_validate_accepts_well_formed_request() {
    let req = json!({
        "version": 1,
        "supersedes": null,
        "agent_id": "did:web:agents.example.com:test",
        "contributors": [],
        "title": "validate test",
        "type": "data_snapshot",
        "data_refs": [],
        "derived_from": [],
        "visibility": "public",
        "content_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "signature": {
            "algorithm": "ed25519",
            "key_id": "did:web:agents.example.com:test#key-1",
            "value": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
        }
    });
    let dir = std::env::temp_dir();
    let path = dir.join(format!("acdp-validate-test-{}.json", std::process::id()));
    std::fs::write(&path, serde_json::to_vec(&req).unwrap()).unwrap();

    let (code, stdout, stderr) = run_cli(&["validate", path.to_str().unwrap()], None);
    let _ = std::fs::remove_file(&path);
    assert_eq!(code, 0, "validate must accept; stderr={stderr}");
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("validate stdout must be JSON");
    assert_eq!(parsed["ok"], true);
    assert!(parsed.get("content_hash_recomputed").is_some());
}

/// FEAT-05 — `acdp validate` exits non-zero and emits an error envelope
/// for schema-invalid input.
#[test]
fn cli_validate_rejects_v1_with_lineage_id() {
    let req = json!({
        "version": 1,
        "supersedes": null,
        "lineage_id": "lin:sha256:1111111111111111111111111111111111111111111111111111111111111111",
        "agent_id": "did:web:agents.example.com:test",
        "contributors": [],
        "title": "v1+lineage rejected",
        "type": "data_snapshot",
        "data_refs": [],
        "derived_from": [],
        "visibility": "public",
        "content_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "signature": {
            "algorithm": "ed25519",
            "key_id": "did:web:agents.example.com:test#key-1",
            "value": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
        }
    });
    let dir = std::env::temp_dir();
    let path = dir.join(format!("acdp-validate-bad-{}.json", std::process::id()));
    std::fs::write(&path, serde_json::to_vec(&req).unwrap()).unwrap();

    let (code, stdout, _stderr) = run_cli(&["validate", path.to_str().unwrap()], None);
    let _ = std::fs::remove_file(&path);
    assert_eq!(
        code, 2,
        "validate of v1+lineage MUST exit 2 (protocol error)"
    );
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("validate error stdout must be JSON envelope");
    assert_eq!(parsed["error"]["code"], "schema_violation");
}

// ── usage / unknown subcommand ───────────────────────────────────────────────

/// Plain usage output: invoking `acdp` with no args exits 1 and prints
/// the usage line on stderr. Catches regressions in arg parsing.
#[test]
fn cli_no_args_prints_usage_and_exits_1() {
    let (code, stdout, stderr) = run_cli(&[], None);
    assert_eq!(code, 1, "no-args MUST exit 1");
    assert!(stdout.is_empty());
    assert!(
        stderr.contains("USAGE"),
        "stderr MUST include usage line; got: {stderr}"
    );
}

/// `acdp publish` includes the new command in the usage block.
#[test]
fn cli_help_lists_new_commands() {
    let (code, _stdout, stderr) = run_cli(&["help"], None);
    assert_eq!(code, 0);
    assert!(stderr.contains("acdp publish"));
    assert!(stderr.contains("acdp validate"));
    assert!(stderr.contains("acdp resolve"));
}

// ── resolve ──────────────────────────────────────────────────────────────────

/// FEAT-05 — `acdp resolve` with no args exits 1 (usage error) and
/// prints the usage line on stderr.
#[test]
fn cli_resolve_no_args_exits_usage_error() {
    let (code, stdout, stderr) = run_cli(&["resolve"], None);
    assert_eq!(code, 1, "resolve with no args MUST exit 1 (usage error)");
    assert!(stdout.is_empty());
    assert!(
        stderr.contains("`resolve` requires") || stderr.contains("USAGE"),
        "stderr MUST surface the missing-arg message, got: {stderr}"
    );
}

/// FEAT-05 — `acdp resolve <malformed>` surfaces a protocol error
/// envelope on stdout and exits 2. The malformed ctx_id is caught at
/// parse time inside `CrossRegistryResolver::resolve`; no network is
/// touched.
#[test]
fn cli_resolve_malformed_ctx_id_exits_protocol_error() {
    let (code, stdout, stderr) = run_cli(&["resolve", "not-a-ctx-id"], None);
    assert_eq!(
        code, 2,
        "resolve with malformed ctx_id MUST exit 2 (protocol error); stderr={stderr}"
    );
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("resolve error envelope MUST be JSON");
    assert!(
        parsed["error"]["code"].is_string(),
        "error envelope MUST carry an `error.code` string, got {parsed}"
    );
}

/// FEAT-05 — `acdp resolve --max-depth bad-int` is a flag-parse error
/// (exit 1), not a protocol error. Catches the easy-to-overlook case
/// where flag-handling errors should surface as user errors, not
/// network errors.
#[test]
fn cli_resolve_bad_max_depth_exits_usage_error() {
    let (code, _stdout, stderr) = run_cli(
        &[
            "resolve",
            "acdp://r.example.com/12345678-1234-4321-8123-123456781234",
            "--max-depth",
            "not-a-number",
        ],
        None,
    );
    assert_eq!(code, 1, "bad --max-depth MUST exit 1 (usage error)");
    assert!(
        stderr.contains("--max-depth") || stderr.contains("invalid"),
        "stderr MUST mention the bad flag, got: {stderr}"
    );
}
