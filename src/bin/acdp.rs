//! `acdp` — command-line front-end to the ACDP library.
//!
//! Subcommands:
//!
//! ```text
//! acdp capabilities <registry-url>
//! acdp retrieve     <registry-url> <ctx_id>
//! acdp body         <registry-url> <ctx_id>
//! acdp search       <registry-url> [--q QUERY] [--limit N] [--type T]
//!                                   [--tags A,B] [--domain D] [--status S]
//!                                   [--agent-id DID] [--cursor C]
//! acdp canonicalize                          # JCS bytes from stdin JSON
//! acdp hash                                  # content_hash from stdin JSON
//! acdp verify       <body.json>              # verify a stored body via DID resolution
//! acdp sign         <seed-hex> <key-id>      # sign content_hash from stdin JSON
//! ```
//!
//! Output is JSON (the resource on success, an error envelope on
//! failure) so the tool composes with `jq`. Exit code is 0 on success,
//! 1 on user / argument errors, 2 on protocol / verification failures.
//!
//! No CLI parser dependency: the binary uses `std::env::args` directly.
//! That keeps the dep graph identical to the library — adding `clap`
//! would pull in 30+ transitive crates for what is ~200 lines of
//! parsing.

use std::process::ExitCode;

use acdp::{
    client::{RegistryClient, VerifiedContext},
    crypto::{canonicalize, compute_content_hash, SigningKey},
    did::WebResolver,
    types::{primitives::ContentHash, Body, CtxId, SearchParams},
    AcdpError,
};

fn print_usage() {
    eprintln!(
        "acdp — Agent Context Description Protocol CLI\n\
         \n\
         USAGE:\n\
         \tacdp capabilities <registry-url>\n\
         \tacdp retrieve     <registry-url> <ctx_id>\n\
         \tacdp body         <registry-url> <ctx_id>\n\
         \tacdp search       <registry-url> [--q QUERY] [--limit N] [--type T]\n\
         \t                                  [--tags A,B] [--domain D] [--status S]\n\
         \t                                  [--agent-id DID] [--cursor C]\n\
         \tacdp canonicalize                          # JCS bytes from stdin JSON\n\
         \tacdp hash                                  # content_hash from stdin JSON\n\
         \tacdp verify       <body.json>              # verify a stored body\n\
         \tacdp sign         <seed-hex> <key-id>      # sign content_hash from stdin\n\
         "
    );
}

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = args.first().map(String::as_str) else {
        print_usage();
        return ExitCode::from(1);
    };
    let rest = &args[1..];
    let result: Result<(), CliError> = match cmd {
        "capabilities" => cmd_capabilities(rest).await,
        "retrieve" => cmd_retrieve(rest).await,
        "body" => cmd_body(rest).await,
        "search" => cmd_search(rest).await,
        "canonicalize" => cmd_canonicalize(),
        "hash" => cmd_hash(),
        "verify" => cmd_verify(rest).await,
        "sign" => cmd_sign(rest),
        "--help" | "-h" | "help" => {
            print_usage();
            return ExitCode::SUCCESS;
        }
        other => {
            eprintln!("acdp: unknown subcommand '{other}'\n");
            print_usage();
            return ExitCode::from(1);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(CliError::Usage(msg)) => {
            eprintln!("acdp: {msg}\n");
            print_usage();
            ExitCode::from(1)
        }
        Err(CliError::Acdp(e)) => {
            // Output a wire-shaped error envelope on stdout so a script
            // can `jq .error.code` to dispatch.
            let envelope = serde_json::json!({
                "error": {
                    "code": classify(&e),
                    "message": e.to_string(),
                }
            });
            println!("{envelope}");
            ExitCode::from(2)
        }
        Err(CliError::Io(msg)) => {
            eprintln!("acdp: {msg}");
            ExitCode::from(1)
        }
    }
}

enum CliError {
    Usage(String),
    Acdp(AcdpError),
    Io(String),
}

impl From<AcdpError> for CliError {
    fn from(e: AcdpError) -> Self {
        Self::Acdp(e)
    }
}

impl From<std::io::Error> for CliError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

impl From<serde_json::Error> for CliError {
    fn from(e: serde_json::Error) -> Self {
        Self::Io(format!("invalid JSON: {e}"))
    }
}

fn classify(e: &AcdpError) -> &'static str {
    match e {
        AcdpError::HashMismatch { .. } | AcdpError::RemoteHashMismatch(_) => "hash_mismatch",
        AcdpError::InvalidSignature(_) => "invalid_signature",
        AcdpError::SchemaViolation(_) => "schema_violation",
        AcdpError::NotFound(_) => "not_found",
        AcdpError::NotAuthorized(_) => "not_authorized",
        AcdpError::KeyNotAuthorized(_) => "key_not_authorized",
        AcdpError::KeyResolution(_) => "key_resolution_failed",
        AcdpError::KeyResolutionUnreachable(_) => "key_resolution_unreachable",
        AcdpError::CrossRegistryResolutionFailed(_) => "cross_registry_resolution_failed",
        AcdpError::PayloadTooLarge(_) => "payload_too_large",
        AcdpError::EmbeddedTooLarge(_) => "embedded_too_large",
        AcdpError::UnsupportedAlgorithm(_) => "unsupported_algorithm",
        AcdpError::RateLimited(_) => "rate_limited",
        AcdpError::Http(_) => "http_error",
        _ => "internal_error",
    }
}

// ── Subcommand implementations ───────────────────────────────────────────────

async fn cmd_capabilities(rest: &[String]) -> Result<(), CliError> {
    let url = rest
        .first()
        .ok_or_else(|| CliError::Usage("`capabilities` requires <registry-url>".into()))?;
    let client = RegistryClient::new(url)?;
    let caps = client.capabilities().await?;
    println!("{}", serde_json::to_string_pretty(&caps)?);
    Ok(())
}

async fn cmd_retrieve(rest: &[String]) -> Result<(), CliError> {
    let url = rest
        .first()
        .ok_or_else(|| CliError::Usage("`retrieve` requires <registry-url> <ctx_id>".into()))?;
    let id = rest
        .get(1)
        .ok_or_else(|| CliError::Usage("`retrieve` requires <ctx_id>".into()))?;
    let client = RegistryClient::new(url)?;
    let resolver = WebResolver::new();
    let ctx = VerifiedContext::fetch(&client, &resolver, &CtxId(id.clone())).await?;
    println!("{}", serde_json::to_string_pretty(&ctx.inner)?);
    Ok(())
}

async fn cmd_body(rest: &[String]) -> Result<(), CliError> {
    let url = rest
        .first()
        .ok_or_else(|| CliError::Usage("`body` requires <registry-url> <ctx_id>".into()))?;
    let id = rest
        .get(1)
        .ok_or_else(|| CliError::Usage("`body` requires <ctx_id>".into()))?;
    let client = RegistryClient::new(url)?;
    let body = client.retrieve_body(&CtxId(id.clone())).await?;
    println!("{}", serde_json::to_string_pretty(&body)?);
    Ok(())
}

async fn cmd_search(rest: &[String]) -> Result<(), CliError> {
    let url = rest
        .first()
        .ok_or_else(|| CliError::Usage("`search` requires <registry-url>".into()))?;
    let mut params = SearchParams::default();
    let mut i = 1;
    while i < rest.len() {
        match rest[i].as_str() {
            "--q" => {
                let v = rest
                    .get(i + 1)
                    .ok_or_else(|| CliError::Usage("--q requires a value".into()))?;
                params.q = Some(v.clone());
                i += 2;
            }
            "--limit" => {
                let v = rest
                    .get(i + 1)
                    .ok_or_else(|| CliError::Usage("--limit requires a value".into()))?;
                params.limit = Some(
                    v.parse()
                        .map_err(|_| CliError::Usage(format!("invalid --limit value: {v}")))?,
                );
                i += 2;
            }
            "--type" => {
                let v = rest
                    .get(i + 1)
                    .ok_or_else(|| CliError::Usage("--type requires a value".into()))?;
                params.context_type = Some(v.clone());
                i += 2;
            }
            "--tags" => {
                let v = rest
                    .get(i + 1)
                    .ok_or_else(|| CliError::Usage("--tags requires a value".into()))?;
                params.tags = Some(v.clone());
                i += 2;
            }
            "--domain" => {
                let v = rest
                    .get(i + 1)
                    .ok_or_else(|| CliError::Usage("--domain requires a value".into()))?;
                params.domain = Some(v.clone());
                i += 2;
            }
            "--status" => {
                let v = rest
                    .get(i + 1)
                    .ok_or_else(|| CliError::Usage("--status requires a value".into()))?;
                params.status = Some(v.clone());
                i += 2;
            }
            "--agent-id" => {
                let v = rest
                    .get(i + 1)
                    .ok_or_else(|| CliError::Usage("--agent-id requires a value".into()))?;
                params.agent_id = Some(v.clone());
                i += 2;
            }
            "--cursor" => {
                let v = rest
                    .get(i + 1)
                    .ok_or_else(|| CliError::Usage("--cursor requires a value".into()))?;
                params.cursor = Some(v.clone());
                i += 2;
            }
            other => return Err(CliError::Usage(format!("unknown search flag '{other}'"))),
        }
    }
    let client = RegistryClient::new(url)?;
    let resp = client.search(&params).await?;
    println!("{}", serde_json::to_string_pretty(&resp.matches)?);
    Ok(())
}

fn cmd_canonicalize() -> Result<(), CliError> {
    let v: serde_json::Value = read_stdin_json()?;
    let bytes = canonicalize(&v)?;
    use std::io::Write;
    std::io::stdout().write_all(&bytes)?;
    println!();
    Ok(())
}

fn cmd_hash() -> Result<(), CliError> {
    let v: serde_json::Value = read_stdin_json()?;
    let h = compute_content_hash(&v)?;
    println!("{h}");
    Ok(())
}

async fn cmd_verify(rest: &[String]) -> Result<(), CliError> {
    let path = rest
        .first()
        .ok_or_else(|| CliError::Usage("`verify` requires <body.json>".into()))?;
    let text = std::fs::read_to_string(path)?;
    let body: Body = serde_json::from_str(&text)?;
    let resolver = WebResolver::new();
    let verifier = acdp::crypto::verify::Verifier::new(&resolver);
    verifier.verify_body(&body).await?;
    println!(
        "{}",
        serde_json::json!({
            "ok": true,
            "ctx_id": body.ctx_id,
            "agent_id": body.agent_id,
            "content_hash": body.content_hash,
        })
    );
    Ok(())
}

fn cmd_sign(rest: &[String]) -> Result<(), CliError> {
    let seed_hex = rest
        .first()
        .ok_or_else(|| CliError::Usage("`sign` requires <seed-hex> <key-id>".into()))?;
    let key_id = rest
        .get(1)
        .ok_or_else(|| CliError::Usage("`sign` requires <key-id>".into()))?;
    let seed =
        hex::decode(seed_hex).map_err(|e| CliError::Usage(format!("invalid hex seed: {e}")))?;
    if seed.len() != 32 {
        return Err(CliError::Usage(format!(
            "seed must be 32 bytes, got {} bytes",
            seed.len()
        )));
    }
    let mut seed_arr = [0u8; 32];
    seed_arr.copy_from_slice(&seed);
    let key = SigningKey::from_bytes(&seed_arr);

    let v: serde_json::Value = read_stdin_json()?;
    // The stdin payload should be ProducerContent (the hash preimage).
    let h = compute_content_hash(&v)?;
    let sig = key.sign_content_hash(&h);

    println!(
        "{}",
        serde_json::json!({
            "content_hash": h,
            "signature": {
                "algorithm": "ed25519",
                "key_id": key_id,
                "value": sig,
            }
        })
    );
    let _: ContentHash = h; // silence unused-import on some feature combos
    Ok(())
}

fn read_stdin_json() -> Result<serde_json::Value, CliError> {
    use std::io::Read;
    let mut buf = String::new();
    std::io::stdin().read_to_string(&mut buf)?;
    let v: serde_json::Value = serde_json::from_str(&buf)?;
    Ok(v)
}
