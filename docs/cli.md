# CLI Reference

The `acdp` binary is a thin command-line wrapper over the library, and is its
own crate (`crates/acdp-cli`). It's useful for scripting, debugging the wire
format, and exercising a registry from a shell. It deliberately uses no
argument-parsing crate (`std::env::args` only), to keep its dependency graph
identical to the library.

```bash
cargo run -p acdp-cli -- <subcommand> [args]
# or install it:
cargo install acdp-cli
acdp <subcommand> [args]
```

## Exit codes & output contract

The CLI is built to be scriptable:

| Exit | Meaning | Output |
|---|---|---|
| `0` | success | result JSON on **stdout** |
| `1` | usage / IO error | message + usage on **stderr** |
| `2` | protocol/verification failure | a wire-shaped `{"error":{"code","message"}}` envelope on **stdout** |

The exit-2 envelope means you can dispatch on failures with `jq`:

```bash
acdp retrieve https://registry.example.com "acdp://…/uuid" \
  || echo "failed: $(acdp ... | jq -r .error.code)"
```

Result output is `serde_json::to_string_pretty`, so it pipes cleanly into `jq`.

## Subcommands

### Network — talk to a registry

These need the registry's HTTPS URL and apply the full
[security defaults](security.md) (HTTPS-only, SSRF filtering, caps).

#### `capabilities`
```bash
acdp capabilities <registry-url>
```
Fetches `GET /.well-known/acdp.json`. Prints the `CapabilitiesDocument`.

#### `retrieve` / `body`
```bash
acdp retrieve <registry-url> <ctx-id>     # full context: body + registry_state
acdp body     <registry-url> <ctx-id>     # body only
```

> The CLI fetches and prints; it does not run the full `VerifiedContext`
> pipeline. To verify a retrieved body offline, pipe it into `acdp verify`.

#### `search`
```bash
acdp search <registry-url> \
  [--q QUERY] [--limit N] [--type T] [--tags A,B] \
  [--domain D] [--status S] [--agent-id DID] [--cursor C]
```
Keyword discovery (RFC-ACDP-0005). Prints the `matches` array. Use `--cursor`
with the previous response's `next_cursor` to page.

#### `publish`
```bash
acdp publish <registry-url> \
  --key-seed <64-hex> \
  --agent-id <DID> --key-id <DID-URL> \
  [--key-algorithm ed25519|ecdsa-p256] \
  [--title T] [--type CT] [--domain D] [--visibility V] \
  [--audience DID,DID] [--summary S] [--description D] [--tags A,B,C] \
  [--idempotency-key UUID] \
  < producer_content.json          # optional stdin overlay
```
Builds, signs, and POSTs a context. The `--key-seed` is a 64-hex-char (32-byte)
private seed. Flags set individual fields; a JSON object on **stdin** is
overlaid for anything the flags don't cover (data_refs, metadata, etc.).

> The seed is passed on the command line, which is visible in process listings
> and shell history. For anything but local testing, prefer building requests in
> code where the key comes from secure storage — see [Producing contexts](producing.md).

#### `resolve`
```bash
acdp resolve <ctx-id> [--max-depth N]
```
Walks the `derived_from` provenance graph via `CrossRegistryResolver`,
verifying each hop. The registry authority is taken from the `ctx-id` itself.
Prints the root context plus its ancestors. `--max-depth` tightens the default
(10).

### Offline — no network

#### `validate`
```bash
acdp validate <file.json>
```
Runs the offline schema validator (`validation::validate_*`) on a file. Exit 2
with an error envelope if invalid.

#### `canonicalize` / `hash`
```bash
echo '{"b":2,"a":1}' | acdp canonicalize    # → RFC 8785 JCS bytes
echo '{"b":2,"a":1}' | acdp hash            # → sha256:<hex> of JCS(stdin)
```
The primitives behind `content_hash`. `hash` is the exact preimage computation —
handy for debugging a hash mismatch.

#### `verify`
```bash
acdp verify <body.json>
```
Verifies a stored body offline: schema → recompute `content_hash` → verify the
Ed25519 signature. (Resolves the producer key the same way the consumer pipeline
does.)

#### `sign`
```bash
echo 'sha256:<hex>' | acdp sign <seed-hex> <key-id>
```
Signs a `content_hash` string from stdin with the given seed. Emits the base64
signature. This is the low-level signing primitive — note the preimage is the
ASCII `"sha256:<hex>"` string, **not** the raw digest (see
[Architecture](architecture.md#three-things-that-trip-people-up)).

## Worked example

Round-trip a hash and signature without any network:

```bash
# 1. canonicalize + hash a producer-content object
H=$(jq -c . producer_content.json | acdp hash)
echo "$H"                                   # sha256:f170…

# 2. sign it
echo "$H" | acdp sign <seed-hex> "did:web:agents.example.com:me#key-1"
```

For everything the CLI can do, the library API does the same with typed results
— the CLI is a convenience layer, not a separate surface.
