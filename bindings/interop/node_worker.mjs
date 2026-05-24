#!/usr/bin/env node
// ACDP interop worker — Node.js side.
//
// A long-lived process speaking line-delimited JSON-RPC over
// stdin/stdout. The Python interop test suite (test_interop.py) spawns
// one of these and drives every step through the Node binding. The
// worker only computes one side of each step; the test relays the wire
// JSON between Python and Node so a green run proves byte-compatible
// PublishRequest output across the two languages.
//
// Protocol (one JSON object per line):
//   request : {"id": int, "method": str, "params": {...}}
//   response: {"id": int, "ok": true,  "result": {...}}
//           | {"id": int, "ok": false, "error": str}
//
// Producer handles are integers into a per-process registry; they are
// opaque to the caller.

import { createInterface } from 'node:readline';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const mod = await import(
  pathToFileURL(join(here, '..', 'acdp-node', 'index.js')).href
);
const AcdpProducer = mod.AcdpProducer ?? mod.default?.AcdpProducer;
const AcdpVerifier = mod.AcdpVerifier ?? mod.default?.AcdpVerifier;
if (!AcdpProducer || !AcdpVerifier) {
  throw new Error(
    'acdp-node binding not built — run `npm run build:debug` in bindings/acdp-node/',
  );
}

const registry = new Map();
let nextHandle = 0;
const store = (obj) => {
  const handle = nextHandle++;
  registry.set(handle, obj);
  return handle;
};

const methods = {
  ping: () => ({ sdk: 'acdp-node', version: '0.1.0' }),

  // Returns { handle, agent_did, key_id, public_key_b64 }.
  new_producer: (p) => {
    const producer = p.seed
      ? AcdpProducer.fromSeed(Buffer.from(p.seed), p.agent_did, p.key_id)
      : AcdpProducer.generate(p.agent_did, p.key_id);
    return {
      handle: store(producer),
      agent_did: producer.agentDid,
      key_id: producer.keyId,
      public_key_b64: producer.publicKeyB64,
    };
  },

  // opts is the JS-side PublishOpts (camelCase). Returns the wire JSON
  // string (so byte equality with the Python side is observable).
  build_publish_request: (p) => ({
    raw: registry.get(p.producer).buildPublishRequest(p.opts),
  }),

  build_supersede_request: (p) => ({
    raw: registry.get(p.producer).buildSupersedeRequest(
      p.previous_body_json,
      p.opts,
    ),
  }),

  sign_challenge: (p) => ({
    signature: registry.get(p.producer).signChallenge(p.signing_input),
  }),

  verify_content_hash: (p) => ({
    ok: AcdpVerifier.verifyContentHash(p.body_json, p.expected_hash),
  }),

  verify_signature: (p) => ({
    ok: AcdpVerifier.verifySignature(
      p.pub_key_b64,
      p.sig_b64,
      p.content_hash,
    ),
  }),
};

const rl = createInterface({ input: process.stdin });
for await (const line of rl) {
  const trimmed = line.trim();
  if (!trimmed) continue;
  const req = JSON.parse(trimmed);
  let resp;
  try {
    const handler = methods[req.method];
    if (!handler) throw new Error(`unknown method: ${req.method}`);
    resp = { id: req.id, ok: true, result: handler(req.params ?? {}) };
  } catch (err) {
    resp = { id: req.id, ok: false, error: String(err?.message ?? err) };
  }
  process.stdout.write(JSON.stringify(resp) + '\n');
}
