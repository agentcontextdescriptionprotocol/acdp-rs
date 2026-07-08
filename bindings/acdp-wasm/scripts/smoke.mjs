// Release smoke test for the built wasm package (`--target web`).
//
// Loads the freshly-built pkg/ in Node's V8 wasm engine and runs the
// sig-001 Ed25519 verification through the published FFI surface. A
// failure means the .wasm about to be published cannot verify a known-
// good golden vector — the strongest cheap check before `npm publish`.
//
// The pkg is verifier-only (no producer), so we pin the sig-001 public
// key, signature, and content_hash (the values the Rust golden_vector
// suite and the Node/Python smokes assert) and check them directly.
import { readFile } from 'node:fs/promises';
import assert from 'node:assert/strict';

import init, { verifySignatureEd25519 } from '../pkg/acdp_wasm.js';

// sig-001 all-zero-seed producer key (hex 3b6a27bc… → base64).
const PUBLIC_KEY_B64 = 'O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=';
const SIGNATURE =
  'ErkbV+FUdn49TgF3zJ3RBe3AmyGxLVAQdMjlhabUfM96qendmWwdVodX/SV3O3aKLypbUu6gmb5Npt3O/w7nDQ==';
const CONTENT_HASH =
  'sha256:f170150ddbf59d99794e7797824591b374d459782084597b644ecc57a41031b5';

const wasmBytes = await readFile(new URL('../pkg/acdp_wasm_bg.wasm', import.meta.url));
await init({ module_or_path: wasmBytes });

const ok = JSON.parse(verifySignatureEd25519(PUBLIC_KEY_B64, SIGNATURE, CONTENT_HASH));
assert.equal(ok.valid, true, 'sig-001 signature must verify');

// Negative control: a tampered hash must NOT verify (proves the wasm is
// really checking, not always-true).
const tampered = CONTENT_HASH.replace('f170', '0000');
const bad = JSON.parse(verifySignatureEd25519(PUBLIC_KEY_B64, SIGNATURE, tampered));
assert.equal(bad.valid, false, 'signature over a tampered hash must fail');

console.log('acdp-wasm smoke OK: sig-001 signature verified through the wasm surface');
