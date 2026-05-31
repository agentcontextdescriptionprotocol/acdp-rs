// In-process tests for the ACDP Node.js SDK.
//
// Build first:  `npm run build:debug` (produces ../index.js + .node)
// Then run:     `node --test tests/`
//
// No HTTP — the JSON each method produces is checked directly against
// the spec's golden vector and against the verifier.

import test from 'node:test';
import assert from 'node:assert/strict';
import { AcdpProducer, AcdpP256Producer, AcdpVerifier } from '../index.js';

const AGENT_DID = 'did:web:registry.example.com:agents:test-agent';
const KEY_ID = `${AGENT_DID}#key-1`;

test('generate produces distinct keys', () => {
  const a = AcdpProducer.generate(AGENT_DID, KEY_ID);
  const b = AcdpProducer.generate(AGENT_DID, KEY_ID);
  assert.notEqual(a.publicKeyB64, b.publicKeyB64);
});

test('fromSeed is deterministic + round-trips through seedBytes', () => {
  const seed = Buffer.alloc(32, 7);
  const a = AcdpProducer.fromSeed(seed, AGENT_DID, KEY_ID);
  const b = AcdpProducer.fromSeed(seed, AGENT_DID, KEY_ID);
  assert.equal(a.publicKeyB64, b.publicKeyB64);
  assert.deepEqual(Buffer.from(a.seedBytes()), seed);
});

test('fromSeed rejects wrong length', () => {
  assert.throws(() =>
    AcdpProducer.fromSeed(Buffer.alloc(31), AGENT_DID, KEY_ID),
  );
});

test('golden content_hash + signature match sig-001', () => {
  // Pinned against `crypto::hash::tests::golden_content_hash` and
  // `crypto::sign::tests::sign_and_verify_ed25519_golden` in the Rust
  // suite. Drift on either side is a protocol break.
  const p = AcdpProducer.fromSeed(
    Buffer.alloc(32, 0),
    'did:web:agents.example.com:test-producer',
    'did:web:agents.example.com:test-producer#key-1',
  );
  const req = JSON.parse(
    p.buildPublishRequest({
      title: 'Golden test vector — minimal first version',
      contextType: 'data_snapshot',
    }),
  );
  assert.equal(
    req.content_hash,
    'sha256:f170150ddbf59d99794e7797824591b374d459782084597b644ecc57a41031b5',
  );
  assert.equal(
    req.signature.value,
    'ErkbV+FUdn49TgF3zJ3RBe3AmyGxLVAQdMjlhabUfM96qendmWwdVodX/SV3O3aKLypbUu6gmb5Npt3O/w7nDQ==',
  );
});

test('minimal publish request structure', () => {
  const p = AcdpProducer.generate(AGENT_DID, KEY_ID);
  const req = JSON.parse(
    p.buildPublishRequest({ title: 'Test', contextType: 'analysis' }),
  );
  assert.equal(req.version, 1);
  assert.equal(req.supersedes, null);
  assert.equal(req.visibility, 'public');
  assert.equal(req.agent_id, AGENT_DID);
  assert.ok(req.content_hash.startsWith('sha256:'));
  assert.equal(req.signature.algorithm, 'ed25519');
  assert.equal(req.signature.key_id, KEY_ID);
});

test('verify content_hash round-trip', () => {
  const p = AcdpProducer.generate(AGENT_DID, KEY_ID);
  const raw = p.buildPublishRequest({
    title: 'T',
    contextType: 'data_snapshot',
  });
  const req = JSON.parse(raw);
  assert.equal(AcdpVerifier.verifyContentHash(raw, req.content_hash), true);
});

test('verify content_hash rejects tampering', () => {
  const p = AcdpProducer.generate(AGENT_DID, KEY_ID);
  const raw = p.buildPublishRequest({
    title: 'Original',
    contextType: 'data_snapshot',
  });
  const req = JSON.parse(raw);
  req.title = 'Tampered';
  assert.throws(() =>
    AcdpVerifier.verifyContentHash(JSON.stringify(req), req.content_hash),
  );
});

test('verify signature round-trip', () => {
  const p = AcdpProducer.generate(AGENT_DID, KEY_ID);
  const raw = p.buildPublishRequest({
    title: 'T',
    contextType: 'data_snapshot',
  });
  const req = JSON.parse(raw);
  assert.equal(
    AcdpVerifier.verifySignature(
      p.publicKeyB64,
      req.signature.value,
      req.content_hash,
    ),
    true,
  );
});

test('signChallenge returns a 64-byte Ed25519 signature', () => {
  const p = AcdpProducer.generate(AGENT_DID, KEY_ID);
  const sig = p.signChallenge(
    'acdp-registry-auth:v1:nonce:did:web:x:reg:123',
  );
  assert.equal(Buffer.from(sig, 'base64').length, 64);
});

test('restricted visibility requires audience', () => {
  const p = AcdpProducer.generate(AGENT_DID, KEY_ID);
  assert.throws(() =>
    p.buildPublishRequest({
      title: 'Secret',
      contextType: 'analysis',
      visibility: 'restricted',
    }),
  );
});

test('metadata round-trips as a JSON object (not a quoted string)', () => {
  const p = AcdpProducer.generate(AGENT_DID, KEY_ID);
  const raw = p.buildPublishRequest({
    title: 't',
    contextType: 'data_snapshot',
    metadata: JSON.stringify({ k: 'v', n: 42, deep: { x: [1, 2, 3] } }),
  });
  const req = JSON.parse(raw);
  assert.deepEqual(req.metadata, { k: 'v', n: 42, deep: { x: [1, 2, 3] } });
  // And the body still re-verifies — metadata WAS in the hash preimage.
  assert.equal(
    AcdpVerifier.verifyContentHash(raw, req.content_hash),
    true,
  );
});

test('invalid metadata JSON is rejected', () => {
  const p = AcdpProducer.generate(AGENT_DID, KEY_ID);
  assert.throws(() =>
    p.buildPublishRequest({
      title: 't',
      contextType: 'data_snapshot',
      metadata: '{not-valid-json',
    }),
  );
});

test('verifyContentHash rejects a malformed expectedHash', () => {
  const p = AcdpProducer.generate(AGENT_DID, KEY_ID);
  const raw = p.buildPublishRequest({
    title: 't',
    contextType: 'data_snapshot',
  });
  assert.throws(() => AcdpVerifier.verifyContentHash(raw, 'not-a-hash'));
  assert.throws(() =>
    AcdpVerifier.verifyContentHash(raw, 'md5:' + 'a'.repeat(32)),
  );
});

test('seedBytes returns a fresh copy each call', () => {
  const p = AcdpProducer.fromSeed(Buffer.alloc(32, 3), AGENT_DID, KEY_ID);
  const a = p.seedBytes();
  const b = p.seedBytes();
  assert.deepEqual(Buffer.from(a), Buffer.alloc(32, 3));
  assert.deepEqual(Buffer.from(b), Buffer.alloc(32, 3));
  // Mutating one copy must not affect the producer's stored seed.
  a[0] = 0xff;
  assert.equal(Buffer.from(p.seedBytes())[0], 3);
});

test('supersede request bumps version and carries lineage_id', () => {
  const p = AcdpProducer.generate(AGENT_DID, KEY_ID);
  const v1 = JSON.parse(
    p.buildPublishRequest({ title: 'v1', contextType: 'data_snapshot' }),
  );
  // Synthesize registry-assigned fields to make a valid Body shape.
  const body = {
    ...v1,
    ctx_id: 'acdp://registry.example.com/12345678-1234-4321-8123-123456781234',
    lineage_id: 'lin:sha256:' + 'a'.repeat(64),
    origin_registry: 'registry.example.com',
    created_at: '2026-01-01T00:00:00.000Z',
  };
  const v2 = JSON.parse(
    p.buildSupersedeRequest(JSON.stringify(body), {
      title: 'v2',
      summary: 'updated',
    }),
  );
  assert.equal(v2.version, 2);
  assert.equal(v2.supersedes, body.ctx_id);
  assert.equal(v2.lineage_id, body.lineage_id);
  assert.equal(v2.title, 'v2');
});

// ── ECDSA-P256 producer (AcdpP256Producer) ──────────────────────────────

// sig-002 golden vector: private scalar = 1 (public key = the P-256
// generator G). RFC 6979 makes the signature value reproducible.
const P256_GOLDEN_SEED = Buffer.concat([Buffer.alloc(31), Buffer.from([1])]);
const P256_GOLDEN_HASH =
  'sha256:f170150ddbf59d99794e7797824591b374d459782084597b644ecc57a41031b5';
const P256_GOLDEN_SIG =
  'O+b+E5OIecgwCnjDyTqsiwwy3VTdBHbVhiRR9k3FAPZHvLJ5dyYYVPPUWbl0dKDdgKMw2dWrnKWRANJVoS9vNw==';

test('p256 generate produces distinct keys', () => {
  const a = AcdpP256Producer.generate(AGENT_DID, KEY_ID);
  const b = AcdpP256Producer.generate(AGENT_DID, KEY_ID);
  assert.notEqual(a.publicKeySec1B64, b.publicKeySec1B64);
});

test('p256 fromSeed is deterministic + round-trips through seedBytes', () => {
  const seed = Buffer.alloc(32, 7);
  const a = AcdpP256Producer.fromSeed(seed, AGENT_DID, KEY_ID);
  const b = AcdpP256Producer.fromSeed(seed, AGENT_DID, KEY_ID);
  assert.equal(a.publicKeySec1B64, b.publicKeySec1B64);
  assert.deepEqual(Buffer.from(a.seedBytes()), seed);
});

test('p256 fromSeed rejects wrong length', () => {
  assert.throws(() =>
    AcdpP256Producer.fromSeed(Buffer.alloc(31), AGENT_DID, KEY_ID),
  );
});

test('p256 public key is SEC1 uncompressed (generator for scalar 1)', () => {
  const p = AcdpP256Producer.fromSeed(P256_GOLDEN_SEED, AGENT_DID, KEY_ID);
  const sec1 = Buffer.from(p.publicKeySec1B64, 'base64');
  assert.equal(sec1.length, 65);
  assert.equal(sec1[0], 0x04);
  assert.equal(
    sec1.toString('hex'),
    '046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296' +
      '4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5',
  );
});

test('p256 golden content_hash + signature match sig-002', () => {
  const p = AcdpP256Producer.fromSeed(
    P256_GOLDEN_SEED,
    'did:web:agents.example.com:test-producer',
    'did:web:agents.example.com:test-producer#key-1',
  );
  const req = JSON.parse(
    p.buildPublishRequest({
      title: 'Golden test vector — minimal first version',
      contextType: 'data_snapshot',
    }),
  );
  assert.equal(req.content_hash, P256_GOLDEN_HASH);
  assert.equal(req.signature.algorithm, 'ecdsa-p256');
  assert.equal(req.signature.value, P256_GOLDEN_SIG);
});

test('p256 minimal publish request structure', () => {
  const p = AcdpP256Producer.generate(AGENT_DID, KEY_ID);
  const req = JSON.parse(
    p.buildPublishRequest({ title: 'P256', contextType: 'analysis' }),
  );
  assert.equal(req.signature.algorithm, 'ecdsa-p256');
  // IEEE 1363 r‖s is 64 raw bytes → 88 base64 chars.
  assert.equal(req.signature.value.length, 88);
  assert.equal(Buffer.from(req.signature.value, 'base64').length, 64);
});

test('p256 content_hash verifies through the (algorithm-agnostic) verifier', () => {
  const p = AcdpP256Producer.generate(AGENT_DID, KEY_ID);
  const raw = p.buildPublishRequest({
    title: 'T',
    contextType: 'data_snapshot',
  });
  const req = JSON.parse(raw);
  assert.equal(AcdpVerifier.verifyContentHash(raw, req.content_hash), true);
});

test('p256 signChallenge returns a 64-byte signature', () => {
  const p = AcdpP256Producer.generate(AGENT_DID, KEY_ID);
  const sig = p.signChallenge('acdp-registry-auth:v1:nonce:did:web:x:reg:123');
  assert.equal(Buffer.from(sig, 'base64').length, 64);
});

test('p256 verifySignatureP256 round-trip', () => {
  const p = AcdpP256Producer.generate(AGENT_DID, KEY_ID);
  const req = JSON.parse(
    p.buildPublishRequest({ title: 'P256 sig', contextType: 'data_snapshot' }),
  );
  assert.equal(
    AcdpVerifier.verifySignatureP256(
      p.publicKeySec1B64,
      req.signature.value,
      req.content_hash,
    ),
    true,
  );
});

test('p256 verifySignatureP256 rejects the wrong key', () => {
  const p = AcdpP256Producer.generate(AGENT_DID, KEY_ID);
  const other = AcdpP256Producer.generate(AGENT_DID, KEY_ID);
  const req = JSON.parse(
    p.buildPublishRequest({ title: 'P256 sig', contextType: 'data_snapshot' }),
  );
  assert.throws(() =>
    AcdpVerifier.verifySignatureP256(
      other.publicKeySec1B64,
      req.signature.value,
      req.content_hash,
    ),
  );
});

test('p256 golden signature verifies (sig-002 end-to-end)', () => {
  const p = AcdpP256Producer.fromSeed(P256_GOLDEN_SEED, AGENT_DID, KEY_ID);
  assert.equal(
    AcdpVerifier.verifySignatureP256(
      p.publicKeySec1B64,
      P256_GOLDEN_SIG,
      P256_GOLDEN_HASH,
    ),
    true,
  );
});

test('p256 publicKeyJwk has EC/P-256 shape', () => {
  const p = AcdpP256Producer.fromSeed(P256_GOLDEN_SEED, AGENT_DID, KEY_ID);
  const jwk = JSON.parse(p.publicKeyJwk);
  assert.equal(jwk.kty, 'EC');
  assert.equal(jwk.crv, 'P-256');
  assert.ok(jwk.x && jwk.y);
  // base64url, no padding.
  assert.ok(!jwk.x.includes('=') && !jwk.y.includes('='));
});

test('p256 didVerificationMethod composes a JsonWebKey2020 entry', () => {
  const p = AcdpP256Producer.fromSeed(P256_GOLDEN_SEED, AGENT_DID, KEY_ID);
  const vm = JSON.parse(p.didVerificationMethod(KEY_ID, AGENT_DID));
  assert.equal(vm.id, KEY_ID);
  assert.equal(vm.type, 'JsonWebKey2020');
  assert.equal(vm.controller, AGENT_DID);
  assert.deepEqual(vm.publicKeyJwk, JSON.parse(p.publicKeyJwk));
});

// ── Extended Body fields (dataRefs / dataPeriod / expiresAt /
//    expectedLineageId) ────────────────────────────────────────────────

test('publish with dataRefs / dataPeriod / expiresAt stays in the hash preimage', () => {
  const p = AcdpProducer.generate(AGENT_DID, KEY_ID);
  const raw = p.buildPublishRequest({
    title: 'Rich body',
    contextType: 'data_snapshot',
    dataRefs: JSON.stringify([
      { type: 'primary_result', location: 'https://example.com/d.parquet' },
    ]),
    dataPeriod: JSON.stringify({
      start: '2026-01-01T00:00:00Z',
      end: '2026-01-02T00:00:00Z',
    }),
    expiresAt: '2026-06-01T00:00:00Z',
  });
  const req = JSON.parse(raw);
  assert.equal(req.data_refs[0].type, 'primary_result');
  assert.equal(req.data_refs[0].location, 'https://example.com/d.parquet');
  assert.ok(req.data_period.start.startsWith('2026-01-01'));
  assert.ok(req.expires_at.startsWith('2026-06-01'));
  // data_refs is part of ProducerContent → must re-verify.
  assert.equal(AcdpVerifier.verifyContentHash(raw, req.content_hash), true);
});

test('invalid dataRefs JSON is rejected', () => {
  const p = AcdpProducer.generate(AGENT_DID, KEY_ID);
  assert.throws(() =>
    p.buildPublishRequest({
      title: 't',
      contextType: 'data_snapshot',
      dataRefs: '[not-json',
    }),
  );
});

test('invalid expiresAt timestamp is rejected', () => {
  const p = AcdpProducer.generate(AGENT_DID, KEY_ID);
  assert.throws(() =>
    p.buildPublishRequest({
      title: 't',
      contextType: 'data_snapshot',
      expiresAt: 'not-a-date',
    }),
  );
});

test('expectedLineageId is rejected on a v1 publish', () => {
  const p = AcdpProducer.generate(AGENT_DID, KEY_ID);
  assert.throws(() =>
    p.buildPublishRequest({
      title: 't',
      contextType: 'data_snapshot',
      expectedLineageId: 'lin:sha256:' + 'a'.repeat(64),
    }),
  );
});

test('supersede accepts an explicit expectedLineageId override', () => {
  const p = AcdpProducer.generate(AGENT_DID, KEY_ID);
  const v1 = JSON.parse(
    p.buildPublishRequest({ title: 'v1', contextType: 'data_snapshot' }),
  );
  const lineage = 'lin:sha256:' + 'b'.repeat(64);
  const body = {
    ...v1,
    ctx_id: 'acdp://registry.example.com/12345678-1234-4321-8123-123456781234',
    lineage_id: lineage,
    origin_registry: 'registry.example.com',
    created_at: '2026-01-01T00:00:00.000Z',
  };
  const v2 = JSON.parse(
    p.buildSupersedeRequest(JSON.stringify(body), {
      title: 'v2',
      expectedLineageId: lineage,
    }),
  );
  assert.equal(v2.version, 2);
  assert.equal(v2.lineage_id, lineage);
});

test('supersede rejects a malformed expectedLineageId', () => {
  const p = AcdpProducer.generate(AGENT_DID, KEY_ID);
  const v1 = JSON.parse(
    p.buildPublishRequest({ title: 'v1', contextType: 'data_snapshot' }),
  );
  const body = {
    ...v1,
    ctx_id: 'acdp://registry.example.com/12345678-1234-4321-8123-123456781234',
    lineage_id: 'lin:sha256:' + 'c'.repeat(64),
    origin_registry: 'registry.example.com',
    created_at: '2026-01-01T00:00:00.000Z',
  };
  assert.throws(() =>
    p.buildSupersedeRequest(JSON.stringify(body), {
      expectedLineageId: 'not-a-lineage-id',
    }),
  );
});
