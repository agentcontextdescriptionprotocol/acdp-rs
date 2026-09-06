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
  //
  // sig-001 was signed under the 0.1.x form where `acdp_version` is
  // OMITTED. Since 0.2 the SDK emits it explicitly by default, so the
  // golden vector is reproduced via the opt-out.
  const p = AcdpProducer.fromSeed(
    Buffer.alloc(32, 0),
    'did:web:agents.example.com:test-producer',
    'did:web:agents.example.com:test-producer#key-1',
  );
  const req = JSON.parse(
    p.buildPublishRequest({
      title: 'Golden test vector — minimal first version',
      contextType: 'data_snapshot',
      omitAcdpVersion: true,
    }),
  );
  assert.ok(!('acdp_version' in req));
  assert.equal(
    req.content_hash,
    'sha256:f170150ddbf59d99794e7797824591b374d459782084597b644ecc57a41031b5',
  );
  assert.equal(
    req.signature.value,
    'ErkbV+FUdn49TgF3zJ3RBe3AmyGxLVAQdMjlhabUfM96qendmWwdVodX/SV3O3aKLypbUu6gmb5Npt3O/w7nDQ==',
  );
});

test('default publish emits acdp_version "0.4.0" explicitly (distinct preimage)', () => {
  // ACDP 0.2+ SDK default: `acdp_version` is emitted explicitly, tracking
  // the newest Final wire line ("0.4.0" as of RFC-ACDP-0015's promotion).
  // Consumers treat the absent field as "0.1.0" (RFC-ACDP-0001 §6), but
  // absent and explicit are different JCS preimages — so the same body
  // hashes differently from the sig-001 omitted form.
  const p = AcdpProducer.fromSeed(
    Buffer.alloc(32, 0),
    'did:web:agents.example.com:test-producer',
    'did:web:agents.example.com:test-producer#key-1',
  );
  const raw = p.buildPublishRequest({
    title: 'Golden test vector — minimal first version',
    contextType: 'data_snapshot',
  });
  const req = JSON.parse(raw);
  assert.equal(req.acdp_version, '0.4.0');
  assert.notEqual(
    req.content_hash,
    'sha256:f170150ddbf59d99794e7797824591b374d459782084597b644ecc57a41031b5',
  );
  // Still self-consistent: the hash covers what was actually emitted.
  assert.equal(AcdpVerifier.verifyContentHash(raw, req.content_hash), true);
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
  // Signed under the 0.1.x omitted-acdp_version form, like sig-001.
  const p = AcdpP256Producer.fromSeed(
    P256_GOLDEN_SEED,
    'did:web:agents.example.com:test-producer',
    'did:web:agents.example.com:test-producer#key-1',
  );
  const req = JSON.parse(
    p.buildPublishRequest({
      title: 'Golden test vector — minimal first version',
      contextType: 'data_snapshot',
      omitAcdpVersion: true,
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

// ── anchors (RFC-ACDP-0016) ──────────────────────────────────────────────

const WELL_FORMED_ANCHOR = {
  scheme: 'macp.commitment',
  content_hash:
    'sha256:fa8fe6b9143b469866d31de09b81928cc44d226ed935162cd346ae80d14fd200',
};

test('publish with anchors stays in the hash preimage', () => {
  const p = AcdpProducer.generate(AGENT_DID, KEY_ID);
  const raw = p.buildPublishRequest({
    title: 'Anchored context',
    contextType: 'data_snapshot',
    anchors: JSON.stringify([WELL_FORMED_ANCHOR]),
  });
  const req = JSON.parse(raw);
  assert.equal(req.anchors[0].scheme, 'macp.commitment');
  assert.equal(req.anchors[0].content_hash, WELL_FORMED_ANCHOR.content_hash);
  // anchors is part of ProducerContent → must re-verify.
  assert.equal(AcdpVerifier.verifyContentHash(raw, req.content_hash), true);
});

test('supersede with anchors', () => {
  // anchors is settable on supersede too (unlike derivedFrom, which is
  // publish-only) — it describes evidence about this version's content,
  // not an immutable lineage fact.
  const p = AcdpProducer.generate(AGENT_DID, KEY_ID);
  const v1 = JSON.parse(
    p.buildPublishRequest({ title: 'v1', contextType: 'data_snapshot' }),
  );
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
      anchors: JSON.stringify([WELL_FORMED_ANCHOR]),
    }),
  );
  assert.equal(v2.anchors[0].scheme, 'macp.commitment');
});

test('invalid anchors JSON is rejected', () => {
  const p = AcdpProducer.generate(AGENT_DID, KEY_ID);
  assert.throws(() =>
    p.buildPublishRequest({
      title: 't',
      contextType: 'data_snapshot',
      anchors: '[not-json',
    }),
  );
});

test('empty anchors array is rejected (absent-when-empty convention)', () => {
  const p = AcdpProducer.generate(AGENT_DID, KEY_ID);
  assert.throws(() =>
    p.buildPublishRequest({
      title: 't',
      contextType: 'data_snapshot',
      anchors: '[]',
    }),
  );
});

test('supersede carries anchors forward when not overridden', () => {
  const p = AcdpProducer.generate(AGENT_DID, KEY_ID);
  const v1 = JSON.parse(
    p.buildPublishRequest({
      title: 'v1',
      contextType: 'data_snapshot',
      anchors: JSON.stringify([WELL_FORMED_ANCHOR]),
    }),
  );
  const body = {
    ...v1,
    ctx_id: 'acdp://registry.example.com/12345678-1234-4321-8123-123456781234',
    lineage_id: 'lin:sha256:' + 'a'.repeat(64),
    origin_registry: 'registry.example.com',
    created_at: '2026-01-01T00:00:00.000Z',
  };
  const v2 = JSON.parse(
    p.buildSupersedeRequest(JSON.stringify(body), { title: 'v2' }),
  );
  assert.equal(v2.anchors[0].scheme, 'macp.commitment');
});

test('clearAnchors is the only way to produce a version with no anchors', () => {
  // Omitting anchors carries the old value forward (previous test); an
  // empty array is rejected by the absent-when-empty rule; clearAnchors
  // is the explicit unset signal.
  const p = AcdpProducer.generate(AGENT_DID, KEY_ID);
  const v1 = JSON.parse(
    p.buildPublishRequest({
      title: 'v1',
      contextType: 'data_snapshot',
      anchors: JSON.stringify([WELL_FORMED_ANCHOR]),
    }),
  );
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
      clearAnchors: true,
    }),
  );
  assert.equal('anchors' in v2, false);
});

test('clearAnchors takes precedence over anchors', () => {
  const p = AcdpProducer.generate(AGENT_DID, KEY_ID);
  const v1 = JSON.parse(
    p.buildPublishRequest({ title: 'v1', contextType: 'data_snapshot' }),
  );
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
      anchors: JSON.stringify([WELL_FORMED_ANCHOR]),
      clearAnchors: true,
    }),
  );
  assert.equal('anchors' in v2, false);
});

test('semantically invalid anchors is rejected', () => {
  // Well-formed JSON but a bad `scheme` format — must be rejected by the
  // existing core validation path (RequestBuilder::build()), not
  // silently accepted by the JSON-parse helper.
  const p = AcdpProducer.generate(AGENT_DID, KEY_ID);
  assert.throws(() =>
    p.buildPublishRequest({
      title: 't',
      contextType: 'data_snapshot',
      anchors: JSON.stringify([{ ...WELL_FORMED_ANCHOR, scheme: 'NOT VALID' }]),
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

// ── did:key identities + offline verification (ACDP 0.2) ───────────────

// sig-003 golden vector: did:key producer from the 0x42-filled Ed25519
// seed, `acdp_version: "0.2.0"` emitted explicitly. Pinned against the
// spec's did:key conformance fixture and the Python binding — drift on
// any side is a protocol break.
const DID_KEY_GOLDEN_SEED = Buffer.alloc(32, 0x42);
const DID_KEY_GOLDEN_DID =
  'did:key:z6MkghLt1e8m1fmANsdJJco3aCLV8Xnigr5UWwC3u5iZFPd3';
const DID_KEY_GOLDEN_HASH =
  'sha256:937448afc35bf79590bcf96f96da328d363d3ef6f2b87d274e2c1b242a09974f';
const DID_KEY_GOLDEN_SIG =
  '3uDdFeyoU0kI53g0tQ6CbIPDaBxMsnZoSD77bE/3Bb0Hv8G+6iARbnZv7pgayyY3mksLjjqPno/DIPlrgeVVCA==';

test('did:key fromSeedDidKey derives agentDid + keyId from the key (sig-003)', () => {
  const p = AcdpProducer.fromSeedDidKey(DID_KEY_GOLDEN_SEED);
  assert.equal(p.agentDid, DID_KEY_GOLDEN_DID);
  assert.equal(
    p.keyId,
    `${DID_KEY_GOLDEN_DID}#${DID_KEY_GOLDEN_DID.slice('did:key:'.length)}`,
  );
});

test('did:key golden content_hash + signature match sig-003', () => {
  const p = AcdpProducer.fromSeedDidKey(DID_KEY_GOLDEN_SEED);
  const raw = p.buildPublishRequest({
    title: 'Golden test vector — did:key first version',
    contextType: 'data_snapshot',
    visibility: 'public',
    acdpVersion: '0.2.0',
  });
  const req = JSON.parse(raw);
  assert.equal(req.agent_id, DID_KEY_GOLDEN_DID);
  assert.equal(req.acdp_version, '0.2.0');
  assert.equal(req.content_hash, DID_KEY_GOLDEN_HASH);
  assert.equal(req.signature.value, DID_KEY_GOLDEN_SIG);
  // The whole point of did:key: the request verifies fully offline.
  assert.equal(AcdpVerifier.verifyPublishRequestOffline(raw), true);
});

test('verifyPublishRequestOffline rejects a tampered title', () => {
  const p = AcdpProducer.fromSeedDidKey(Buffer.alloc(32));
  const req = JSON.parse(
    p.buildPublishRequest({
      title: 'Golden test vector — minimal first version',
      contextType: 'data_snapshot',
    }),
  );
  req.title = 'Tampered';
  assert.throws(() =>
    AcdpVerifier.verifyPublishRequestOffline(JSON.stringify(req)),
  );
});

test('verifyBodyOffline verifies a did:key FullContext body end-to-end', () => {
  const p = AcdpProducer.fromSeedDidKey(Buffer.alloc(32));
  const req = JSON.parse(
    p.buildPublishRequest({
      title: 'offline body',
      contextType: 'data_snapshot',
    }),
  );
  // Synthesize the registry-assigned fields (excluded from the §5.7
  // hash preimage) to make a valid retrieval-shape Body.
  const body = {
    ...req,
    ctx_id: 'acdp://registry.example.com/12345678-1234-4321-8123-123456781234',
    lineage_id: 'lin:sha256:' + 'a'.repeat(64),
    origin_registry: 'registry.example.com',
    created_at: '2026-01-01T00:00:00.000Z',
  };
  assert.equal(AcdpVerifier.verifyBodyOffline(JSON.stringify(body)), true);
  // Tampering with a producer-controlled field breaks it.
  const tampered = { ...body, title: 'Tampered' };
  assert.throws(() => AcdpVerifier.verifyBodyOffline(JSON.stringify(tampered)));
});

test('verifyBodyOffline rejects did:web bodies (resolution is host-side)', () => {
  const p = AcdpProducer.generate(AGENT_DID, KEY_ID);
  const req = JSON.parse(
    p.buildPublishRequest({ title: 'web', contextType: 'data_snapshot' }),
  );
  const body = {
    ...req,
    ctx_id: 'acdp://registry.example.com/12345678-1234-4321-8123-123456781234',
    lineage_id: 'lin:sha256:' + 'a'.repeat(64),
    origin_registry: 'registry.example.com',
    created_at: '2026-01-01T00:00:00.000Z',
  };
  assert.throws(() => AcdpVerifier.verifyBodyOffline(JSON.stringify(body)));
});

// ── verifyCtxIdBinding (RFC-ACDP-0006 §4.1 step 7) ────────────────────────────

const CTX_BINDING_CTX =
  'acdp://registry.example.com/12345678-1234-4321-8123-123456781234';
const CTX_BINDING_OTHER_UUID =
  'acdp://registry.example.com/00000000-0000-4000-8000-000000000000';
const CTX_BINDING_OTHER_AUTHORITY =
  'acdp://other.example.com/12345678-1234-4321-8123-123456781234';
// Mirrors the core `verify_ctx_id_binding` fixture: only the last three
// UUID hex chars are uppercase.
const CTX_BINDING_UPPERCASE_UUID =
  'acdp://registry.example.com/00000000-0000-4000-8000-000000000AAA';

function bodyWithCtxId(ctxId) {
  const p = AcdpProducer.fromSeedDidKey(Buffer.alloc(32));
  const req = JSON.parse(
    p.buildPublishRequest({ title: 'ctx binding', contextType: 'data_snapshot' }),
  );
  return {
    ...req,
    ctx_id: ctxId,
    lineage_id: 'lin:sha256:' + 'a'.repeat(64),
    origin_registry: 'registry.example.com',
    created_at: '2026-01-01T00:00:00.000Z',
  };
}

test('verifyCtxIdBinding accepts matching served/expected ctx_id', () => {
  // Positive control for every failure case below.
  const body = bodyWithCtxId(CTX_BINDING_CTX);
  assert.equal(
    AcdpVerifier.verifyCtxIdBinding(JSON.stringify(body), CTX_BINDING_CTX),
    true,
  );
});

test('verifyCtxIdBinding rejects a UUID-only mismatch', () => {
  const body = bodyWithCtxId(CTX_BINDING_CTX);
  assert.throws(
    () => AcdpVerifier.verifyCtxIdBinding(JSON.stringify(body), CTX_BINDING_OTHER_UUID),
    /context substitution/i,
  );
});

test('verifyCtxIdBinding rejects an authority-only mismatch', () => {
  const body = bodyWithCtxId(CTX_BINDING_CTX);
  assert.throws(
    () =>
      AcdpVerifier.verifyCtxIdBinding(JSON.stringify(body), CTX_BINDING_OTHER_AUTHORITY),
    /context substitution/i,
  );
});

test('verifyCtxIdBinding rejects a malformed expectedCtxId', () => {
  const body = bodyWithCtxId(CTX_BINDING_CTX);
  assert.throws(
    () => AcdpVerifier.verifyCtxIdBinding(JSON.stringify(body), 'not-a-ctx-id'),
    /schema violation|invalid|ctx_id/i,
  );
});

test('verifyCtxIdBinding rejects an uppercase-UUID served ctx_id', () => {
  // Uppercase-UUID rejection must be enforced on the served side too,
  // not just the expected side.
  const body = bodyWithCtxId(CTX_BINDING_UPPERCASE_UUID);
  assert.throws(
    () => AcdpVerifier.verifyCtxIdBinding(JSON.stringify(body), CTX_BINDING_CTX),
    /schema violation|invalid|ctx_id/i,
  );
});

test('verifyCtxIdBinding rejects an uppercase-UUID expected ctx_id', () => {
  const body = bodyWithCtxId(CTX_BINDING_CTX);
  assert.throws(
    () => AcdpVerifier.verifyCtxIdBinding(JSON.stringify(body), CTX_BINDING_UPPERCASE_UUID),
    /schema violation|invalid|ctx_id/i,
  );
});

test('verifyCtxIdBinding rejects malformed body JSON', () => {
  assert.throws(
    () => AcdpVerifier.verifyCtxIdBinding('not json', CTX_BINDING_CTX),
    /invalid body json/i,
  );
});

test('verifyPublishRequestOffline rejects did:web requests (resolution is host-side)', () => {
  const p = AcdpProducer.generate(AGENT_DID, KEY_ID);
  const raw = p.buildPublishRequest({
    title: 'web identity',
    contextType: 'data_snapshot',
  });
  assert.throws(() => AcdpVerifier.verifyPublishRequestOffline(raw));
});

test('did:key generateDidKey produces distinct self-derived identities', () => {
  const a = AcdpProducer.generateDidKey();
  const b = AcdpProducer.generateDidKey();
  assert.ok(a.agentDid.startsWith('did:key:z6Mk'));
  assert.notEqual(a.agentDid, b.agentDid);
  assert.equal(a.keyId, `${a.agentDid}#${a.agentDid.slice('did:key:'.length)}`);
});

test('fromSeed with a mismatched did:key agent DID throws on build', () => {
  // DID_KEY_GOLDEN_DID belongs to the 0x42 seed; pair it with the
  // all-zero seed. A did:key identity IS its key, so the SDK must
  // refuse to sign under a DID the seed does not derive — silently
  // re-deriving would publish under a different identity than the
  // caller stored.
  const mispaired = AcdpProducer.fromSeed(
    Buffer.alloc(32, 0),
    DID_KEY_GOLDEN_DID,
    `${DID_KEY_GOLDEN_DID}#${DID_KEY_GOLDEN_DID.slice('did:key:'.length)}`,
  );
  assert.throws(
    () =>
      mispaired.buildPublishRequest({
        title: 'mispaired did:key',
        contextType: 'data_snapshot',
      }),
    /does not correspond to the stored did:key/,
  );
  // The matching seed for the same DID still builds fine.
  const matched = AcdpProducer.fromSeed(
    DID_KEY_GOLDEN_SEED,
    DID_KEY_GOLDEN_DID,
    `${DID_KEY_GOLDEN_DID}#${DID_KEY_GOLDEN_DID.slice('did:key:'.length)}`,
  );
  const req = JSON.parse(
    matched.buildPublishRequest({
      title: 'matched did:key',
      contextType: 'data_snapshot',
    }),
  );
  assert.equal(req.agent_id, DID_KEY_GOLDEN_DID);
});

test('p256 fromSeed with a mismatched did:key agent DID throws on build', () => {
  const a = AcdpP256Producer.generateDidKey();
  const b = AcdpP256Producer.generateDidKey();
  // b's seed paired with a's did:key identity.
  const mispaired = AcdpP256Producer.fromSeed(
    Buffer.from(b.seedBytes()),
    a.agentDid,
    a.keyId,
  );
  assert.throws(
    () =>
      mispaired.buildPublishRequest({
        title: 'mispaired p256 did:key',
        contextType: 'data_snapshot',
      }),
    /does not correspond to the stored did:key/,
  );
});

test('p256 did:key factories derive a did:key:zDn… identity that round-trips', () => {
  const a = AcdpP256Producer.generateDidKey();
  assert.ok(a.agentDid.startsWith('did:key:zDn'));
  assert.equal(a.keyId, `${a.agentDid}#${a.agentDid.slice('did:key:'.length)}`);
  const b = AcdpP256Producer.fromSeedDidKey(Buffer.from(a.seedBytes()));
  assert.equal(b.agentDid, a.agentDid);
  const raw = b.buildPublishRequest({
    title: 'p256 did:key',
    contextType: 'data_snapshot',
  });
  const req = JSON.parse(raw);
  assert.equal(req.agent_id, a.agentDid);
  assert.equal(req.signature.algorithm, 'ecdsa-p256');
  assert.equal(AcdpVerifier.verifyPublishRequestOffline(raw), true);
});

// ── Hash-divergence diagnostics (ACDP 0.2, WS-D2) ───────────────────────

test('canonicalPreimage strips the §5.7 exclusion set', () => {
  const p = AcdpProducer.fromSeedDidKey(Buffer.alloc(32));
  const raw = p.buildPublishRequest({
    title: 'preimage',
    contextType: 'data_snapshot',
  });
  const preimage = JSON.parse(AcdpVerifier.canonicalPreimage(raw));
  assert.equal(preimage.title, 'preimage');
  assert.ok(!('content_hash' in preimage));
  assert.ok(!('signature' in preimage));
});

test('explainHashMismatch names the acdp_version divergence', () => {
  const p = AcdpProducer.fromSeedDidKey(Buffer.alloc(32));
  // Hash signed under the OMITTED form…
  const omitted = JSON.parse(
    p.buildPublishRequest({
      title: 'divergence',
      contextType: 'data_snapshot',
      omitAcdpVersion: true,
    }),
  );
  // …checked against the same body emitted WITH the field.
  const explicit = p.buildPublishRequest({
    title: 'divergence',
    contextType: 'data_snapshot',
  });
  const report = AcdpVerifier.explainHashMismatch(
    explicit,
    omitted.content_hash,
  );
  assert.match(report, /acdp_version/);
  // And the no-divergence case says so.
  const aligned = JSON.parse(explicit);
  assert.match(
    AcdpVerifier.explainHashMismatch(explicit, aligned.content_hash),
    /no divergence/,
  );
});

// ── Key fingerprints + registry receipts (ACDP 0.2, RFC-ACDP-0010) ─────

test('fingerprintEd25519B64 matches fp-001', () => {
  // Fingerprint of the all-zero-seed Ed25519 public key.
  const p = AcdpProducer.fromSeed(Buffer.alloc(32), AGENT_DID, KEY_ID);
  assert.equal(
    AcdpVerifier.fingerprintEd25519B64(p.publicKeyB64),
    'sha256:139e3940e64b5491722088d9a0d741628fc826e09475d341a780acde3c4b8070',
  );
});

// rcpt-001 golden vector: receipt minted by the [0x11u8; 32]-seed
// registry key, binding the sig-001 content_hash and the fp-001
// producer-key fingerprint.
const RCPT_001 = {
  registry_did: 'did:web:registry.example.com',
  ctx_id:
    'acdp://registry.example.com/12345678-1234-4321-8123-123456781234',
  lineage_id:
    'lin:sha256:c7fef01c000f8edaa9cb46122ceb5d7bca38328f002fb0f40e362e3b289bbb2a',
  origin_registry: 'registry.example.com',
  created_at: '2026-04-16T10:30:15.123Z',
  content_hash:
    'sha256:f170150ddbf59d99794e7797824591b374d459782084597b644ecc57a41031b5',
  key_fingerprint:
    'sha256:139e3940e64b5491722088d9a0d741628fc826e09475d341a780acde3c4b8070',
  signature: {
    algorithm: 'ed25519',
    key_id: 'did:web:registry.example.com#receipt-key-1',
    value:
      'vBgQKmn17pHXXY95C07BBeconmjDIdYIvxN5B+YXrQ7tIzFsDNsh1TglzgxOyPUp8lwTz7zwMNiK+Sn5whveDg==',
  },
};

// The registry's receipt-signing public key. DID resolution stays in JS
// land by design — here the "resolved" key is derived from the known
// test seed.
const RCPT_REGISTRY_KEY_B64 = AcdpProducer.fromSeed(
  Buffer.alloc(32, 0x11),
  'did:web:x',
  'did:web:x#k',
).publicKeyB64;

test('rcpt-001 registry signing key matches the spec-pinned public key', () => {
  assert.equal(
    RCPT_REGISTRY_KEY_B64,
    '0EqyMnQrtKs6E2i9RhXk5tAiSrcaAWuvhSCjMsl3hzc=',
  );
});

test('verifyReceipt accepts rcpt-001', () => {
  assert.equal(
    AcdpVerifier.verifyReceipt(
      JSON.stringify(RCPT_001),
      RCPT_REGISTRY_KEY_B64,
      RCPT_001.ctx_id,
      RCPT_001.content_hash,
      RCPT_001.key_fingerprint,
    ),
    true,
  );
});

test('verifyReceipt rejects a producer-key fingerprint mismatch', () => {
  assert.throws(() =>
    AcdpVerifier.verifyReceipt(
      JSON.stringify(RCPT_001),
      RCPT_REGISTRY_KEY_B64,
      RCPT_001.ctx_id,
      RCPT_001.content_hash,
      'sha256:' + '9'.repeat(64),
    ),
  );
});

test('verifyReceipt rejects a mutated created_at (signature break)', () => {
  const tampered = { ...RCPT_001, created_at: '2026-04-16T10:30:15.124Z' };
  assert.throws(() =>
    AcdpVerifier.verifyReceipt(
      JSON.stringify(tampered),
      RCPT_REGISTRY_KEY_B64,
      RCPT_001.ctx_id,
      RCPT_001.content_hash,
      RCPT_001.key_fingerprint,
    ),
  );
});

test('verifyReceipt rejects a non-canonical created_at byte form', () => {
  // Same instant, wrong byte form: two fractional digits instead of the
  // canonical three (RFC-ACDP-0010 §8 step 6). The raw wire bytes must
  // be canonical BEFORE hashing — a struct-re-serializing verifier
  // would normalize ".12" to ".120" and hash a preimage the registry
  // never signed.
  const nonCanonical = { ...RCPT_001, created_at: '2026-04-16T10:30:15.12Z' };
  assert.throws(
    () =>
      AcdpVerifier.verifyReceipt(
        JSON.stringify(nonCanonical),
        RCPT_REGISTRY_KEY_B64,
        RCPT_001.ctx_id,
        RCPT_001.content_hash,
        RCPT_001.key_fingerprint,
      ),
    /canonical/,
  );
});

test('verifyReceipt rejects unknown receipt members (closed schema)', () => {
  // RegistryReceipt is deny_unknown_fields since ACDP 0.2 — an extra
  // member must fail parsing outright, not be silently ignored.
  const extended = { ...RCPT_001, extra_member: 'x' };
  assert.throws(() =>
    AcdpVerifier.verifyReceipt(
      JSON.stringify(extended),
      RCPT_REGISTRY_KEY_B64,
      RCPT_001.ctx_id,
      RCPT_001.content_hash,
      RCPT_001.key_fingerprint,
    ),
  );
});

// ── derivedFrom CtxId validation (issue #206 gap G1) ──────────────────────
//
// `buildPublishRequest`'s `derivedFrom` option is now routed through
// `CtxId::parse` at the setter (not deferred to `.build()`'s downstream
// `validate_publish_request` check), so a malformed entry throws here.

test('buildPublishRequest accepts a valid derivedFrom ctx_id', () => {
  // Positive control: a well-formed derivedFrom entry builds fine.
  const p = AcdpProducer.generate(AGENT_DID, KEY_ID);
  const raw = p.buildPublishRequest({
    title: 'derived',
    contextType: 'data_snapshot',
    derivedFrom: [
      'acdp://registry.example.com/12345678-1234-4321-8123-123456781234',
    ],
  });
  const req = JSON.parse(raw);
  assert.deepEqual(req.derived_from, [
    'acdp://registry.example.com/12345678-1234-4321-8123-123456781234',
  ]);
});

test('buildPublishRequest rejects a malformed derivedFrom ctx_id', () => {
  // A malformed derivedFrom entry must throw at the setter, not later
  // at .build().
  const p = AcdpProducer.generate(AGENT_DID, KEY_ID);
  assert.throws(
    () =>
      p.buildPublishRequest({
        title: 'derived',
        contextType: 'data_snapshot',
        derivedFrom: ['not-a-ctx-id'],
      }),
    /schema violation|invalid|ctx_id/i,
  );
});
