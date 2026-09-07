// In-process tests for the ACDP Node.js SDK did:web helpers:
// AcdpDid (URL translation) and AcdpDidDocument (parse + key extraction
// with the assertionMethod gate and the algorithm-downgrade defense).
//
// Build first:  `npm run build:debug`
// Then run:     `node --test tests/`
//
// These mirror the Python SDK's test_did.py so both bindings stay in
// sync against the same Rust `acdp::did` core.

import test from 'node:test';
import assert from 'node:assert/strict';
import { AcdpDid, AcdpDidDocument, AcdpProducer, AcdpP256Producer, AcdpVerifier } from '../index.js';

const DID = 'did:web:agents.example.com';
const KEY_ID = `${DID}#key-1`;

// Build a did:web document carrying `producer`'s public key as the
// JsonWebKey2020 verification method `#key-1`, authorized for assertion.
function ed25519Doc(producer, { authorized = true } = {}) {
  const x = Buffer.from(producer.publicKeyB64, 'base64').toString('base64url');
  return JSON.stringify({
    id: DID,
    verificationMethod: [
      {
        id: KEY_ID,
        type: 'JsonWebKey2020',
        controller: DID,
        publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x },
      },
    ],
    assertionMethod: authorized ? [KEY_ID] : [],
  });
}

// ── AcdpDid ───────────────────────────────────────────────────────────

test('webToUrl maps a bare authority to /.well-known/did.json', () => {
  assert.equal(
    AcdpDid.webToUrl('did:web:example.com'),
    'https://example.com/.well-known/did.json',
  );
});

test('webToUrl maps path segments to a nested did.json', () => {
  assert.equal(
    AcdpDid.webToUrl('did:web:example.com:users:alice'),
    'https://example.com/users/alice/did.json',
  );
});

test('webToUrl rejects a non-did:web DID with code not_did_web', () => {
  assert.throws(
    () => AcdpDid.webToUrl('did:key:z6Mk'),
    (e) => e.code === 'not_did_web',
  );
});

test('stripFragment removes the #fragment', () => {
  assert.equal(AcdpDid.stripFragment(KEY_ID), DID);
  assert.equal(AcdpDid.stripFragment(DID), DID);
});

// ── AcdpDidDocument ─────────────────────────────────────────────────────

test('parse rejects an id that does not match the requested DID', () => {
  const p = AcdpProducer.generate(DID, KEY_ID);
  assert.throws(
    () => AcdpDidDocument.parse(ed25519Doc(p), 'did:web:other.com'),
    (e) => e.code === 'id_mismatch',
  );
});

test('keyForAlgorithm extracts the Ed25519 key the producer signed with', () => {
  const p = AcdpProducer.generate(DID, KEY_ID);
  const doc = AcdpDidDocument.parse(ed25519Doc(p), DID);
  const k = doc.keyForAlgorithm(KEY_ID, 'ed25519');
  assert.equal(k.algorithm, 'ed25519');
  assert.equal(k.keyId, KEY_ID);
  assert.equal(k.publicKeyB64, p.publicKeyB64);
});

test('keyForAlgorithm enforces the algorithm-downgrade defense', () => {
  const p = AcdpProducer.generate(DID, KEY_ID);
  const doc = AcdpDidDocument.parse(ed25519Doc(p), DID);
  assert.throws(
    () => doc.keyForAlgorithm(KEY_ID, 'ecdsa-p256'),
    (e) => e.code === 'alg_mismatch',
  );
});

test('keyForAlgorithm requires the key to be in assertionMethod', () => {
  const p = AcdpProducer.generate(DID, KEY_ID);
  const doc = AcdpDidDocument.parse(ed25519Doc(p, { authorized: false }), DID);
  assert.throws(
    () => doc.keyForAlgorithm(KEY_ID, 'ed25519'),
    (e) => e.code === 'key_not_authorized',
  );
});

test('keyForAlgorithm reports key_not_found for an unknown fragment', () => {
  const p = AcdpProducer.generate(DID, KEY_ID);
  const doc = AcdpDidDocument.parse(ed25519Doc(p), DID);
  assert.throws(
    () => doc.keyForAlgorithm(`${DID}#key-2`, 'ed25519'),
    (e) => e.code === 'key_not_found',
  );
});

test('keyForAlgorithm rejects an unsupported algorithm', () => {
  const p = AcdpProducer.generate(DID, KEY_ID);
  const doc = AcdpDidDocument.parse(ed25519Doc(p), DID);
  assert.throws(
    () => doc.keyForAlgorithm(KEY_ID, 'rsa'),
    (e) => e.code === 'unsupported_algorithm',
  );
});

test('keyForAlgorithm extracts a P-256 SEC1 key from a JWK method', () => {
  const p = AcdpP256Producer.generate(DID, KEY_ID);
  const docJson = JSON.stringify({
    id: DID,
    verificationMethod: [JSON.parse(p.didVerificationMethod(KEY_ID, DID))],
    assertionMethod: [KEY_ID],
  });
  const doc = AcdpDidDocument.parse(docJson, DID);
  const k = doc.keyForAlgorithm(KEY_ID, 'ecdsa-p256');
  assert.equal(k.algorithm, 'ecdsa-p256');
  assert.equal(k.publicKeyB64, p.publicKeySec1B64);
});

// ── receiptKeyForAlgorithm — RFC-ACDP-0010 §9 receipt-key lifecycle ─────────

test('receiptKeyForAlgorithm resolves a retired key as historical', () => {
  // Retained in verificationMethod, removed from assertionMethod:
  // keyForAlgorithm refuses it; the receipt helper resolves it with
  // historical=true so an auditor reports "historically authorized"
  // instead of an error verdict.
  const p = AcdpProducer.generate(DID, KEY_ID);
  const doc = AcdpDidDocument.parse(ed25519Doc(p, { authorized: false }), DID);

  assert.throws(
    () => doc.keyForAlgorithm(KEY_ID, 'ed25519'),
    (e) => e.code === 'key_not_authorized',
  );

  const k = doc.receiptKeyForAlgorithm(KEY_ID, 'ed25519');
  assert.equal(k.publicKeyB64, p.publicKeyB64);
  assert.equal(k.historical, true);
});

test('receiptKeyForAlgorithm marks a current key as not historical', () => {
  const p = AcdpProducer.generate(DID, KEY_ID);
  const doc = AcdpDidDocument.parse(ed25519Doc(p), DID);
  const k = doc.receiptKeyForAlgorithm(KEY_ID, 'ed25519');
  assert.equal(k.historical, false);
  assert.equal(k.publicKeyB64, p.publicKeyB64);
});

test('receiptKeyForAlgorithm fails closed for a fully removed key', () => {
  // Full removal from verificationMethod is the compromise-revocation
  // signal — same key_not_found as the strict helper.
  const p = AcdpProducer.generate(DID, KEY_ID);
  const doc = AcdpDidDocument.parse(ed25519Doc(p), DID);
  assert.throws(
    () => doc.receiptKeyForAlgorithm(`${DID}#retired-key-9`, 'ed25519'),
    (e) => e.code === 'key_not_found',
  );
});

test('receiptKeyForAlgorithm keeps the algorithm-downgrade defense', () => {
  const p = AcdpProducer.generate(DID, KEY_ID);
  const doc = AcdpDidDocument.parse(ed25519Doc(p, { authorized: false }), DID);
  assert.throws(
    () => doc.receiptKeyForAlgorithm(KEY_ID, 'ecdsa-p256'),
    (e) => e.code === 'alg_mismatch',
  );
});

test('retired receipt key verifies the rcpt-001 receipt end-to-end', () => {
  // Auditor path: rcpt-001 registry key rotated out of assertionMethod,
  // resolved via the receipt helper, fed to verifyReceipt — verifies,
  // with the historical flag telling the auditor which status to report.
  const registryDid = 'did:web:registry.example.com';
  const receiptKeyId = `${registryDid}#receipt-key-1`;
  const registry = AcdpProducer.fromSeed(Buffer.alloc(32, 0x11), registryDid, receiptKeyId);
  const b64url = (b64) => Buffer.from(b64, 'base64').toString('base64url');
  const docJson = JSON.stringify({
    id: registryDid,
    verificationMethod: [
      {
        id: receiptKeyId,
        type: 'Ed25519VerificationKey2020',
        controller: registryDid,
        publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: b64url(registry.publicKeyB64) },
      },
    ],
    assertionMethod: [],
  });
  const doc = AcdpDidDocument.parse(docJson, registryDid);
  const resolved = doc.receiptKeyForAlgorithm(receiptKeyId, 'ed25519');
  assert.equal(resolved.historical, true);

  const receipt = JSON.stringify({
    registry_did: registryDid,
    ctx_id: 'acdp://registry.example.com/12345678-1234-4321-8123-123456781234',
    lineage_id: 'lin:sha256:c7fef01c000f8edaa9cb46122ceb5d7bca38328f002fb0f40e362e3b289bbb2a',
    origin_registry: 'registry.example.com',
    created_at: '2026-04-16T10:30:15.123Z',
    content_hash: 'sha256:f170150ddbf59d99794e7797824591b374d459782084597b644ecc57a41031b5',
    key_fingerprint: 'sha256:139e3940e64b5491722088d9a0d741628fc826e09475d341a780acde3c4b8070',
    signature: {
      algorithm: 'ed25519',
      key_id: receiptKeyId,
      value: 'vBgQKmn17pHXXY95C07BBeconmjDIdYIvxN5B+YXrQ7tIzFsDNsh1TglzgxOyPUp8lwTz7zwMNiK+Sn5whveDg==',
    },
  });
  // The sig-001 body this receipt attests (assembled from
  // `producer_content` + `registry_assigned`; see RCPT_BODY in
  // test.mjs for the full derivation).
  const body = JSON.stringify({
    ctx_id: 'acdp://registry.example.com/12345678-1234-4321-8123-123456781234',
    lineage_id: 'lin:sha256:c7fef01c000f8edaa9cb46122ceb5d7bca38328f002fb0f40e362e3b289bbb2a',
    origin_registry: 'registry.example.com',
    created_at: '2026-04-16T10:30:15.123Z',
    content_hash: 'sha256:f170150ddbf59d99794e7797824591b374d459782084597b644ecc57a41031b5',
    signature: {
      algorithm: 'ed25519',
      key_id: 'did:web:agents.example.com:test-producer#key-1',
      value: 'ErkbV+FUdn49TgF3zJ3RBe3AmyGxLVAQdMjlhabUfM96qendmWwdVodX/SV3O3aKLypbUu6gmb5Npt3O/w7nDQ==',
    },
    version: 1,
    supersedes: null,
    agent_id: 'did:web:agents.example.com:test-producer',
    contributors: [],
    title: 'Golden test vector — minimal first version',
    type: 'data_snapshot',
    data_refs: [],
    derived_from: [],
    visibility: 'public',
  });
  assert.ok(
    AcdpVerifier.verifyReceipt(
      receipt,
      body,
      resolved.publicKeyB64,
      'acdp://registry.example.com/12345678-1234-4321-8123-123456781234',
      'sha256:f170150ddbf59d99794e7797824591b374d459782084597b644ecc57a41031b5',
      'sha256:139e3940e64b5491722088d9a0d741628fc826e09475d341a780acde3c4b8070',
    ),
  );
});
