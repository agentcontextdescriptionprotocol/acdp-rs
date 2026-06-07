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
import { AcdpDid, AcdpDidDocument, AcdpProducer, AcdpP256Producer } from '../index.js';

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
