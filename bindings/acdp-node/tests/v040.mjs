// ACDP 0.4 surface: transparency-log witness cosignatures
// (RFC-ACDP-0015).
//
// Pins the spec conformance fixtures byte-for-byte: wit-001 (the golden
// cosignature — a single witness cosigns the log-001 tree-size-5
// checkpoint with its own Ed25519 key, seed 0x33*32), wit-003 (two
// distinct witnesses over one tuple → 2-witnessed), and wit-004 (a
// cosignature signed by the WRONG witness key → invalid_witness_cosignature).
// All keys are the publicly-known spec TEST keypairs — never production
// material.
//
// Build first:  `npm run build:debug`
// Then run:     `node --test tests/*.mjs`
//
// These mirror the Python SDK's test_v040.py so both bindings stay in
// sync against the same Rust core.

import test from 'node:test';
import assert from 'node:assert/strict';
import { AcdpVerifier } from '../index.js';

const REGISTRY_DID = 'did:web:registry.example.com';
const RECEIPT_KEY_ID = `${REGISTRY_DID}#receipt-key-1`;
const LOG_ID = 'did:web:registry.example.com/log/1';
const ROOT =
  'sha256:0b5978172c671ca050b44790a749b18fc29d58a7a17495fbb4e0f86eb885f731';

const WITNESS_A = 'did:web:witness.example.org';
const WITNESS_A_SEED_HEX = '33'.repeat(32);
const WITNESS_A_PUB_HEX =
  '17cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce';
const WITNESS_B = 'did:web:witness-2.example.org';
const WITNESS_B_SEED_HEX = '44'.repeat(32);
const WITNESS_B_PUB_HEX =
  'd759793bbc13a2819a827c76adb6fba8a49aee007f49f2d0992d99b825ad2c48';

const WITNESSED_CHECKPOINT = {
  log_id: LOG_ID,
  tree_size: 5,
  root_hash: ROOT,
  timestamp: '2026-07-04T12:00:00.000Z',
};

const WITNESSED_AT_A = '2026-07-04T12:00:05.000Z';
const WITNESSED_AT_B = '2026-07-04T12:03:00.000Z';

const WIT001_SIG_B64 =
  'omUcflbxeirUvPyIbuiGW0t7fch/xO2lSzTQwAvOAqsawocn4Y5J69Nwracq1I2Zercj5Qdnlc18NZQyoPcEBA==';
const WIT001_LOG_COSIGNATURE = {
  cosignature_version: 'acdp-cosig/1',
  witness_id: WITNESS_A,
  witnessed_checkpoint: WITNESSED_CHECKPOINT,
  witnessed_at: WITNESSED_AT_A,
  signature: {
    algorithm: 'ed25519',
    key_id: `${WITNESS_A}#witness-key-1`,
    value: WIT001_SIG_B64,
  },
};

const WIT003_B_SIG_B64 =
  'RYgjh3FYtkrHBupbZ8cXPbJ0rmHVrXtux23V66szHHMW8946IbXP3Kv9AbJReq/HbjarLqMGBk7rt8HtUnQyDA==';

const WIT004_COSIG = {
  cosignature_version: 'acdp-cosig/1',
  witness_id: WITNESS_A,
  witnessed_checkpoint: WITNESSED_CHECKPOINT,
  witnessed_at: WITNESSED_AT_A,
  signature: {
    algorithm: 'ed25519',
    key_id: `${WITNESS_A}#witness-key-1`,
    value:
      'q904p7YsZEtlVsTioF90JlFyY76z7+cD3mHTiC8sTI0VCGQ/ec0lf7pqILeqnL2w/PvUdaGFoGHlI0+8a31SBQ==',
  },
};

const LOG001_CHECKPOINT = {
  checkpoint_version: 'acdp-log/1',
  log_id: LOG_ID,
  tree_size: 5,
  root_hash: ROOT,
  timestamp: '2026-07-04T12:00:00.000Z',
  signature: {
    algorithm: 'ed25519',
    key_id: RECEIPT_KEY_ID,
    value:
      'o5rJmVE+1w/f7xAvW2P4vHA9FqWcMpS0crUPkMUZKSrBhrCVt/jyS+PCgnHNsNpmr+N+sR9I9qbqQ/Y0ZfOrDQ==',
  },
};

// A minimal witness DID document with the key in BOTH verificationMethod
// and assertionMethod (RFC-ACDP-0015 §9).
function witnessDoc(did, pubHex) {
  const keyId = `${did}#witness-key-1`;
  const x = Buffer.from(pubHex, 'hex').toString('base64url');
  return JSON.stringify({
    id: did,
    verificationMethod: [
      {
        id: keyId,
        type: 'Ed25519VerificationKey2020',
        controller: did,
        publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x },
      },
    ],
    assertionMethod: [keyId],
  });
}

const build = (did, seedHex, witnessedAt) =>
  AcdpVerifier.buildWitnessCosignature(
    JSON.stringify(WITNESSED_CHECKPOINT),
    did,
    seedHex,
    witnessedAt,
  );

// ── wit-001 — build (mint) golden vector ──────────────────────────────

test('wit-001 build reproduces the golden cosignature byte-for-byte', () => {
  const cosig = JSON.parse(build(WITNESS_A, WITNESS_A_SEED_HEX, WITNESSED_AT_A));
  assert.deepEqual(cosig, WIT001_LOG_COSIGNATURE);
  assert.equal(cosig.signature.value, WIT001_SIG_B64);
});

test('wit-001 minted cosignature round-trips through verification', () => {
  const out = build(WITNESS_A, WITNESS_A_SEED_HEX, WITNESSED_AT_A);
  const verdict = JSON.parse(
    AcdpVerifier.verifyWitnessCosignature(
      out,
      witnessDoc(WITNESS_A, WITNESS_A_PUB_HEX),
      JSON.stringify(LOG001_CHECKPOINT),
      '2026-07-04T12:00:10.000Z',
    ),
  );
  assert.deepEqual(verdict, {
    valid: true,
    witness_id: WITNESS_A,
    age_secs: 5,
    stale: false,
  });
});

test('wit-001 stale but valid is a freshness verdict', () => {
  const verdict = JSON.parse(
    AcdpVerifier.verifyWitnessCosignature(
      JSON.stringify(WIT001_LOG_COSIGNATURE),
      witnessDoc(WITNESS_A, WITNESS_A_PUB_HEX),
      JSON.stringify(LOG001_CHECKPOINT),
      '2026-07-04T12:10:05.000Z',
    ),
  );
  assert.ok(verdict.valid && verdict.stale && verdict.age_secs === 600);
});

test('wit-001 checkpoint binding fires on a different tuple', () => {
  const other = { ...LOG001_CHECKPOINT, tree_size: 6, root_hash: `sha256:${'aa'.repeat(32)}` };
  const verdict = JSON.parse(
    AcdpVerifier.verifyWitnessCosignature(
      JSON.stringify(WIT001_LOG_COSIGNATURE),
      witnessDoc(WITNESS_A, WITNESS_A_PUB_HEX),
      JSON.stringify(other),
      '2026-07-04T12:00:10.000Z',
    ),
  );
  assert.ok(!verdict.valid);
  assert.equal(verdict.code, 'invalid_witness_cosignature');
});

test('wit-001 wrong witness doc id fails step 3', () => {
  const verdict = JSON.parse(
    AcdpVerifier.verifyWitnessCosignature(
      JSON.stringify(WIT001_LOG_COSIGNATURE),
      witnessDoc(WITNESS_B, WITNESS_A_PUB_HEX),
      JSON.stringify(LOG001_CHECKPOINT),
      '2026-07-04T12:00:10.000Z',
    ),
  );
  assert.ok(!verdict.valid && verdict.code === 'invalid_witness_cosignature');
});

// ── wit-003 — quorum golden vector ────────────────────────────────────

test('wit-003 two distinct witnesses are 2-witnessed', () => {
  const cosigA = build(WITNESS_A, WITNESS_A_SEED_HEX, WITNESSED_AT_A);
  const cosigB = build(WITNESS_B, WITNESS_B_SEED_HEX, WITNESSED_AT_B);
  assert.equal(JSON.parse(cosigB).signature.value, WIT003_B_SIG_B64);

  const docs = {
    [WITNESS_A]: JSON.parse(witnessDoc(WITNESS_A, WITNESS_A_PUB_HEX)),
    [WITNESS_B]: JSON.parse(witnessDoc(WITNESS_B, WITNESS_B_PUB_HEX)),
  };
  const report = JSON.parse(
    AcdpVerifier.evaluateWitnessQuorum(
      JSON.stringify([JSON.parse(cosigA), JSON.parse(cosigB)]),
      JSON.stringify(LOG001_CHECKPOINT),
      JSON.stringify([WITNESS_A, WITNESS_B]),
      JSON.stringify(docs),
      JSON.stringify({ min_witnesses: 2 }),
      '2026-07-04T12:10:00.000Z',
    ),
  );
  assert.equal(report.witnessed_count, 2);
  assert.equal(report.meets_quorum, true);
  assert.deepEqual(report.witnesses, [WITNESS_B, WITNESS_A]);
  assert.deepEqual(report.failures, []);
});

test('wit-003 repeat from one witness counts once; min policy not met', () => {
  const cosigA = JSON.parse(build(WITNESS_A, WITNESS_A_SEED_HEX, WITNESSED_AT_A));
  const cosigA2 = JSON.parse(
    build(WITNESS_A, WITNESS_A_SEED_HEX, '2026-07-04T12:00:06.000Z'),
  );
  const docs = { [WITNESS_A]: JSON.parse(witnessDoc(WITNESS_A, WITNESS_A_PUB_HEX)) };
  const report = JSON.parse(
    AcdpVerifier.evaluateWitnessQuorum(
      JSON.stringify([cosigA, cosigA2]),
      JSON.stringify(LOG001_CHECKPOINT),
      JSON.stringify([WITNESS_A]),
      JSON.stringify(docs),
      JSON.stringify({ min_witnesses: 2 }),
      '2026-07-04T12:10:00.000Z',
    ),
  );
  assert.equal(report.witnessed_count, 1);
  assert.equal(report.meets_quorum, false);
});

// ── wit-004 — cosignature key mismatch ────────────────────────────────

test('wit-004 wrong key fails with invalid_witness_cosignature', () => {
  const verdict = JSON.parse(
    AcdpVerifier.verifyWitnessCosignature(
      JSON.stringify(WIT004_COSIG),
      witnessDoc(WITNESS_A, WITNESS_A_PUB_HEX),
      JSON.stringify(LOG001_CHECKPOINT),
      '2026-07-04T12:00:10.000Z',
    ),
  );
  assert.ok(!verdict.valid);
  assert.equal(verdict.code, 'invalid_witness_cosignature');
});

test('wit-004 does not count toward quorum', () => {
  const docs = { [WITNESS_A]: JSON.parse(witnessDoc(WITNESS_A, WITNESS_A_PUB_HEX)) };
  const report = JSON.parse(
    AcdpVerifier.evaluateWitnessQuorum(
      JSON.stringify([WIT004_COSIG]),
      JSON.stringify(LOG001_CHECKPOINT),
      JSON.stringify([WITNESS_A]),
      JSON.stringify(docs),
      JSON.stringify({}),
      '2026-07-04T12:00:10.000Z',
    ),
  );
  assert.equal(report.witnessed_count, 0);
  assert.equal(report.meets_quorum, false);
  assert.equal(report.failures.length, 1);
  assert.equal(report.failures[0].code, 'invalid_witness_cosignature');
});

// ── Host-input errors + stable .code ──────────────────────────────────

test('build throws on a malformed seed and identity', () => {
  assert.throws(
    () =>
      AcdpVerifier.buildWitnessCosignature(
        JSON.stringify(WITNESSED_CHECKPOINT),
        WITNESS_A,
        'abcd',
        WITNESSED_AT_A,
      ),
    /witnessSeedHex/,
  );
  assert.throws(() =>
    AcdpVerifier.buildWitnessCosignature(
      JSON.stringify(WITNESSED_CHECKPOINT),
      'not-a-did',
      WITNESS_A_SEED_HEX,
      WITNESSED_AT_A,
    ),
  );
});
