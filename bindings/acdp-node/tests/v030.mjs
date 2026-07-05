// ACDP 0.3 surface: lineage-head receipts (RFC-ACDP-0011),
// transparency-log verification (RFC-ACDP-0012), lifecycle events
// (RFC-ACDP-0013), and key revocation (RFC-ACDP-0014).
//
// Pins the spec conformance fixtures byte-for-byte: lhr-001, log-001,
// log-003, rev-001, plus the failure fixtures lhr-002/003/004,
// log-002/004 and the rev-002 boundary scenarios. All keys are the
// publicly-known spec TEST keypairs (registry receipt key seed
// [0x11]*32; producer K2 seed [0x42]*32) — never production material.
//
// Build first:  `npm run build:debug`
// Then run:     `node --test tests/*.mjs`
//
// These mirror the Python SDK's test_v030.py so both bindings stay in
// sync against the same Rust core.

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  AcdpCanonicalizer,
  AcdpMerkle,
  AcdpProducer,
  AcdpVerifier,
} from '../index.js';

const REGISTRY_DID = 'did:web:registry.example.com';
const RECEIPT_KEY_ID = `${REGISTRY_DID}#receipt-key-1`;
const REGISTRY_SEED = Buffer.alloc(32, 0x11);

const LINEAGE =
  'lin:sha256:c7fef01c000f8edaa9cb46122ceb5d7bca38328f002fb0f40e362e3b289bbb2a';
const CTX =
  'acdp://registry.example.com/12345678-1234-4321-8123-123456781234';
const LOG_ID = 'did:web:registry.example.com/log/1';

// fp-001 / K1 — the sig-001 producer key fingerprint.
const K1_FP =
  'sha256:139e3940e64b5491722088d9a0d741628fc826e09475d341a780acde3c4b8070';
// rev-001 / K2 — the producer's current key (sig-003 seed).
const K2_FP =
  'sha256:3097e2dee2cb4a34b53840cdb705aed71067c36f68db0e0f559c3f3fa043315f';

const b64url = (standardB64) =>
  Buffer.from(standardB64, 'base64').toString('base64url');

// The registry's DID document carrying the [0x11]*32 receipt key,
// optionally rotated out of assertionMethod (retired receipt key).
function registryDoc(assertion = true) {
  const registry = AcdpProducer.fromSeed(
    REGISTRY_SEED,
    REGISTRY_DID,
    RECEIPT_KEY_ID,
  );
  return JSON.stringify({
    id: REGISTRY_DID,
    verificationMethod: [
      {
        id: RECEIPT_KEY_ID,
        type: 'Ed25519VerificationKey2020',
        controller: REGISTRY_DID,
        publicKeyJwk: {
          kty: 'OKP',
          crv: 'Ed25519',
          x: b64url(registry.publicKeyB64),
        },
      },
    ],
    assertionMethod: assertion ? [RECEIPT_KEY_ID] : [],
  });
}

// ── lhr-001 — lineage-head receipt golden vector (RFC-ACDP-0011 §5) ────

const LHR001 = {
  receipt_version: 'acdp-lhr/1',
  registry_did: REGISTRY_DID,
  lineage_id: LINEAGE,
  head_ctx_id: CTX,
  head_version: 1,
  head_status: 'active',
  as_of: '2026-07-04T09:00:00.000Z',
  signature: {
    algorithm: 'ed25519',
    key_id: RECEIPT_KEY_ID,
    value:
      'h4w9cdnmpNXWBkmQQLgbcQ2p22c1wKZCqnHx1sQXE2GuMRP2nlVt+twGikpFPP6zpRCjqEa3UxIxC8Y9qnl7BA==',
  },
};

const LHR_EXPECTED = {
  authority: 'registry.example.com',
  lineage_id: LINEAGE,
  head_ctx_id: CTX,
  head_version: 1,
  head_status: 'active',
};

const verifyLhr = ({
  receipt = LHR001,
  expected = LHR_EXPECTED,
  doc = registryDoc(),
  now = '2026-07-04T09:00:30.000Z',
  maxSkew = null,
  maxAge = null,
} = {}) =>
  JSON.parse(
    AcdpVerifier.verifyLineageHeadReceipt(
      JSON.stringify(receipt),
      JSON.stringify(expected),
      doc,
      now,
      maxSkew,
      maxAge,
    ),
  );

test('lhr-001 golden head receipt verifies', () => {
  assert.deepEqual(verifyLhr(), {
    valid: true,
    stale: false,
    age_secs: 30,
    historical: false,
  });
});

test('lhr-001 signature pins the golden bytes', () => {
  const { signature, ...unsigned } = LHR001;
  const receiptHash = AcdpCanonicalizer.contentHash(JSON.stringify(unsigned));
  assert.equal(
    receiptHash,
    'sha256:ae53a9479349d5bc224a8d0ac2464762d47831e0ec74462e48b9aa6a6081ea2a',
  );
  const registry = AcdpProducer.fromSeed(
    REGISTRY_SEED,
    REGISTRY_DID,
    RECEIPT_KEY_ID,
  );
  assert.equal(registry.signChallenge(receiptHash), signature.value);
});

test('lhr stale-but-valid is a freshness verdict, not a failure', () => {
  let v = verifyLhr({ now: '2026-07-04T10:00:00.000Z' });
  assert.ok(v.valid && v.stale && v.age_secs === 3600);
  v = verifyLhr({ now: '2026-07-04T10:00:00.000Z', maxAge: 7200 });
  assert.ok(v.valid && !v.stale);
});

test('lhr retired receipt key verifies as historical', () => {
  const v = verifyLhr({ doc: registryDoc(false) });
  assert.ok(v.valid && v.historical);
});

test('lhr-002: stale-head mismatch on /current fails step 5', () => {
  const v = verifyLhr({
    expected: {
      ...LHR_EXPECTED,
      head_ctx_id:
        'acdp://registry.example.com/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      head_version: 2,
    },
  });
  assert.ok(!v.valid);
  assert.equal(v.code, 'invalid_receipt');
  assert.match(v.error, /head_ctx_id/);
});

test('lhr step 5b: superseded full retrieval is consistent', () => {
  const receipt = {
    ...LHR001,
    head_ctx_id:
      'acdp://registry.example.com/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    head_version: 2,
  };
  const { signature: _drop, ...unsigned } = receipt;
  const registry = AcdpProducer.fromSeed(
    REGISTRY_SEED,
    REGISTRY_DID,
    RECEIPT_KEY_ID,
  );
  receipt.signature = {
    algorithm: 'ed25519',
    key_id: RECEIPT_KEY_ID,
    value: registry.signChallenge(
      AcdpCanonicalizer.contentHash(JSON.stringify(unsigned)),
    ),
  };
  assert.ok(
    verifyLhr({
      receipt,
      expected: {
        ...LHR_EXPECTED,
        head_status: 'superseded',
        on_current_endpoint: false,
      },
    }).valid,
  );
  // Self-contradictory: served status still 'active'.
  const v = verifyLhr({
    receipt,
    expected: { ...LHR_EXPECTED, on_current_endpoint: false },
  });
  assert.ok(!v.valid && v.code === 'invalid_receipt');
});

test('lhr-003: replay on hostile authority fails step 3', () => {
  let v = verifyLhr({
    expected: { ...LHR_EXPECTED, authority: 'hostile.example' },
  });
  assert.ok(!v.valid && v.code === 'invalid_receipt');
  v = verifyLhr({
    expected: { ...LHR_EXPECTED, registry_did: 'did:web:other.example' },
  });
  assert.ok(!v.valid && v.code === 'invalid_receipt');
});

test('lhr-004: future as_of fails step 6; honest skew passes', () => {
  const receipt = {
    ...LHR001,
    as_of: '2036-01-01T00:00:00.000Z',
    signature: {
      ...LHR001.signature,
      value:
        'DjQpxCPq2Yai85KlTLCFhMu+nEOZE7dHhSLIsTEbcl+DI5p8cBx/bL+eHPenzD2Wd1d6p2hZpK9g+/xavLc3BA==',
    },
  };
  const v = verifyLhr({ receipt, now: '2026-07-04T09:00:00.000Z' });
  assert.ok(!v.valid && v.code === 'invalid_receipt');
  assert.match(v.error, /as_of/);
  // Within-skew future as_of (60s ahead) passes.
  assert.ok(verifyLhr({ now: '2026-07-04T08:59:00.000Z' }).valid);
});

test('lhr tampered field / unknown member fail', () => {
  let v = verifyLhr({
    receipt: { ...LHR001, head_status: 'expired' },
    expected: { ...LHR_EXPECTED, head_status: 'expired' },
  });
  assert.ok(!v.valid && v.code === 'invalid_receipt');
  v = verifyLhr({ receipt: { ...LHR001, freshness_proof: true } });
  assert.ok(!v.valid && v.code === 'invalid_receipt');
});

test('lhr malformed expected throws on host input', () => {
  assert.throws(() =>
    AcdpVerifier.verifyLineageHeadReceipt(
      JSON.stringify(LHR001),
      JSON.stringify({ authority: 'registry.example.com' }),
      registryDoc(),
      null,
      null,
      null,
    ),
  );
});

// ── log-001 — transparency-log golden vector (RFC-ACDP-0012) ───────────

const LOG001_LEAF0 = {
  leaf_version: 'acdp-log-leaf/1',
  ctx_id: CTX,
  lineage_id: LINEAGE,
  origin_registry: 'registry.example.com',
  created_at: '2026-04-16T10:30:15.123Z',
  content_hash:
    'sha256:f170150ddbf59d99794e7797824591b374d459782084597b644ecc57a41031b5',
  key_fingerprint: K1_FP,
  receipt_hash:
    'sha256:9deaa52778ad3b6be27a96d607c3017e9e11442905891a8972f34d8c2dbca9cf',
};

const LOG001_LEAF_HASHES = [
  'sha256:95d99654d4d3de54a4d7cc04e079de61135023c78bb8192bdb79a09253afb8c1',
  'sha256:846b4d6c07ca099eea348c1e219345ddd426c0531cc30d3dd626d0fa34ec7704',
  'sha256:db94dd74b5c68f6d362129703ea587c8756d65cad0cc9859829021746a114451',
  'sha256:dc309b7856483acb5b2a92323dd9c1571a778bdb7b446587100022b49ee5fb3b',
  'sha256:6f673f8532d24869047264d89e2ad65f6ff2fa3c2674bb2fb9fa02855e090b3a',
];

const LOG001_ROOT =
  'sha256:0b5978172c671ca050b44790a749b18fc29d58a7a17495fbb4e0f86eb885f731';
const EMPTY_ROOT =
  'sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

const LOG001_CHECKPOINT = {
  checkpoint_version: 'acdp-log/1',
  log_id: LOG_ID,
  tree_size: 5,
  root_hash: LOG001_ROOT,
  timestamp: '2026-07-04T12:00:00.000Z',
  signature: {
    algorithm: 'ed25519',
    key_id: RECEIPT_KEY_ID,
    value:
      'o5rJmVE+1w/f7xAvW2P4vHA9FqWcMpS0crUPkMUZKSrBhrCVt/jyS+PCgnHNsNpmr+N+sR9I9qbqQ/Y0ZfOrDQ==',
  },
};

const LOG001_INCLUSION = {
  log_id: LOG_ID,
  leaf_index: 0,
  tree_size: 5,
  inclusion_path: [
    'sha256:846b4d6c07ca099eea348c1e219345ddd426c0531cc30d3dd626d0fa34ec7704',
    'sha256:54d7edc4ba9d151eedd7f4bb872884f0af5ff32b39f98866d67873b00687c605',
    'sha256:6f673f8532d24869047264d89e2ad65f6ff2fa3c2674bb2fb9fa02855e090b3a',
  ],
};

// rcpt-001: leaf 0's source receipt.
const RCPT001 = {
  registry_did: REGISTRY_DID,
  ctx_id: CTX,
  lineage_id: LINEAGE,
  origin_registry: 'registry.example.com',
  created_at: '2026-04-16T10:30:15.123Z',
  content_hash:
    'sha256:f170150ddbf59d99794e7797824591b374d459782084597b644ecc57a41031b5',
  key_fingerprint: K1_FP,
  signature: {
    algorithm: 'ed25519',
    key_id: RECEIPT_KEY_ID,
    value:
      'vBgQKmn17pHXXY95C07BBeconmjDIdYIvxN5B+YXrQ7tIzFsDNsh1TglzgxOyPUp8lwTz7zwMNiK+Sn5whveDg==',
  },
};

test('log-001: leaf 0 hash and Merkle root match the golden vector', () => {
  assert.equal(
    AcdpMerkle.leafHash(JSON.stringify(LOG001_LEAF0)),
    LOG001_LEAF_HASHES[0],
  );
  assert.equal(
    AcdpMerkle.rootHash(JSON.stringify(LOG001_LEAF_HASHES)),
    LOG001_ROOT,
  );
  assert.equal(AcdpMerkle.rootHash('[]'), EMPTY_ROOT);
});

test('nodeHash rebuilds the node(leaf0, leaf1) interior node', () => {
  assert.equal(
    AcdpMerkle.nodeHash(LOG001_LEAF_HASHES[0], LOG001_LEAF_HASHES[1]),
    'sha256:96659974ae162b1243bdf8b32a8f462cfc00c08a43d77574fad5361042d0a1bc',
  );
});

test('AcdpMerkle rejects malformed inputs with .code invalid_log_proof', () => {
  assert.throws(
    () => AcdpMerkle.nodeHash('sha256:short', LOG001_LEAF_HASHES[0]),
    (err) => err.code === 'invalid_log_proof',
  );
  assert.throws(
    () => AcdpMerkle.rootHash(JSON.stringify(['not-a-hash'])),
    (err) => err.code === 'invalid_log_proof',
  );
  assert.throws(
    () => AcdpMerkle.leafHash(JSON.stringify({ ...LOG001_LEAF0, note: 'x' })),
    (err) => err.code === 'invalid_log_proof',
  );
});

test('buildLogLeaf reconstructs leaf 0 from the verified rcpt-001', () => {
  const leaf = AcdpVerifier.buildLogLeaf(JSON.stringify(RCPT001));
  assert.deepEqual(JSON.parse(leaf), LOG001_LEAF0);
  assert.throws(
    () =>
      AcdpVerifier.buildLogLeaf(
        JSON.stringify({ ...RCPT001, created_at: '2026-04-16T10:30:15Z' }),
      ),
    (err) => err.code === 'invalid_receipt',
  );
});

test('log-001 checkpoint verifies; log_id pin detects history resets', () => {
  const v = JSON.parse(
    AcdpVerifier.verifyLogCheckpoint(
      JSON.stringify(LOG001_CHECKPOINT),
      registryDoc(),
      LOG_ID,
      '2026-07-04T12:00:10.000Z',
      null,
    ),
  );
  assert.ok(v.valid);
  assert.equal(v.tree_size, 5);
  assert.equal(v.root_hash, LOG001_ROOT);
  assert.ok(!v.historical);

  const pinned = JSON.parse(
    AcdpVerifier.verifyLogCheckpoint(
      JSON.stringify(LOG001_CHECKPOINT),
      registryDoc(),
      'did:web:registry.example.com/log/2',
      '2026-07-04T12:00:10.000Z',
      null,
    ),
  );
  assert.ok(!pinned.valid && pinned.code === 'invalid_log_proof');
});

test('log-004: tampered root_hash fails the checkpoint signature', () => {
  const v = JSON.parse(
    AcdpVerifier.verifyLogCheckpoint(
      JSON.stringify({
        ...LOG001_CHECKPOINT,
        root_hash:
          'sha256:fb5978172c671ca050b44790a749b18fc29d58a7a17495fbb4e0f86eb885f731',
      }),
      registryDoc(),
      LOG_ID,
      '2026-07-04T12:00:10.000Z',
      null,
    ),
  );
  assert.ok(!v.valid && v.code === 'invalid_log_proof');
});

test('log-001 inclusion proof verifies over the reconstructed leaf', () => {
  const leaf = AcdpVerifier.buildLogLeaf(JSON.stringify(RCPT001));
  const v = JSON.parse(
    AcdpVerifier.verifyLogInclusion(
      JSON.stringify(LOG001_INCLUSION),
      JSON.stringify(LOG001_CHECKPOINT),
      leaf,
    ),
  );
  assert.deepEqual(v, { valid: true, leaf_hash: LOG001_LEAF_HASHES[0] });
});

test('log-002: tampered inclusion path fails the fold', () => {
  const leaf = AcdpVerifier.buildLogLeaf(JSON.stringify(RCPT001));
  const tampered = {
    ...LOG001_INCLUSION,
    inclusion_path: [
      LOG001_INCLUSION.inclusion_path[0],
      'sha256:04d7edc4ba9d151eedd7f4bb872884f0af5ff32b39f98866d67873b00687c605',
      LOG001_INCLUSION.inclusion_path[2],
    ],
  };
  const v = JSON.parse(
    AcdpVerifier.verifyLogInclusion(
      JSON.stringify(tampered),
      JSON.stringify(LOG001_CHECKPOINT),
      leaf,
    ),
  );
  assert.ok(!v.valid && v.code === 'invalid_log_proof');
});

test('inclusion refuses a substituted embedded checkpoint', () => {
  const leaf = AcdpVerifier.buildLogLeaf(JSON.stringify(RCPT001));
  const v = JSON.parse(
    AcdpVerifier.verifyLogInclusion(
      JSON.stringify({
        ...LOG001_INCLUSION,
        log_checkpoint: { ...LOG001_CHECKPOINT, tree_size: 6 },
      }),
      JSON.stringify(LOG001_CHECKPOINT),
      leaf,
    ),
  );
  assert.ok(!v.valid);
  assert.match(v.error, /differs/);
});

// ── log-003 — consistency proof golden vector (§9.2) ───────────────────

const LOG003_FIRST_ROOT =
  'sha256:cf4604eee5578b1ca5b9414d901840b1c0e6e275222d3f613301989d20f58e9d';

const LOG003_PROOF = {
  log_id: LOG_ID,
  first_tree_size: 3,
  second_tree_size: 5,
  consistency_path: [
    'sha256:db94dd74b5c68f6d362129703ea587c8756d65cad0cc9859829021746a114451',
    'sha256:dc309b7856483acb5b2a92323dd9c1571a778bdb7b446587100022b49ee5fb3b',
    'sha256:96659974ae162b1243bdf8b32a8f462cfc00c08a43d77574fad5361042d0a1bc',
    'sha256:6f673f8532d24869047264d89e2ad65f6ff2fa3c2674bb2fb9fa02855e090b3a',
  ],
};

test('log-003: consistency proof between sizes 3 and 5 verifies', () => {
  assert.equal(
    AcdpMerkle.rootHash(JSON.stringify(LOG001_LEAF_HASHES.slice(0, 3))),
    LOG003_FIRST_ROOT,
  );
  const v = JSON.parse(
    AcdpVerifier.verifyLogConsistency(
      JSON.stringify(LOG003_PROOF),
      JSON.stringify(LOG001_CHECKPOINT),
      LOG003_FIRST_ROOT,
    ),
  );
  assert.deepEqual(v, { valid: true });
});

test('log-003: history rewrite (wrong retained root) is detected', () => {
  const v = JSON.parse(
    AcdpVerifier.verifyLogConsistency(
      JSON.stringify(LOG003_PROOF),
      JSON.stringify(LOG001_CHECKPOINT),
      'sha256:' + 'e'.repeat(64),
    ),
  );
  assert.ok(!v.valid && v.code === 'invalid_log_proof');
});

// ── Lifecycle events (RFC-ACDP-0013) ───────────────────────────────────

const EVENT_ID = '018f6d0a-7b2e-4c4d-9e1f-3a5b7c9d1e2f';

// Mint a §5-signed lifecycle event with the binding's own crypto: the
// signature is over the ASCII bytes of the preimage hash (the event
// minus `signature`) — the receipt construction verbatim.
function signedEvent(producer, overrides = {}) {
  const event = {
    event_id: EVENT_ID,
    ctx_id: CTX,
    event_type: 'retracted',
    occurred_at: '2026-07-04T09:15:42.000Z',
    actor: producer.agentDid,
    reason: 'underlying data source found to be fabricated',
    ...overrides,
  };
  const preimageHash = AcdpCanonicalizer.contentHash(JSON.stringify(event));
  event.signature = {
    algorithm: 'ed25519',
    key_id: producer.keyId,
    value: producer.signChallenge(preimageHash),
  };
  return event;
}

test('lifecycle event with did:key actor verifies offline', () => {
  const p = AcdpProducer.generateDidKey();
  const event = signedEvent(p);
  const v = JSON.parse(
    AcdpVerifier.verifyLifecycleEvent(JSON.stringify(event), null, CTX),
  );
  assert.ok(v.valid);
  assert.equal(v.event_type, 'retracted');
  assert.equal(v.actor, p.agentDid);
});

test('lifecycle event with did:web actor verifies against a supplied doc', () => {
  const actorDid = 'did:web:agents.example.com:test-producer';
  const keyId = `${actorDid}#key-2`;
  const p = AcdpProducer.generate(actorDid, keyId);
  const doc = JSON.stringify({
    id: actorDid,
    verificationMethod: [
      {
        id: keyId,
        type: 'Ed25519VerificationKey2020',
        controller: actorDid,
        publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: b64url(p.publicKeyB64) },
      },
    ],
    assertionMethod: [keyId],
  });
  const event = signedEvent(p);
  let v = JSON.parse(
    AcdpVerifier.verifyLifecycleEvent(JSON.stringify(event), doc, CTX),
  );
  assert.ok(v.valid);

  // did:web actor without a document → the host forgot resolution.
  v = JSON.parse(
    AcdpVerifier.verifyLifecycleEvent(JSON.stringify(event), null, CTX),
  );
  assert.ok(!v.valid && v.code === 'key_resolution');
});

test('lifecycle event cannot be replayed against another ctx_id', () => {
  const p = AcdpProducer.generateDidKey();
  const event = signedEvent(p);
  const v = JSON.parse(
    AcdpVerifier.verifyLifecycleEvent(
      JSON.stringify(event),
      null,
      'acdp://registry.example.com/00000000-0000-4000-8000-000000000009',
    ),
  );
  assert.ok(!v.valid);
  assert.match(v.error, /ctx_id/);
});

test('lifecycle tampering, unsigned and closed-schema violations fail', () => {
  const p = AcdpProducer.generateDidKey();
  const event = signedEvent(p);

  let v = JSON.parse(
    AcdpVerifier.verifyLifecycleEvent(
      JSON.stringify({ ...event, reason: 'innocuous edit' }),
      null,
      CTX,
    ),
  );
  assert.ok(!v.valid);

  const { signature: _sig, ...unsigned } = event;
  v = JSON.parse(
    AcdpVerifier.verifyLifecycleEvent(JSON.stringify(unsigned), null, CTX),
  );
  assert.ok(!v.valid);
  assert.match(v.error, /signature/);

  v = JSON.parse(
    AcdpVerifier.verifyLifecycleEvent(
      JSON.stringify({ ...event, severity: 'high' }),
      null,
      CTX,
    ),
  );
  assert.ok(!v.valid);

  v = JSON.parse(
    AcdpVerifier.verifyLifecycleEvent(
      JSON.stringify({ ...event, occurred_at: '2026-07-04T09:15:42Z' }),
      null,
      CTX,
    ),
  );
  assert.ok(!v.valid);
});

test('unknown lifecycle event_type verifies (inert for retraction)', () => {
  const p = AcdpProducer.generateDidKey();
  const event = signedEvent(p, { event_type: 'annotated' });
  const v = JSON.parse(
    AcdpVerifier.verifyLifecycleEvent(JSON.stringify(event), null, CTX),
  );
  assert.ok(v.valid);
  assert.equal(v.event_type, 'annotated');
});

// ── rev-001 / rev-002 — key revocation (RFC-ACDP-0014) ─────────────────

const REV001_BODY = {
  version: 1,
  supersedes: null,
  agent_id: 'did:web:agents.example.com:test-producer',
  contributors: [],
  title: 'Key revocation — key-1 compromised',
  summary:
    'Revocation of the Ed25519 key did:web:agents.example.com:test-producer#key-1, compromised since 2026-05-01T00:00:00.000Z.',
  type: 'key-revocation',
  data_refs: [],
  derived_from: [],
  visibility: 'public',
  metadata: {
    revoked_key_fingerprint: K1_FP,
    compromised_since: '2026-05-01T00:00:00.000Z',
    reason: 'laptop theft; private key material presumed exfiltrated',
  },
  acdp_version: '0.3.0',
  content_hash:
    'sha256:210bb03ec4bd39de893eb7d39ee992913cda80f767b135a02992a71491bf57ca',
  signature: {
    algorithm: 'ed25519',
    key_id: 'did:web:agents.example.com:test-producer#key-2',
    value:
      'Lf7P+ZifUGPXIkR2i9Vy4LByaTb6ktsakKcjm4ZFUlcgTs2r9/3eyjDJDNWfT+qAseNYecvYggTIGnT7EZiPAw==',
  },
  // registry-assigned (rev-001 registry_assigned block)
  ctx_id: 'acdp://registry.example.com/9f1e2d3c-5a6b-4c7d-8e9f-0a1b2c3d4e5f',
  lineage_id:
    'lin:sha256:6af6229c1c6a4a119695c77e47f6554941aebce3d25ba8567e2ae6ffbb6059cb',
  origin_registry: 'registry.example.com',
  created_at: '2026-05-02T08:00:00.000Z',
};

test('rev-001: body hash + K2 signature are the golden ones', () => {
  assert.ok(
    AcdpVerifier.verifyContentHash(
      JSON.stringify(REV001_BODY),
      REV001_BODY.content_hash,
    ),
  );
  const k2 = AcdpProducer.fromSeed(
    Buffer.alloc(32, 0x42),
    'did:web:agents.example.com:test-producer',
    'did:web:agents.example.com:test-producer#key-2',
  );
  assert.ok(
    AcdpVerifier.verifySignature(
      k2.publicKeyB64,
      REV001_BODY.signature.value,
      REV001_BODY.content_hash,
    ),
  );
  assert.equal(AcdpVerifier.fingerprintEd25519B64(k2.publicKeyB64), K2_FP);
});

test('rev-001 parses with the producer_signed trust class', () => {
  const rev = JSON.parse(
    AcdpVerifier.parseKeyRevocation(JSON.stringify(REV001_BODY), K2_FP),
  );
  assert.deepEqual(rev, {
    revoked_key_fingerprint: K1_FP,
    compromised_since: '2026-05-01T00:00:00.000Z',
    reason: 'laptop theft; private key material presumed exfiltrated',
    revoked_key_controller: 'did:web:agents.example.com:test-producer',
    publisher: 'did:web:agents.example.com:test-producer',
    trust_class: 'producer_signed',
  });
});

test('rev-001: a self-signed revocation is rejected (§5 step 2)', () => {
  assert.throws(
    () => AcdpVerifier.parseKeyRevocation(JSON.stringify(REV001_BODY), K1_FP),
    (err) => err.code === 'key_not_authorized',
  );
});

test('registry-attested trust class is distinguishable (§6)', () => {
  const body = JSON.parse(JSON.stringify(REV001_BODY));
  body.agent_id = REGISTRY_DID;
  body.metadata.revoked_key_controller =
    'did:web:agents.example.com:test-producer';
  const rev = JSON.parse(AcdpVerifier.parseKeyRevocation(JSON.stringify(body)));
  assert.equal(rev.trust_class, 'registry_attested');
  assert.equal(rev.publisher, REGISTRY_DID);
});

test('rev §4 shape violations throw schema_violation', () => {
  assert.throws(
    () =>
      AcdpVerifier.parseKeyRevocation(
        JSON.stringify({ ...REV001_BODY, visibility: 'private' }),
      ),
    (err) => err.code === 'schema_violation',
  );
  const badTs = JSON.parse(JSON.stringify(REV001_BODY));
  badTs.metadata.compromised_since = '2026-05-01T00:00:00Z';
  assert.throws(
    () => AcdpVerifier.parseKeyRevocation(JSON.stringify(badTs)),
    (err) => err.code === 'schema_violation',
  );
});

const rev001Parsed = () =>
  AcdpVerifier.parseKeyRevocation(JSON.stringify(REV001_BODY), K2_FP);

test('rev-002 A: pre-compromise receipt-attested time is distinguishable', () => {
  const v = JSON.parse(
    AcdpVerifier.classifyUnderRevocation(
      `[${rev001Parsed()}]`,
      K1_FP,
      '2026-04-16T10:30:15.123Z',
    ),
  );
  assert.deepEqual(v, {
    authorization: 'historically_authorized_pre_compromise',
    boundary: '2026-05-01T00:00:00.000Z',
  });
});

test('rev-002 B: at/after the boundary fails closed', () => {
  let v = JSON.parse(
    AcdpVerifier.classifyUnderRevocation(
      `[${rev001Parsed()}]`,
      K1_FP,
      '2026-05-03T09:00:00.000Z',
    ),
  );
  assert.equal(v.authorization, 'none');
  assert.match(v.error, /step 3/);
  // Exactly-at-T is already inside the window (strict boundary).
  v = JSON.parse(
    AcdpVerifier.classifyUnderRevocation(
      `[${rev001Parsed()}]`,
      K1_FP,
      '2026-05-01T00:00:00.000Z',
    ),
  );
  assert.equal(v.authorization, 'none');
  assert.ok(v.error);
});

test('rev-002 C: no verified receipt fails closed', () => {
  const v = JSON.parse(
    AcdpVerifier.classifyUnderRevocation(`[${rev001Parsed()}]`, K1_FP, null),
  );
  assert.equal(v.authorization, 'none');
  assert.match(v.error, /step 4/);
});

test('unrelated fingerprint / empty set are inert', () => {
  assert.deepEqual(
    JSON.parse(
      AcdpVerifier.classifyUnderRevocation(`[${rev001Parsed()}]`, K2_FP, null),
    ),
    { authorization: 'none' },
  );
  assert.deepEqual(
    JSON.parse(AcdpVerifier.classifyUnderRevocation('[]', K1_FP, null)),
    { authorization: 'none' },
  );
});

test('earliest boundary wins across a revocation lineage (§4)', () => {
  const later = JSON.parse(rev001Parsed());
  const earlier = { ...later, compromised_since: '2026-04-01T00:00:00.000Z' };
  const revs = JSON.stringify([later, earlier]);
  let v = JSON.parse(
    AcdpVerifier.classifyUnderRevocation(revs, K1_FP, '2026-04-15T00:00:00.000Z'),
  );
  assert.equal(v.authorization, 'none');
  assert.equal(v.boundary, '2026-04-01T00:00:00.000Z');
  v = JSON.parse(
    AcdpVerifier.classifyUnderRevocation(revs, K1_FP, '2026-03-01T00:00:00.000Z'),
  );
  assert.equal(v.authorization, 'historically_authorized_pre_compromise');
});
