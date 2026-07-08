// Release smoke test for the built Node.js SDK artifact.
//
// Loads the freshly-built `../index.js` (which loads the local
// `acdp.<platform>.node`) and reproduces the sig-001 golden vector from
// the all-zero seed. A mismatch here means the .node about to be
// published is broken — the strongest cheap check before `npm publish`.
//
// Pinned constants match tests/test.mjs, the Rust golden_vector suite,
// and the Python/wasm smokes. Drift on any side is a protocol break.
import assert from 'node:assert/strict';
import { AcdpProducer } from '../index.js';

const CONTENT_HASH =
  'sha256:f170150ddbf59d99794e7797824591b374d459782084597b644ecc57a41031b5';
const SIGNATURE =
  'ErkbV+FUdn49TgF3zJ3RBe3AmyGxLVAQdMjlhabUfM96qendmWwdVodX/SV3O3aKLypbUu6gmb5Npt3O/w7nDQ==';

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

assert.equal(req.content_hash, CONTENT_HASH, 'content_hash drifted from sig-001');
assert.equal(req.signature.value, SIGNATURE, 'signature drifted from sig-001');

console.log('acdp-node smoke OK: sig-001 golden vector reproduced');
