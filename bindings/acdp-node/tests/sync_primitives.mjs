// In-process tests for the ACDP Node.js SDK sync primitives:
// AcdpCanonicalizer (RFC 8785 + content hashing) and AcdpSsrfPolicy.
//
// Build first:  `npm run build:debug`
// Then run:     `node --test tests/`
//
// These mirror the Python SDK's test_canonicalizer.py / test_safe_http.py
// so both bindings stay in sync against the same Rust core.

import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { AcdpCanonicalizer, AcdpSsrfPolicy, AcdpProducer } from '../index.js';

const sha256Envelope = (canonical) =>
  'sha256:' + createHash('sha256').update(canonical, 'utf8').digest('hex');

// ── AcdpCanonicalizer ───────────────────────────────────────────────────

test('canonicalize sorts keys and strips whitespace', () => {
  assert.equal(
    AcdpCanonicalizer.canonicalize('{ "b": 1,\n  "a": 2 }'),
    '{"a":2,"b":1}',
  );
});

test('canonicalize normalizes negative zero', () => {
  assert.equal(AcdpCanonicalizer.canonicalize('{"x": -0.0}'), '{"x":0}');
});

test('canonicalize sorts nested objects and preserves array order', () => {
  assert.equal(
    AcdpCanonicalizer.canonicalize('{"z": [3, 2, 1], "a": {"d": 4, "c": 3}}'),
    '{"a":{"c":3,"d":4},"z":[3,2,1]}',
  );
});

test('canonicalize passes unicode through as UTF-8', () => {
  assert.equal(
    AcdpCanonicalizer.canonicalize('{"k": "café — π"}'),
    '{"k":"café — π"}',
  );
});

test('contentHash matches sha256 over the canonical form', () => {
  const doc = '{ "b": 1, "a": 2 }';
  const canonical = AcdpCanonicalizer.canonicalize(doc);
  assert.equal(AcdpCanonicalizer.contentHash(doc), sha256Envelope(canonical));
});

test('contentHash is order-independent', () => {
  const a = AcdpCanonicalizer.contentHash('{"a":1,"b":2}');
  const b = AcdpCanonicalizer.contentHash('{"b":2,"a":1}');
  assert.equal(a, b);
  assert.ok(a.startsWith('sha256:'));
  assert.equal(a.length, 7 + 64);
});

test('contentHash over producer content reproduces the producer content_hash', () => {
  const p = AcdpProducer.fromSeed(
    Buffer.alloc(32),
    'did:web:agents.example.com:test-producer',
    'did:web:agents.example.com:test-producer#key-1',
  );
  const req = JSON.parse(
    p.buildPublishRequest({
      title: 'Golden test vector — minimal first version',
      contextType: 'data_snapshot',
    }),
  );
  const EXCLUDE = new Set([
    'content_hash',
    'signature',
    'ctx_id',
    'lineage_id',
    'origin_registry',
    'created_at',
  ]);
  const producerContent = Object.fromEntries(
    Object.entries(req).filter(([k]) => !EXCLUDE.has(k)),
  );
  assert.equal(
    AcdpCanonicalizer.contentHash(JSON.stringify(producerContent)),
    req.content_hash,
  );
});

test('canonicalize / contentHash reject malformed JSON', () => {
  assert.throws(() => AcdpCanonicalizer.canonicalize('{not valid'));
  assert.throws(() => AcdpCanonicalizer.contentHash('{not valid'));
});

// ── AcdpSsrfPolicy ──────────────────────────────────────────────────────

const prod = () => AcdpSsrfPolicy.production();

test('https public host is allowed', () => {
  assert.doesNotThrow(() => prod().checkUrl('https://registry.example.com'));
});

test('http scheme is rejected with code non_https', () => {
  assert.throws(() => prod().checkUrl('http://registry.example.com'), {
    code: 'non_https',
  });
});

test('IP-literal URLs are rejected with code ip_literal', () => {
  assert.throws(() => prod().checkUrl('https://192.168.1.1'), {
    code: 'ip_literal',
  });
  assert.throws(() => prod().checkUrl('https://[::1]'), { code: 'ip_literal' });
});

test('malformed URL is rejected with code invalid_url', () => {
  assert.throws(() => prod().checkUrl('not a url'), { code: 'invalid_url' });
});

const IP_REASONS = [
  ['127.0.0.1', 'loopback'],
  ['10.0.0.1', 'private'],
  ['172.16.5.5', 'private'],
  ['192.168.1.1', 'private'],
  ['100.64.0.1', 'private'],
  ['169.254.169.254', 'imds'],
  ['239.0.0.1', 'multicast_or_reserved'],
  ['0.0.0.1', 'multicast_or_reserved'],
  ['240.0.0.1', 'multicast_or_reserved'],
  ['::1', 'loopback'],
  ['fc00::1', 'private'],
  ['fe80::1', 'imds'],
  ['64:ff9b::a9fe:a9fe', 'imds'],
  ['::ffff:10.0.0.1', 'private'],
];

for (const [ip, code] of IP_REASONS) {
  test(`checkIp(${ip}) rejects with code ${code}`, () => {
    assert.throws(() => prod().checkIp(ip), { code });
  });
}

for (const ip of ['8.8.8.8', '203.0.113.1', '2001:db8::1']) {
  test(`checkIp(${ip}) allows a public address`, () => {
    assert.doesNotThrow(() => prod().checkIp(ip));
  });
}

test('checkIp rejects garbage with code invalid_ip', () => {
  assert.throws(() => prod().checkIp('not-an-ip'), { code: 'invalid_ip' });
});

test('allowTestLoopback permits loopback but nothing else', () => {
  const pol = AcdpSsrfPolicy.allowTestLoopback();
  assert.doesNotThrow(() => pol.checkIp('127.0.0.1'));
  assert.doesNotThrow(() => pol.checkIp('::1'));
  assert.throws(() => pol.checkIp('10.0.0.1'), { code: 'private' });
});

test('redirect within the same authority is allowed', () => {
  assert.doesNotThrow(() =>
    prod().checkRedirectAuthority('https://a.example/x', 'https://a.example/y'),
  );
});

test('redirect with explicit :443 equals the implicit https default', () => {
  assert.doesNotThrow(() =>
    prod().checkRedirectAuthority(
      'https://a.example/x',
      'https://a.example:443/y',
    ),
  );
});

for (const [from, to] of [
  ['https://a.example/x', 'https://b.example/y'], // cross host
  ['https://a.example/x', 'https://a.example:8443/y'], // port change
  ['https://a.example/x', 'http://a.example/y'], // scheme downgrade
]) {
  test(`redirect ${from} -> ${to} is rejected as cross_authority`, () => {
    assert.throws(() => prod().checkRedirectAuthority(from, to), {
      code: 'cross_authority',
    });
  });
}
