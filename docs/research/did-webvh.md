# Research memo: `did:webvh` evaluation

**Status:** evaluation / not scheduled
**Scope:** whether to add `did:webvh` (did:web + Verifiable History) as a second
*resolvable producer* DID method alongside `did:web`, to close the historical-
key-validity gap independently of registry receipts.
**Effort:** **L** (large) — a new resolver, an RFC amendment to the method
allowlist, and a verification-status story. Additive; nothing breaks.

---

## 1. Problem being targeted

Three related gaps in the current design, all documented in the RFCs:

1. **Historical key validity (RFC-ACDP-0008 §9.3).** "Verifying a context whose
   producer has rotated keys requires knowing which key was valid at
   `created_at`. Most DID methods do not expose reliable historical key
   validity." `did:web` serves only the *current* DID document over HTTPS; there
   is no signed record of what the document said last year.

2. **The domain-lapse / host-trust problem.** `did:web` binds identity to a DNS
   name and a live HTTPS host. If the domain lapses or is hijacked (the
   RFC-ACDP-0008 §3.3 producer-impersonation class), an attacker who reacquires
   the name can serve *any* DID document — and there is no cryptographic history
   to contradict them. Verification outlives neither the domain registration nor
   the host. (RFC-ACDP-0001 §5.4 already notes `did:key` is "immune to … domain-
   lapse hijacking … because the DID *is* the key" — but `did:key` cannot
   rotate, which is the opposite failure mode.)

3. **`did:web` resolution requires trusting the current host.** A `did:web`
   document is whatever the server returns *now*. There is no offline,
   tamper-evident proof that a given key was ever authorized.

The current mitigations are **receipts** (RFC-ACDP-0010) plus a **key-retention
discipline**:

- The receipt's `key_fingerprint` is the registry's *publish-time* attestation
  of which producer key verified the body (RFC-ACDP-0010 §10, "Workstream B").
- Producers SHOULD retain rotated keys in `verificationMethod` indefinitely,
  removing them from `assertionMethod` only (RFC-ACDP-0001 §5.11,
  RFC-ACDP-0010 §10).
- Result: a receipt-bearing historical context verifies with the distinguishable
  status *historically authorized (receipt-attested)* (RFC-ACDP-0008 §9.3).
- RFC-ACDP-0014 time-scopes this further (a key-revocation context splits a
  fingerprint's history at a boundary T).

**But receipts attest the *registry's* view of publish-time key state.** They do
not give the producer an independent, self-authenticating record of its own key
history. `did:webvh` targets exactly that missing piece.

---

## 2. What `did:webvh` is

`did:webvh` ("did:web + Verifiable History", formerly `did:tdw`) is a DID method
that keeps everything `did:web` gives (HTTPS-hosted, DNS-anchored, human-
meaningful identifier) and **adds a hash-chained, cryptographically verifiable
log of the DID document's entire history**. Its salient features:

- **DID log (`did.jsonl`).** An append-only list of entries, each recording a
  version of the DID document plus a proof. Each entry hash-chains to the
  previous (an `entryHash` / version-id linked list), so the whole history is
  tamper-evident: you cannot alter or drop a past version without breaking the
  chain.
- **SCID (Self-Certifying IDentifier).** The DID string embeds a hash derived
  from the first log entry (the genesis parameters). This binds the identifier
  to its own genesis state — an attacker who seizes the domain **cannot forge a
  history that produces the same SCID**, so a lapsed/hijacked domain can serve a
  fresh `did:webvh` but not *the same* one. This is the property `did:web`
  fundamentally lacks and the direct answer to problem (2) above.
- **Key pre-rotation.** An entry can commit (via a hash) to the *next*
  authorized key before it is used, so compromise of the current key does not
  let an attacker rewrite the forward history — they cannot produce the pre-
  committed next key.
- **Witnesses.** `did:webvh` supports independent witnesses that co-observe and
  attest log entries — **note the strong conceptual overlap with RFC-ACDP-0015
  witness cosigning**, which does the same thing for transparency-log
  checkpoints (independent DIDs cosigning an append-only structure to defeat
  split-view / equivocation). Both are "trust one honest external observer"
  constructions; a `did:webvh` integration and RFC-0015 could plausibly **share
  a witness abstraction** rather than growing two.
- **Offline / host-independent verifiability.** Given the DID log, a verifier
  can validate the entire key history — SCID binding, chain integrity, proofs,
  pre-rotation commitments — **without trusting the current host** and, once the
  log is in hand, **without any network at all**. This is the qualitative
  difference from `did:web`, whose document is only ever "what the server says
  right now."

---

## 3. How it maps onto the ACDP trust model

### Complementary to receipts, not a replacement

The two mechanisms attest **different facts from different parties**:

| | Attests | Signed by | Answers |
|---|---|---|---|
| **Receipt** (RFC-0010) | This exact key verified this exact body at this `created_at` | the **registry** | "What did the registry see at publish time?" |
| **`did:webvh` log** | This key was an authorized assertion key of the producer during \[version interval] | the **producer** (self-certifying chain) | "What was the producer's own key history, provably?" |

They reinforce each other: a receipt says *key K verified the body*; a
`did:webvh` log says *K was genuinely one of my keys at that time, here is the
signed, hash-chained proof, and here is the pre-rotation commitment that proves
I did not backfill it*. Together they upgrade *historically authorized
(receipt-attested)* from "the registry vouches" to "the registry vouches **and**
the producer's own tamper-evident history agrees" — and crucially the
`did:webvh` half survives the registry going away, the domain lapsing, and going
offline. Receipts remain necessary for the registry-honesty facts receipts
uniquely bind (`ctx_id`, `lineage_id`, `origin_registry`, `created_at` — RFC-
ACDP-0008 §9.1); `did:webvh` says nothing about those.

### What it would take to add as a *supported* method

1. **RFC amendment to the §5.4 method allowlist.** RFC-ACDP-0001 §5.4 currently
   pins `agent_id` and `signature.key_id` (DID portion) to `did:web`, with
   `did:key` added as a gated second method in 0.2.0. Adding `did:webvh` is the
   same *shape* of amendment `did:key` already was: a new row in the §5.4 scope
   table ("`did:web`, or *(0.2.0)* `did:key`, or *(0.x.0)* `did:webvh` where
   advertised"), a new value in the registry's `supported_did_methods`
   capability (RFC-ACDP-0007 §3.1), and a rejection code choice (reuse
   `key_resolution_failed`, permanent HTTP 400, matching the `did:key` `dk-003`
   precedent) when a registry that does not advertise it receives a `did:webvh`
   publish.

2. **A resolver in `acdp-did` alongside `WebResolver`.** `acdp-did` today has
   `web.rs` (`WebResolver`, network, LRU-cached, SSRF-gated) and `key.rs`
   (`resolve_did_key`, pure/offline). A `did:webvh` resolver is a **hybrid**:
   fetch the `did.jsonl` log over HTTPS (reuse the `WebResolver`'s
   `acdp-safe-http` client, so all the RFC-ACDP-0006 §7 / RFC-ACDP-0008 SSRF
   defenses — HTTPS-only, IP-literal rejection, private-range blocking, DNS-
   rebinding protection, body caps — apply unchanged), then **verify the chain
   offline**: SCID check, per-entry hash-chain, entry proofs, pre-rotation
   commitments, and resolve the key valid **at a given version/time**. The
   offline half slots naturally next to the offline verification already in
   `acdp-verify`. The dispatch point is small: the resolver-backed `Verifier` in
   `acdp-verify` already dispatches key resolution by DID method; a `did:webvh`
   arm resolves-with-history and can return the *time-scoped* key set that
   RFC-ACDP-0008 §9.3 / RFC-ACDP-0014's boundary logic wants.

3. **A verification-status story.** Because the log resolves *which key was valid
   when*, a `did:webvh` producer can achieve *historically authorized* **without
   a receipt** — the producer's own history supplies the temporal binding the
   receipt otherwise supplies. This is worth stating explicitly in the amendment
   (it is the whole payoff): `did:webvh` gives receipt-independent historical
   verification, where `did:web` cannot.

---

## 4. Where it belongs, and the compatibility story

- **Additive, gated, non-breaking — like `did:key` was.** `did:web` stays
  mandatory and unchanged; `did:webvh` is opt-in per registry via
  `supported_did_methods` and per producer per identity. No v0.1.0 body, hash,
  or signature semantic changes. `registry_did` stays `did:web`-only for the
  same reason `did:key` did not touch it (RFC-ACDP-0001 §5.4: the registry-
  identity↔authority equality of RFC-ACDP-0006 §4.1 / RFC-ACDP-0010 §8 depends
  on `did:web`'s DNS binding).
- **Spec line.** Sits naturally in a future 0.4.0/0.5.0 trust-hardening drop,
  ideally **sequenced with or after RFC-ACDP-0015** so the witness abstraction
  can be shared rather than duplicated (see open questions). It is a larger lift
  than `did:key` (which was pure offline decode) because of the log-verification
  machinery, hence **effort L**.
- **Migration.** A producer migrates by publishing a `did:webvh` DID (its SCID-
  bearing genesis log) and pointing new `agent_id` / `signature.key_id` at it.
  Existing `did:web` and `did:key` contexts keep verifying by their existing
  paths. Because `supersedes` requires the same `agent_id` (RFC-ACDP-0003 §3.1),
  switching methods starts a new lineage — the same constraint `did:key`
  documents; worth calling out so producers choose their method per identity up
  front.

---

## 5. Open questions

- **Witness reuse with RFC-ACDP-0015.** `did:webvh` witnesses and RFC-0015
  transparency-log witnesses are the same idea at two layers (DID-history vs
  registry-log). Can ACDP define **one** witness/cosignature construction
  (RFC-0010 §5 signing reused verbatim, as RFC-0015 already does) that serves
  both? If yes, a `did:webvh` integration should wait for or co-design with
  RFC-0015 to avoid two witness models. This is the strongest argument for
  sequencing over shipping now.
- **Resolver caching + SSRF for `did.jsonl`.** The log is append-only and can
  grow; caching must key on `(did, version)` and must not let a stale/truncated
  log downgrade history. The fetch must go through `acdp-safe-http` exactly like
  `WebResolver` (same DNS-rebinding, private-range, body-cap defenses); the
  64 KB DID-document cap may be too small for a long log — a separate,
  documented cap is needed, and unbounded logs are a DoS surface.
- **Time source for "valid at `created_at`".** The historical-key check needs a
  trustworthy `created_at`. Without a receipt, `created_at` is registry-asserted
  (RFC-ACDP-0008 §9.1). So `did:webvh` fully closes §9.3 **only** when paired
  with a receipt (or a witnessed transparency-log timestamp) that fixes the
  publish time; alone it proves *the key history* but not *the moment to index
  into it*. This complementarity should be stated, not glossed.
- **Spec/library maturity.** `did:webvh` is a newer, still-evolving method
  (multiple format revisions during its `did:tdw` → `did:webvh` rename). Pin a
  specific method version in the amendment and treat the resolver as versioned;
  do not track a moving target in a wire-frozen protocol.

---

## 6. Recommendation

`did:webvh` is the **most direct structural answer** the DID ecosystem offers to
the two hardest residual gaps ACDP has openly documented — historical key
validity (RFC-ACDP-0008 §9.3) and domain-lapse/host-trust (§3.3) — because it
adds a self-certifying, hash-chained, offline-verifiable key history that
`did:web` architecturally cannot provide and that receipts can only partially
substitute for. It is **complementary** to receipts, not competitive. Recommend
tracking it as a candidate for a 0.4.0/0.5.0 trust-hardening drop, **sequenced
with RFC-ACDP-0015** so the witness machinery is shared, structured exactly like
the `did:key` amendment (additive, capability-gated, `did:web` untouched), with
the resolver reusing `acdp-safe-http` for the network half and slotting its
offline chain-verification next to `acdp-verify`'s existing offline path. Not
imminent; a strong forward bet.
