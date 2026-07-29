# Threat model

What `sm-authority` defends, and — just as important — what it does not. `sm-authority` is an
evidence-envelope format and a verification framework; it makes narrow, checkable guarantees and
states its boundaries plainly. The single most important boundary, which shapes every other row:

> **A VERIFIED envelope is only as trustworthy as its injected verifiers and the trust anchors
> they are given.** The framework itself verifies no provider and establishes no ground truth — it
> checks structure, the issuer signature, and the *binding* of each verifier's result to the
> envelope, then aggregates. A permissive injected validator, or a mis-chosen trust anchor, yields
> a weak result that is still labelled VERIFIED.

## What it defends

**Envelope tampering.** The issuer's Ed25519 signature covers the JCS-canonical bytes of the whole
envelope (subject, anchor, grantor_did, every evidence block). Altering any field invalidates it →
`REFUTED(bad_signature)`. `verify_envelope_signature` returns a falsy result on hostile input; it
never raises.

**Prior-key replay.** A `prior_binding_key` (or `did_control`) signature is computed over bytes
that bind *both* the `subject` and the `grantor_did`. A signature captured for one subject/key
cannot be replayed onto a different subject or a different grantor_did — the verifier recomputes
over the envelope's own values and rejects a mismatch (`bad_prior_signature`).

**Untrusted attestors.** When a trusted-prior-DID set is supplied, a signature by any key outside
it is `REFUTED(untrusted_prior_key)`, not silently accepted.

**Anchor drift (OIDC).** `OIDCVerifier` refuses a token whose `iss` ≠ the envelope's anchor issuer
(`issuer_mismatch`), whose `sub`/`oid` ≠ the anchor id (`anchor_mismatch`), or whose nonce does not
match (`nonce_mismatch`).

**Silent under-verification.** An evidence type with no registered verifier is
`INDETERMINATE(unsupported_evidence_type)` — it does not count toward the policy and is never
treated as a pass. A verifier (or an injected validator) that *raises* is `INDETERMINATE`
(`verifier_error` / `validator_error`), never a crash and never a pass.

**Refutation poisoning.** A single REFUTED block makes the whole envelope REFUTED, regardless of
how many other blocks verified.

## What it does NOT defend — stated boundaries

**Provider verification.** This is the central limitation, not an edge case. Whether an OIDC token
is genuinely signed by the issuer's JWKS, whether a Shopify/Wix/Toast install is real, whether a
domain challenge was actually satisfied — all of this is the *injected* verifier's job. The
framework checks the binding of the verifier's output to the anchor; it does not perform the
provider call. Ship a real verifier before relying on a source.

**Trust-anchor selection.** The set of trusted prior DIDs, the accepted issuers, and the audience
are supplied by the caller. sm-authority enforces them; it does not decide them.

**Anchor privacy.** The envelope records the anchor as given; it does not prevent the correlation a
global `oid` enables, nor does it choose pairwise identifiers for you.

**Multi-binding precedence and enumeration.** Which of several bindings for one subject wins, and
preventing bulk lookup of subjects, are resolver/registry concerns (cf. `sm-divergence`).

**Timestamp truth, key custody.** `at` and the envelope timestamps gate validity but are
caller-asserted; generation, storage, and rotation of issuer/attestor keys are out of scope.

## Determinism note

Envelopes are signed over sorted-key compact JSON (JCS) with deterministic Ed25519; equal inputs
produce byte-identical envelopes. This is a correctness property, not a security one, but it is
what lets two independent implementations — and the conformance corpus under `vectors/` — agree
byte-for-byte.

---

*Personal research contributions aligned with [Project NANDA](https://projectnanda.org) standards. [Stellarminds.ai](https://stellarminds.ai)*
