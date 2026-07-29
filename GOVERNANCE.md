# Governance

## Scope

| In scope | Out of scope |
| --- | --- |
| The Authority Evidence envelope, the evidence-profile vocabulary and their required claims, the three-valued verification framework and its aggregation policy, and the `AuthorityBinding` / `covers()` output that discharges sm-dat O1. | Provider-specific verification (the injected verifiers: JWT/JWKS, platform APIs, domain challenges). Anchor privacy and anti-enumeration. Multi-binding precedence → the resolver (`sm-divergence`). Key custody. |

The primitive owns one thing — *is this `grantor_did` bound to this `subject`, and how strongly?* —
and anything outside the table belongs to a companion package, an injected verifier, or the
consumer's stack.

## Versioning

Semantic Versioning 2.0.0. The evidence surface (the envelope shape, the profile vocabulary, the
verification order, and the aggregation policy) is frozen within a major and versioned as
`authority/<major.minor>` in the envelope. A change to it requires an RFC-style PR to `SPEC.md`
before code.

## Conformance

`vectors/authority/0.1/` (replayed by `tests/`) is the authoritative behavioural specification:
each vector pins an expected `(status, reason)` under a fixed verifier registry. A change in
behaviour without a corresponding vector/test change is a bug. Regenerate with
`python vectors/_generate.py`; CI fails if the corpus drifts from the generator.

## Contributions

- PRs must include vectors/tests and pass `ruff` + `mypy --strict` + `pytest`.
- No expansion of the evidence surface (new profiles, new envelope fields, new aggregation rules)
  without an accepted RFC.
- `INDETERMINATE` must never be collapsed into a pass or fail; an unsupported evidence type or a
  raising verifier is `INDETERMINATE`, never a silent pass.
- The framework must remain provider-agnostic: no bundled network or provider code in the core —
  verifiers are injected.
- No domain-specific or deployment-specific content — this is a generic primitive.
- Sign off with the Developer Certificate of Origin (DCO).

## Attribution

Composes [`sm-arp`](https://github.com/Sharathvc23/sm-arp) (identity, JCS, Ed25519). Establishes
the O1 precondition named in [`sm-dat`](https://github.com/Sharathvc23/sm-dat) SPEC §5.4; the
`AuthorityBinding` it produces is what `sm-provision` grants are checked against at a registry.

---

*Personal research contributions aligned with [Project NANDA](https://projectnanda.org) standards. [Stellarminds.ai](https://stellarminds.ai)*
