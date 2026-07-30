# sm-authority — the Common Authority Evidence envelope

**Establishes the one thing a delegated grant can't prove about itself:** that its `grantor_did`
(and the human-readable `subject` locator) is controlled by the *real owner*. That is
[`sm-dat`](https://github.com/Sharathvc23/sm-dat) SPEC **O1** — stated there as a precondition the
grant verifier cannot check and must be given out of band. This is the out-of-band mechanism, in
**one interoperable form** across every source of authority an actor might have — including actors
with no DNS and no registry account.

One envelope binds a **subject locator → durable anchor → grantor_did**, justified by **evidence
blocks** (`oidc`, `platform_install`, `domain_control`, `did_control`, `civic`,
`prior_binding_key`), each checked by an injected per-type verifier and aggregated into a
three-valued verdict (VERIFIED / REFUTED / INDETERMINATE). A VERIFIED result *is* the
locator↔anchor record a registry checks a binding grant against.

```python
from sm_authority import (Identity, build_anchor, build_evidence, build_authority_evidence,
                          sign_authority_evidence, sign_binding_challenge,
                          verify_authority_evidence, covers, PriorBindingKeyVerifier,
                          PRIOR_BINDING_KEY)

issuer, owner, recovery = Identity.generate(), Identity.generate(), Identity.generate()

env = sign_authority_evidence(issuer, build_authority_evidence(
    subject="john@hotmail.com",
    anchor=build_anchor(method="oidc", issuer="https://login.microsoftonline.com", anchor_id="<oid>"),
    grantor_did=owner.did,
    evidence=[build_evidence(PRIOR_BINDING_KEY, prior_did=recovery.did, challenge="c1",
                             signature=sign_binding_challenge(recovery, subject="john@hotmail.com",
                                                              grantor_did=owner.did, challenge="c1"))],
    issued_at="2026-07-28T12:00:00Z", not_after="2027-01-01T00:00:00Z",
))

verifiers = {PRIOR_BINDING_KEY: PriorBindingKeyVerifier(trusted_prior_dids={recovery.did})}
v = verify_authority_evidence(env, verifiers, "2026-07-29T12:00:00Z")
assert v.status == "VERIFIED"
assert covers(v.binding, grantor_did=owner.did, subject="john@hotmail.com")   # O1 discharged
```

## Two decisions that define this library

- **Locator ≠ anchor.** The `subject` is a discoverable label; the `anchor` is the issuer-controlled
  immutable id you actually trust (emails are mutable and reusable). The verified binding records
  the relationship — it does not treat the locator as the authority.
- **A refutation always wins.** One REFUTED evidence block poisons the whole envelope; an
  unverifiable *extra* block never demotes a solid verification. You need *enough* positive proof,
  and any disproof kills it — fail-closed, like the rest of the stack.

## Injected, not assumed

The framework does no crypto and trusts no provider. Real JWT/JWKS verification and platform/domain
checks are **injected** verifiers — the package ships the framework plus two references: the
fully-offline `prior_binding_key` (Ed25519 recovery-key attestation) and `OIDCVerifier` (the
anchor-binding check, with the token validator injected). No insecure default: an unsupported
evidence type is INDETERMINATE, never ignored.

## Status

- **[SPEC.md](./SPEC.md)** — normative draft (`authority/0.1-draft`); §6 shows how a registry
  discharges O1 before honouring a binding grant.
- `vectors/authority/0.1/` — deterministic conformance corpus; regenerate with
  `python vectors/_generate.py`, replay with `pytest`.
- Depends only on `sm-arp` (identity, canonicalization, signatures). No transport, no framework.

## License

MIT © 2026 StellarMinds. See [LICENSE](./LICENSE).

---

Part of the **NANDA** ecosystem · built by [StellarMinds](https://stellarminds.ai).
