# sm-authority — Common Authority Evidence — Whitepaper

## Abstract

Every delegated grant rests on a precondition it cannot check about itself: that the grantor is
the real principal, not the agent that will act. [`sm-dat`](https://github.com/Sharathvc23/sm-dat)
states this as obligation **O1** and refuses to fake it — a valid signature proves only
key-possession. `sm-authority` is the out-of-band mechanism that establishes it: **one
interoperable envelope** binding a human-readable `subject` locator to a durable `anchor` and to
the `grantor_did`, justified by evidence blocks drawn from sources that have nothing in common — an
identity-provider token, a commerce-platform install, a domain challenge, a DID signature, a civic
credential, an existing recovery key — each checked by an injected verifier and aggregated into a
three-valued verdict. A VERIFIED envelope yields an `AuthorityBinding`: the locator↔anchor record a
registry checks a grant against.

The contribution is one credential model across incompatible sources, with two deliberate design
commitments. **Locator ≠ anchor**: the email or brand domain is a mutable, discoverable label; the
anchor is the issuer-controlled immutable id you actually trust. And **the framework verifies no
provider** — it does no crypto and trusts no source; the provider-specific work lives in injected
verifiers, so the core cannot silently vouch for something it did not check.

## 1. Problem

The actors who most need an agent binding often have no DNS and no registry account:
`john@hotmail.com`, a restaurant whose only control plane is Toast. Their authority is fragmented
across an IdP token here, a platform install there, a domain challenge, a civic credential, an old
recovery key. Domain Connect could assume one unambiguous authority — control of the DNS zone.
Here there is none, and no common way to state "this key is controlled by the party behind this
locator." So O1 goes unmet and every downstream grant is a leap of faith.

## 2. Design axioms

1. **Locator ≠ anchor.** `subject` is a discoverable label; `anchor` (`{method, issuer, id}`) is
   the durable, issuer-controlled identifier — because emails are mutable and reusable (Microsoft's
   own warning against email as an authorization identifier). The binding records the relationship;
   it never treats the locator as the authority.
2. **The framework verifies nothing; verifiers are injected.** Real JWT/JWKS checking, platform
   APIs, and domain challenges are plugged in, exactly like sm-bridge's trust-profile seam. No
   insecure default: an evidence type with no verifier is `INDETERMINATE`, never ignored.
3. **A refutation always wins.** One REFUTED block poisons the whole envelope; an unverifiable
   *extra* block never demotes a solid verification. You need *enough* positive proof, and any
   disproof kills it — fail-closed, like the rest of the stack.
4. **The output is a checkable record.** A VERIFIED envelope produces an `AuthorityBinding`; a
   registry discharges O1 with `covers(grantor_did, subject)` — no live authority server in the
   loop, reproducible by any third party.

## 3. The primitive

- `build_authority_evidence(...)` + `sign_authority_evidence(issuer, env)` → an issuer-signed
  envelope carrying subject, anchor, grantor_did, and a list of evidence blocks.
- `verify_authority_evidence(env, verifiers, at, *, policy)` → structure → issuer signature →
  temporal → per-evidence (each block through its injected verifier) → aggregate (refutation
  poisons; else require `policy.min_verified` VERIFIED, plus any `required_types`).
- Two reference verifiers ship: the fully-offline `PriorBindingKeyVerifier` (a recovery key signs a
  challenge bound to *both* subject and grantor_did, so it cannot be replayed onto another), and
  `OIDCVerifier` (the anchor-binding check, with the JWT/JWKS validator injected).

## 4. Composition with the portfolio

```
  evidence blocks  ──►  verify_authority_evidence  ──►  AuthorityBinding
   (oidc, platform,       (framework + injected            │  covers(grantor_did, subject)
    domain, did,           per-type verifiers)              ▼
    civic, prior-key)                              discharges sm-dat O1
                                                            │
                                          sm-provision grant honored by sm-bridge
        └── sm-arp (identity, JCS, Ed25519)
```

Aligned to **W3C Verifiable Credentials** (an envelope with per-source evidence), **OIDC** (the
`iss`+`sub`/`oid` anchor), and the **IETF NANDA** draft's open "common authority evidence" work.

## 5. Open questions

- **Anchor privacy.** A global `oid` buys cross-store portability but enables cross-application
  correlation; a pairwise `sub` buys privacy but complicates migration. Unresolved by design.
- **More reference verifiers.** `platform_install` / `domain_control` / `civic` define the injected
  shape; their implementations (and a JWKS-backed OIDC validator behind an extra) follow.
- **Privacy-preserving exact lookup.** Determining whether a subject has a binding without enabling
  bulk enumeration is a resolver concern, not this envelope's.

---

*Personal research contributions aligned with [Project NANDA](https://projectnanda.org) standards. [Stellarminds.ai](https://stellarminds.ai)*
