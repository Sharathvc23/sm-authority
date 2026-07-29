# Common Authority Evidence — establishing O1

**Spec version:** `authority/0.1-draft`
**Status:** DRAFT. Normative intent, not frozen.
**Discharges:** [DAT — Delegated Authority Token](https://github.com/Sharathvc23/sm-dat) SPEC §5.4 **O1** ("grantor is the human").
**Crypto/identity substrate:** reused from `sm-arp` (Ed25519, JCS, `did:key`).

The keywords MUST, MUST NOT, SHOULD, MAY are to be interpreted as in RFC 2119.

---

## 1. Introduction

sm-dat names one precondition a grant verifier **cannot** check: that a grant's `grantor_did` is
controlled by the real principal, not by the agent — "a valid signature proves only key
possession." This spec is the out-of-band mechanism that establishes it, in **one interoperable
form** across the many sources of authority an actor might have — including actors with no DNS
and no registry account (`john@hotmail.com`, a Toast-only restaurant).

An **Authority Evidence envelope** binds three things:

- a human-readable **`subject`** locator (email / brand domain) — mutable, discoverable;
- a durable **`anchor`** — an issuer-controlled immutable id (`iss+sub`/`oid`, a platform GUID, a
  DID) — the thing actually trusted, because locators are reusable;
- the **`grantor_did`** that will sign binding grants.

The binding is justified by **evidence blocks**, each verified by a per-type verifier, aggregated
into a three-valued verdict. A VERIFIED envelope yields an `AuthorityBinding` — the record a
registry checks a binding grant against (§6).

---

## 2. Roles

| Term | Meaning |
|------|---------|
| **Owner** | The subject's real controlling party; controls `grantor_did`. |
| **Issuer** | The party that assembles + signs the envelope (e.g. the agent store). Integrity, not authority. |
| **Verifier** | The party (registry) that checks the envelope and enforces policy. |
| **Anchor** | `{method, issuer, id}` — the durable, issuer-controlled immutable identifier. |

---

## 3. The envelope

```json
{
  "version": "authority/0.1",
  "subject": "john@hotmail.com",
  "anchor": {"method": "oidc", "issuer": "https://login.microsoftonline.com", "id": "<oid>"},
  "grantor_did": "did:key:z6Mk…",
  "evidence": [ { "type": "…", "claims": { … } } ],
  "issued_at": "…", "not_before": "…", "not_after": "…",
  "issuer_did": "did:key:z…",
  "signature": "…"
}
```

All fields listed are REQUIRED. `signature` is Ed25519 over the JCS-canonical envelope (minus
`signature`) by `issuer_did` — an unsigned or tampered envelope is `REFUTED` (§5).

---

## 4. Evidence profiles

| `type` | Required claims | Source of authority |
|--------|-----------------|---------------------|
| `oidc` | `token` | Identity-provider token (Microsoft/Google) |
| `platform_install` | `platform`, `install_id` | Shopify shop / Wix site / Toast restaurant install |
| `domain_control` | `domain`, `method` | Domain/HTTP/email (ACME-style) challenge |
| `did_control` | `challenge`, `signature` | A signature by the DID itself |
| `civic` | `scheme`, `credential` | Government / telecom / institutional credential |
| `prior_binding_key` | `prior_did`, `challenge`, `signature` | An existing binding / recovery key (migration & recovery) |

`build_evidence` enforces the required claims at construction. A verifier MAY require more.

---

## 5. Verification

`verify_authority_evidence(env, verifiers, at, *, policy)` → three-valued `AuthorityVerdict`.
Order:

1. **Structure** — required fields present, known `version`, else `REFUTED(malformed)`.
2. **Issuer signature** — verifies under `issuer_did`, else `REFUTED(bad_signature)`.
3. **Temporal** — `not_before ≤ at ≤ not_after`, else `REFUTED(not_yet_valid | expired)`.
4. **Per-evidence** — each block runs through `verifiers[type]`. **No verifier for a type ⇒
   `INDETERMINATE(unsupported_evidence_type)`** for that block — never silently ignored. A
   verifier that raises ⇒ `INDETERMINATE`, never a pass.
5. **Aggregation** (deliberately *not* sm-dat's strict any-INDETERMINATE-blocks):
   - Any **REFUTED** block ⇒ envelope `REFUTED` (a refutation is evidence the claim is *false*).
   - Else `VERIFIED` iff ≥ `policy.min_verified` blocks VERIFIED **and** all
     `policy.required_types` are among the verified. Extra INDETERMINATE/unsupported blocks
     neither help nor block.
   - Else `INDETERMINATE(insufficient_evidence | required_evidence_missing)`.

A refutation always wins; an unverifiable extra never demotes a solid verification.

---

## 6. Output and O1 discharge

A VERIFIED verdict carries an `AuthorityBinding {subject, anchor, grantor_did, verified_by,
issued_at, not_after}` — this **is** the locator↔anchor record. A registry discharges O1 by
requiring that a binding grant's signer and subject match a VERIFIED binding:

```
covers(binding, grantor_did=grant.grantor_did, subject=grant.binding_subject)
```

Only then is the sm-provision grant honoured. Resolution/precedence among *multiple* competing
bindings for one subject is the registry's job (e.g. via sm-divergence), not this spec's.

---

## 7. Verifier obligations

The framework does no crypto and trusts no provider; each injected verifier MUST establish its
own facts and, where it cannot, return `INDETERMINATE`/`REFUTED` — never an implicit pass:

- **`OIDCVerifier`** — the injected `token_validator` MUST verify the JWT signature against the
  issuer's JWKS, and the audience and expiry. This framework checks only the *binding* of the
  validated claims (`iss`, `sub`/`oid`, `nonce`) to the anchor. A `None` from the validator is
  `REFUTED`; a raise is `INDETERMINATE`.
- **`PriorBindingKeyVerifier`** — the caller MUST supply the set of trusted prior/recovery DIDs;
  an untrusted signer is `REFUTED(untrusted_prior_key)`. The signature MUST bind both `subject`
  and `grantor_did` (it does — §`binding_challenge_bytes`), so it cannot be replayed onto another
  subject or key.

---

## 8. What this does not own

Real JWT/JWKS verification, Shopify/Wix/Toast install verification, and domain-challenge checking
are **injected** verifiers, not shipped here (the package ships the framework + two references:
the fully-offline `prior_binding_key`, and the `OIDCVerifier` binding-check with the token
validator injected). Multi-binding precedence, transparency, and dispute belong to the registry.

---

## 9. Conformance

`vectors/authority/0.1/` — deterministic vectors `{env, at, policy?, expect:[status, reason]}`
replayed against a fixed registry (`PriorBindingKeyVerifier` + `OIDCVerifier` over the demo
validator). Coverage: each source verified/refuted, refutation-poisons, insufficient/required
policy, unsupported type, temporal, and tampered signature. Regenerate: `python vectors/_generate.py`.

---

## 10. Deferred

Reference JWKS-backed OIDC validator (behind an extra) · `platform_install` / `domain_control` /
`civic` reference verifiers · anchor privacy (pairwise `sub` vs `oid` correlation) · normative
freeze alongside `dat/0.2`.
