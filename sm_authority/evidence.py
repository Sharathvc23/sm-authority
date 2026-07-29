"""The Common Authority Evidence envelope and its evidence-block profiles.

sm-dat SPEC O1 names the one precondition a grant verifier cannot itself check:
that a grant's ``grantor_did`` is controlled by the real principal, not by the
agent. This package is the out-of-band mechanism that establishes it — in **one**
interoperable form across many sources of authority:

  - ``oidc``               — an identity-provider token (Sign in with Microsoft/Google).
  - ``platform_install``   — a commerce/website platform install (Shopify/Wix/Toast).
  - ``domain_control``     — a domain/HTTP/email challenge (ACME-style).
  - ``did_control``        — a signature by the DID itself.
  - ``civic``              — a government/telecom/institutional credential.
  - ``prior_binding_key``  — an existing binding/recovery key, for migration & recovery.

An envelope binds a human-readable ``subject`` locator (an email or brand domain)
to a durable ``anchor`` — an issuer-controlled immutable id, the thing you
actually trust, since locators are mutable and reusable (Microsoft's own warning
about email as an authorization identifier) — and to the ``grantor_did`` that will
sign binding grants. The evidence blocks are the proofs; ``verify.py`` runs each
through a per-type verifier and aggregates a three-valued verdict.

Crypto (Ed25519, JCS canonicalization, did:key) is reused from ``sm-arp``. The
envelope is signed by its **issuer** — the party that assembled the evidence — for
integrity and non-repudiation of assembly; authority itself comes from the
evidence blocks, not the issuer.
"""

from __future__ import annotations

import base64
from collections.abc import Iterable
from typing import Any

from sm_arp import Identity, canonical_bytes, pubkey_from_did

AUTHORITY_VERSION = "authority/0.1"

# --- evidence type vocabulary ------------------------------------------------
OIDC = "oidc"
PLATFORM_INSTALL = "platform_install"
DOMAIN_CONTROL = "domain_control"
DID_CONTROL = "did_control"
CIVIC = "civic"
PRIOR_BINDING_KEY = "prior_binding_key"
EVIDENCE_TYPES = frozenset({
    OIDC, PLATFORM_INSTALL, DOMAIN_CONTROL, DID_CONTROL, CIVIC, PRIOR_BINDING_KEY,
})

# Minimum claims each profile must carry to be well-formed at construction. A
# verifier may require more; this only rejects the obviously incomplete.
PROFILE_REQUIRED_CLAIMS: dict[str, frozenset[str]] = {
    OIDC: frozenset({"token"}),
    PLATFORM_INSTALL: frozenset({"platform", "install_id"}),
    DOMAIN_CONTROL: frozenset({"domain", "method"}),
    DID_CONTROL: frozenset({"challenge", "signature"}),
    CIVIC: frozenset({"scheme", "credential"}),
    PRIOR_BINDING_KEY: frozenset({"prior_did", "challenge", "signature"}),
}


def build_anchor(*, method: str, issuer: str, anchor_id: str) -> dict[str, str]:
    """The durable authority anchor: an issuer-controlled immutable identifier.

    e.g. ``build_anchor(method="oidc", issuer="https://login.microsoftonline.com",
    anchor_id="00000000-0000-0000-0000-000000000abc")`` for a Microsoft ``oid``.
    """
    return {"method": method, "issuer": issuer, "id": anchor_id}


def build_evidence(evidence_type: str, **claims: Any) -> dict[str, Any]:
    """One evidence block ``{type, claims}``. Validates structure only."""
    if evidence_type not in EVIDENCE_TYPES:
        raise ValueError(f"unknown evidence type: {evidence_type!r}")
    missing = PROFILE_REQUIRED_CLAIMS[evidence_type] - claims.keys()
    if missing:
        raise ValueError(f"{evidence_type} evidence missing required claims: {sorted(missing)}")
    return {"type": evidence_type, "claims": dict(claims)}


def build_authority_evidence(
    *,
    subject: str,
    anchor: dict[str, str],
    grantor_did: str,
    evidence: Iterable[dict[str, Any]],
    not_after: str,
    issued_at: str,
    not_before: str | None = None,
) -> dict[str, Any]:
    """An *unsigned* Authority Evidence envelope. Sign with
    :func:`sign_authority_evidence` using the assembling issuer's key."""
    ev = list(evidence)
    if not ev:
        raise ValueError("at least one evidence block is required")
    return {
        "version": AUTHORITY_VERSION,
        "subject": subject,
        "anchor": dict(anchor),
        "grantor_did": grantor_did,
        "evidence": ev,
        "issued_at": issued_at,
        "not_before": not_before or issued_at,
        "not_after": not_after,
        "issuer_did": None,
    }


def sign_authority_evidence(issuer: Identity, env: dict[str, Any]) -> dict[str, Any]:
    """Stamp ``issuer_did`` and Ed25519-sign the JCS-canonical envelope."""
    e = {k: v for k, v in env.items() if k != "signature"}
    e["issuer_did"] = issuer.did
    sig = issuer.sign(canonical_bytes(e, include_signature=False))
    e["signature"] = base64.b64encode(sig).decode("ascii")
    return e


def verify_envelope_signature(env: dict[str, Any]) -> bool:
    """True iff ``signature`` verifies under ``issuer_did`` over the canonical
    envelope. Keyed off ``issuer_did`` (who assembled the evidence)."""
    sig = env.get("signature")
    issuer = env.get("issuer_did")
    if not sig or not issuer:
        return False
    body = {k: v for k, v in env.items() if k != "signature"}
    try:
        pubkey_from_did(issuer).verify(
            base64.b64decode(sig), canonical_bytes(body, include_signature=False)
        )
        return True
    except Exception:  # noqa: BLE001 — any failure is a failed verification
        return False


def binding_challenge_bytes(subject: str, grantor_did: str, challenge: str) -> bytes:
    """Canonical bytes a prior/recovery key (or the DID itself) signs to attest
    that ``grantor_did`` controls ``subject``. Binding the signature to both the
    subject and the grantor_did is what stops a captured signature being replayed
    onto a different subject or a different key."""
    data: bytes = canonical_bytes(
        {"subject": subject, "grantor_did": grantor_did, "challenge": challenge},
        include_signature=False,
    )
    return data


def sign_binding_challenge(
    signer: Identity, *, subject: str, grantor_did: str, challenge: str,
) -> str:
    """Client helper: sign :func:`binding_challenge_bytes` with a prior/recovery
    key (or the DID itself), returning base64 — the ``signature`` claim of a
    ``prior_binding_key`` / ``did_control`` evidence block."""
    return base64.b64encode(
        signer.sign(binding_challenge_bytes(subject, grantor_did, challenge))
    ).decode("ascii")
