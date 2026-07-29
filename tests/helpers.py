"""Shared fixtures for the authority tests + conformance corpus.

The OIDC token here is a **stand-in**: a base64 JSON blob decoded by
``demo_token_validator``. It is NOT a real JWT verifier and is deliberately kept
out of the shipped library — a real deployment injects a JWKS-backed validator.
It lives here so the corpus can exercise the OIDCVerifier binding logic
deterministically without network or crypto for the token itself.
"""

from __future__ import annotations

import base64
import json
from typing import Any

from sm_authority import (
    Identity,
    build_anchor,
    build_authority_evidence,
    build_evidence,
    sign_authority_evidence,
    sign_binding_challenge,
)
from sm_authority.evidence import OIDC, PRIOR_BINDING_KEY

ISSUER = Identity.from_seed(b"\x31" * 32)  # store assembling the evidence
OWNER = Identity.from_seed(b"\x32" * 32)   # grantor_did (owner's binding key)
PRIOR = Identity.from_seed(b"\x33" * 32)   # owner's prior / recovery key
OTHER = Identity.from_seed(b"\x34" * 32)   # unrelated party

ISS = "2026-07-28T12:00:00Z"
AT = "2026-07-29T12:00:00Z"
SUBJECT = "john@hotmail.com"
ANCHOR = build_anchor(
    method="oidc", issuer="https://login.microsoftonline.com", anchor_id="oid-abc"
)


def make_oidc_token(claims: dict[str, Any]) -> str:
    return base64.b64encode(json.dumps(claims, sort_keys=True).encode()).decode("ascii")


def demo_token_validator(token: str) -> dict[str, Any] | None:
    try:
        return json.loads(base64.b64decode(token))
    except Exception:
        return None


def prior_evidence(*, signer: Identity = PRIOR, grantor: str | None = None,
                   subject: str = SUBJECT, challenge: str = "chal-1") -> dict:
    grantor = grantor or OWNER.did
    return build_evidence(
        PRIOR_BINDING_KEY, prior_did=signer.did, challenge=challenge,
        signature=sign_binding_challenge(
            signer, subject=subject, grantor_did=grantor, challenge=challenge
        ),
    )


def oidc_evidence(*, iss: str = "https://login.microsoftonline.com",
                  oid: str = "oid-abc", nonce: str | None = "n1") -> dict:
    claims = {"iss": iss, "oid": oid}
    if nonce is not None:
        claims["nonce"] = nonce
    return build_evidence(OIDC, token=make_oidc_token(claims), nonce=nonce)


def envelope(evidence_blocks, *, subject: str = SUBJECT, anchor=None,
             grantor: str | None = None, issued_at: str = ISS,
             not_after: str = "2027-01-01T00:00:00Z", not_before: str | None = None) -> dict:
    return sign_authority_evidence(ISSUER, build_authority_evidence(
        subject=subject, anchor=anchor or ANCHOR, grantor_did=grantor or OWNER.did,
        evidence=evidence_blocks, issued_at=issued_at, not_after=not_after, not_before=not_before,
    ))
