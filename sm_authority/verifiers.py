"""Reference evidence verifiers.

Two are shipped:

  - :class:`PriorBindingKeyVerifier` — fully offline (Ed25519 via sm-arp): a
    prior/recovery key vouches that ``grantor_did`` now controls ``subject``. This
    is the migration & recovery source, and it needs no network, so it is the
    verifier the conformance corpus leans on.

  - :class:`OIDCVerifier` — the framework for an identity-provider token, with the
    JWT/JWKS crypto **injected** as a ``token_validator`` so the core stays
    zero-dependency. The package intentionally ships **no** token validator: a
    real deployment injects one that fetches the issuer's JWKS and verifies the
    signature, audience, nonce and expiry. A validator returning ``None`` is a
    REFUTED token; one that raises is INDETERMINATE — never a silent pass.

Verifiers for ``platform_install`` / ``domain_control`` / ``civic`` follow the
same injected shape and are left to their providers.
"""

from __future__ import annotations

import base64
from collections.abc import Callable
from typing import Any

from sm_arp import pubkey_from_did

from .evidence import binding_challenge_bytes
from .verify import INDETERMINATE, REFUTED, VERIFIED, EvidenceVerdict


class PriorBindingKeyVerifier:
    """A prior/recovery key attests ``grantor_did`` controls ``subject`` by signing
    :func:`binding_challenge_bytes`. Optionally restrict to a set of trusted prior
    DIDs (the owner's recovery delegates); an untrusted signer is REFUTED, not
    silently accepted."""

    def __init__(self, trusted_prior_dids: set[str] | None = None):
        self._trusted = trusted_prior_dids

    def verify(self, block: dict[str, Any], env: dict[str, Any]) -> EvidenceVerdict:
        c = block.get("claims") or {}
        prior_did, sig, challenge = c.get("prior_did"), c.get("signature"), c.get("challenge")
        if not (prior_did and sig and challenge):
            return EvidenceVerdict(INDETERMINATE, "malformed_evidence")
        if self._trusted is not None and prior_did not in self._trusted:
            return EvidenceVerdict(REFUTED, "untrusted_prior_key", str(prior_did))
        msg = binding_challenge_bytes(env["subject"], env["grantor_did"], challenge)
        try:
            pubkey_from_did(prior_did).verify(base64.b64decode(sig), msg)
        except Exception:  # noqa: BLE001 — an invalid signature is a refutation
            return EvidenceVerdict(REFUTED, "bad_prior_signature")
        return EvidenceVerdict(VERIFIED, "ok")


class OIDCVerifier:
    """Verifies an ``oidc`` block binds to the envelope's anchor. JWT verification
    is injected: ``token_validator(token) -> claims | None`` (None ⇒ invalid).
    The verifier checks the *binding* — issuer, subject/oid, and nonce — against
    the envelope anchor, which is the part specific to this envelope."""

    def __init__(self, token_validator: Callable[[str], dict[str, Any] | None]):
        self._validate = token_validator

    def verify(self, block: dict[str, Any], env: dict[str, Any]) -> EvidenceVerdict:
        c = block.get("claims") or {}
        token = c.get("token")
        anchor = env.get("anchor") or {}
        if not token:
            return EvidenceVerdict(INDETERMINATE, "malformed_evidence")
        try:
            claims = self._validate(token)
        except Exception as e:  # noqa: BLE001 — a broken validator must not pass
            return EvidenceVerdict(INDETERMINATE, "validator_error", str(e))
        if claims is None:
            return EvidenceVerdict(REFUTED, "token_invalid")
        if claims.get("iss") != anchor.get("issuer"):
            return EvidenceVerdict(REFUTED, "issuer_mismatch")
        subject_id = claims.get("oid") or claims.get("sub")
        if subject_id != anchor.get("id"):
            return EvidenceVerdict(REFUTED, "anchor_mismatch")
        nonce = c.get("nonce")
        if nonce is not None and claims.get("nonce") != nonce:
            return EvidenceVerdict(REFUTED, "nonce_mismatch")
        return EvidenceVerdict(VERIFIED, "ok")
