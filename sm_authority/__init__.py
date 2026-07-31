"""sm-authority — the Common Authority Evidence envelope.

Establishes sm-dat SPEC O1 out of band: that a grant's ``grantor_did`` (and the
human-readable ``subject`` locator) is controlled by the real owner. One
interoperable envelope over many authority sources (OIDC, platform install,
domain control, DID, civic, prior/recovery key), verified through an injected,
three-valued (VERIFIED/REFUTED/INDETERMINATE) framework. A VERIFIED result is an
:class:`AuthorityBinding` — the locator↔anchor↔grantor_did record. See SPEC.md.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError as _PackageNotFoundError
from importlib.metadata import version as _dist_version

from sm_arp import Identity  # re-export the shared identity primitive

from .evidence import (
    AUTHORITY_VERSION,
    CIVIC,
    DID_CONTROL,
    DOMAIN_CONTROL,
    EVIDENCE_TYPES,
    OIDC,
    PLATFORM_INSTALL,
    PRIOR_BINDING_KEY,
    PROFILE_REQUIRED_CLAIMS,
    binding_challenge_bytes,
    build_anchor,
    build_authority_evidence,
    build_evidence,
    did_key_jwk_thumbprint,
    oidc_binding_nonce,
    sign_authority_evidence,
    sign_binding_challenge,
    verify_envelope_signature,
)
from .verifiers import OIDCVerifier, PriorBindingKeyVerifier
from .verify import (
    INDETERMINATE,
    REFUTED,
    VERIFIED,
    AuthorityBinding,
    AuthorityVerdict,
    EvidenceVerdict,
    EvidenceVerifier,
    Policy,
    covers,
    verify_authority_evidence,
)

# Derived from installed distribution metadata, never hand-maintained. A literal
# here is a second copy of pyproject's ``version`` with nothing comparing them:
# the 0.1.0 wheel shipped ``__version__ == "0.0.1"`` against correct dist metadata
# for exactly that reason, so a consumer's runtime version assertion read the
# wrong number and could not detect the vulnerable release (sm-authority#2).
try:  # pragma: no cover - trivial branch, both sides asserted in tests
    __version__ = _dist_version("sm-authority")
except _PackageNotFoundError:  # running from a source tree, not installed
    __version__ = "0.0.0.dev0"

__all__ = [
    "AUTHORITY_VERSION",
    "Identity",
    # evidence types
    "OIDC",
    "PLATFORM_INSTALL",
    "DOMAIN_CONTROL",
    "DID_CONTROL",
    "CIVIC",
    "PRIOR_BINDING_KEY",
    "EVIDENCE_TYPES",
    "PROFILE_REQUIRED_CLAIMS",
    # envelope
    "build_anchor",
    "build_evidence",
    "build_authority_evidence",
    "sign_authority_evidence",
    "verify_envelope_signature",
    "binding_challenge_bytes",
    "sign_binding_challenge",
    "oidc_binding_nonce",
    "did_key_jwk_thumbprint",
    # verification
    "verify_authority_evidence",
    "covers",
    "Policy",
    "AuthorityVerdict",
    "AuthorityBinding",
    "EvidenceVerdict",
    "EvidenceVerifier",
    "VERIFIED",
    "REFUTED",
    "INDETERMINATE",
    # reference verifiers
    "PriorBindingKeyVerifier",
    "OIDCVerifier",
]
