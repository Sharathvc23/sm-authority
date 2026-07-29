"""Three-valued verification of an Authority Evidence envelope.

VERIFIED / REFUTED / INDETERMINATE — the same fail-closed discipline as sm-dat.
Each evidence block is run through an injected per-type verifier; the framework
here does no crypto and knows no provider, exactly like sm-bridge's trust-profile
plugin seam. A verifier is *injected*, never a silent default, so an unsupported
evidence type is INDETERMINATE, never ignored.

Aggregation policy (deliberately not sm-dat's strict "any-INDETERMINATE-blocks"):

  - A single **REFUTED** block poisons the whole envelope → REFUTED. A refuted
    proof is evidence the claim is *false*, not merely unproven.
  - Otherwise the envelope is **VERIFIED** iff at least ``policy.min_verified``
    blocks VERIFIED (and any ``policy.required_types`` are among them). Extra
    INDETERMINATE/unsupported blocks neither help nor block — they simply do not
    count. This is right for a multi-source model: you need *enough* positive
    proof; an unverifiable extra should not demote a solid verification, but a
    refutation must always win.
  - Otherwise INDETERMINATE.

A VERIFIED verdict yields an :class:`AuthorityBinding` — the established
locator↔anchor↔grantor_did record a registry checks a binding grant against.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol, runtime_checkable

from .evidence import verify_envelope_signature

VERIFIED = "VERIFIED"
REFUTED = "REFUTED"
INDETERMINATE = "INDETERMINATE"

_REQUIRED = ("version", "subject", "anchor", "grantor_did", "evidence",
             "issued_at", "not_before", "not_after", "issuer_did", "signature")


@dataclass(frozen=True)
class EvidenceVerdict:
    """One evidence block's verdict from its verifier."""
    status: str            # VERIFIED | REFUTED | INDETERMINATE
    reason: str = "ok"
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.status == VERIFIED


@dataclass(frozen=True)
class AuthorityBinding:
    """The established locator↔anchor↔grantor_did record — the output of a
    VERIFIED envelope, and the record a registry checks a binding grant against."""
    subject: str
    anchor: dict[str, str]
    grantor_did: str
    verified_by: tuple[str, ...]
    issued_at: str
    not_after: str


@dataclass(frozen=True)
class AuthorityVerdict:
    status: str
    reason: str
    binding: AuthorityBinding | None = None
    evidence_results: tuple[tuple[str, EvidenceVerdict], ...] = ()
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.status == VERIFIED


@runtime_checkable
class EvidenceVerifier(Protocol):
    """Verifies one evidence block against its envelope. Injected per type."""

    def verify(self, block: dict[str, Any], env: dict[str, Any]) -> EvidenceVerdict: ...


@dataclass(frozen=True)
class Policy:
    min_verified: int = 1
    required_types: frozenset[str] = field(default_factory=frozenset)


def _t(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(UTC)


def verify_authority_evidence(
    env: dict[str, Any],
    verifiers: dict[str, EvidenceVerifier],
    at: str,
    *,
    policy: Policy | None = None,
) -> AuthorityVerdict:
    """Verify an Authority Evidence envelope as of ``at``. ``verifiers`` maps an
    evidence ``type`` to its :class:`EvidenceVerifier`."""
    policy = policy or Policy()

    # 1. structure
    for f in _REQUIRED:
        if f not in env:
            return AuthorityVerdict(REFUTED, "malformed", detail=f"missing {f!r}")
    if env["version"] != "authority/0.1":
        return AuthorityVerdict(REFUTED, "malformed", detail=f"version {env['version']!r}")

    # 2. issuer signature — integrity of the assembled envelope
    if not verify_envelope_signature(env):
        return AuthorityVerdict(REFUTED, "bad_signature")

    # 3. temporal
    t = _t(at)
    if t < _t(env["not_before"]):
        return AuthorityVerdict(REFUTED, "not_yet_valid")
    if t > _t(env["not_after"]):
        return AuthorityVerdict(REFUTED, "expired")

    # 4. per-evidence verification
    results: list[tuple[str, EvidenceVerdict]] = []
    verified_types: set[str] = set()
    refuted: EvidenceVerdict | None = None
    for block in env["evidence"]:
        t_ = block.get("type")
        verifier = verifiers.get(t_)
        if verifier is None:
            vr = EvidenceVerdict(INDETERMINATE, "unsupported_evidence_type", str(t_))
        else:
            try:
                vr = verifier.verify(block, env)
            except Exception as e:  # noqa: BLE001 — a broken verifier must not pass
                vr = EvidenceVerdict(INDETERMINATE, "verifier_error", str(e))
        results.append((str(t_), vr))
        if vr.status == REFUTED and refuted is None:
            refuted = vr
        elif vr.status == VERIFIED:
            verified_types.add(str(t_))

    res = tuple(results)

    # 5. aggregate — refutation poisons; else require enough positive proof.
    if refuted is not None:
        return AuthorityVerdict(REFUTED, refuted.reason, None, res)
    missing = policy.required_types - verified_types
    if missing:
        return AuthorityVerdict(INDETERMINATE, "required_evidence_missing",
                                None, res)
    if len(verified_types) < policy.min_verified:
        return AuthorityVerdict(INDETERMINATE, "insufficient_evidence", None, res)

    binding = AuthorityBinding(
        subject=env["subject"], anchor=env["anchor"], grantor_did=env["grantor_did"],
        verified_by=tuple(sorted(verified_types)),
        issued_at=env["issued_at"], not_after=env["not_after"],
    )
    return AuthorityVerdict(VERIFIED, "ok", binding, res)


def covers(binding: AuthorityBinding | None, *, grantor_did: str, subject: str) -> bool:
    """True iff ``binding`` establishes that ``grantor_did`` controls ``subject``.
    The cross-check a registry runs: a binding grant's signer (``grantor_did``) and
    ``binding_subject`` MUST match a VERIFIED AuthorityBinding — this is where O1 is
    discharged before a grant is honoured."""
    return (
        binding is not None
        and binding.grantor_did == grantor_did
        and binding.subject == subject
    )
