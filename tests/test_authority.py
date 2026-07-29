"""Behavioural tests for Authority Evidence verification."""

from __future__ import annotations

import pytest

from sm_authority import (
    OIDCVerifier,
    Policy,
    PriorBindingKeyVerifier,
    build_authority_evidence,
    build_evidence,
    covers,
    verify_authority_evidence,
)
from sm_authority.evidence import CIVIC, OIDC, PRIOR_BINDING_KEY

from .helpers import (
    ANCHOR,
    AT,
    OTHER,
    OWNER,
    PRIOR,
    SUBJECT,
    demo_token_validator,
    envelope,
    oidc_evidence,
    prior_evidence,
)


def _prior_verifiers(trusted=None):
    return {PRIOR_BINDING_KEY: PriorBindingKeyVerifier(trusted or {PRIOR.did})}


def _oidc_verifiers():
    return {OIDC: OIDCVerifier(demo_token_validator)}


# --- prior-binding-key (fully offline) ---------------------------------------

def test_prior_key_verified_yields_binding():
    v = verify_authority_evidence(envelope([prior_evidence()]), _prior_verifiers(), AT)
    assert v.status == "VERIFIED", v
    assert v.binding.verified_by == ("prior_binding_key",)
    assert covers(v.binding, grantor_did=OWNER.did, subject=SUBJECT)
    assert not covers(v.binding, grantor_did=OTHER.did, subject=SUBJECT)


def test_untrusted_prior_key_refuted():
    v = verify_authority_evidence(envelope([prior_evidence()]),
                                  _prior_verifiers(trusted={OTHER.did}), AT)
    assert v.status == "REFUTED" and v.reason == "untrusted_prior_key", v


def test_prior_signature_over_wrong_grantor_refuted():
    # Signature is computed binding the challenge to OTHER's did, but the envelope
    # names OWNER as grantor — the verifier recomputes over OWNER and rejects.
    ev = prior_evidence(signer=PRIOR, grantor=OTHER.did)
    v = verify_authority_evidence(envelope([ev]), _prior_verifiers(), AT)
    assert v.status == "REFUTED" and v.reason == "bad_prior_signature", v


# --- oidc (injected validator) -----------------------------------------------

def test_oidc_verified():
    v = verify_authority_evidence(envelope([oidc_evidence()]), _oidc_verifiers(), AT)
    assert v.status == "VERIFIED", v
    assert v.binding.verified_by == ("oidc",)


def test_oidc_issuer_mismatch_refuted():
    ev = oidc_evidence(iss="https://accounts.google.com")
    v = verify_authority_evidence(envelope([ev]), _oidc_verifiers(), AT)
    assert v.status == "REFUTED" and v.reason == "issuer_mismatch", v


def test_oidc_anchor_mismatch_refuted():
    ev = oidc_evidence(oid="oid-someone-else")
    v = verify_authority_evidence(envelope([ev]), _oidc_verifiers(), AT)
    assert v.status == "REFUTED" and v.reason == "anchor_mismatch", v


def test_oidc_invalid_token_refuted():
    ev = build_evidence(OIDC, token="%%not-base64%%", nonce="n1")
    v = verify_authority_evidence(envelope([ev]), _oidc_verifiers(), AT)
    assert v.status == "REFUTED" and v.reason == "token_invalid", v


# --- aggregation policy ------------------------------------------------------

def test_refutation_poisons_the_envelope():
    verifiers = {**_prior_verifiers(), **_oidc_verifiers()}
    env = envelope([prior_evidence(), oidc_evidence(iss="https://evil.example")])
    v = verify_authority_evidence(env, verifiers, AT)
    assert v.status == "REFUTED" and v.reason == "issuer_mismatch", v


def test_insufficient_evidence_is_indeterminate():
    v = verify_authority_evidence(envelope([prior_evidence()]), _prior_verifiers(),
                                  AT, policy=Policy(min_verified=2))
    assert v.status == "INDETERMINATE" and v.reason == "insufficient_evidence", v


def test_unsupported_evidence_type_does_not_verify_alone():
    ev = build_evidence(CIVIC, scheme="us-login-gov", credential="opaque")
    v = verify_authority_evidence(envelope([ev]), _prior_verifiers(), AT)  # no civic verifier
    assert v.status == "INDETERMINATE" and v.reason == "insufficient_evidence", v
    assert v.evidence_results[0][1].reason == "unsupported_evidence_type"


def test_required_type_missing_is_indeterminate():
    # prior verifies, but policy requires an oidc verification too.
    verifiers = {**_prior_verifiers(), **_oidc_verifiers()}
    v = verify_authority_evidence(envelope([prior_evidence()]), verifiers, AT,
                                  policy=Policy(required_types=frozenset({OIDC})))
    assert v.status == "INDETERMINATE" and v.reason == "required_evidence_missing", v


# --- envelope-level checks ---------------------------------------------------

def test_expired_envelope_refuted():
    env = envelope([prior_evidence()], not_after="2026-07-01T00:00:00Z")
    v = verify_authority_evidence(env, _prior_verifiers(), AT)
    assert v.status == "REFUTED" and v.reason == "expired", v


def test_not_yet_valid_envelope_refuted():
    env = envelope([prior_evidence()], issued_at="2026-08-01T00:00:00Z")
    v = verify_authority_evidence(env, _prior_verifiers(), AT)
    assert v.status == "REFUTED" and v.reason == "not_yet_valid", v


def test_tampered_envelope_refuted_on_signature():
    env = dict(envelope([prior_evidence()]))
    env["subject"] = "attacker@evil.example"  # invalidates issuer signature
    v = verify_authority_evidence(env, _prior_verifiers(), AT)
    assert v.status == "REFUTED" and v.reason == "bad_signature", v


def test_missing_required_field_is_malformed():
    env = dict(envelope([prior_evidence()]))
    del env["anchor"]  # structure check runs before signature
    v = verify_authority_evidence(env, _prior_verifiers(), AT)
    assert v.status == "REFUTED" and v.reason == "malformed", v
    assert "anchor" in v.detail


def test_unknown_version_is_malformed():
    env = dict(envelope([prior_evidence()]))
    env["version"] = "authority/9.9"
    v = verify_authority_evidence(env, _prior_verifiers(), AT)
    assert v.status == "REFUTED" and v.reason == "malformed", v


# --- construction-time validation --------------------------------------------

def test_build_evidence_requires_profile_claims():
    with pytest.raises(ValueError):
        build_evidence(OIDC)  # missing token


def test_build_envelope_requires_evidence():
    with pytest.raises(ValueError):
        build_authority_evidence(subject=SUBJECT, anchor=ANCHOR, grantor_did=OWNER.did,
                                 evidence=[], issued_at="2026-07-28T12:00:00Z",
                                 not_after="2027-01-01T00:00:00Z")
