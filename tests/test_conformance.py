"""Replay the authority/0.1 conformance corpus against the reference verifier.

Each JSON vector pins an expected (status, reason). The verifier registry is
fixed: a PriorBindingKeyVerifier trusting PRIOR, and an OIDCVerifier over the
demo token validator (a stand-in — see tests/helpers.py). Regenerate with
``python vectors/_generate.py``.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from sm_authority import (
    OIDCVerifier,
    Policy,
    PriorBindingKeyVerifier,
    verify_authority_evidence,
)
from sm_authority.evidence import OIDC, PRIOR_BINDING_KEY

from .helpers import PRIOR, demo_token_validator

VEC = pathlib.Path(__file__).parent.parent / "vectors" / "authority" / "0.1"
FILES = sorted(VEC.glob("*.json"))

VERIFIERS = {
    PRIOR_BINDING_KEY: PriorBindingKeyVerifier({PRIOR.did}),
    OIDC: OIDCVerifier(demo_token_validator),
}


@pytest.mark.parametrize("path", FILES, ids=[p.stem for p in FILES])
def test_vector(path):
    v = json.loads(path.read_text())
    want_status, want_reason = v["expect"]
    p = v.get("policy") or {}
    policy = Policy(
        min_verified=p.get("min_verified", 1),
        required_types=frozenset(p.get("required_types", [])),
    )
    verdict = verify_authority_evidence(v["env"], VERIFIERS, v["at"], policy=policy)
    assert verdict.status == want_status, \
        f"{path.stem}: status {verdict.status} != {want_status} ({verdict.reason})"
    assert verdict.reason == want_reason, \
        f"{path.stem}: reason {verdict.reason!r} != {want_reason!r}"


def test_corpus_nonempty():
    assert FILES, "no conformance vectors — run vectors/_generate.py"
