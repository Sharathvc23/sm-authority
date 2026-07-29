"""Deterministically generate the authority/0.1 conformance corpus.

Run: ``python vectors/_generate.py``. Fixed key seeds (from tests.helpers) ⇒
stable signatures ⇒ a byte-for-byte reproducible corpus. Each vector is one JSON
file the conformance test replays through ``verify_authority_evidence`` with a
fixed verifier registry (a PriorBindingKeyVerifier trusting PRIOR, and an
OIDCVerifier over the demo token validator).
"""

from __future__ import annotations

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from sm_authority import build_evidence  # noqa: E402
from sm_authority.evidence import CIVIC, OIDC  # noqa: E402

from tests.helpers import (  # noqa: E402
    AT,
    OTHER,
    envelope,
    oidc_evidence,
    prior_evidence,
)

OUT = pathlib.Path(__file__).parent / "authority" / "0.1"
OUT.mkdir(parents=True, exist_ok=True)

vectors: list[dict] = []


def add(name, *, env, at=AT, expect, policy=None):
    v = {"name": name, "env": env, "at": at, "expect": expect}
    if policy is not None:
        v["policy"] = policy
    vectors.append(v)


# --- prior-binding-key -------------------------------------------------------
add("prior_verified", env=envelope([prior_evidence()]), expect=["VERIFIED", "ok"])
add("untrusted_prior", env=envelope([prior_evidence(signer=OTHER)]),
    expect=["REFUTED", "untrusted_prior_key"])
add("bad_prior_signature", env=envelope([prior_evidence(grantor=OTHER.did)]),
    expect=["REFUTED", "bad_prior_signature"])

# --- oidc --------------------------------------------------------------------
add("oidc_verified", env=envelope([oidc_evidence()]), expect=["VERIFIED", "ok"])
add("oidc_issuer_mismatch", env=envelope([oidc_evidence(iss="https://accounts.google.com")]),
    expect=["REFUTED", "issuer_mismatch"])
add("oidc_anchor_mismatch", env=envelope([oidc_evidence(oid="oid-someone-else")]),
    expect=["REFUTED", "anchor_mismatch"])
add("oidc_token_invalid",
    env=envelope([build_evidence(OIDC, token="%%not-base64%%", nonce="n1")]),
    expect=["REFUTED", "token_invalid"])

# --- aggregation policy ------------------------------------------------------
add("refutation_poisons",
    env=envelope([prior_evidence(), oidc_evidence(iss="https://evil.example")]),
    expect=["REFUTED", "issuer_mismatch"])
add("two_sources_verified",
    env=envelope([prior_evidence(), oidc_evidence()]),
    policy={"min_verified": 2}, expect=["VERIFIED", "ok"])
add("insufficient_min2", env=envelope([prior_evidence()]),
    policy={"min_verified": 2}, expect=["INDETERMINATE", "insufficient_evidence"])
add("unsupported_civic_alone",
    env=envelope([build_evidence(CIVIC, scheme="us-login-gov", credential="opaque")]),
    expect=["INDETERMINATE", "insufficient_evidence"])
add("required_oidc_missing", env=envelope([prior_evidence()]),
    policy={"required_types": [OIDC]}, expect=["INDETERMINATE", "required_evidence_missing"])

# --- envelope-level ----------------------------------------------------------
add("expired", env=envelope([prior_evidence()], not_after="2026-07-01T00:00:00Z"),
    expect=["REFUTED", "expired"])
add("not_yet_valid", env=envelope([prior_evidence()], issued_at="2026-08-01T00:00:00Z"),
    expect=["REFUTED", "not_yet_valid"])

_tampered = dict(envelope([prior_evidence()]))
_tampered["subject"] = "attacker@evil.example"
add("tampered_signature", env=_tampered, expect=["REFUTED", "bad_signature"])


def main() -> None:
    for old in OUT.glob("*.json"):
        old.unlink()
    for i, v in enumerate(vectors):
        (OUT / f"{i:02d}-{v['name']}.json").write_text(
            json.dumps(v, indent=2, sort_keys=True) + "\n"
        )
    print(f"wrote {len(vectors)} vectors to {OUT}")


if __name__ == "__main__":
    main()
