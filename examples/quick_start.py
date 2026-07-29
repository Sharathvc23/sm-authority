# SPDX-License-Identifier: MIT
"""Establish O1 with a recovery-key attestation, verify it, and show a tamper fail.

Run: python examples/quick_start.py

Actually run this before publishing — a README snippet that never executes is
exactly how a stale example ships.
"""

from __future__ import annotations

from sm_authority import (
    PRIOR_BINDING_KEY,
    Identity,
    PriorBindingKeyVerifier,
    build_anchor,
    build_authority_evidence,
    build_evidence,
    covers,
    sign_authority_evidence,
    sign_binding_challenge,
    verify_authority_evidence,
)


def main() -> None:
    issuer, owner, recovery = Identity.generate(), Identity.generate(), Identity.generate()
    subject = "john@hotmail.com"
    challenge = "c1"

    anchor = build_anchor(
        method="oidc", issuer="https://login.microsoftonline.com", anchor_id="oid-abc"
    )
    evidence = build_evidence(
        PRIOR_BINDING_KEY, prior_did=recovery.did, challenge=challenge,
        signature=sign_binding_challenge(
            recovery, subject=subject, grantor_did=owner.did, challenge=challenge
        ),
    )
    env = sign_authority_evidence(issuer, build_authority_evidence(
        subject=subject, anchor=anchor, grantor_did=owner.did, evidence=[evidence],
        issued_at="2026-07-28T12:00:00Z", not_after="2027-01-01T00:00:00Z",
    ))

    verifiers = {PRIOR_BINDING_KEY: PriorBindingKeyVerifier(trusted_prior_dids={recovery.did})}
    at = "2026-07-29T12:00:00Z"

    v = verify_authority_evidence(env, verifiers, at)
    o1_ok = covers(v.binding, grantor_did=owner.did, subject=subject)
    print(f"verify:   {v.status}")
    print(f"O1 owner→subject: {'PASS' if o1_ok else 'FAIL'}")

    tampered = dict(env)
    tampered["subject"] = "attacker@evil.example"
    vt = verify_authority_evidence(tampered, verifiers, at)
    print(f"tampered: {vt.status} ({vt.reason})  <- REFUTED as expected")


if __name__ == "__main__":
    main()
