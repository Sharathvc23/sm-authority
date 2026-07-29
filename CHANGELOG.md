# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and this project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0]

### Added
- Initial working-draft release of `sm-authority`.
- Common Authority Evidence envelope binding a subject locator → durable anchor →
  `grantor_did`, with six evidence profiles (`oidc`, `platform_install`,
  `domain_control`, `did_control`, `civic`, `prior_binding_key`).
- Three-valued verification framework (`verify_authority_evidence`) with injected
  per-type verifiers and a refutation-poisons aggregation policy; yields an
  `AuthorityBinding` and a `covers()` check that discharges sm-dat SPEC O1.
- Reference verifiers: fully-offline `PriorBindingKeyVerifier`, and `OIDCVerifier`
  with the JWT/JWKS validator injected.
- Deterministic conformance corpus (`vectors/authority/0.1/`) and `SPEC.md`.
