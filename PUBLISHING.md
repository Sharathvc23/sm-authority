# Publishing sm-authority to PyPI

`sm-authority` publishes via **PyPI Trusted Publishing** — no API tokens. You tell
PyPI once that this repo's `release.yml` workflow may publish; after that, pushing
a version tag builds and uploads automatically.

## One-time setup (≈5 minutes — this is the part only you can do)

1. Sign in to PyPI (the same account that publishes `sm-arp` / `sm-bridge`).
2. Go to **https://pypi.org/manage/account/publishing/** → "Add a pending
   publisher" (use *pending*, because the `sm-authority` project doesn't exist on
   PyPI yet — the first publish creates it).
3. Fill the form with **exactly** these values:

   | Field | Value |
   |-------|-------|
   | PyPI Project Name | `sm-authority` |
   | Owner | `Sharathvc23` |
   | Repository name | `sm-authority` |
   | **Workflow name** | `release.yml`  ← just the filename |
   | Environment name | *(leave blank)* |

That's it. No secret is created or stored anywhere.

## Releasing (every time, after setup)

```bash
# bump `version` in pyproject.toml + update CHANGELOG, commit, then:
git tag v0.1.0
git push origin v0.1.0
```

The `release` workflow builds the sdist + wheel, runs `twine check`, and uploads
to PyPI over OIDC. Watch it under the repo's **Actions** tab. Within a minute,
`pip install sm-authority` works for everyone.

## Notes

- The tag (`v0.1.0`) and `version` in `pyproject.toml` must match.
- Dry run anytime, no upload: `python -m build && python -m twine check dist/*`.
- The wheel ships only the `sm_authority/` package; the spec, vectors, and
  examples are not part of the installable distribution.
