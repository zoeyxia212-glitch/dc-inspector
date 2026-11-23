# Contributing

## Branching model

| Branch | Purpose | Who writes to it |
|---|---|---|
| `main` | Released, stable code. Every commit is deployable. | Pull requests from `dev` only |
| `dev` | Integration of finished features. | Pull requests from `feature/*` |
| `feature/<short-name>` | One feature or fix, branched from `dev`. | You |
| `staging` | *(added when there is a cloud deployment)* pre-production environment | — |

`main` and `dev` are protected: changes go through a pull request, the `test` and `docker` checks
must pass, force pushes and deletion are blocked. There is no `test` branch — tests run in CI on
every pull request.

```bash
git switch dev && git pull
git switch -c feature/rack-power-alerts
# ... work, commit ...
git push -u origin feature/rack-power-alerts      # open a PR into dev
```

## Local checks

```bash
make install    # pip install -e ".[dev]"
make check      # ruff lint + format check, mypy, pytest with the coverage gate
pre-commit install   # optional: run lint/format/type checks on every commit
```

CI runs the same commands, plus compatibility tests on Python 3.10–3.13, CodeQL, pip-audit and a
container image scan.

## Commit messages

[Conventional Commits](https://www.conventionalcommits.org/): `type: summary` in the imperative,
for example `feat: group host_down alerts by rack`, `fix: resolve alerts when ping data is absent`.
Types: `feat`, `fix`, `perf`, `refactor`, `test`, `docs`, `ci`, `chore`.

## Pull requests

- Small and focused; describe what changed and how it was tested (the template asks).
- New behaviour needs tests; every bug fix needs a regression test.
- User-visible changes get a line in `CHANGELOG.md` under **Unreleased**.
- Schema changes are added as a new migration in `inspector/db.py` — never edit a released one.

## Releases

1. On `dev`: move **Unreleased** in `CHANGELOG.md` to a new version section, bump
   `inspector/__version__` (Semantic Versioning).
2. Pull request `dev` → `main`; merge when green.
3. Tag `main`: `git tag v2.1.0 && git push origin v2.1.0`. The release workflow verifies the tag
   matches the version, publishes `ghcr.io/zoeyxia212-glitch/dc-inspector:2.1.0` with an SBOM, and
   creates the GitHub Release from the changelog.
