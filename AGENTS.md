# Agent instructions

Sigrid customer and system are in `.sigrid/profile.md`.

## Guardrails

Principles: single responsibility, self-documenting code, simple control flow.
Before reporting done:
1. Run Sigrid guardrails_quality_check on changed production code (skip tests, docs, generated), with customer and system from `.sigrid/profile.md`.
2. Fix all maintainability findings judged against the principles — skip only if the code already honors them; say which and why.
3. Security findings: fix if contained, otherwise flag to user.

Before pushing code or opening a pull request, run the architecture-drift skill.
If it reports drift, fix it, or explain why the new dependency is intended.

## Boundaries

- Never change files under `.github/`.
- Never push to `main`, never force-push, never merge.
- Keep changes behaviour-preserving (move, extract, rename); leave public APIs and tests as they are.
- Do not run the full build or test suite; the pull request checks do that.
