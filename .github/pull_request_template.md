## Summary

<!-- What does this PR do? Why? -->

## Type of change

<!-- Delete what does not apply -->

- feat: new user-facing feature
- fix: bug fix
- chore / docs / refactor / test / ci / style / perf
- BREAKING CHANGE (also use `feat!:` or `fix!:` in the title)

## Checklist

- [ ] PR **title** follows [Conventional Commits](https://www.conventionalcommits.org/) — this becomes the squash-merge commit message and is parsed by release-please.
- [ ] Changes are scoped to a single logical concern.
- [ ] I tested the change locally on at least one platform (if behavior changed).
- [ ] `pnpm-lock.yaml` is updated and committed if dependencies changed.
- [ ] Documentation (`README.md`, `CONTRIBUTING.md`, etc.) is updated where relevant.
- [ ] No secrets, tokens, signing keys, or personal data are included.

## Release impact

<!-- Fill in if your change touches `clients/apps/desktop/`. Otherwise it will NOT trigger a release. -->

- [ ] This PR is intentionally **outside** `clients/apps/desktop/` and should not bump the version.
- [ ] This PR **should** trigger a version bump (touches `clients/apps/desktop/`).
  - Expected bump: <!-- patch / minor / major -->

## Verification & narrated evidence

<!--
  Required by AGENTS.md and .agents/skills/pr-video-evidence/SKILL.md.
  Validated by the `pr-video-evidence` GitHub Actions check.
  For genuinely non-demonstrable changes, replace Recording with `Not applicable: <reason>`
  and list equivalent verification artifacts under Automated checks.
-->

### Narrated verification

- **Recording**: <!-- Playable attachment / authorized accessible link, or `Not applicable: <reason>` -->
- **Commit**: <!-- Exact 40-char verified commit SHA matching PR HEAD -->
- **Captured at**: <!-- ISO-8601 UTC timestamp, e.g. 2026-11-28T10:30:00Z -->
- **Surface / route**: <!-- e.g. clients/apps/web (/app/settings?settings=connections, /app/report) -->
- **Environment**: <!-- e.g. isolated local Next.js 16 + seeded fake-rowboat-api.mjs -->

### Demonstrated behavior

| Acceptance criterion | Timestamp | Verification |
| -------------------- | --------- | ------------ |
| <!-- Criterion -->   | 00:00     | Passed       |

### Independent engineering review

- **Reviewers dispatched**: <!-- e.g. senior-code-critic, review-changes, ponytail-review + domain specialists -->
- **Findings summary**: <!-- P0: 0, P1: 0, P2 open: 0 (all resolved / accepted), P3: 0 -->
- **Recommendation**: <!-- Approved / Changes verified -->

### Automated checks

<!-- List exact commands executed and their observed pass/fail results. -->

- [ ] `<command>` — Passed

### Known limitations

<!-- Document any unverified behavior, environmental constraints, or outstanding concerns (or `None.`). -->

## Notes for reviewers

<!-- Anything reviewers should pay extra attention to. -->
