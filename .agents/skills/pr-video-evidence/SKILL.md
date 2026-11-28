---
name: pr-video-evidence
description: >
  Repository-specific adaptation of the mandatory pr-video-evidence skill for
  PlaybookMediaLLC/oppulence (Rowboat / Oppulence monorepo). Integrates
  independent engineering review, isolated application verification, Kokoro-82M
  human-sounding narrated Playwright capture, and GitHub Actions validation
  with this repository's DevX infrastructure.
---

# PR Video Evidence — `PlaybookMediaLLC/oppulence` Adaptation

This document is the repository-specific operational guide for
`PlaybookMediaLLC/oppulence` (`clients/apps/web`, `clients/apps/desktop`,
`server`, and root DevX tooling). Policy triggers live in `AGENTS.md`;
follow the reusable `pr-video-evidence` skill for general narration, review,
and feedback-loop principles.

## 1. Repository Surface & DevX Mapping

Reuse this repository's real application harnesses and quality gates instead of
creating parallel mock interfaces:

| Surface                              | Application & Isolated Harness                                                                                                                                                    | Mandatory Quality Gates                                                                                               |
| ------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| **Web / BFF (`clients/apps/web`)**   | Next.js 16 App Router (`npm run build && npm run start`) against deterministic `clients/apps/web/e2e/fake-rowboat-api.mjs` + Playwright (`clients/apps/web/playwright.config.ts`) | `npm run verify:fast` (pre-push) / `npm run verify` / `npm run test:e2e`                                              |
| **Desktop (`clients/apps/desktop`)** | Electron desktop (`cd clients/apps/desktop && npm run deps`) + CDP capture (`scripts/rowboat-desktop-smoke.sh` / `make smoke-desktop`)                                            | `cd clients/apps/desktop && pnpm verify` (Electron Architecture Gauntlet)                                             |
| **Backend (`server`)**               | Go API (`scripts/rowboat-api-local-verify.sh`, `make api-up`) — demonstrate via narrated terminal, API responses, DB assertions, or test runs                                     | `cd server && make verify`                                                                                            |
| **Root tooling / CI**                | Root scripts, workflows, docs, and `scripts/devx/video-evidence/`                                                                                                                 | `pnpm exec prettier --check <changed-files>`, `pnpm run test:video-evidence`, `pnpm run devx:video-evidence:validate` |

### Strict Separation from Marketing Capture

- Keep `clients/apps/web/scripts/capture-marketing-screenshots.ts` (`make www-capture-screenshots`) untouched and dedicated to marketing imagery.
- Engineering verification recordings use the dedicated `engineering-verification` profile (`pnpm run devx:video-evidence`), with no marketing duration caps, branding animations, background music, or promotional copy.

## 2. Independent Engineering Review Roster

Before generating the final narrated video, dispatch independent read-only
reviewers (the implementing agent coordinates remediation and must never be the
sole reviewer; review-only subagents must not recursively initiate this
workflow):

1. **Core reviewers (mandatory for every substantive change)**:
   - **Senior Engineering Critic (`senior-code-critic`)**: Correctness, architectural integrity, security, error handling, race conditions, maintainability, and test quality.
   - **Structural & Blast-Radius Reviewer (`review-changes`)**: Use `code-review-graph` MCP when available; otherwise explicit source-based impact analysis — never fabricate graph output.
   - **Simplicity & Production-Quality Reviewer (`ponytail-review`)**: Evaluate in priority order: correctness → safety → behavior under load → adequate testing → performance → simplicity.
2. **Domain specialists (dispatch based on touched surfaces)**:
   - `clients/apps/web`: Next.js App Router / React lifecycle / BFF cookie & redirect safety / growth standard (`WEB029`–`WEB031`), plus UI/a11y review for visual changes.
   - `server`: OpenAPI/Zod contract integrity, authorization, tenant isolation, billing/financial minor-unit invariants, migrations, and transaction boundaries.
   - `clients/apps/desktop`: Electron IPC Zod contracts, contextBridge/preload security, fuses, and Electron Architecture Gauntlet compliance.
   - `.github/workflows/` & `scripts/`: Least-privilege permissions, zero shell-injection from untrusted PR fields, and secret hygiene.

Resolve all **P0** and **P1** findings (and **P2** findings unless explicitly
accepted by an authorized human reviewer), rerun tests, and obtain independent
re-review verification before capturing the final video.

## 3. Running `devx:video-evidence`

### Prerequisites

- **FFmpeg** (`ffmpeg` + `ffprobe` with `libx264`, `aac`, `libass` / `libfreetype`)
- **Kokoro-82M local neural TTS** (`python3` + `kokoro-onnx` + `soundfile` + `numpy`; SHA-256-verified model files cached under `~/.cache/kokoro-onnx/kokoro-v1.0.onnx` and `voices-v1.0.bin`, auto-downloadable via `--download-tts` or `KOKORO_MODEL_DIR`)
- **Playwright Chromium** (installed via `clients/apps/web` or `/usr/bin/google-chrome`)

### Commands

```bash
# 1. Run a local dry-run capture (draft mode before review-report.json exists)
pnpm run devx:video-evidence -- --scenario rowboat-www-connectors --voice am_michael --draft

# 2. Run the final verification capture with a completed independent review report
pnpm run devx:video-evidence -- \
  --scenario rowboat-www-connectors \
  --voice am_michael \
  --review-report path/to/review-report.json \
  --checks path/to/automated-checks.json

# 3. Validate a generated manifest against the current HEAD commit
pnpm run devx:video-evidence:validate -- \
  --manifest .pr-video-evidence/<run-id>/evidence-manifest.json \
  --expected-sha "$(git rev-parse HEAD)"

# 4. Validate a pull request description body (same check run in GitHub Actions)
pnpm run devx:video-evidence:validate -- \
  --pr-body-file /tmp/pr-body.md \
  --head-sha "$(git rev-parse HEAD)"

# 5. Run unit tests for the video-evidence pipeline and validator
pnpm run test:video-evidence
```

To add a new verification scenario for another workflow, create a scenario
module under `scripts/devx/video-evidence/scenarios/` and register it in
`SCENARIOS` inside `scripts/devx/video-evidence/cli.mjs`.

### Human-Sounding Narration Standard

- Default TTS engine: **Kokoro-82M (`kokoro-onnx`)** local neural TTS (`--voice am_michael`, `af_heart`, or `af_bella`, `--speed 0.98`).
- Never ship robotic formant voices (`espeak`, `espeak-ng`, `flite`, `festival`, `pico2wave`) as completed narrated evidence.
- Write conversational, senior-engineer phrasing: natural contractions, short crisp sentences (10–20 words), clean pronunciation of acronyms, natural breath pauses (`140 ms` lead-in, `190 ms` between sentences, `340 ms` beat tail), and `-16 LUFS` loudness normalization (`-1.5 dBTP` true peak).
- Describe **observed behavior only** synchronized with active cursor movements, click indicators, element bounding boxes, restrained zooms, and burned-in (1920 × 1080 `.ass`) + `.srt`/`.vtt` captions.

## 4. Artifact Storage & Repository Hygiene

- All generated artifacts are written under `.pr-video-evidence/<run-id>/` (ignored via `.gitignore`, `.dockerignore`, and `.prettierignore`):
  - `demo.mp4` — final 1920 × 1080 @ 30 fps H.264/AAC narrated MP4 with burned-in captions
  - `raw/` — unmodified per-beat capture segments
  - `audio/` — per-beat Kokoro WAV narration files & `narration-timings.json`
  - `captions.ass`, `captions.srt`, `captions.vtt`, `transcript.txt`
  - `keyframes/beat-*.png` — extracted inspection frames for every beat
  - `trace.zip` — Playwright trace
  - `review-report.json` — consolidated independent engineering review record (copied when `--review-report` is supplied)
  - `evidence-manifest.json` — strictly validated metadata manifest
  - `pr-evidence.md` — ready-to-paste PR description summary block
- **Never** commit binary video/audio/trace artifacts to git. `cli.mjs` rejects `--out-dir` targets inside the repository outside `.pr-video-evidence/`.
- **Never** expose real credentials, tokens, financial accounts, or customer data in recordings, transcripts, manifests, or PR bodies.

## 5. GitHub Actions Verification Check (`pr-video-evidence`)

`.github/workflows/pr-video-evidence.yml` runs the `pr-video-evidence` check on
every pull request (`opened`, `edited`, `synchronize`, `reopened`,
`ready_for_review`), validating:

1. Evidence availability (accessible HTTPS link or playable attachment reference — never local paths — or explicit substantive `Not applicable: <reason>` with equivalent verification checks).
2. Exact commit SHA freshness (matches `pull_request.head.sha`).
3. Required metadata (ISO-8601 capture timestamp, surface/route, environment, demonstrated behavior table with valid timestamps and passing status, independent engineering review with `P0: 0`, `P1: 0`, approved recommendation, and known limitations).
4. Passing automated check results (checked items, zero failed/skipped checks, zero exposed secrets).

Automated dependency/release bot PRs (`dependabot[bot]`, `release-please[bot]`)
run the validator unit tests and report an explicit automated-PR exemption in
the job summary so enabling `pr-video-evidence` as a required branch protection
rule will not stall automated maintenance PRs.

This check is prepared for use as a required GitHub branch protection rule once
validated and explicitly approved by a repository maintainer.
