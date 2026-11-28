import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { parseCliArgs } from "../cli.mjs";
import { buildCaptionCues, formatAssTime, parseVolumedetect, wrapTwoLines } from "../compose.mjs";
import {
  extractField,
  renderPrEvidenceMarkdown,
  validateEvidenceManifest,
  validatePrEvidenceMarkdown,
} from "../schema.mjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, "../../../..");
const VALIDATE_CLI = path.join(__dirname, "../validate-cli.mjs");

const VALID_SHA = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678";
const OTHER_SHA = "ffffffffffffffffffffffffffffffffffffffff";
const VALID_HASH = "0".repeat(64);

function makeValidManifest(overrides = {}) {
  return {
    schemaVersion: 1,
    profile: "engineering-verification",
    applicable: true,
    repository: "PlaybookMediaLLC/oppulence",
    branch: "feat/pr-video-evidence-workflow",
    commitSha: VALID_SHA,
    pullRequestNumber: 817,
    capturedAt: "2026-11-28T10:30:00Z",
    app: "apps/rowboat-www",
    routes: ["/app/settings?settings=connections", "/app/report"],
    testEnvironment: "Isolated Next.js 16 + seeded fake-rowboat-api.mjs",
    acceptanceCriteria: [
      {
        criterion: "Connect Google completes OAuth claim and renders Active/Healthy",
        timestamp: "00:12",
        status: "passed",
        assertion: "Verified status='Connected.' and consumedTickets=['ticket-1']",
      },
    ],
    automatedChecks: [
      {
        command: "pnpm run test:video-evidence",
        exitCode: 0,
        status: "passed",
        summary: "all assertions passed",
      },
    ],
    reviewReport: {
      reviewers: ["senior-code-critic", "review-changes", "ponytail-review"],
      p0Count: 0,
      p1Count: 0,
      p2OpenCount: 0,
      p3Count: 1,
      recommendation: "Approved",
    },
    video: {
      codec: "h264",
      pixelFormat: "yuv420p",
      width: 1920,
      height: 1080,
      fps: 30,
      audioCodec: "aac",
      audioSampleRate: 48000,
      durationSec: 52.4,
      fileSizeBytes: 8_400_000,
      sha256: VALID_HASH,
      audioAudible: true,
      audioClipping: false,
      ttsProvider: "kokoro-onnx",
      ttsVoice: "am_michael",
    },
    artifacts: {
      finalVideo: "demo.mp4",
      captionsSrt: "captions.srt",
      captionsVtt: "captions.vtt",
      transcript: "transcript.txt",
      trace: "trace.zip",
    },
    limitations: ["Captured against deterministic fake-rowboat-api.mjs."],
    ...overrides,
  };
}

function makeValidPrBody(sha = VALID_SHA) {
  return renderPrEvidenceMarkdown(makeValidManifest({ commitSha: sha }));
}

test("validateEvidenceManifest accepts a complete, fresh manifest", () => {
  const result = validateEvidenceManifest(makeValidManifest(), { expectedSha: VALID_SHA });
  assert.equal(result.ok, true, `Unexpected errors: ${result.errors.join("; ")}`);
  assert.equal(result.errors.length, 0);
});

test("validateEvidenceManifest rejects stale commit SHA", () => {
  const result = validateEvidenceManifest(makeValidManifest(), { expectedSha: OTHER_SHA });
  assert.equal(result.ok, false);
  assert.ok(result.errors.some((e) => /Stale evidence/i.test(e)));
});

test("validateEvidenceManifest rejects robotic TTS variants, silent audio, and clipping", () => {
  for (const engine of ["espeak", "espeak-ng", "ESPEAK", "flite", "festival"]) {
    const manifest = makeValidManifest({
      video: {
        ...makeValidManifest().video,
        ttsProvider: engine,
        audioAudible: false,
        audioClipping: true,
      },
    });
    const result = validateEvidenceManifest(manifest);
    assert.equal(result.ok, false, `Expected ${engine} to be rejected`);
    assert.ok(result.errors.some((e) => /Robotic formant TTS/i.test(e)));
    assert.ok(result.errors.some((e) => /audioAudible/i.test(e)));
    assert.ok(result.errors.some((e) => /audioClipping/i.test(e)));
  }
});

test("validateEvidenceManifest rejects pending review placeholders, non-approvals, NaN/negative counts, and unaccepted P2", () => {
  const pending = validateEvidenceManifest(
    makeValidManifest({
      reviewReport: {
        reviewers: ["pending-independent-review"],
        p0Count: 0,
        p1Count: 0,
        p2OpenCount: 0,
        recommendation: "Pending independent engineering review attachment",
      },
    }),
  );
  assert.equal(pending.ok, false);
  assert.ok(pending.errors.some((e) => /placeholder\/pending reviewer/i.test(e)));
  assert.ok(pending.errors.some((e) => /explicit approval/i.test(e)));

  const badCounts = validateEvidenceManifest(
    makeValidManifest({
      reviewReport: {
        reviewers: ["senior-code-critic"],
        p0Count: Number.NaN,
        p1Count: -1,
        p2OpenCount: 2,
        recommendation: "Changes requested",
      },
      video: {
        ...makeValidManifest().video,
        fps: Number.NaN,
        durationSec: Number.NaN,
      },
    }),
  );
  assert.equal(badCounts.ok, false);
  assert.ok(badCounts.errors.some((e) => /p0Count/i.test(e)));
  assert.ok(badCounts.errors.some((e) => /p1Count/i.test(e)));
  assert.ok(badCounts.errors.some((e) => /p2OpenCount/i.test(e)));
  assert.ok(badCounts.errors.some((e) => /video\.fps/i.test(e)));
  assert.ok(badCounts.errors.some((e) => /video\.durationSec/i.test(e)));

  const acceptedP2 = validateEvidenceManifest(
    makeValidManifest({
      reviewReport: {
        reviewers: ["senior-code-critic"],
        p0Count: 0,
        p1Count: 0,
        p2OpenCount: 1,
        p2Acceptance: "Accepted by maintainer for follow-up PR",
        recommendation: "Approved",
      },
    }),
  );
  assert.equal(acceptedP2.ok, true, `Unexpected errors: ${acceptedP2.errors.join("; ")}`);
});

test("validateEvidenceManifest accepts genuinely non-demonstrable change with substantive justification", () => {
  const manifest = makeValidManifest({
    applicable: false,
    video: undefined,
    notApplicableReason: "Documentation-only typo fix with no runtime behavior change.",
    equivalentArtifacts: ["pnpm exec prettier --check README.md (exit 0)"],
  });
  const result = validateEvidenceManifest(manifest, { expectedSha: VALID_SHA });
  assert.equal(result.ok, true, `Unexpected errors: ${result.errors.join("; ")}`);
});

test("renderPrEvidenceMarkdown round-trips cleanly including mixed Passed + Not applicable criteria", () => {
  const manifest = makeValidManifest({
    acceptanceCriteria: [
      ...makeValidManifest().acceptanceCriteria,
      {
        criterion: "Legacy billing path untouched",
        timestamp: "00:00",
        status: "not_applicable",
        assertion: "Verified diff does not touch billing packages",
      },
    ],
  });
  const md = renderPrEvidenceMarkdown(manifest);
  const validation = validatePrEvidenceMarkdown(md, { expectedHeadSha: VALID_SHA });
  assert.equal(validation.ok, true, `Unexpected errors: ${validation.errors.join("; ")}`);
  assert.equal(validation.parsed.behaviorRows.length, 2);
});

test("extractField never bleeds across newlines and supports bold-colon markdown syntax", () => {
  const section = [
    "- **Recording**:",
    "- **Commit:** `" + VALID_SHA + "`",
    "- **Surface / route**:",
    "- **Environment**: Isolated local",
  ].join("\n");

  assert.equal(extractField(section, "Recording"), null);
  assert.equal(extractField(section, "Surface\\s*/\\s*route"), null);
  assert.equal(extractField(section, "Commit")?.replace(/`/g, ""), VALID_SHA);
  assert.equal(extractField(section, "Environment"), "Isolated local");
});

test("validatePrEvidenceMarkdown flags every blank required field on untouched PR template", () => {
  const template = fs.readFileSync(
    path.join(REPO_ROOT, ".github/pull_request_template.md"),
    "utf8",
  );
  const res = validatePrEvidenceMarkdown(template, { expectedHeadSha: VALID_SHA });
  assert.equal(res.ok, false);
  assert.ok(res.errors.some((e) => /Recording:/i.test(e)));
  assert.ok(res.errors.some((e) => /Commit:/i.test(e)));
  assert.ok(res.errors.some((e) => /Captured at:/i.test(e)));
  assert.ok(res.errors.some((e) => /Surface \/ route:/i.test(e)));
  assert.ok(res.errors.some((e) => /Environment:/i.test(e)));
  assert.ok(res.errors.some((e) => /Reviewers dispatched:/i.test(e)));
  assert.ok(res.errors.some((e) => /<command>/i.test(e)));
});

test("validatePrEvidenceMarkdown blocks Recording bypasses (local paths, loopback, TODO, short Not applicable)", () => {
  const badRecordings = [
    "`/home/antigravity/.pr-video-evidence/demo.mp4`",
    "file:///home/antigravity/demo.mp4",
    "Playable MP4 at /Users/alice/demo.mp4",
    "http://127.0.0.1:4317/demo.mp4",
    "Not yet attached (demo.mp4)",
    "Not applicable: TODO TBD",
  ];
  for (const rec of badRecordings) {
    const body = makeValidPrBody().replace(/^- \*\*Recording\*\*: .+$/m, `- **Recording**: ${rec}`);
    const res = validatePrEvidenceMarkdown(body, { expectedHeadSha: VALID_SHA });
    assert.equal(res.ok, false, `Expected Recording "${rec}" to be rejected`);
  }
});

test("validatePrEvidenceMarkdown blocks Automated checks bypasses while allowing passing commands containing 'error'", () => {
  const goodWithErrorFilename = makeValidPrBody().replace(
    /^- \[x\] .+$/m,
    "- [x] `vitest run src/error-boundary.test.ts` — Passed (0 errors)",
  );
  const goodRes = validatePrEvidenceMarkdown(goodWithErrorFilename, {
    expectedHeadSha: VALID_SHA,
  });
  assert.equal(goodRes.ok, true, `Unexpected errors: ${goodRes.errors.join("; ")}`);

  const badCases = [
    "* [ ] `pnpm test` — Passed",
    "- [x] `pnpm test` — FAILED (0 failed in lint, 3 failed in e2e)",
    "- [x] `pnpm test` — Skipped",
    "- [x] `<command>` — Passed",
  ];
  for (const checkLine of badCases) {
    const body = makeValidPrBody().replace(/^- \[x\] .+$/m, checkLine);
    const res = validatePrEvidenceMarkdown(body, { expectedHeadSha: VALID_SHA });
    assert.equal(res.ok, false, `Expected automated check "${checkLine}" to fail`);
  }
});

test("validatePrEvidenceMarkdown detects secrets inside HTML comments and modern API key prefixes", () => {
  // Dynamically construct synthetic tokens so no high-entropy secret literal exists in source.
  const fakeGhToken = ["ghp", "0".repeat(24)].join("_");
  const fakeOpenAiKey = ["sk", "proj", "a".repeat(24)].join("-");
  const fakeAnthropicKey = ["sk", "ant", "api03", "b".repeat(24)].join("-");

  for (const secret of [fakeGhToken, fakeOpenAiKey, fakeAnthropicKey]) {
    const bodyWithCommentSecret = `${makeValidPrBody()}\n<!-- debug: ${secret} -->\n`;
    const res = validatePrEvidenceMarkdown(bodyWithCommentSecret, { expectedHeadSha: VALID_SHA });
    assert.equal(res.ok, false, `Expected secret prefix "${secret.slice(0, 7)}" to be caught`);
    assert.ok(res.errors.some((e) => /secret or credential/i.test(e)));
  }
});

test("validatePrEvidenceMarkdown rejects Not passed, invalid timestamps, invalid dates, and fenced code headings", () => {
  const badVerdict = makeValidPrBody().replace("| Passed |", "| Not passed |");
  assert.equal(validatePrEvidenceMarkdown(badVerdict, { expectedHeadSha: VALID_SHA }).ok, false);

  const badTime = makeValidPrBody().replace("| 00:12 |", "| 99:99 |");
  assert.equal(validatePrEvidenceMarkdown(badTime, { expectedHeadSha: VALID_SHA }).ok, false);

  const badDate = makeValidPrBody().replace("2026-11-28T10:30:00Z", "9999-99-99T99:99:99Z");
  assert.equal(validatePrEvidenceMarkdown(badDate, { expectedHeadSha: VALID_SHA }).ok, false);

  // A `# comment` inside a fenced code block under Automated checks must NOT prematurely end the section.
  const fencedCheckBody = makeValidPrBody().replace(
    "### Automated checks\n",
    "### Automated checks\n\n```bash\n# Run tests locally\npnpm run test:video-evidence\n```\n",
  );
  const fencedRes = validatePrEvidenceMarkdown(fencedCheckBody, { expectedHeadSha: VALID_SHA });
  assert.equal(fencedRes.ok, true, `Unexpected errors: ${fencedRes.errors.join("; ")}`);
});

test("compose helpers produce monotonic cues, clean single-token wrapping, ASS timestamps, and accurate clipping checks", () => {
  const cues = buildCaptionCues(
    "Short beat with several words that split across multiple cues cleanly without zero or inverted timestamps.",
    0,
    1.1,
  );
  assert.ok(cues.length >= 1);
  for (const cue of cues) {
    assert.ok(cue.endSec > cue.startSec, `Expected endSec > startSec: ${JSON.stringify(cue)}`);
  }

  const longUrl = "https://example.com/" + "segment-".repeat(12);
  assert.equal(wrapTwoLines(longUrl, 56), longUrl);
  assert.equal(formatAssTime(65.25), "0:01:05.25");

  const cleanAudio = parseVolumedetect(
    "[Parsed_volumedetect_0] mean_volume: -19.8 dB\n[Parsed_volumedetect_0] max_volume: -1.4 dB\n",
  );
  assert.equal(cleanAudio.audioAudible, true);
  assert.equal(cleanAudio.audioClipping, false);

  const clippedAudio = parseVolumedetect(
    "[Parsed_volumedetect_0] mean_volume: -3.2 dB\n[Parsed_volumedetect_0] max_volume: 0.0 dB\n[Parsed_volumedetect_0] histogram_0db: 10900\n",
  );
  assert.equal(clippedAudio.audioAudible, true);
  assert.equal(clippedAudio.audioClipping, true);
});

test("cli parseCliArgs rejects missing flag values and out-of-range speed", () => {
  assert.throws(() => parseCliArgs(["--voice", "--draft"]), /requires a value/i);
  assert.throws(() => parseCliArgs(["--speed", "5.0"]), /between 0\.5 and 2\.0/i);
  assert.throws(() => parseCliArgs(["--pr", "abc"]), /positive integer/i);
  assert.throws(() => parseCliArgs(["--storyboard", "foo.json"]), /Unknown argument/i);
});

test("validate-cli.mjs supports --github-event-path, fails closed on empty SHA, and sanitizes step summary", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "pr-video-evidence-test-"));
  try {
    const eventPath = path.join(tmpDir, "event.json");
    const summaryPath = path.join(tmpDir, "summary.md");
    fs.writeFileSync(
      eventPath,
      JSON.stringify({
        pull_request: {
          head: { sha: VALID_SHA },
          body: makeValidPrBody(VALID_SHA),
        },
      }),
      "utf8",
    );

    const passRun = spawnSync(
      process.execPath,
      [VALIDATE_CLI, "--github-event-path", eventPath, "--summary-file", summaryPath],
      { encoding: "utf8" },
    );
    assert.equal(passRun.status, 0, `Expected pass, got stderr: ${passRun.stderr}`);

    // Empty --head-sha must fail closed (exit 2)
    const prFile = path.join(tmpDir, "pr.md");
    fs.writeFileSync(prFile, makeValidPrBody(VALID_SHA), "utf8");
    const emptyShaRun = spawnSync(
      process.execPath,
      [VALIDATE_CLI, "--pr-body-file", prFile, "--head-sha", ""],
      { encoding: "utf8" },
    );
    assert.equal(emptyShaRun.status, 2);

    // Swapped --expected-sha works in --pr-body-file mode and catches stale SHA
    const staleRun = spawnSync(
      process.execPath,
      [VALIDATE_CLI, "--pr-body-file", prFile, "--expected-sha", OTHER_SHA],
      { encoding: "utf8" },
    );
    assert.equal(staleRun.status, 1);

    // Summary escapes HTML/Markdown injection attempts from untrusted PR body
    const evilEventPath = path.join(tmpDir, "evil-event.json");
    const evilSummaryPath = path.join(tmpDir, "evil-summary.md");
    fs.writeFileSync(
      evilEventPath,
      JSON.stringify({
        pull_request: {
          head: { sha: VALID_SHA },
          body: makeValidPrBody(VALID_SHA).replace(
            "Approved",
            "Rejected <script>alert(1)</script> [click](https://evil.test)",
          ),
        },
      }),
      "utf8",
    );
    const evilRun = spawnSync(
      process.execPath,
      [VALIDATE_CLI, "--github-event-path", evilEventPath, "--summary-file", evilSummaryPath],
      { encoding: "utf8" },
    );
    assert.equal(evilRun.status, 1);
    const summaryText = fs.readFileSync(evilSummaryPath, "utf8");
    assert.ok(!summaryText.includes("<script>"), "Step summary must escape raw HTML tags");
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
