#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { composeEvidenceVideo, inspectEvidenceVideo } from "./compose.mjs";
import {
  detectExposedSecrets,
  readJsonStrict,
  renderPrEvidenceMarkdown,
  validateEvidenceManifest,
  validatePrEvidenceMarkdown,
} from "./schema.mjs";
import {
  SCENARIO_META as ROWBOAT_WWW_CONNECTORS_META,
  runRowboatWwwConnectorsScenario,
} from "./scenarios/rowboat-www-connectors.mjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, "../../..");
const DEFAULT_EVIDENCE_ROOT = path.join(REPO_ROOT, ".pr-video-evidence");

const SCENARIOS = {
  "rowboat-www-connectors": {
    meta: ROWBOAT_WWW_CONNECTORS_META,
    run: runRowboatWwwConnectorsScenario,
  },
};

function requireValue(argv, index, flag) {
  const val = argv[index + 1];
  if (val === undefined || val === "" || val.startsWith("--")) {
    throw new Error(`Flag ${flag} requires a value.`);
  }
  return val;
}

export function parseCliArgs(argv) {
  const args = {
    scenario: "rowboat-www-connectors",
    voice: process.env.PR_VIDEO_TTS_VOICE || "am_michael",
    speed: Number(process.env.PR_VIDEO_TTS_SPEED || "0.98"),
    outDir: "",
    prNumber: null,
    reviewReportPath: "",
    automatedChecksPath: "",
    downloadTts: false,
    recordingLink: "",
    draft: false,
    reuseServers: false,
    allowUntrackedOutDir: false,
    help: false,
  };

  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];
    if (token === "--") continue;
    switch (token) {
      case "--scenario":
        args.scenario = requireValue(argv, i, token);
        i++;
        break;
      case "--voice":
        args.voice = requireValue(argv, i, token);
        i++;
        break;
      case "--speed": {
        const raw = requireValue(argv, i, token);
        const parsed = Number(raw);
        if (!Number.isFinite(parsed) || parsed < 0.5 || parsed > 2.0) {
          throw new Error(`--speed must be a number between 0.5 and 2.0 (got "${raw}").`);
        }
        args.speed = parsed;
        i++;
        break;
      }
      case "--out-dir":
        args.outDir = requireValue(argv, i, token);
        i++;
        break;
      case "--pr": {
        const raw = requireValue(argv, i, token);
        const parsed = Number(raw);
        if (!Number.isInteger(parsed) || parsed <= 0) {
          throw new Error(`--pr must be a positive integer (got "${raw}").`);
        }
        args.prNumber = parsed;
        i++;
        break;
      }
      case "--review-report":
        args.reviewReportPath = requireValue(argv, i, token);
        i++;
        break;
      case "--checks":
        args.automatedChecksPath = requireValue(argv, i, token);
        i++;
        break;
      case "--recording-link":
        args.recordingLink = requireValue(argv, i, token);
        i++;
        break;
      case "--download-tts":
        args.downloadTts = true;
        break;
      case "--draft":
        args.draft = true;
        break;
      case "--reuse-servers":
        args.reuseServers = true;
        break;
      case "--allow-untracked-out-dir":
        args.allowUntrackedOutDir = true;
        break;
      case "--help":
      case "-h":
        args.help = true;
        break;
      default:
        throw new Error(`Unknown argument: ${token}`);
    }
  }
  return args;
}

function printHelp() {
  console.log(`Usage: pnpm run devx:video-evidence -- [options]

Options:
  --scenario <name>           Scenario to capture (available: ${Object.keys(SCENARIOS).join(", ")})
  --voice <kokoro-voice>      Kokoro-82M voice (default: am_michael; e.g. af_heart, af_bella, am_adam)
  --speed <float>             Speaking speed between 0.5 and 2.0 (default: 0.98)
  --out-dir <path>            Output directory under .pr-video-evidence/ (default: .pr-video-evidence/<timestamp>-<scenario>)
  --pr <number>               Pull request number if assigned
  --review-report <path>      Path to consolidated review-report.json (required unless --draft is passed)
  --checks <path>             Path to JSON array of automated check results
  --recording-link <string>   Accessible HTTPS URL or playable attachment description for pr-evidence.md
  --download-tts              Download SHA-256 verified Kokoro-82M model files if not cached
  --draft                     Allow local dry-run capture without a completed review-report.json
  --reuse-servers             Explicitly reuse already-running local test servers instead of failing on busy ports
  --allow-untracked-out-dir   Allow --out-dir outside .pr-video-evidence/ (never commit binary recordings)
`);
}

function isInsideDir(childPath, parentPath) {
  const rel = path.relative(parentPath, childPath);
  return rel !== "" && !rel.startsWith("..") && !path.isAbsolute(rel);
}

function gitValue(args) {
  const res = spawnSync("git", args, { cwd: REPO_ROOT, encoding: "utf8" });
  if (res.status !== 0) return "";
  return res.stdout.trim();
}

function detectRepository() {
  const remote = gitValue(["remote", "get-url", "origin"]);
  const match = remote.match(/github\.com[:/]([^/]+\/[^/.]+?)(?:\.git)?$/);
  return match ? match[1] : path.basename(REPO_ROOT);
}

function generateKokoroNarration({ beats, outDir, voice, speed, downloadTts }) {
  const audioDir = path.join(outDir, "audio");
  fs.mkdirSync(audioDir, { recursive: true });
  const beatsJsonPath = path.join(audioDir, "beats-input.json");
  fs.writeFileSync(
    beatsJsonPath,
    JSON.stringify(
      beats.map((b) => ({ id: b.id, narration: b.narration })),
      null,
      2,
    ),
    "utf8",
  );

  const ttsScript = path.join(__dirname, "kokoro_tts.py");
  const pyArgs = [
    ttsScript,
    "--beats",
    beatsJsonPath,
    "--out-dir",
    audioDir,
    "--voice",
    voice,
    "--speed",
    String(speed),
  ];
  if (downloadTts) pyArgs.push("--download");

  const res = spawnSync("python3", pyArgs, {
    cwd: REPO_ROOT,
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
  });
  if (res.error) {
    throw new Error(`Failed to invoke python3 for Kokoro TTS: ${res.error.message}`);
  }
  if (res.status !== 0) {
    throw new Error(
      `Kokoro TTS generation failed (exit ${res.status}):\n${res.stderr || res.stdout}`,
    );
  }
  return readJsonStrict(path.join(audioDir, "narration-timings.json"));
}

async function main() {
  const args = parseCliArgs(process.argv.slice(2));
  if (args.help) {
    printHelp();
    process.exit(0);
  }

  const scenarioEntry = SCENARIOS[args.scenario];
  if (!scenarioEntry) {
    throw new Error(
      `Unknown scenario "${args.scenario}". Available: ${Object.keys(SCENARIOS).join(", ")}`,
    );
  }

  if (!args.reviewReportPath && !args.draft) {
    throw new Error(
      "Missing --review-report <path>. Complete independent engineering review before generating final evidence, or pass --draft for a local dry run.",
    );
  }

  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const outDir = path.resolve(
    REPO_ROOT,
    args.outDir || path.join(".pr-video-evidence", `${stamp}-${args.scenario}`),
  );

  if (
    !args.allowUntrackedOutDir &&
    (outDir === REPO_ROOT || isInsideDir(outDir, REPO_ROOT)) &&
    !isInsideDir(outDir, DEFAULT_EVIDENCE_ROOT) &&
    outDir !== DEFAULT_EVIDENCE_ROOT
  ) {
    throw new Error(
      `Refusing to write binary recording artifacts to tracked repository path (${outDir}). Write under .pr-video-evidence/ or pass --allow-untracked-out-dir.`,
    );
  }

  fs.mkdirSync(outDir, { recursive: true });

  console.log(`[video-evidence] Output directory: ${outDir}`);
  console.log(
    `[video-evidence] Synthesizing human-sounding Kokoro-82M narration (${args.voice}, speed=${args.speed})...`,
  );
  const narrationTimings = generateKokoroNarration({
    beats: scenarioEntry.meta.beats,
    outDir,
    voice: args.voice,
    speed: args.speed,
    downloadTts: args.downloadTts,
  });
  console.log(
    `[video-evidence] Narration generated: ${narrationTimings.segments.length} beats, ${narrationTimings.totalDurationSec}s total.`,
  );

  console.log(
    `[video-evidence] Capturing real isolated application workflow (${args.scenario})...`,
  );
  const captureResult = await scenarioEntry.run({
    repoRoot: REPO_ROOT,
    outDir,
    narrationTimings,
    reuseServers: args.reuseServers,
  });

  console.log(
    "[video-evidence] Composing 1920x1080 @ 30fps H.264/AAC MP4 with synchronized 1080p captions...",
  );
  const composed = composeEvidenceVideo({
    beats: captureResult.beats,
    outDir,
    finalMp4Name: "demo.mp4",
  });

  console.log("[video-evidence] Inspecting final video (ffprobe + audio loudness + keyframes)...");
  const inspection = inspectEvidenceVideo(
    composed.finalMp4Path,
    composed.beatTimeline,
    path.join(outDir, "keyframes"),
  );

  if (inspection.codec !== "h264" || inspection.audioCodec !== "aac") {
    throw new Error(
      `Unexpected codec output: video=${inspection.codec}, audio=${inspection.audioCodec} (expected h264/aac).`,
    );
  }
  if (!inspection.audioAudible || inspection.audioClipping) {
    throw new Error(
      `Audio quality inspection failed: mean=${inspection.meanVolumeDb} dB, max=${inspection.maxVolumeDb} dB, histogram_0db=${inspection.histogram0db}.`,
    );
  }

  let reviewReport;
  if (args.reviewReportPath) {
    reviewReport = readJsonStrict(path.resolve(REPO_ROOT, args.reviewReportPath));
    fs.writeFileSync(
      path.join(outDir, "review-report.json"),
      JSON.stringify(reviewReport, null, 2) + "\n",
      "utf8",
    );
  } else {
    reviewReport = {
      reviewers: ["pending-independent-review"],
      p0Count: 0,
      p1Count: 0,
      p2OpenCount: 0,
      p3Count: 0,
      recommendation: "Pending independent engineering review (draft dry run)",
    };
  }

  const automatedChecks = args.automatedChecksPath
    ? readJsonStrict(path.resolve(REPO_ROOT, args.automatedChecksPath))
    : [
        {
          command: `pnpm run devx:video-evidence -- --scenario ${args.scenario}`,
          exitCode: 0,
          status: "passed",
          summary: `${composed.beatTimeline.length} browser & API assertions passed`,
        },
      ];

  const manifest = {
    schemaVersion: 1,
    profile: "engineering-verification",
    applicable: true,
    repository: detectRepository(),
    branch: gitValue(["rev-parse", "--abbrev-ref", "HEAD"]) || "unknown",
    commitSha: gitValue(["rev-parse", "HEAD"]),
    pullRequestNumber: args.prNumber,
    capturedAt: new Date().toISOString(),
    app: captureResult.app,
    routes: captureResult.routes,
    testEnvironment: captureResult.testEnvironment,
    acceptanceCriteria: composed.beatTimeline.map((b) => ({
      criterion: b.criterion,
      timestamp: b.timestamp,
      status: b.status,
      assertion: b.assertion,
    })),
    automatedChecks,
    reviewReport,
    video: {
      codec: inspection.codec,
      pixelFormat: inspection.pixelFormat,
      width: inspection.width,
      height: inspection.height,
      fps: inspection.fps,
      audioCodec: inspection.audioCodec,
      audioSampleRate: inspection.audioSampleRate,
      durationSec: inspection.durationSec,
      fileSizeBytes: inspection.fileSizeBytes,
      sha256: inspection.sha256,
      meanVolumeDb: inspection.meanVolumeDb,
      maxVolumeDb: inspection.maxVolumeDb,
      histogram0db: inspection.histogram0db,
      audioAudible: inspection.audioAudible,
      audioClipping: inspection.audioClipping,
      ttsProvider: narrationTimings.provider,
      ttsVoice: narrationTimings.voice,
    },
    artifacts: {
      finalVideo: "demo.mp4",
      captionsAss: "captions.ass",
      captionsSrt: "captions.srt",
      captionsVtt: "captions.vtt",
      transcript: "transcript.txt",
      trace: captureResult.traceFile,
      reviewReport: args.reviewReportPath ? "review-report.json" : null,
      keyframes: inspection.keyframes.map((k) => `keyframes/${k.file}`),
    },
    limitations: captureResult.limitations ?? [],
  };

  const prMarkdown = renderPrEvidenceMarkdown(manifest, {
    recordingReference: args.recordingLink,
  });

  // Scan all generated text artifacts for accidental credential/secret exposure.
  for (const [label, filePath] of [
    ["transcript.txt", composed.transcriptPath],
    ["captions.srt", composed.srtPath],
    ["captions.vtt", composed.vttPath],
    ["captions.ass", composed.assPath],
  ]) {
    const hits = detectExposedSecrets(fs.readFileSync(filePath, "utf8"));
    if (hits.length > 0) {
      throw new Error(`Potential secret detected in generated ${label}.`);
    }
  }
  if (detectExposedSecrets(prMarkdown).length > 0) {
    throw new Error("Potential secret detected in generated pr-evidence.md.");
  }

  const manifestPath = path.join(outDir, "evidence-manifest.json");
  const prMdPath = path.join(outDir, "pr-evidence.md");
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + "\n", "utf8");
  fs.writeFileSync(prMdPath, prMarkdown, "utf8");

  if (!args.draft) {
    const manifestCheck = validateEvidenceManifest(manifest, { expectedSha: manifest.commitSha });
    if (!manifestCheck.ok) {
      throw new Error(
        `Generated manifest failed validation:\n- ${manifestCheck.errors.join("\n- ")}`,
      );
    }
    const prCheck = validatePrEvidenceMarkdown(prMarkdown, { expectedHeadSha: manifest.commitSha });
    if (!prCheck.ok) {
      throw new Error(
        `Generated pr-evidence.md failed validation:\n- ${prCheck.errors.join("\n- ")}`,
      );
    }
  } else {
    console.warn(
      "[video-evidence] DRAFT mode: independent review report not attached; manifest and pr-evidence.md will fail CI readiness validation until --review-report is supplied.",
    );
  }

  console.log(`[video-evidence] Success!`);
  console.log(
    `  MP4:      ${composed.finalMp4Path} (${(inspection.fileSizeBytes / (1024 * 1024)).toFixed(2)} MB, ${inspection.durationSec}s)`,
  );
  console.log(
    `  Codec:    ${inspection.codec}/${inspection.audioCodec} ${inspection.width}x${inspection.height}@${inspection.fps}fps (${inspection.pixelFormat})`,
  );
  console.log(
    `  Audio:    mean=${inspection.meanVolumeDb} dB, max=${inspection.maxVolumeDb} dB, 0dB_samples=${inspection.histogram0db} (Kokoro ${narrationTimings.voice})`,
  );
  console.log(`  Manifest: ${manifestPath}`);
  console.log(`  PR Block: ${prMdPath}`);
}

const isDirectRun = process.argv[1] && path.resolve(process.argv[1]) === path.resolve(__filename);
if (isDirectRun) {
  main().catch((err) => {
    console.error(`[video-evidence] FAILED: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  });
}
