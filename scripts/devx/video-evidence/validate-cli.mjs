#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";

import { readJsonStrict, validateEvidenceManifest, validatePrEvidenceMarkdown } from "./schema.mjs";

const HEX_40_RE = /^[0-9a-f]{40}$/i;

function requireValue(argv, index, flag) {
  const val = argv[index + 1];
  if (val === undefined || val === "" || val.startsWith("--")) {
    throw new Error(`Flag ${flag} requires a non-empty value.`);
  }
  return val;
}

function parseArgs(argv) {
  const args = {
    manifest: "",
    prBodyFile: "",
    githubEventPath: "",
    expectedSha: "",
    shaFlagProvided: false,
    summaryFile: process.env.GITHUB_STEP_SUMMARY || "",
  };
  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];
    if (token === "--") continue;
    switch (token) {
      case "--manifest":
        args.manifest = requireValue(argv, i, token);
        i++;
        break;
      case "--pr-body-file":
        args.prBodyFile = requireValue(argv, i, token);
        i++;
        break;
      case "--github-event-path":
        args.githubEventPath = requireValue(argv, i, token);
        i++;
        break;
      case "--expected-sha":
      case "--head-sha": {
        args.shaFlagProvided = true;
        const val = argv[i + 1];
        if (val === undefined || val === "" || val.startsWith("--")) {
          throw new Error(`Flag ${token} requires a 40-character hex commit SHA.`);
        }
        if (args.expectedSha && args.expectedSha.toLowerCase() !== val.toLowerCase()) {
          throw new Error(`Conflicting SHA values provided (${args.expectedSha} vs ${val}).`);
        }
        args.expectedSha = val;
        i++;
        break;
      }
      case "--summary-file":
        args.summaryFile = requireValue(argv, i, token);
        i++;
        break;
      case "--help":
      case "-h":
        console.log(`Usage:
  pnpm run devx:video-evidence:validate -- --manifest <path> [--expected-sha <40-hex-sha>]
  pnpm run devx:video-evidence:validate -- --pr-body-file <path> [--head-sha <40-hex-sha>]
  pnpm run devx:video-evidence:validate -- --github-event-path <path>
`);
        process.exit(0);
        break;
      default:
        throw new Error(`Unknown argument: ${token}`);
    }
  }
  return args;
}

function escapeSummaryLine(text) {
  return String(text ?? "")
    .replace(/[\r\n]+/g, " ")
    .replace(/[&<>`[\]]/g, (ch) => {
      switch (ch) {
        case "&":
          return "&amp;";
        case "<":
          return "&lt;";
        case ">":
          return "&gt;";
        case "`":
          return "'";
        case "[":
          return "(";
        case "]":
          return ")";
        default:
          return ch;
      }
    });
}

function writeSummary(summaryFile, title, result) {
  if (!summaryFile) return;
  const lines = [`## ${title}`, "", result.ok ? "Status: **PASSED**" : "Status: **FAILED**", ""];
  if (result.errors.length > 0) {
    lines.push("### Errors", "", ...result.errors.map((e) => `- ${escapeSummaryLine(e)}`), "");
  }
  if (result.warnings.length > 0) {
    lines.push("### Warnings", "", ...result.warnings.map((w) => `- ${escapeSummaryLine(w)}`), "");
  }
  fs.appendFileSync(summaryFile, lines.join("\n") + "\n", "utf8");
}

function main() {
  let args;
  try {
    args = parseArgs(process.argv.slice(2));
  } catch (err) {
    console.error(
      `[pr-video-evidence] Argument error: ${err instanceof Error ? err.message : String(err)}`,
    );
    process.exit(2);
  }

  const modeCount = [args.manifest, args.prBodyFile, args.githubEventPath].filter(Boolean).length;
  if (modeCount !== 1) {
    console.error(
      "Provide exactly one of --manifest <path>, --pr-body-file <path>, or --github-event-path <path>.",
    );
    process.exit(2);
  }

  if (args.shaFlagProvided && !HEX_40_RE.test(args.expectedSha)) {
    console.error(
      `[pr-video-evidence] Invalid commit SHA "${args.expectedSha}": expected a 40-character hex git SHA.`,
    );
    process.exit(2);
  }

  if (process.env.GITHUB_ACTIONS === "true" && !args.githubEventPath && !args.expectedSha) {
    console.error(
      "[pr-video-evidence] Running in GitHub Actions requires --github-event-path or an explicit 40-char --head-sha/--expected-sha.",
    );
    process.exit(2);
  }

  let result;
  let title;

  if (args.manifest) {
    title = `PR Video Evidence Manifest Validation (${path.basename(args.manifest)})`;
    const raw = readJsonStrict(args.manifest);
    result = validateEvidenceManifest(raw, { expectedSha: args.expectedSha || undefined });
  } else if (args.githubEventPath) {
    title = "PR Video Evidence Check (`pr-video-evidence`)";
    const event = readJsonStrict(args.githubEventPath);
    const pr = event?.pull_request;
    const headSha = pr?.head?.sha;
    if (typeof headSha !== "string" || !HEX_40_RE.test(headSha)) {
      console.error(
        `[pr-video-evidence] GitHub event payload at ${args.githubEventPath} is missing a valid pull_request.head.sha.`,
      );
      process.exit(2);
    }
    const body = typeof pr?.body === "string" ? pr.body : "";
    result = validatePrEvidenceMarkdown(body, { expectedHeadSha: headSha });
  } else {
    title = "PR Video Evidence Check (`pr-video-evidence`)";
    const body = fs.readFileSync(args.prBodyFile, "utf8");
    result = validatePrEvidenceMarkdown(body, { expectedHeadSha: args.expectedSha || undefined });
  }

  writeSummary(args.summaryFile, title, result);

  if (result.warnings.length > 0) {
    for (const warning of result.warnings) {
      console.warn(`[pr-video-evidence] WARNING: ${warning}`);
    }
  }

  if (!result.ok) {
    console.error(`[pr-video-evidence] FAILED (${result.errors.length} error(s)):`);
    for (const err of result.errors) {
      console.error(`  - ${err}`);
    }
    process.exit(1);
  }

  console.log(
    "[pr-video-evidence] PASSED: all evidence availability, freshness, metadata, and test checks verified.",
  );
}

main();
