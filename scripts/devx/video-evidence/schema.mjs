import fs from "node:fs";

const HEX_40_RE = /^[0-9a-f]{40}$/i;
const ISO_UTC_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;
const PLACEHOLDER_RE = /^(?:todo|tbd|n\/a|none yet|pending|placeholder|\-+|\.{3,}|<[^>]+>)$/i;
const ROBOTIC_TTS_RE = /^(?:espeak|espeak-ng|flite|festival|pico2wave)$/i;
const PLACEHOLDER_REVIEWER_RE = /^(?:pending|pending-independent-review|none|self|todo|tbd|n\/a)$/i;
const APPROVED_RECOMMENDATION_RE = /^(?:approved|approve|changes verified|ready for review)\b/i;
const REJECTED_RECOMMENDATION_RE =
  /\b(?:pending|not approved|unapproved|changes requested|block|blocked|reject|rejected|do not merge|hold|needs fixes?|incomplete)\b/i;

const SECRET_PATTERNS = [
  /-----BEGIN [A-Z0-9 ]*(?:PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----/,
  /\bgh[pousr]_[A-Za-z0-9]{20,}\b/,
  /\bgithub_pat_[A-Za-z0-9_]{20,}\b/,
  /\bsk-(?:proj|ant|svcacct|live|test)?[-_A-Za-z0-9]{20,}\b/,
  /\b[rs]k_live_[A-Za-z0-9]{16,}\b/,
  /\bwhsec_[A-Za-z0-9]{20,}\b/,
  /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/,
  /\bAIza[0-9A-Za-z\-_]{35}\b/,
  /\bya29\.[0-9A-Za-z\-_]{20,}\b/,
  /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/,
  /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/,
  /\bBearer\s+[A-Za-z0-9._-]{24,}\b/,
  /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss):\/\/[^:\s/@]+:[^@\s/]+@[^\s]+/i,
];

function isNonEmptyString(value) {
  return typeof value === "string" && value.trim().length > 0;
}

function isPlainObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isValidIsoTimestamp(value) {
  return isNonEmptyString(value) && ISO_UTC_RE.test(value) && Number.isFinite(Date.parse(value));
}

export function isValidTimestamp(value) {
  if (!isNonEmptyString(value)) return false;
  const parts = value.trim().split(":");
  if (parts.length !== 2 && parts.length !== 3) return false;
  if (!parts.every((p) => /^\d{2}$/.test(p))) return false;
  const nums = parts.map(Number);
  if (parts.length === 2) {
    return nums[0] < 60 && nums[1] < 60;
  }
  return nums[0] < 100 && nums[1] < 60 && nums[2] < 60;
}

export function detectExposedSecrets(text) {
  const hits = [];
  for (const pattern of SECRET_PATTERNS) {
    if (pattern.test(text)) {
      hits.push(pattern.source);
    }
  }
  return hits;
}

function sanitizeSnippet(text, maxLen = 96) {
  const cleaned = String(text ?? "")
    .replace(/[\r\n\t]+/g, " ")
    .replace(/[`<>[\]]/g, "")
    .trim();
  return cleaned.length > maxLen ? `${cleaned.slice(0, maxLen - 3)}...` : cleaned;
}

function isValidRecommendation(value) {
  if (!isNonEmptyString(value)) return false;
  const trimmed = value.trim();
  if (REJECTED_RECOMMENDATION_RE.test(trimmed)) return false;
  return APPROVED_RECOMMENDATION_RE.test(trimmed);
}

/**
 * Strictly validates an engineering verification evidence manifest.
 * @param {unknown} raw
 * @param {{ expectedSha?: string }} [options]
 * @returns {{ ok: boolean, errors: string[], warnings: string[] }}
 */
export function validateEvidenceManifest(raw, options = {}) {
  const errors = [];
  const warnings = [];

  if (!isPlainObject(raw)) {
    return { ok: false, errors: ["Manifest must be a JSON object."], warnings };
  }

  const serialized = JSON.stringify(raw);
  const secretHits = detectExposedSecrets(serialized);
  if (secretHits.length > 0) {
    errors.push(
      `Potential secret or credential pattern detected in manifest (${secretHits.length} match(es)).`,
    );
  }

  if (raw.schemaVersion !== 1) {
    errors.push("schemaVersion must equal 1.");
  }
  if (raw.profile !== "engineering-verification") {
    errors.push(
      'profile must equal "engineering-verification" (keep separate from marketing profiles).',
    );
  }
  if (!isNonEmptyString(raw.repository) || PLACEHOLDER_RE.test(raw.repository.trim())) {
    errors.push("repository is required.");
  }
  if (!isNonEmptyString(raw.branch) || PLACEHOLDER_RE.test(raw.branch.trim())) {
    errors.push("branch is required.");
  }
  if (!isNonEmptyString(raw.commitSha) || !HEX_40_RE.test(raw.commitSha)) {
    errors.push("commitSha must be a full 40-character hex git SHA.");
  } else if (
    options.expectedSha &&
    raw.commitSha.toLowerCase() !== options.expectedSha.toLowerCase()
  ) {
    errors.push(
      `Stale evidence: manifest commitSha (${raw.commitSha}) does not match expected HEAD SHA (${options.expectedSha}).`,
    );
  }
  if (
    raw.pullRequestNumber !== null &&
    raw.pullRequestNumber !== undefined &&
    (!Number.isInteger(raw.pullRequestNumber) || raw.pullRequestNumber <= 0)
  ) {
    errors.push("pullRequestNumber must be a positive integer or null.");
  }
  if (!isValidIsoTimestamp(raw.capturedAt)) {
    errors.push("capturedAt must be a valid ISO-8601 timestamp.");
  }
  if (!isNonEmptyString(raw.app) || PLACEHOLDER_RE.test(raw.app.trim())) {
    errors.push("app is required.");
  }
  if (
    !Array.isArray(raw.routes) ||
    raw.routes.length === 0 ||
    !raw.routes.every((r) => isNonEmptyString(r) && !PLACEHOLDER_RE.test(r.trim()))
  ) {
    errors.push("routes must be a non-empty array of valid route/surface strings.");
  }
  if (!isNonEmptyString(raw.testEnvironment) || PLACEHOLDER_RE.test(raw.testEnvironment.trim())) {
    errors.push("testEnvironment is required.");
  }

  let passedCriteriaCount = 0;
  if (!Array.isArray(raw.acceptanceCriteria) || raw.acceptanceCriteria.length === 0) {
    errors.push("acceptanceCriteria must contain at least one verified criterion.");
  } else {
    raw.acceptanceCriteria.forEach((item, index) => {
      if (!isPlainObject(item)) {
        errors.push(`acceptanceCriteria[${index}] must be an object.`);
        return;
      }
      if (!isNonEmptyString(item.criterion) || PLACEHOLDER_RE.test(item.criterion.trim())) {
        errors.push(`acceptanceCriteria[${index}].criterion is required.`);
      }
      if (!isValidTimestamp(item.timestamp)) {
        errors.push(`acceptanceCriteria[${index}].timestamp must be a valid MM:SS or HH:MM:SS.`);
      }
      if (!["passed", "failed", "not_applicable"].includes(item.status)) {
        errors.push(
          `acceptanceCriteria[${index}].status must be passed, failed, or not_applicable.`,
        );
      }
      if (item.status === "failed") {
        errors.push(
          `acceptanceCriteria[${index}] ("${sanitizeSnippet(item.criterion)}") failed verification.`,
        );
      }
      if (item.status === "passed") {
        passedCriteriaCount++;
      }
      if (!isNonEmptyString(item.assertion) || PLACEHOLDER_RE.test(item.assertion.trim())) {
        errors.push(`acceptanceCriteria[${index}].assertion is required.`);
      }
    });
  }

  if (!Array.isArray(raw.automatedChecks) || raw.automatedChecks.length === 0) {
    errors.push("automatedChecks must list at least one executed verification command.");
  } else {
    raw.automatedChecks.forEach((check, index) => {
      if (!isPlainObject(check)) {
        errors.push(`automatedChecks[${index}] must be an object.`);
        return;
      }
      if (!isNonEmptyString(check.command)) {
        errors.push(`automatedChecks[${index}].command is required.`);
      }
      if (!["passed", "failed"].includes(check.status)) {
        errors.push(`automatedChecks[${index}].status must be passed or failed.`);
      }
      if (
        check.status === "failed" ||
        (check.exitCode !== undefined &&
          (!Number.isInteger(check.exitCode) || check.exitCode !== 0))
      ) {
        errors.push(`Automated check failed: ${sanitizeSnippet(check.command)}`);
      }
    });
  }

  if (!isPlainObject(raw.reviewReport)) {
    errors.push("reviewReport is required (independent engineering review must be recorded).");
  } else {
    const reviewers = raw.reviewReport.reviewers;
    if (!Array.isArray(reviewers) || reviewers.length === 0 || !reviewers.every(isNonEmptyString)) {
      errors.push("reviewReport.reviewers must list the independent reviewers dispatched.");
    } else if (reviewers.some((r) => PLACEHOLDER_REVIEWER_RE.test(r.trim()))) {
      errors.push(
        "reviewReport.reviewers contains a placeholder/pending reviewer; complete independent engineering review first.",
      );
    }

    if (!Number.isInteger(raw.reviewReport.p0Count) || raw.reviewReport.p0Count !== 0) {
      errors.push("reviewReport.p0Count must be integer 0 before readiness.");
    }
    if (!Number.isInteger(raw.reviewReport.p1Count) || raw.reviewReport.p1Count !== 0) {
      errors.push("reviewReport.p1Count must be integer 0 before readiness.");
    }
    if (!Number.isInteger(raw.reviewReport.p2OpenCount) || raw.reviewReport.p2OpenCount < 0) {
      errors.push("reviewReport.p2OpenCount must be a non-negative integer.");
    } else if (raw.reviewReport.p2OpenCount > 0) {
      const acceptanceText = String(
        raw.reviewReport.p2Acceptance ?? raw.reviewReport.p2Summary ?? "",
      );
      if (
        !/\baccepted\b/i.test(acceptanceText) ||
        /\b(?:not|un)[\s-]*accepted\b/i.test(acceptanceText) ||
        PLACEHOLDER_RE.test(acceptanceText.trim())
      ) {
        errors.push(
          "reviewReport.p2OpenCount > 0 requires explicit acceptance rationale in p2Acceptance/p2Summary.",
        );
      }
    }
    if (!isValidRecommendation(raw.reviewReport.recommendation)) {
      errors.push(
        `reviewReport.recommendation must be an explicit approval (e.g. "Approved" or "Changes verified"), got "${sanitizeSnippet(raw.reviewReport.recommendation)}".`,
      );
    }
  }

  if (!Array.isArray(raw.limitations) || !raw.limitations.every(isNonEmptyString)) {
    errors.push("limitations must be an array of non-empty strings (use [] when none).");
  }

  if (typeof raw.applicable !== "boolean") {
    errors.push("applicable must be a boolean.");
  } else if (raw.applicable) {
    if (passedCriteriaCount === 0) {
      errors.push(
        "When applicable is true, at least one acceptance criterion must have status 'passed'.",
      );
    }
    if (!isPlainObject(raw.video)) {
      errors.push("video metadata object is required when applicable is true.");
    } else {
      if (raw.video.codec !== "h264") {
        errors.push(`video.codec must be "h264" (received "${sanitizeSnippet(raw.video.codec)}").`);
      }
      if (raw.video.audioCodec !== "aac") {
        errors.push(
          `video.audioCodec must be "aac" (received "${sanitizeSnippet(raw.video.audioCodec)}").`,
        );
      }
      if (raw.video.width !== 1920 || raw.video.height !== 1080) {
        warnings.push(
          `Non-default resolution ${raw.video.width}x${raw.video.height} (default is 1920x1080).`,
        );
      }
      if (
        typeof raw.video.fps !== "number" ||
        !Number.isFinite(raw.video.fps) ||
        raw.video.fps < 24
      ) {
        errors.push("video.fps must be a finite frame rate >= 24 (default 30).");
      }
      if (
        typeof raw.video.durationSec !== "number" ||
        !Number.isFinite(raw.video.durationSec) ||
        raw.video.durationSec <= 0
      ) {
        errors.push("video.durationSec must be a finite number > 0.");
      }
      if (raw.video.audioAudible !== true) {
        errors.push("video.audioAudible must be true (recording must contain audible narration).");
      }
      if (raw.video.audioClipping === true) {
        errors.push("video.audioClipping must be false (narration audio is clipping).");
      }
      if (!isNonEmptyString(raw.video.ttsProvider)) {
        errors.push("video.ttsProvider is required (e.g. kokoro-onnx).");
      } else if (ROBOTIC_TTS_RE.test(raw.video.ttsProvider.trim())) {
        errors.push(
          `Robotic formant TTS (${sanitizeSnippet(raw.video.ttsProvider)}) is not permitted for completed narrated evidence.`,
        );
      }
      if (!isNonEmptyString(raw.video.sha256) || !/^[0-9a-f]{64}$/i.test(raw.video.sha256)) {
        errors.push("video.sha256 must be a 64-char hex digest.");
      }
    }
  } else {
    if (
      !isNonEmptyString(raw.notApplicableReason) ||
      raw.notApplicableReason.trim().length < 20 ||
      PLACEHOLDER_RE.test(raw.notApplicableReason.trim())
    ) {
      errors.push(
        "notApplicableReason must be a substantive explanation (>= 20 chars) when applicable is false.",
      );
    }
    if (
      !Array.isArray(raw.equivalentArtifacts) ||
      raw.equivalentArtifacts.length === 0 ||
      !raw.equivalentArtifacts.every(isNonEmptyString)
    ) {
      errors.push(
        "equivalentArtifacts must list non-empty equivalent verification evidence when applicable is false.",
      );
    }
  }

  return { ok: errors.length === 0, errors, warnings };
}

function stripHtmlComments(text) {
  return text.replace(/<!--[\s\S]*?-->/g, "");
}

function extractSections(body, headingRegex) {
  const lines = body.split(/\r?\n/);
  const matches = [];
  let inFence = false;
  let fenceChar = "";

  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trim();
    const fenceMatch = trimmed.match(/^(`{3,}|~{3,})/);
    if (fenceMatch) {
      if (!inFence) {
        inFence = true;
        fenceChar = fenceMatch[1][0];
      } else if (fenceMatch[1][0] === fenceChar) {
        inFence = false;
        fenceChar = "";
      }
      continue;
    }
    if (inFence) continue;

    const match = lines[i].match(/^(#{2,6})\s+(.+?)\s*$/);
    if (match && headingRegex.test(match[2].trim())) {
      const headingLevel = match[1].length;
      const collected = [];
      let subFence = false;
      let subFenceChar = "";
      for (let j = i + 1; j < lines.length; j++) {
        const subTrimmed = lines[j].trim();
        const subFenceMatch = subTrimmed.match(/^(`{3,}|~{3,})/);
        if (subFenceMatch) {
          if (!subFence) {
            subFence = true;
            subFenceChar = subFenceMatch[1][0];
          } else if (subFenceMatch[1][0] === subFenceChar) {
            subFence = false;
            subFenceChar = "";
          }
          collected.push(lines[j]);
          continue;
        }
        if (!subFence) {
          const nextHeading = lines[j].match(/^(#{1,6})\s+/);
          if (nextHeading && nextHeading[1].length <= headingLevel) {
            break;
          }
        }
        collected.push(lines[j]);
      }
      matches.push(collected.join("\n").trim());
    }
  }
  return matches;
}

/**
 * Extracts a single-line bullet/label field from a markdown section.
 * Uses horizontal whitespace only so blank fields NEVER capture the following line.
 * Supports both `**Label**: value` and `**Label:** value`.
 */
export function extractField(section, label) {
  if (!section) return null;
  const re = new RegExp(
    `^[ \\t]*(?:[-*][ \\t]+)?(?:\\*\\*)?${label}(?:\\*\\*)?[ \\t]*:[ \\t]*(?:\\*\\*)?[ \\t]*([^\\r\\n]+?)[ \\t]*$`,
    "im",
  );
  const match = section.match(re);
  return match ? match[1].trim() : null;
}

function containsLocalOrLoopbackPath(value) {
  const normalized = value.replace(/[`]/g, " ");
  if (/\bfile:\/\//i.test(normalized)) return true;
  if (/\bhttps?:\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])(?::\d+)?\b/i.test(normalized)) {
    return true;
  }
  if (
    /(?:^|[\s([<"'])(?:\/(?:home|Users|tmp|var|etc|opt|mnt)\b|~\/|\.\.?\/|\.pr-video-evidence\/|[A-Za-z]:\\)/i.test(
      normalized,
    )
  ) {
    return true;
  }
  if (/^\s*\/[^\s]+/.test(normalized)) return true;
  return false;
}

function validateRecordingValue(rawRecording, errors) {
  const unwrapped = rawRecording.replace(/^`+|`+$/g, "").trim();
  const naMatch = unwrapped.match(/^Not applicable\s*:\s*(.+)$/i);
  if (naMatch) {
    const reason = naMatch[1].trim();
    if (reason.length < 20 || PLACEHOLDER_RE.test(reason) || /\b(?:todo|tbd)\b/i.test(reason)) {
      errors.push(
        "`Recording: Not applicable: ...` requires a substantive explanation (>= 20 chars, no TODO/TBD).",
      );
      return { isNotApplicable: false, notApplicableReason: null };
    }
    return { isNotApplicable: true, notApplicableReason: reason };
  }

  if (
    /^\[Playable demonstration\]$/i.test(unwrapped) ||
    PLACEHOLDER_RE.test(unwrapped) ||
    /\b(?:todo|tbd|pending|placeholder|not yet attached|not attached|not playable|no artifact|no recording)\b/i.test(
      unwrapped,
    )
  ) {
    errors.push(
      "`Recording:` contains a placeholder or missing-attachment statement instead of verified video evidence.",
    );
    return { isNotApplicable: false, notApplicableReason: null };
  }

  if (containsLocalOrLoopbackPath(unwrapped)) {
    errors.push(
      "`Recording:` must reference an accessible HTTPS link or playable review-thread attachment, never a local filesystem or loopback path.",
    );
    return { isNotApplicable: false, notApplicableReason: null };
  }

  const hasHttpsUrl = /\bhttps:\/\/[^\s<>)\]]+/.test(unwrapped);
  const hasExplicitAttachment = /\b(?:attached|attachment|playable)\b/i.test(unwrapped);
  if (!hasHttpsUrl && !hasExplicitAttachment) {
    errors.push(
      "`Recording:` must include an accessible `https://` URL or an explicit playable attachment reference (or `Not applicable: <reason>`).",
    );
  }
  return { isNotApplicable: false, notApplicableReason: null };
}

/**
 * Parses and validates the PR description evidence summary block used in GitHub Actions.
 * @param {string} rawBody
 * @param {{ expectedHeadSha?: string }} [options]
 * @returns {{ ok: boolean, errors: string[], warnings: string[], parsed: Record<string, unknown> }}
 */
export function validatePrEvidenceMarkdown(rawBody, options = {}) {
  const errors = [];
  const warnings = [];
  const rawText = String(rawBody ?? "");

  // Scan raw body BEFORE stripping HTML comments so commented-out secrets never slip through.
  const secretHits = detectExposedSecrets(rawText);
  if (secretHits.length > 0) {
    errors.push(
      `Potential secret or credential detected in PR description (${secretHits.length} match(es)).`,
    );
  }

  const body = stripHtmlComments(rawText);

  const narratedMatches = extractSections(body, /^Narrated verification$/i);
  const behaviorMatches = extractSections(body, /^Demonstrated behavior$/i);
  const reviewMatches = extractSections(body, /^Independent engineering review$/i);
  const checksMatches = extractSections(body, /^Automated checks$/i);
  const limitationsMatches = extractSections(body, /^Known limitations$/i);

  if (narratedMatches.length > 1)
    errors.push("Duplicate `### Narrated verification` sections found.");
  if (behaviorMatches.length > 1)
    errors.push("Duplicate `### Demonstrated behavior` sections found.");
  if (reviewMatches.length > 1)
    errors.push("Duplicate `### Independent engineering review` sections found.");
  if (checksMatches.length > 1) errors.push("Duplicate `### Automated checks` sections found.");
  if (limitationsMatches.length > 1)
    errors.push("Duplicate `### Known limitations` sections found.");

  const narratedSection = narratedMatches[0] ?? null;
  const behaviorSection = behaviorMatches[0] ?? null;
  const reviewSection = reviewMatches[0] ?? null;
  const checksSection = checksMatches[0] ?? null;
  const limitationsSection = limitationsMatches[0] ?? null;

  if (!narratedSection) {
    errors.push("Missing `### Narrated verification` section in PR description.");
  }

  const recording = extractField(narratedSection, "Recording");
  const commit = extractField(narratedSection, "Commit")?.replace(/`/g, "").trim() ?? null;
  const capturedAt = extractField(narratedSection, "Captured at")?.replace(/`/g, "").trim() ?? null;
  const surface =
    extractField(narratedSection, "Surface\\s*/\\s*route") ??
    extractField(narratedSection, "Route");
  const environment = extractField(narratedSection, "Environment");

  let isNotApplicable = false;
  let notApplicableReason = null;

  if (!isNonEmptyString(recording)) {
    errors.push("Missing `Recording:` entry under `### Narrated verification`.");
  } else {
    const recResult = validateRecordingValue(recording, errors);
    isNotApplicable = recResult.isNotApplicable;
    notApplicableReason = recResult.notApplicableReason;
  }

  if (!isNonEmptyString(commit) || !HEX_40_RE.test(commit)) {
    errors.push(
      "`Commit:` under `### Narrated verification` must be a full 40-character git commit SHA.",
    );
  } else if (
    options.expectedHeadSha &&
    commit.toLowerCase() !== options.expectedHeadSha.toLowerCase()
  ) {
    errors.push(
      `Stale evidence: PR verified Commit (${commit}) does not match current PR HEAD SHA (${options.expectedHeadSha}).`,
    );
  }

  if (!isValidIsoTimestamp(capturedAt)) {
    errors.push(
      "`Captured at:` under `### Narrated verification` must be a valid ISO-8601 UTC timestamp.",
    );
  }
  if (!isNonEmptyString(surface) || PLACEHOLDER_RE.test(surface.trim())) {
    errors.push("`Surface / route:` metadata is required under `### Narrated verification`.");
  }
  if (!isNonEmptyString(environment) || PLACEHOLDER_RE.test(environment.trim())) {
    errors.push("`Environment:` metadata is required under `### Narrated verification`.");
  }

  const behaviorRows = [];
  if (!isNotApplicable) {
    if (!behaviorSection) {
      errors.push("Missing `### Demonstrated behavior` table in PR description.");
    } else {
      const tableLines = behaviorSection
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter((line) => line.startsWith("|") && line.endsWith("|"));

      for (const line of tableLines) {
        const cells = line
          .slice(1, -1)
          .split("|")
          .map((c) => c.trim());
        if (cells.length < 3) continue;
        if (/^Acceptance criterion$/i.test(cells[0])) continue;
        if (cells.every((c) => /^:?-{3,}:?$/.test(c))) continue;
        if (!cells[0] || PLACEHOLDER_RE.test(cells[0])) continue;
        behaviorRows.push({
          criterion: cells[0],
          timestamp: cells[1],
          verification: cells[2],
        });
      }

      if (behaviorRows.length === 0) {
        errors.push(
          "`### Demonstrated behavior` must contain at least one verified acceptance criterion row.",
        );
      } else {
        let passedRows = 0;
        for (const row of behaviorRows) {
          if (!isValidTimestamp(row.timestamp)) {
            errors.push(
              `Demonstrated behavior row "${sanitizeSnippet(row.criterion)}" has invalid timestamp "${sanitizeSnippet(row.timestamp)}" (expected valid MM:SS).`,
            );
          }
          const verdict = row.verification.trim();
          const isNegatedPass =
            /\b(?:not|un|never|did not|didn't)\s+pass/i.test(verdict) || /\bbypass/i.test(verdict);
          if (/\bfail/i.test(verdict) || isNegatedPass) {
            errors.push(
              `Demonstrated behavior row "${sanitizeSnippet(row.criterion)}" did not pass: ${sanitizeSnippet(verdict)}.`,
            );
          } else if (/^(?:passed|pass|verified)\b/i.test(verdict)) {
            passedRows++;
          } else if (!/^not applicable\b/i.test(verdict)) {
            errors.push(
              `Demonstrated behavior row "${sanitizeSnippet(row.criterion)}" must report Passed (or Not applicable), got "${sanitizeSnippet(verdict)}".`,
            );
          }
        }
        if (passedRows === 0) {
          errors.push(
            "`### Demonstrated behavior` must include at least one row with Passed verification.",
          );
        }
      }
    }
  }

  if (!reviewSection) {
    errors.push("Missing `### Independent engineering review` section in PR description.");
  } else {
    const reviewers = extractField(reviewSection, "Reviewers dispatched");
    const findings = extractField(reviewSection, "Findings summary");
    const recommendation = extractField(reviewSection, "Recommendation");

    if (!isNonEmptyString(reviewers) || PLACEHOLDER_RE.test(reviewers.trim())) {
      errors.push(
        "`Reviewers dispatched:` is required under `### Independent engineering review`.",
      );
    } else {
      const reviewerTokens = reviewers
        .split(/[,;/]+/)
        .map((r) => r.trim())
        .filter(Boolean);
      if (
        reviewerTokens.length === 0 ||
        reviewerTokens.some((r) => PLACEHOLDER_REVIEWER_RE.test(r))
      ) {
        errors.push(
          "`Reviewers dispatched:` contains a placeholder/pending reviewer; complete independent review before readiness.",
        );
      }
    }

    if (!isNonEmptyString(findings)) {
      errors.push("`Findings summary:` is required under `### Independent engineering review`.");
    } else {
      const p0Matches = [...findings.matchAll(/\bP0(?:\s+open)?\s*:\s*(\d+)/gi)];
      const p1Matches = [...findings.matchAll(/\bP1(?:\s+open)?\s*:\s*(\d+)/gi)];
      if (p0Matches.length === 0 || p1Matches.length === 0) {
        errors.push("`Findings summary:` must explicitly include `P0: <n>` and `P1: <n>` counts.");
      } else {
        for (const m of p0Matches) {
          if (Number(m[1]) > 0) {
            errors.push(`Blocking P0 findings remain open (${m[1]}).`);
          }
        }
        for (const m of p1Matches) {
          if (Number(m[1]) > 0) {
            errors.push(`Blocking P1 findings remain open (${m[1]}).`);
          }
        }
      }
      const p2OpenMatches = [...findings.matchAll(/\bP2\s+open\s*:\s*(\d+)/gi)];
      for (const m of p2OpenMatches) {
        if (
          Number(m[1]) > 0 &&
          (!/\baccepted\b/i.test(findings) || /\b(?:not|un)[\s-]*accepted\b/i.test(findings))
        ) {
          errors.push(
            `Open P2 findings (${m[1]}) require resolution or explicit human acceptance in Findings summary.`,
          );
        }
      }
    }

    if (!isValidRecommendation(recommendation)) {
      errors.push(
        `Independent engineering review \`Recommendation:\` must explicitly approve readiness (e.g. Approved / Changes verified), got "${sanitizeSnippet(recommendation)}".`,
      );
    }
  }

  const checkLines = [];
  if (!checksSection) {
    errors.push("Missing `### Automated checks` section in PR description.");
  } else {
    const lines = checksSection
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => /^[-*]\s+/.test(l));

    for (const line of lines) {
      if (/<command>/i.test(line)) {
        errors.push("`### Automated checks` still contains the `<command>` template placeholder.");
        continue;
      }
      checkLines.push(line);

      if (/^[-*]\s*\[\s*\]/.test(line)) {
        errors.push(`Unchecked automated check item: ${sanitizeSnippet(line)}`);
        continue;
      }
      if (!/^[-*]\s*\[[xX]\]\s+/.test(line)) {
        errors.push(
          `Automated check must use checked task syntax \`- [x] ...\`: ${sanitizeSnippet(line)}`,
        );
        continue;
      }

      // Inspect outcome text outside inline code spans so command names like `error.test.ts` do not trigger false failures.
      const withoutCode = line
        .replace(/^[-*]\s*\[[xX]\]\s+/, "")
        .replace(/`[^`]*`/g, " ")
        .replace(/\b0\s+(?:failed|errors?)\b/gi, " ")
        .replace(/\bno\s+errors?\b/gi, " ");

      if (
        /\b(?:fail|failed|failing|failure|error|errored|crashed|timed?\s*out|timeout|skipped|not\s+run|pending|todo|tbd|exit\s+(?:code\s+)?[1-9]\d*)\b/i.test(
          withoutCode,
        )
      ) {
        errors.push(`Failed or incomplete automated check reported: ${sanitizeSnippet(line)}`);
      } else if (!/\b(?:passed|pass|ok|succeeded|exit\s+(?:code\s+)?0)\b/i.test(withoutCode)) {
        errors.push(
          `Automated check must state an explicit passing outcome: ${sanitizeSnippet(line)}`,
        );
      }
    }

    if (checkLines.length === 0) {
      errors.push("`### Automated checks` must list at least one executed check and its result.");
    }
  }

  if (!isNonEmptyString(limitationsSection) || PLACEHOLDER_RE.test(limitationsSection.trim())) {
    errors.push("Missing `### Known limitations` section (write `None.` if no limitations apply).");
  }

  return {
    ok: errors.length === 0,
    errors,
    warnings,
    parsed: {
      recording,
      isNotApplicable,
      notApplicableReason,
      commit,
      capturedAt,
      surface,
      environment,
      behaviorRows,
      checkCount: checkLines.length,
    },
  };
}

/**
 * Formats an evidence manifest into the canonical PR description markdown block.
 * @param {Record<string, any>} manifest
 * @param {{ recordingReference?: string }} [options]
 */
export function renderPrEvidenceMarkdown(manifest, options = {}) {
  const recordingLine = manifest.applicable
    ? options.recordingReference ||
      `Playable MP4 attached in review thread (\`${manifest.artifacts?.finalVideo ?? "demo.mp4"}\`, ${manifest.video?.width}x${manifest.video?.height} @ ${manifest.video?.fps}fps H.264/AAC, ${manifest.video?.durationSec}s, TTS: ${manifest.video?.ttsProvider}/${manifest.video?.ttsVoice})`
    : `Not applicable: ${manifest.notApplicableReason}`;

  const behaviorRows = (manifest.acceptanceCriteria ?? [])
    .map((item) => {
      const label =
        item.status === "passed"
          ? "Passed"
          : item.status === "not_applicable"
            ? "Not applicable"
            : "Failed";
      return `| ${item.criterion} | ${item.timestamp} | ${label} |`;
    })
    .join("\n");

  const review = manifest.reviewReport ?? {};
  const p2Open = Number(review.p2OpenCount ?? 0);
  const p2Detail =
    review.p2Acceptance ||
    review.p2Summary ||
    (p2Open === 0 ? "all resolved" : "acceptance required");

  const checkLines = (manifest.automatedChecks ?? [])
    .map((check) => {
      const box = check.status === "passed" ? "x" : " ";
      const outcome = check.status === "passed" ? "Passed" : "Failed";
      const detail = check.summary ? ` (${check.summary})` : "";
      return `- [${box}] \`${check.command}\` — ${outcome}${detail}`;
    })
    .join("\n");

  const limitationsBlock =
    Array.isArray(manifest.limitations) && manifest.limitations.length > 0
      ? manifest.limitations.map((item) => `- ${item}`).join("\n")
      : "None.";

  return [
    "### Narrated verification",
    "",
    `- **Recording**: ${recordingLine}`,
    `- **Commit**: \`${manifest.commitSha}\``,
    `- **Captured at**: \`${manifest.capturedAt}\``,
    `- **Surface / route**: ${manifest.app} (${(manifest.routes ?? []).join(", ")})`,
    `- **Environment**: ${manifest.testEnvironment}`,
    "",
    "### Demonstrated behavior",
    "",
    "| Acceptance criterion | Timestamp | Verification |",
    "| --- | --- | --- |",
    behaviorRows,
    "",
    "### Independent engineering review",
    "",
    `- **Reviewers dispatched**: ${(review.reviewers ?? []).join(", ")}`,
    `- **Findings summary**: P0: ${review.p0Count ?? 0}, P1: ${review.p1Count ?? 0}, P2 open: ${p2Open} (${p2Detail}), P3: ${review.p3Count ?? 0}`,
    `- **Recommendation**: ${review.recommendation ?? "Pending independent engineering review"}`,
    "",
    "### Automated checks",
    "",
    checkLines,
    "",
    "### Known limitations",
    "",
    limitationsBlock,
    "",
  ].join("\n");
}

export function readJsonStrict(filePath) {
  const raw = fs.readFileSync(filePath, "utf8");
  return JSON.parse(raw);
}
