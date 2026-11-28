import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { createRequire } from "node:module";

import {
  clearHighlight,
  clickLocatorWithIndicator,
  highlightLocator,
  installOverlay,
  moveCursorTo,
  setRestrainedZoom,
} from "../overlay.mjs";

const APP_PORT = 4317;
const FAKE_API_PORT = 4318;
const APP_ORIGIN = `http://127.0.0.1:${APP_PORT}`;
const FAKE_API_ORIGIN = `http://127.0.0.1:${FAKE_API_PORT}`;

export const SCENARIO_META = {
  id: "rowboat-www-connectors",
  app: "clients/apps/web",
  routes: ["/app/settings?settings=connections", "/api/connectors/oauth/callback", "/app/report"],
  testEnvironment:
    "Isolated Next.js 16 production server (127.0.0.1:4317) + seeded fake-rowboat-api.mjs (127.0.0.1:4318)",
  limitations: [
    "Captured against isolated deterministic fake-rowboat-api.mjs rather than live WorkOS or Google OAuth credentials.",
  ],
  beats: [
    {
      id: "initial-connections",
      criterion:
        "Connections page displays disconnected Google state and disables unconfigured connectors",
      route: "/app/settings?settings=connections",
      narration:
        "Here's the Connections screen running locally against the seeded test API. Google starts disconnected, and the disabled connector stays locked so users can't launch an unconfigured OAuth flow.",
    },
    {
      id: "connect-google-oauth",
      criterion:
        "Connect Google completes hosted OAuth claim and renders Active, Healthy status with granted scopes",
      route: "/app/settings?settings=connections",
      narration:
        "Clicking Connect Google walks through the hosted OAuth callback and claims the one-time ticket. The status updates to Active and Healthy, permissions show Read email evidence, and the backend confirms ticket one was consumed with bearer auth.",
    },
    {
      id: "replay-and-error-safety",
      criterion:
        "Replayed, expired, and anonymous OAuth callbacks fail safely without retaining one-time tickets",
      route: "/api/connectors/oauth/callback",
      narration:
        "Next, we check replay and expiry edge cases. Replaying ticket one is rejected because the link was already used, and an expired ticket fails safely too. We also verify via HTTP that an anonymous callback returns status 303 to sign in without keeping the ticket.",
    },
    {
      id: "open-promises-report",
      criterion: "Open Promises report renders completed scan commitments and export controls",
      route: "/app/report?scan=00000000-0000-4000-8000-000000000001",
      narration:
        "Finally, on the Open Promises report, the completed scan renders the seeded commitments, including Send the revised proposal for Acme Corp, alongside the report download control. All browser and API assertions passed on this commit.",
    },
  ],
};

function isPortOpen(port, host = "127.0.0.1") {
  return new Promise((resolve) => {
    const socket = net.createConnection({ port, host });
    socket.once("connect", () => {
      socket.destroy();
      resolve(true);
    });
    socket.once("error", () => {
      socket.destroy();
      resolve(false);
    });
  });
}

function readLogTail(logPath, maxChars = 1500) {
  try {
    const raw = fs.readFileSync(logPath, "utf8");
    return raw.length > maxChars ? raw.slice(-maxChars) : raw;
  } catch {
    return "(no log output)";
  }
}

function isChildRunning(child) {
  return Boolean(child) && child.exitCode === null && child.signalCode === null;
}

async function waitForHttp(url, label, child, logPath, timeoutMs = 45_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (child && !isChildRunning(child)) {
      throw new Error(
        `${label} exited early (code=${child.exitCode}, signal=${child.signalCode}) before becoming healthy.\nLog tail:\n${readLogTail(logPath)}`,
      );
    }
    try {
      const res = await fetch(url);
      if (res.ok) return;
    } catch {
      // Server still booting
    }
    await new Promise((resolve) => setTimeout(resolve, 350));
  }
  throw new Error(`Timed out waiting for ${label} at ${url}.\nLog tail:\n${readLogTail(logPath)}`);
}

function killGroup(child, signal) {
  if (!isChildRunning(child)) return;
  try {
    process.kill(-child.pid, signal);
  } catch {
    try {
      child.kill(signal);
    } catch {
      // Already exited
    }
  }
}

async function stopChildGracefully(child, graceMs = 3000) {
  if (!isChildRunning(child)) return;
  killGroup(child, "SIGTERM");
  const deadline = Date.now() + graceMs;
  while (isChildRunning(child) && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  if (isChildRunning(child)) {
    killGroup(child, "SIGKILL");
  }
}

function resolveWebAppDir(repoRoot) {
  const candidates = ["clients/apps/web", "apps/rowboat-www"];
  for (const rel of candidates) {
    const abs = path.join(repoRoot, rel);
    if (fs.existsSync(path.join(abs, "package.json"))) {
      return { rel, abs };
    }
  }
  throw new Error(`Could not locate web app directory (tried ${candidates.join(", ")}).`);
}

function loadPlaywright(webAppDir) {
  const wwwPkg = path.join(webAppDir, "package.json");
  const requireFromWww = createRequire(wwwPkg);
  try {
    return requireFromWww("playwright-core");
  } catch {
    return requireFromWww("@playwright/test");
  }
}

function resolveChromeExecutable() {
  const candidates = [
    process.env.PLAYWRIGHT_CHROME_PATH,
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
  ].filter(Boolean);
  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) return candidate;
  }
  return undefined;
}

async function waitForTextVisible(page, textOrRegex, timeoutMs = 15_000) {
  const loc =
    textOrRegex instanceof RegExp
      ? page.getByText(textOrRegex).first()
      : page.getByText(textOrRegex, { exact: false }).first();
  await loc.waitFor({ state: "visible", timeout: timeoutMs });
  return loc;
}

/**
 * Runs the real isolated Next.js 16 + fake-rowboat-api.mjs workflow and captures
 * per-beat 1920x1080 raw video segments + Playwright trace + strict assertions.
 */
export async function runRowboatWwwConnectorsScenario({
  repoRoot,
  outDir,
  narrationTimings,
  reuseServers = false,
}) {
  const { rel: webAppRel, abs: wwwDir } = resolveWebAppDir(repoRoot);
  const buildIdPath = path.join(wwwDir, ".next/BUILD_ID");
  if (!fs.existsSync(buildIdPath)) {
    throw new Error(
      `${webAppRel} has not been built yet (${buildIdPath} missing). Run \`cd ${webAppRel} && npm run build\` first.`,
    );
  }

  const rawDir = path.join(outDir, "raw");
  const logsDir = path.join(outDir, "logs");
  fs.mkdirSync(rawDir, { recursive: true });
  fs.mkdirSync(logsDir, { recursive: true });

  const children = [];
  const logFds = [];
  let browser;
  let cleanedUp = false;

  const cleanupSync = () => {
    if (cleanedUp) return;
    cleanedUp = true;
    for (const child of [...children].reverse()) {
      killGroup(child, "SIGTERM");
    }
  };

  const onSignal = (signal) => {
    cleanupSync();
    process.exit(signal === "SIGINT" ? 130 : 143);
  };
  process.once("SIGINT", onSignal);
  process.once("SIGTERM", onSignal);

  const startServer = (name, command, args, env) => {
    const logPath = path.join(logsDir, `${name}.log`);
    const fd = fs.openSync(logPath, "w");
    logFds.push(fd);
    const child = spawn(command, args, {
      cwd: wwwDir,
      detached: true,
      env: { ...process.env, ...env },
      stdio: ["ignore", fd, fd],
    });
    children.push(child);
    return { child, logPath };
  };

  try {
    const apiPortBusy = await isPortOpen(FAKE_API_PORT);
    const appPortBusy = await isPortOpen(APP_PORT);

    if (!reuseServers && (apiPortBusy || appPortBusy)) {
      const busyList = [
        apiPortBusy ? `127.0.0.1:${FAKE_API_PORT}` : null,
        appPortBusy ? `127.0.0.1:${APP_PORT}` : null,
      ]
        .filter(Boolean)
        .join(", ");
      throw new Error(
        `Refusing to record against pre-existing server(s) on ${busyList} to avoid capturing a stale build. Stop those listeners first or pass --reuse-servers explicitly.`,
      );
    }

    if (!apiPortBusy) {
      const { child, logPath } = startServer(
        "fake-rowboat-api",
        "node",
        ["e2e/fake-rowboat-api.mjs"],
        {},
      );
      await waitForHttp(`${FAKE_API_ORIGIN}/__test/state`, "fake-rowboat-api", child, logPath);
    }

    if (!appPortBusy) {
      const { child, logPath } = startServer(
        "rowboat-www",
        "npm",
        ["run", "start", "--", "--hostname", "127.0.0.1", "--port", String(APP_PORT)],
        {
          ROWBOAT_WWW_API_PROXY_URL: FAKE_API_ORIGIN,
          ROWBOAT_WWW_PUBLIC_API_BASE_URL: FAKE_API_ORIGIN,
          ROWBOAT_WWW_PUBLIC_APP_URL: APP_ORIGIN,
          ROWBOAT_WWW_SESSION_SECRET: "playwright-rowboat-www-session-secret-0001",
        },
      );
      await waitForHttp(`${APP_ORIGIN}/healthz`, "rowboat-www Next.js server", child, logPath);
    }

    const pw = loadPlaywright(wwwDir);
    const executablePath = resolveChromeExecutable();
    browser = await pw.chromium.launch({
      headless: true,
      ...(executablePath ? { executablePath } : {}),
      args: ["--no-sandbox", "--disable-dev-shm-usage"],
    });

    // Reset deterministic fake backend and acquire a sealed WorkOS session once.
    const resetRes = await fetch(`${FAKE_API_ORIGIN}/__test/reset`);
    assert.equal(resetRes.status, 200, "Failed to reset fake-rowboat-api state");

    const authContext = await browser.newContext({ viewport: { width: 1920, height: 1080 } });
    let storageState;
    try {
      const authPage = await authContext.newPage();
      await authPage.goto(
        `${APP_ORIGIN}/api/auth/workos/login?return_to=${encodeURIComponent("/app/settings?settings=connections")}`,
        { waitUntil: "networkidle" },
      );
      await waitForTextVisible(authPage, "Not connected");
      storageState = await authContext.storageState();
    } finally {
      await authContext.close();
    }

    const durationFor = (beatId) => {
      const seg = (narrationTimings?.segments ?? []).find((s) => s.id === beatId);
      return seg ? Number(seg.durationSec) : 8;
    };

    const capturedBeats = [];

    const recordBeat = async (index, beatMeta, { keepTrace = false }, runner) => {
      const beatRawDir = path.join(rawDir, `beat-${String(index + 1).padStart(2, "0")}`);
      fs.mkdirSync(beatRawDir, { recursive: true });
      const context = await browser.newContext({
        viewport: { width: 1920, height: 1080 },
        storageState,
        recordVideo: { dir: beatRawDir, size: { width: 1920, height: 1080 } },
      });
      await context.tracing.start({ screenshots: true, snapshots: true, sources: false });
      const page = await context.newPage();
      const video = page.video();

      let assertion;
      let failed = false;
      try {
        const startedAt = Date.now();
        assertion = await runner(page, context);

        const elapsedSec = (Date.now() - startedAt) / 1000;
        const targetHoldSec = Math.min(durationFor(beatMeta.id), Math.max(elapsedSec + 0.9, 3.5));
        const remainingMs = Math.max(450, Math.round((targetHoldSec - elapsedSec) * 1000));
        await page.waitForTimeout(remainingMs);
      } catch (err) {
        failed = true;
        throw err;
      } finally {
        if (failed) {
          await context.tracing
            .stop({ path: path.join(outDir, `trace-failed-${beatMeta.id}.zip`) })
            .catch(() => {});
        } else if (keepTrace) {
          await context.tracing.stop({ path: path.join(outDir, "trace.zip") });
        } else {
          await context.tracing.stop().catch(() => {});
        }
        await context.close();
      }

      const videoPath = await video.path();
      const stableRawPath = path.join(
        rawDir,
        `${String(index + 1).padStart(2, "0")}-${beatMeta.id}.webm`,
      );
      fs.renameSync(videoPath, stableRawPath);

      const seg = (narrationTimings?.segments ?? []).find((s) => s.id === beatMeta.id);
      if (!seg?.wavPath) {
        throw new Error(`Missing synthesized narration audio for beat "${beatMeta.id}".`);
      }
      capturedBeats.push({
        id: beatMeta.id,
        criterion: beatMeta.criterion,
        narration: beatMeta.narration,
        assertion,
        status: "passed",
        rawVideoPath: stableRawPath,
        audioWavPath: seg.wavPath,
      });
    };

    // Beat 1: Initial disconnected state + disabled connector guard
    await recordBeat(0, SCENARIO_META.beats[0], { keepTrace: false }, async (page) => {
      await page.goto(`${APP_ORIGIN}/app/settings?settings=connections`, {
        waitUntil: "networkidle",
      });
      await installOverlay(page);
      const googleCard = page.getByTestId("connector-google");
      await googleCard.waitFor({ state: "visible" });
      await googleCard.getByText("Not connected").waitFor({ state: "visible" });

      const disabledBtn = page.getByRole("button", { name: "Connect Disabled Connector" });
      assert.equal(
        await disabledBtn.isDisabled(),
        true,
        "Disabled connector button must be disabled",
      );

      const googleBox = await highlightLocator(page, googleCard, {
        stepNumber: 1,
        label: "Google starts disconnected",
      });
      if (googleBox) {
        await moveCursorTo(
          page,
          googleBox.x + googleBox.width * 0.7,
          googleBox.y + googleBox.height * 0.5,
          650,
        );
      }
      await page.waitForTimeout(1600);

      const disabledBox = await highlightLocator(page, disabledBtn, {
        stepNumber: 1,
        label: "Unconfigured connector stays disabled",
        placement: "right",
      });
      if (disabledBox) {
        await moveCursorTo(
          page,
          disabledBox.x + disabledBox.width / 2,
          disabledBox.y + disabledBox.height / 2,
          650,
        );
      }
      await page.waitForTimeout(1200);
      return "Verified connector-google shows 'Not connected' and 'Connect Disabled Connector' is disabled.";
    });

    // Beat 2: Connect Google OAuth flow + active/healthy badges + backend ticket claim assertion
    await recordBeat(1, SCENARIO_META.beats[1], { keepTrace: true }, async (page) => {
      await page.goto(`${APP_ORIGIN}/app/settings?settings=connections`, {
        waitUntil: "networkidle",
      });
      await installOverlay(page);
      const googleCard = page.getByTestId("connector-google");
      const connectBtn = googleCard.getByRole("button", { name: "Connect Google" });
      await connectBtn.waitFor({ state: "visible" });

      await clickLocatorWithIndicator(page, connectBtn, {
        stepNumber: 2,
        label: "Connect Google (hosted OAuth)",
        placement: "right",
      });

      const statusBanner = page.getByRole("status");
      await statusBanner.waitFor({ state: "visible" });
      const statusText = (await statusBanner.textContent()) || "";
      assert.match(statusText, /Connected\./, `Expected Connected. banner, got: ${statusText}`);
      await googleCard.getByText("Active").waitFor({ state: "visible" });
      await googleCard.getByText("Healthy").waitFor({ state: "visible" });
      await googleCard.getByText("Permissions: Read email evidence").waitFor({ state: "visible" });
      assert.equal(page.url(), `${APP_ORIGIN}/app/settings?settings=connections`);

      const state = await (await fetch(`${FAKE_API_ORIGIN}/__test/state`)).json();
      assert.deepEqual(state.consumedTickets, ["ticket-1"]);
      assert.match(String(state.lastClaimAuthorization), /^Bearer /);

      await installOverlay(page);
      const activeBox = await highlightLocator(page, googleCard, {
        stepNumber: 2,
        label: "Active · Healthy · ticket-1 claimed",
      });
      if (activeBox) {
        await setRestrainedZoom(page, activeBox, 1.14);
        await moveCursorTo(
          page,
          activeBox.x + activeBox.width * 0.45,
          activeBox.y + activeBox.height * 0.55,
          700,
        );
      }
      await page.waitForTimeout(2400);
      await setRestrainedZoom(page, null, 1.0);
      return "Verified OAuth claim: status='Connected.', card='Active'/'Healthy', scope='Read email evidence', backend consumedTickets=['ticket-1'] with Bearer auth.";
    });

    // Beat 3: Replay, expiry, and anonymous callback edge cases
    await recordBeat(2, SCENARIO_META.beats[2], { keepTrace: false }, async (page) => {
      await page.goto(
        `${APP_ORIGIN}/api/connectors/oauth/callback?connector=google&status=success&session=ticket-1`,
        { waitUntil: "networkidle" },
      );
      await installOverlay(page);
      const replayBanner = await waitForTextVisible(page, /connection link was already used/i);
      assert.equal(page.url(), `${APP_ORIGIN}/app/settings?settings=connections`);
      const replayBox = await highlightLocator(page, replayBanner, {
        stepNumber: 3,
        label: "Replay rejected safely",
      });
      if (replayBox) {
        await moveCursorTo(
          page,
          replayBox.x + replayBox.width * 0.5,
          replayBox.y + replayBox.height * 0.5,
          650,
        );
      }
      await page.waitForTimeout(2400);

      await page.goto(
        `${APP_ORIGIN}/api/connectors/oauth/callback?connector=google&status=success&session=expired-ticket`,
        { waitUntil: "networkidle" },
      );
      await installOverlay(page);
      const expiredBanner = await waitForTextVisible(page, /connection link expired/i);
      assert.equal(page.url(), `${APP_ORIGIN}/app/settings?settings=connections`);
      const expiredBox = await highlightLocator(page, expiredBanner, {
        stepNumber: 3,
        label: "Expired ticket rejected safely",
      });
      if (expiredBox) {
        await moveCursorTo(
          page,
          expiredBox.x + expiredBox.width * 0.5,
          expiredBox.y + expiredBox.height * 0.5,
          650,
        );
      }

      const anonRes = await fetch(
        `${APP_ORIGIN}/api/connectors/oauth/callback?connector=google&status=success&session=secret-ticket`,
        { redirect: "manual" },
      );
      assert.equal(anonRes.status, 303, "Anonymous callback must return HTTP 303");
      const locHeader = anonRes.headers.get("location") || "";
      assert.ok(locHeader.includes("/sign-in"), `Expected redirect to /sign-in, got ${locHeader}`);
      assert.ok(
        !locHeader.includes("secret-ticket"),
        "Redirect URL must not retain one-time ticket",
      );

      await page.waitForTimeout(1600);
      return "Verified replay rejection ('already used'), expiry rejection ('expired'), and anonymous HTTP 303 redirect to /sign-in without retaining one-time ticket.";
    });

    // Beat 4: Completed Open Promises scan report
    await recordBeat(3, SCENARIO_META.beats[3], { keepTrace: false }, async (page) => {
      const claimRes = await fetch(`${FAKE_API_ORIGIN}/v1/google-oauth/claim`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ session: "native-google-ticket" }),
      });
      assert.equal(claimRes.status, 200);

      await page.goto(`${APP_ORIGIN}/app/report?scan=00000000-0000-4000-8000-000000000001`, {
        waitUntil: "networkidle",
      });
      await installOverlay(page);

      const header = page.locator("main > header");
      await header.waitFor({ state: "visible" });
      assert.equal((await header.textContent())?.trim(), "Open promises");
      await waitForTextVisible(page, "We promised");
      const proposalItem = await waitForTextVisible(page, "Send the revised proposal");
      const downloadBtn = page.getByRole("button", { name: "Download the report" });
      await downloadBtn.waitFor({ state: "visible" });

      const proposalBox = await highlightLocator(page, proposalItem, {
        stepNumber: 4,
        label: "Seeded commitment rendered",
        placement: "right",
      });
      if (proposalBox) {
        await setRestrainedZoom(page, proposalBox, 1.12);
        await moveCursorTo(
          page,
          proposalBox.x + proposalBox.width * 0.5,
          proposalBox.y + proposalBox.height * 0.5,
          650,
        );
      }
      await page.waitForTimeout(2200);
      await setRestrainedZoom(page, null, 1.0);

      const downloadBox = await highlightLocator(page, downloadBtn, {
        stepNumber: 4,
        label: "Export report control ready",
        placement: "right",
      });
      if (downloadBox) {
        await moveCursorTo(
          page,
          downloadBox.x + downloadBox.width / 2,
          downloadBox.y + downloadBox.height / 2,
          650,
        );
      }
      await page.waitForTimeout(1200);
      await clearHighlight(page);
      return "Verified Open promises report renders 'We promised', 'Send the revised proposal', and 'Download the report' button.";
    });

    return {
      app: webAppRel,
      routes: SCENARIO_META.routes,
      testEnvironment: SCENARIO_META.testEnvironment,
      limitations: SCENARIO_META.limitations,
      beats: capturedBeats,
      traceFile: "trace.zip",
    };
  } finally {
    process.removeListener("SIGINT", onSignal);
    process.removeListener("SIGTERM", onSignal);
    cleanedUp = true;
    if (browser) {
      await browser.close().catch(() => {});
    }
    for (const child of [...children].reverse()) {
      await stopChildGracefully(child);
    }
    for (const fd of logFds) {
      try {
        fs.closeSync(fd);
      } catch {
        // Ignore
      }
    }
  }
}
