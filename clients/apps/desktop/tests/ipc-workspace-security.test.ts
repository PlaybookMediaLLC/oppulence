import assert from "node:assert/strict";
import test from "node:test";

import {
  assertAllowedRendererWorkspaceRelPath,
  formatMcpSpawnDialogDetail,
  getShellOpenBlockReason,
  normalizeRendererWorkspaceRelPath,
  sanitizeNativeDialogText,
  validateRendererConfigWriteContent,
} from "../apps/main/src/ipc-workspace-security.ts";
import { normalizeNavigationTarget } from "../apps/main/src/browser/navigation.ts";

test("blocks non-canonical renderer workspace paths to credentials, runs, .trash, and .git", () => {
  const blockedReadPaths = [
    "config/oauth.json",
    "config//oauth.json",
    "config/./oauth.json",
    "config/oauth.json.invalid-1234",
    "config/oauth-clients.json",
    "config/exa-search.json",
    "runs/r1.jsonl",
    ".trash/123-config/oauth.json",
    "knowledge/.git/config",
    "../outside.txt",
    "/etc/passwd",
  ];
  for (const p of blockedReadPaths) {
    assert.throws(
      () => assertAllowedRendererWorkspaceRelPath(p, "read", "linux"),
      `expected read blocked for ${p}`,
    );
  }

  // Windows ADS and trailing dots/spaces blocked on win32
  for (const winPath of [
    "config/oauth.json.",
    "config/oauth.json::$DATA",
    "runs./r1.jsonl",
    "knowledge/note.md ",
  ]) {
    assert.throws(
      () => assertAllowedRendererWorkspaceRelPath(winPath, "read", "win32"),
      `expected win32 path blocked: ${winPath}`,
    );
  }

  // Structural mutations (rename/remove/copy) on config/ or config/** are blocked
  for (const p of ["config", "config/mcp.json", "config/security.json", "config//security.json"]) {
    assert.throws(
      () => assertAllowedRendererWorkspaceRelPath(p, "mutate-structure", "linux"),
      `expected structural mutation blocked for ${p}`,
    );
  }

  // Legitimate workspace note paths pass
  assert.equal(
    normalizeRendererWorkspaceRelPath("knowledge//./note.md", "linux"),
    "knowledge/note.md",
  );
  assert.equal(
    assertAllowedRendererWorkspaceRelPath("knowledge/note.md", "write", "linux"),
    "knowledge/note.md",
  );
  assert.equal(
    assertAllowedRendererWorkspaceRelPath("config/mcp.json", "write", "linux"),
    "config/mcp.json",
  );
});

test("validates config/mcp.json and config/security.json renderer writes with Zod", () => {
  const validators = {
    isSensitiveOrBroadExternalGrantPrefix: (prefix: string) =>
      prefix === "/" || prefix.includes(".ssh"),
    isProtectedWorkspacePath: (target: string) => target.includes("config"),
  };

  assert.equal(
    validateRendererConfigWriteContent(
      "config/mcp.json",
      JSON.stringify({
        mcpServers: { demo: { type: "stdio", command: "node", args: ["srv.js"] } },
      }),
      validators,
    ),
    true,
  );
  assert.throws(() =>
    validateRendererConfigWriteContent("config/mcp.json", "{bad json", validators),
  );
  assert.throws(() =>
    validateRendererConfigWriteContent(
      "config/mcp.json",
      JSON.stringify({ mcpServers: { bad: {} } }),
      validators,
    ),
  );

  // security.json rejects invalid schema, wildcard "*", broad/sensitive prefixes, and protected workspace paths
  assert.throws(() =>
    validateRendererConfigWriteContent(
      "config/security.json",
      '{"allowedCommands":["*"]}',
      validators,
    ),
  );
  assert.throws(() =>
    validateRendererConfigWriteContent(
      "config/security.json",
      JSON.stringify({ allowedFileAccess: [{ operation: "read", pathPrefix: "/" }] }),
      validators,
    ),
  );
  assert.throws(() =>
    validateRendererConfigWriteContent(
      "config/security.json",
      JSON.stringify({ allowedFileAccess: [{ operation: "write", pathPrefix: "/ws/config" }] }),
      validators,
    ),
  );
  assert.equal(
    validateRendererConfigWriteContent(
      "config/security.json",
      JSON.stringify({
        allowedCommands: ["rg"],
        allowedFileAccess: [{ operation: "read", pathPrefix: "/safe/docs" }],
      }),
      validators,
    ),
    false,
  );
});

test("blocks dangerous shell:openPath launcher extensions, extensionless POSIX executables, and Windows UNC/ADS/device paths", () => {
  const regularFile = { isFile: () => true, mode: 0o644 };
  const execFile = { isFile: () => true, mode: 0o755 };

  for (const p of [
    "/tmp/evil.terminal",
    "/tmp/evil.desktop",
    "/tmp/evil.AppImage",
    "/tmp/evil.webloc",
    "/tmp/evil.inetloc",
    "/tmp/evil.action",
    "/tmp/evil.zsh",
    "/tmp/evil.scptd",
  ]) {
    assert.ok(getShellOpenBlockReason(p, p, regularFile, "darwin"), `expected blocked: ${p}`);
  }

  // Extensionless executable file on POSIX is blocked; regular non-exec .md file is allowed
  assert.ok(getShellOpenBlockReason("/tmp/payload", "/tmp/payload", execFile, "darwin"));
  assert.equal(
    getShellOpenBlockReason("/tmp/notes.md", "/tmp/notes.md", regularFile, "darwin"),
    null,
  );

  // Windows launcher extensions, ADS, trailing dots, UNC, and device paths are blocked
  for (const wp of [
    "C:\\Users\\alice\\evil.url",
    "C:\\Users\\alice\\evil.reg",
    "C:\\Users\\alice\\evil.cpl",
    "C:\\Users\\alice\\evil.bat::$DATA",
    "C:\\Users\\alice\\evil.bat.",
    "\\\\attacker\\share\\invoice.pdf",
    "\\\\.\\PhysicalDrive0",
  ]) {
    assert.ok(
      getShellOpenBlockReason(wp, wp, regularFile, "win32"),
      `expected win32 blocked: ${wp}`,
    );
  }
});

test("sanitizes native MCP confirmation dialogs and exposes dangerous env overrides", () => {
  const sanitized = sanitizeNativeDialogText("demo\u202Eserver\u{E0069}");
  assert.ok(sanitized.includes("[U+202E]"));
  assert.ok(sanitized.includes("[U+E0069]"));

  const detail = formatMcpSpawnDialogDetail({
    command: "node",
    args: ["server.js"],
    env: { NODE_OPTIONS: "--require=/tmp/pwn.js", SAFE_VAR: "ok" },
  });
  assert.ok(detail.includes("NODE_OPTIONS"));
  assert.ok(detail.includes("execution-sensitive env vars"));
  assert.ok(detail.includes("SAFE_VAR=ok"));
});

test("browser normalizeNavigationTarget enforces strict http/https allowlist and blocks metadata IPs", () => {
  assert.equal(normalizeNavigationTarget("https://example.com/path"), "https://example.com/path");
  for (const bad of [
    "file:/etc/passwd",
    "file:///etc/passwd",
    "app://-/index.html",
    "view-source:https://example.com",
    "javascript:alert(1)",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::ffff:169.254.169.254]/",
    "http://metadata.google.internal/",
  ]) {
    assert.throws(() => normalizeNavigationTarget(bad), `expected navigation blocked: ${bad}`);
  }
});
