import path from "node:path";
import { McpServerConfig } from "@x/shared/mcp";
import { SecurityConfigFileSchema } from "@x/shared/security";

const BLOCKED_RENDERER_CONFIG_FILE_PREFIXES = [
  "config/oauth.json",
  "config/oauth-clients.json",
  "config/exa-search.json",
] as const;

const BLOCKED_SHELL_OPEN_EXTENSIONS = new Set([
  ".sh",
  ".bash",
  ".zsh",
  ".csh",
  ".command",
  ".app",
  ".action",
  ".terminal",
  ".inetloc",
  ".webloc",
  ".mpkg",
  ".desktop",
  ".appimage",
  ".exe",
  ".bat",
  ".cmd",
  ".ps1",
  ".ps2",
  ".psm1",
  ".psd1",
  ".vbs",
  ".vbe",
  ".js",
  ".mjs",
  ".cjs",
  ".jse",
  ".wsf",
  ".wsh",
  ".py",
  ".pyw",
  ".rb",
  ".pl",
  ".jar",
  ".msi",
  ".msp",
  ".dmg",
  ".pkg",
  ".scr",
  ".com",
  ".pif",
  ".hta",
  ".lnk",
  ".url",
  ".reg",
  ".cpl",
  ".msc",
  ".chm",
  ".inf",
  ".scf",
  ".appref-ms",
  ".scpt",
  ".scptd",
  ".applescript",
  ".osascript",
  ".workflow",
]);

const DANGEROUS_DIALOG_ENV_KEYS = new Set([
  "NODE_OPTIONS",
  "NODE_PATH",
  "LD_PRELOAD",
  "LD_LIBRARY_PATH",
  "DYLD_INSERT_LIBRARIES",
  "DYLD_LIBRARY_PATH",
  "DYLD_FRAMEWORK_PATH",
  "PYTHONPATH",
  "PYTHONSTARTUP",
  "BASH_ENV",
  "ENV",
  "PATH",
  "COMSPEC",
  "PATHEXT",
  "OPENSSL_CONF",
  "OPENSSL_ENGINES",
  "OPENSSL_MODULES",
  "GIT_SSH_COMMAND",
  "GIT_PAGER",
  "GIT_EDITOR",
  "SSH_ASKPASS",
  "SUDO_ASKPASS",
  "PSMODULEPATH",
]);

const DANGEROUS_DIALOG_ENV_PREFIXES = [
  "LD_",
  "DYLD_",
  "NODE_",
  "NPM_CONFIG_",
  "PYTHON",
  "PIP_",
  "UV_",
  "GIT_",
  "JAVA_",
  "_JAVA_",
  "ELECTRON_",
] as const;

function isHiddenOrControlCodePoint(cp: number): boolean {
  return (
    (cp >= 0x0000 && cp <= 0x0008) ||
    (cp >= 0x000b && cp <= 0x001f) ||
    (cp >= 0x007f && cp <= 0x009f) ||
    cp === 0x00ad ||
    cp === 0x034f ||
    cp === 0x061c ||
    cp === 0x115f ||
    cp === 0x1160 ||
    cp === 0x180e ||
    (cp >= 0x200b && cp <= 0x200f) ||
    (cp >= 0x2028 && cp <= 0x202e) ||
    (cp >= 0x2060 && cp <= 0x206f) ||
    cp === 0x2800 ||
    cp === 0x3164 ||
    (cp >= 0xfe00 && cp <= 0xfe0f) ||
    cp === 0xfeff ||
    cp === 0xffa0 ||
    (cp >= 0xfff9 && cp <= 0xfffb) ||
    (cp >= 0xe0000 && cp <= 0xe007f) ||
    (cp >= 0xe0100 && cp <= 0xe01ef)
  );
}

export function sanitizeNativeDialogText(input: string): string {
  let out = "";
  for (const ch of input) {
    const cp = ch.codePointAt(0);
    if (cp !== undefined && isHiddenOrControlCodePoint(cp)) {
      out += `[U+${cp.toString(16).toUpperCase().padStart(4, "0")}]`;
    } else {
      out += ch;
    }
  }
  return out;
}

export function formatMcpSpawnDialogDetail(requirement: {
  readonly command: string;
  readonly args: readonly string[];
  readonly env: Readonly<Record<string, string>>;
}): string {
  const cmdDisplay = sanitizeNativeDialogText([requirement.command, ...requirement.args].join(" "));
  const lines = [`Command: ${cmdDisplay}`];
  const envEntries = Object.entries(requirement.env);
  if (envEntries.length > 0) {
    const dangerousKeys: string[] = [];
    const formattedEnv: string[] = [];
    for (const [k, v] of envEntries) {
      const upper = k.toUpperCase();
      if (
        DANGEROUS_DIALOG_ENV_KEYS.has(upper) ||
        DANGEROUS_DIALOG_ENV_PREFIXES.some((prefix) => upper.startsWith(prefix))
      ) {
        dangerousKeys.push(sanitizeNativeDialogText(k));
      }
      formattedEnv.push(`${sanitizeNativeDialogText(k)}=${sanitizeNativeDialogText(v)}`);
    }
    if (dangerousKeys.length > 0) {
      lines.push(`Warning: sets execution-sensitive env vars: ${dangerousKeys.join(", ")}`);
    }
    lines.push(`Environment:\n${formattedEnv.join("\n")}`);
  }
  return lines.join("\n\n");
}

/**
 * Normalizes a workspace-relative path for renderer IPC access control.
 * Collapses repeated slashes and `/./` segments, rejects traversal (`..`),
 * absolute paths, and Windows NTFS ADS / trailing dot or space segments.
 */
export function normalizeRendererWorkspaceRelPath(
  relPath: string,
  platform: NodeJS.Platform = process.platform,
): string {
  if (relPath.includes("\0")) {
    throw new Error(`Invalid workspace path "${relPath}".`);
  }
  const rawSlash = relPath.replace(/\\/g, "/");
  if (platform === "win32") {
    for (const seg of rawSlash.split("/")) {
      if (!seg || seg === ".") continue;
      if (seg.includes(":") || /[. ]$/.test(seg)) {
        throw new Error(
          `Unsafe Windows path segment in "${relPath}" is not permitted via workspace IPC.`,
        );
      }
    }
  }
  const raw = relPath.trim();
  if (!raw) return "";
  const slashPath = raw.replace(/\\/g, "/");
  if (slashPath.startsWith("/") || /^[a-zA-Z]:/.test(slashPath)) {
    throw new Error(`Absolute path "${relPath}" is not permitted via workspace IPC.`);
  }
  const rawSegments = slashPath.split("/");
  for (const seg of rawSegments) {
    if (!seg || seg === ".") continue;
    if (seg === "..") {
      throw new Error(`Parent traversal in "${relPath}" is not permitted via workspace IPC.`);
    }
  }
  const normalized = path.posix
    .normalize(slashPath)
    .replace(/^(?:\.\/)+/, "")
    .replace(/\/+$/, "");
  if (normalized === ".") return "";
  if (normalized === ".." || normalized.startsWith("../")) {
    throw new Error(`Parent traversal in "${relPath}" is not permitted via workspace IPC.`);
  }
  return normalized.toLowerCase();
}

export type RendererWorkspaceOperation = "read" | "write" | "mutate-structure";

export function assertAllowedRendererWorkspaceRelPath(
  relPath: string,
  operation: RendererWorkspaceOperation = "read",
  platform: NodeJS.Platform = process.platform,
): string {
  const normalized = normalizeRendererWorkspaceRelPath(relPath, platform);
  if (!normalized) {
    if (operation === "mutate-structure") {
      throw new Error("Modifying the workspace root via workspace IPC is not permitted.");
    }
    return "";
  }
  const segments = normalized.split("/").filter(Boolean);
  const top = segments[0] ?? "";
  const isBlockedCredentialFile = BLOCKED_RENDERER_CONFIG_FILE_PREFIXES.some(
    (prefix) => normalized === prefix || normalized.startsWith(`${prefix}.`),
  );

  if (isBlockedCredentialFile || segments.includes(".git") || top === "runs" || top === ".trash") {
    throw new Error(
      `Access to protected workspace path "${relPath}" is not permitted via workspace IPC.`,
    );
  }

  // Prevent moving, trashing, copying, or renaming the `config/` directory or any file
  // inside `config/` via workspace:rename / workspace:copy / workspace:remove, which
  // would otherwise expose credentials via `.trash/` or bypass config write validation.
  if (operation === "mutate-structure" && top === "config") {
    throw new Error(
      `Structural mutation of protected config path "${relPath}" is not permitted via workspace IPC.`,
    );
  }

  return normalized;
}

export type SecurityGrantValidators = {
  readonly isSensitiveOrBroadExternalGrantPrefix: (prefix: string) => boolean;
  readonly isProtectedWorkspacePath: (
    targetPath: string,
    operation: "read" | "list" | "search" | "write" | "delete",
  ) => boolean;
};

/**
 * Validates renderer writes to `config/mcp.json` and `config/security.json` using
 * shared Zod schemas. Returns `true` when `config/mcp.json` was written (caller
 * must tear down cached MCP clients).
 */
export function validateRendererConfigWriteContent(
  normalizedRelPath: string,
  data: string,
  validators: SecurityGrantValidators,
): boolean {
  if (normalizedRelPath === "config/mcp.json") {
    let parsed: unknown;
    try {
      parsed = JSON.parse(data);
    } catch (err) {
      throw new Error("Invalid JSON for config/mcp.json", { cause: err });
    }
    const result = McpServerConfig.safeParse(parsed);
    if (!result.success) {
      throw new Error(`Invalid MCP configuration: ${result.error.message}`);
    }
    return true;
  }

  if (normalizedRelPath === "config/security.json") {
    let parsed: unknown;
    try {
      parsed = JSON.parse(data);
    } catch (err) {
      throw new Error("Invalid JSON for config/security.json", { cause: err });
    }
    const result = SecurityConfigFileSchema.safeParse(parsed);
    if (!result.success) {
      throw new Error(`Invalid security configuration: ${result.error.message}`);
    }
    for (const cmd of result.data.allowedCommands ?? []) {
      if (cmd.trim() === "*") {
        throw new Error('Wildcard "*" is not permitted in config/security.json');
      }
    }
    for (const entry of result.data.allowedFileAccess ?? []) {
      if (
        validators.isSensitiveOrBroadExternalGrantPrefix(entry.pathPrefix) ||
        validators.isProtectedWorkspacePath(entry.pathPrefix, entry.operation)
      ) {
        throw new Error(
          `Refusing overly broad or sensitive file access grant: "${entry.pathPrefix}"`,
        );
      }
    }
  }
  return false;
}

function extractShellOpenExtension(
  filePath: string,
  platform: NodeJS.Platform = process.platform,
): string {
  const pathImpl = platform === "win32" ? path.win32 : path.posix;
  let base = pathImpl.basename(filePath);
  if (platform === "win32") {
    const colonIdx = base.indexOf(":");
    if (colonIdx !== -1) {
      base = base.slice(0, colonIdx);
    }
    base = base.replace(/[. ]+$/, "");
  }
  return pathImpl.extname(base).toLowerCase();
}

export function isBlockedWindowsShellPath(
  inputPath: string,
  platform: NodeJS.Platform = process.platform,
): boolean {
  if (platform !== "win32") return false;
  const slash = inputPath.replace(/\\/g, "/");
  if (/^\/\/[.?]\//i.test(slash) || /^\/\/[^/?.\s][^/]*/i.test(slash)) {
    return true;
  }
  const withoutDrive = slash.replace(/^[a-z]:/i, "");
  for (const seg of withoutDrive.split("/")) {
    if (!seg || seg === "." || seg === "..") continue;
    if (seg.includes(":") || /[. ]$/.test(seg)) return true;
  }
  return false;
}

export function getShellOpenBlockReason(
  inputPath: string,
  canonicalPath: string,
  stat: { readonly isFile: () => boolean; readonly mode?: number } | null,
  platform: NodeJS.Platform = process.platform,
): string | null {
  if (
    isBlockedWindowsShellPath(inputPath, platform) ||
    isBlockedWindowsShellPath(canonicalPath, platform)
  ) {
    return "Refusing to open Windows device, UNC, ADS, or trailing-dot path";
  }
  const ext = extractShellOpenExtension(canonicalPath, platform);
  if (BLOCKED_SHELL_OPEN_EXTENSIONS.has(ext)) {
    return `Refusing to directly open executable or launcher file type "${ext}"`;
  }
  if (
    platform !== "win32" &&
    stat &&
    stat.isFile() &&
    ext === "" &&
    typeof stat.mode === "number" &&
    (stat.mode & 0o111) !== 0
  ) {
    return "Refusing to directly open extensionless executable file";
  }
  return null;
}
