import { jsonSchema, ModelMessage } from "ai";
import { withPromptCaching } from "./prompt-caching.js";
import fs from "fs";
import os from "os";
import path from "path";
import { WorkDir } from "../config/config.js";
import { Agent, ToolAttachment } from "@x/shared/agent";
import {
  AssistantContentPart,
  AssistantMessage,
  Message,
  MessageList,
  ProviderOptions,
  ToolCallPart,
  ToolMessage,
  UserMessageContext,
} from "@x/shared/message";
import { LanguageModel, stepCountIs, streamText, tool, Tool, ToolSet } from "ai";
import { z } from "zod";
import { LlmStepStreamEvent } from "@x/shared/llm-step-events";
import {
  computeStdioMcpConfigDigest,
  execTool,
  getStdioMcpSpawnRequirement,
  type McpSpawnPolicy,
} from "../application/lib/exec-tool.js";
import { McpServerDefinition, McpServerName } from "@x/shared/mcp";
import {
  AskHumanRequestEvent,
  RunEvent,
  ToolPermissionMetadata,
  ToolPermissionRequestEvent,
} from "@x/shared/runs";
import { BuiltinTools } from "../application/lib/builtin-tools.js";
import { buildCopilotAgent } from "../application/assistant/agent.js";
import { buildLiveNoteAgent } from "../knowledge/live-note/agent.js";
import { buildBackgroundTaskAgent } from "../background-tasks/agent.js";
import {
  evaluateCommandSecurity,
  extractCommandNames,
  isAlwaysRequireApprovalCommand,
  resolveCommandWorkingDir,
} from "../application/lib/command-executor.js";
import {
  getFileAccessAllowList,
  getMcpServerAllowList,
  isSameNormalizedPath,
  isAgentNotesWorkspacePath,
  isPathInsideDir,
  isProtectedWorkspacePath,
  isSensitiveOrBroadExternalGrantPrefix,
  type FileAccessGrant,
  type FileAccessOperation,
} from "../config/security.js";
import { resolveFilePathForPermission } from "../filesystem/files.js";
import container from "../di/container.js";
import { IModelConfigRepo } from "../models/repo.js";
import { createProvider } from "../models/models.js";
import { resolveProviderConfig } from "../models/defaults.js";
import { IAgentsRepo } from "./repo.js";
import { IMonotonicallyIncreasingIdGenerator } from "../application/lib/id-gen.js";
import { IBus } from "../application/lib/bus.js";
import { IMessageQueue, type MiddlePaneContext } from "../application/lib/message-queue.js";
import { IRunsRepo } from "../runs/repo.js";
import { IRunsLock } from "../runs/lock.js";
import { IAbortRegistry } from "../runs/abort-registry.js";
import { PrefixLogger } from "@x/shared";
import { parse } from "yaml";
import { captureLlmUsage } from "../analytics/usage.js";
import { enterUseCase, withUseCase, type UseCase } from "../analytics/use_case.js";
import { getRaw as getNoteCreationRaw } from "../knowledge/note_creation.js";
import { getRaw as getLabelingAgentRaw } from "../knowledge/labeling_agent.js";
import { getRaw as getNoteTaggingAgentRaw } from "../knowledge/note_tagging_agent.js";
import { getRaw as getInlineTaskAgentRaw } from "../knowledge/inline_task_agent.js";
import { getRaw as getAgentNotesAgentRaw } from "../knowledge/agent_notes_agent.js";
import {
  classifyToolPermissions,
  type AutoPermissionCandidate,
} from "../security/auto-permission-classifier.js";
import { splitFrontmatter } from "../application/lib/parse-frontmatter.js";
import { isCloudMetadataHostOrIp, isPrivateOrLocalIpAddress } from "../security/network-safety.js";

const AGENT_NOTES_DIR = path.join(WorkDir, "knowledge", "Agent Notes");

const DANGEROUS_MCP_ENV_VARS = new Set([
  "NODE_OPTIONS",
  "NODE_PATH",
  "ELECTRON_RUN_AS_NODE",
  "LD_PRELOAD",
  "LD_LIBRARY_PATH",
  "LD_AUDIT",
  "GLIBC_TUNABLES",
  "GCONV_PATH",
  "DYLD_INSERT_LIBRARIES",
  "DYLD_LIBRARY_PATH",
  "DYLD_FRAMEWORK_PATH",
  "PATH",
  "PATHEXT",
  "COMSPEC",
  "SHELL",
  "HOME",
  "BASH_ENV",
  "ENV",
  "ZDOTDIR",
  "PROMPT_COMMAND",
  "FPATH",
  "EDITOR",
  "VISUAL",
  "BROWSER",
  "PAGER",
  "PYTHONSTARTUP",
  "PYTHONPATH",
  "PYTHONHOME",
  "PIP_INDEX_URL",
  "PIP_EXTRA_INDEX_URL",
  "PIP_CONFIG_FILE",
  "PIP_FIND_LINKS",
  "UV_INDEX_URL",
  "UV_EXTRA_INDEX_URL",
  "UV_DEFAULT_INDEX",
  "UV_PYTHON",
  "NPM_CONFIG_SCRIPT_SHELL",
  "RUBYOPT",
  "RUBYLIB",
  "PERL5OPT",
  "PERL5LIB",
  "PERL5DB",
  "PERLLIB",
  "JAVA_TOOL_OPTIONS",
  "_JAVA_OPTIONS",
  "JDK_JAVA_OPTIONS",
  "CLASSPATH",
  "DOTNET_STARTUP_HOOKS",
  "CORECLR_PROFILER",
  "CORECLR_ENABLE_PROFILING",
  "GOFLAGS",
  "RUSTC_WRAPPER",
  "PHP_INI_SCAN_DIR",
  "PHPRC",
  "LUA_INIT",
  "GIT_SSH_COMMAND",
  "GIT_EXEC_PATH",
  "IFS",
  "HTTP_PROXY",
  "HTTPS_PROXY",
  "ALL_PROXY",
  "SSL_CERT_FILE",
  "SSL_CERT_DIR",
  "REQUESTS_CA_BUNDLE",
  "CURL_CA_BUNDLE",
  "AWS_CA_BUNDLE",
  "NODE_EXTRA_CA_CERTS",
  "NODE_TLS_REJECT_UNAUTHORIZED",
  "XDG_CONFIG_HOME",
  "XDG_DATA_HOME",
  "SSH_ASKPASS",
  "SUDO_ASKPASS",
  "OPENSSL_CONF",
  "OPENSSL_ENGINES",
  "OPENSSL_MODULES",
  "GOENV",
  "GOPROXY",
  "GOPATH",
  "GOBIN",
  "PSMODULEPATH",
  "LUA_PATH",
  "LUA_CPATH",
]);

const DANGEROUS_MCP_ENV_PREFIXES = [
  "LD_",
  "DYLD_",
  "NPM_CONFIG_",
  "NODE_",
  "PYTHON",
  "PIP_",
  "UV_",
  "GIT_",
  "JAVA_",
  "_JAVA_",
  "JDK_",
  "DOTNET_",
  "CORECLR_",
  "CARGO_",
  "RUSTC_",
  "XDG_",
  "CURL_",
  "SSH_",
  "BUNDLE_",
  "GEM_",
  "PHP_",
  "ELECTRON_",
  "LUA_INIT_",
] as const;

function isDangerousMcpEnvKey(key: string): boolean {
  const upper = key.toUpperCase();
  if (DANGEROUS_MCP_ENV_VARS.has(upper)) {
    return true;
  }
  return DANGEROUS_MCP_ENV_PREFIXES.some((prefix) => upper.startsWith(prefix));
}

// Work directory is scoped per run (per chat). Each run gets its own sidecar
// config file so setting it in one chat does not leak into others.
function workDirConfigFile(runId: string): string {
  return path.join(WorkDir, "config", `workdir-${runId}.json`);
}

type ToolPermissionMetadataValue = z.infer<typeof ToolPermissionMetadata>;

function isPathInside(parent: string, child: string): boolean {
  return isPathInsideDir(parent, child);
}

function fileGrantCoversPath(
  grant: FileAccessGrant,
  operation: FileAccessOperation,
  resolvedPath: string,
): boolean {
  return (
    grant.operation === operation &&
    isPathInside(path.resolve(grant.pathPrefix), path.resolve(resolvedPath))
  );
}

function commonPathPrefix(paths: readonly string[]): string {
  if (!paths.length) return path.resolve(WorkDir);
  const resolvedPaths = paths.map((p) => path.resolve(p));
  const roots = resolvedPaths.map((p) => path.parse(p).root);
  const firstRoot = roots[0];
  if (!roots.every((r) => r.toLowerCase() === firstRoot.toLowerCase())) {
    // Disjoint filesystem roots (e.g. C:\ and D:\) — cannot safely coalesce
    return firstRoot;
  }
  const split = resolvedPaths.map((p) =>
    p
      .slice(firstRoot.length)
      .split(/[\\/]+/)
      .filter(Boolean),
  );
  const first = split[0];
  const common: string[] = [];
  for (let i = 0; i < first.length; i++) {
    if (split.every((parts) => parts[i] === first[i])) {
      common.push(first[i]);
    } else {
      break;
    }
  }
  return common.length === 0 ? firstRoot : path.resolve(firstRoot, ...common);
}

function grantPrefixForTool(toolName: string, resolvedPaths: readonly string[]): string {
  if (
    toolName === "file-list" ||
    toolName === "file-glob" ||
    toolName === "file-grep" ||
    toolName === "file-mkdir"
  ) {
    return commonPathPrefix(resolvedPaths);
  }
  const parentPaths = resolvedPaths.map((p) => path.dirname(p));
  return commonPathPrefix(parentPaths);
}

const PROTECTED_TOP_DIR_NAMES = [
  "config",
  "runs",
  ".trash",
  "code-mode",
  "runtime",
  "models",
  "cache",
  "index",
  "events",
  "logs",
  ".git",
] as const;

function firstSegmentCouldMatchProtectedDir(segment: string): boolean {
  const lower = segment.toLowerCase();
  if (!lower || lower === "*" || lower === "**") return false;
  if (!/[*?[]/.test(lower)) return false;
  // Convert basic glob segment into regex to detect patterns like `config*`, `con?ig`, `[c]onfig`
  const escaped = lower
    .replace(/[.+^${}()|\\]/g, "\\$&")
    .replace(/\*/g, ".*")
    .replace(/\?/g, ".");
  try {
    const re = new RegExp(`^${escaped}$`, "i");
    return PROTECTED_TOP_DIR_NAMES.some((dir) => re.test(dir));
  } catch {
    return true;
  }
}

function extractGlobTargetInfo(
  baseDir: string,
  globPattern: string,
): { targetPath: string | null; forceSingleApproval: boolean } {
  const trimmed = globPattern.trim();
  if (!trimmed) return { targetPath: null, forceSingleApproval: false };
  const normalizedSlash = trimmed.replace(/\\/g, "/");
  const globIndex = normalizedSlash.search(/[*?[{]/);
  // Slice static directory prefix strictly before the wildcard segment (up to last `/`)
  let staticDirPrefix: string;
  if (globIndex === -1) {
    staticDirPrefix = normalizedSlash;
  } else {
    const beforeGlob = normalizedSlash.slice(0, globIndex);
    const lastSlash = beforeGlob.lastIndexOf("/");
    staticDirPrefix = lastSlash === -1 ? "" : beforeGlob.slice(0, lastSlash);
  }
  const normalizedPrefix = staticDirPrefix.replace(/\/+$/, "");

  // Brace expansion (`{/etc/passwd,x}`, `{..,x}/.ssh/*`) can expand to arbitrary
  // absolute or traversal paths — always require explicit per-call approval.
  if (normalizedSlash.includes("{") || normalizedSlash.includes("}")) {
    return {
      targetPath: path.resolve(baseDir),
      forceSingleApproval: true,
    };
  }

  // Check `..` traversal components BEFORE absolute-path handling so patterns
  // like `<WorkDir>/knowledge/*/../../config/oauth.json` or `/abs/*/../etc/*`
  // always require explicit per-call approval.
  const isAbsoluteOrHome =
    normalizedSlash.startsWith("/") ||
    normalizedSlash.startsWith("~") ||
    /^[A-Za-z]:/.test(normalizedSlash) ||
    trimmed.startsWith("\\\\");

  if (normalizedSlash.split("/").includes("..")) {
    if (isAbsoluteOrHome) {
      const fallbackRoot = normalizedSlash.startsWith("~")
        ? "~"
        : /^[A-Za-z]:/.test(normalizedSlash)
          ? normalizedSlash.slice(0, 2) + "/"
          : "/";
      return {
        targetPath: normalizedPrefix || fallbackRoot,
        forceSingleApproval: true,
      };
    }
    const dotDotCount = normalizedSlash.split("/").filter((seg) => seg === "..").length;
    const traversalTarget =
      globIndex === -1 || normalizedPrefix.split("/").includes("..")
        ? path.join(baseDir, normalizedPrefix || "..")
        : path.join(baseDir, ...Array<string>(dotDotCount).fill(".."));
    return { targetPath: traversalTarget, forceSingleApproval: true };
  }

  if (isAbsoluteOrHome) {
    const fallbackRoot = normalizedSlash.startsWith("~")
      ? "~"
      : /^[A-Za-z]:/.test(normalizedSlash)
        ? normalizedSlash.slice(0, 2) + "/"
        : "/";
    const candidateTarget = normalizedPrefix || fallbackRoot;
    const hasWildcard = globIndex !== -1;
    // An absolute wildcard rooted at WorkDir itself (e.g. `<WorkDir>/**/*`) or at a
    // filesystem/home root could reach protected subtrees — require single approval.
    const resolvedCandidate =
      candidateTarget === "~"
        ? os.homedir()
        : candidateTarget.startsWith("~/")
          ? path.join(os.homedir(), candidateTarget.slice(2))
          : path.resolve(candidateTarget);
    const rootsAtWorkspace = isSameNormalizedPath(resolvedCandidate, WorkDir);
    return {
      targetPath: candidateTarget,
      forceSingleApproval: hasWildcard && (rootsAtWorkspace || !normalizedPrefix),
    };
  }

  // Case-insensitive detection of protected workspace subtrees (stripping repeated `./`)
  const strippedRel = normalizedSlash.replace(/^(?:\.\/)+/, "");
  const segments = strippedRel.split("/").filter(Boolean);
  const firstSegment = segments[0] ?? "";
  if (
    /^(?:config|runs|\.trash|code-mode|runtime|models|cache|index|events|logs|\.git)(?:\/|$)/i.test(
      strippedRel,
    ) ||
    firstSegmentCouldMatchProtectedDir(firstSegment)
  ) {
    const cleanedPrefix = normalizedPrefix.replace(/^(?:\.\/)+/, "");
    return {
      targetPath: path.join(baseDir, cleanedPrefix || firstSegment || "config"),
      forceSingleApproval: true,
    };
  }

  // Any nested `.git` segment (e.g. `knowledge/.git/config`) must be gated.
  if (segments.some((seg) => seg.toLowerCase() === ".git")) {
    const cleanedPrefix = normalizedPrefix.replace(/^(?:\.\/)+/, "");
    return {
      targetPath: path.join(baseDir, cleanedPrefix || strippedRel),
      forceSingleApproval: true,
    };
  }

  // Whenever there is a static directory prefix before the wildcard (e.g.
  // `knowledge/link_to_config/oauth.json` or `knowledge/*.md`), return it so
  // `getToolPermissionMetadata` canonicalizes it through symlinks and checks
  // workspace and protected boundaries.
  const cleanedPrefix = normalizedPrefix.replace(/^(?:\.\/)+/, "");
  if (cleanedPrefix) {
    return {
      targetPath: path.join(baseDir, cleanedPrefix),
      forceSingleApproval: false,
    };
  }

  return { targetPath: null, forceSingleApproval: false };
}

type FilePermissionTargetEntry = {
  readonly path: string;
  readonly operation: FileAccessOperation;
};

function filePermissionTargets(
  toolName: string,
  args: Record<string, unknown>,
): {
  primaryOperation: FileAccessOperation;
  entries: FilePermissionTargetEntry[];
  forceSingleApproval?: boolean;
} | null {
  const pathArg = typeof args.path === "string" ? args.path : undefined;
  switch (toolName) {
    case "file-readText":
    case "parseFile":
    case "LLMParse":
    case "file-exists":
    case "file-stat":
      return pathArg
        ? { primaryOperation: "read", entries: [{ path: pathArg, operation: "read" }] }
        : null;
    case "file-list":
      return {
        primaryOperation: "list",
        entries: [{ path: pathArg && pathArg.trim() ? pathArg : ".", operation: "list" }],
      };
    case "file-glob": {
      const cwd = typeof args.cwd === "string" && args.cwd ? args.cwd : ".";
      const entries: FilePermissionTargetEntry[] = [{ path: cwd, operation: "search" }];
      let forceSingleApproval = false;
      if (typeof args.pattern === "string") {
        const extra = extractGlobTargetInfo(cwd, args.pattern);
        if (extra.targetPath) entries.push({ path: extra.targetPath, operation: "search" });
        if (extra.forceSingleApproval) forceSingleApproval = true;
      }
      return {
        primaryOperation: "search",
        entries,
        forceSingleApproval,
      };
    }
    case "file-grep": {
      const searchPath =
        typeof args.searchPath === "string" && args.searchPath ? args.searchPath : ".";
      const entries: FilePermissionTargetEntry[] = [{ path: searchPath, operation: "search" }];
      let forceSingleApproval = false;
      if (typeof args.fileGlob === "string") {
        const extra = extractGlobTargetInfo(searchPath, args.fileGlob);
        if (extra.targetPath) entries.push({ path: extra.targetPath, operation: "search" });
        if (extra.forceSingleApproval) forceSingleApproval = true;
      }
      return {
        primaryOperation: "search",
        entries,
        forceSingleApproval,
      };
    }
    case "file-writeText":
    case "file-editText":
    case "file-mkdir":
      return pathArg
        ? { primaryOperation: "write", entries: [{ path: pathArg, operation: "write" }] }
        : null;
    case "file-copy": {
      const from = typeof args.from === "string" ? args.from : undefined;
      const to = typeof args.to === "string" ? args.to : undefined;
      return from && to
        ? {
            primaryOperation: "write",
            entries: [
              { path: from, operation: "read" },
              { path: to, operation: "write" },
            ],
          }
        : null;
    }
    case "file-rename": {
      const from = typeof args.from === "string" ? args.from : undefined;
      const to = typeof args.to === "string" ? args.to : undefined;
      return from && to
        ? {
            primaryOperation: "write",
            entries: [
              { path: from, operation: "delete" },
              { path: to, operation: "write" },
            ],
          }
        : null;
    }
    case "file-remove":
      return pathArg
        ? { primaryOperation: "delete", entries: [{ path: pathArg, operation: "delete" }] }
        : null;
    default:
      return null;
  }
}

function inspectMcpEnv(env: Readonly<Record<string, string>> | undefined): {
  envKeys: string[];
  envEntries: Array<{ key: string; value: string; dangerous: boolean }>;
  hasDangerousEnv: boolean;
  warnings: string[];
} {
  if (!env) {
    return { envKeys: [], envEntries: [], hasDangerousEnv: false, warnings: [] };
  }
  const keys = Object.keys(env).sort();
  const envEntries = keys.map((key) => ({
    key,
    value: env[key],
    dangerous: isDangerousMcpEnvKey(key),
  }));
  const dangerousKeys = envEntries.filter((e) => e.dangerous).map((e) => e.key);
  const warnings =
    dangerousKeys.length > 0
      ? [`Sets execution-influencing environment variables: ${dangerousKeys.join(", ")}`]
      : [];
  return {
    envKeys: keys,
    envEntries,
    hasDangerousEnv: dangerousKeys.length > 0,
    warnings,
  };
}

export function isLocalOrPrivateHostname(rawHostname: string): boolean {
  const host = rawHostname
    .toLowerCase()
    .replace(/^\[|\]$/g, "")
    .replace(/\.+$/, "");
  if (!host) return false;
  if (host === "localhost" || host.endsWith(".localhost")) {
    return true;
  }
  return isCloudMetadataHostOrIp(host) || isPrivateOrLocalIpAddress(host);
}

const INLINE_TASK_FENCE_OPEN_RE = /^\s*```(?:task|tell-solomon|tell-rowboat)(?:\s|$|[^\s]*)/i;

function extractInlineTaskBlocks(text: string): string[] {
  const lines = text.split(/\r?\n/);
  const blocks: string[] = [];
  let inBlock = false;
  let current: string[] = [];
  for (const line of lines) {
    const trimmed = line.trim();
    if (!inBlock) {
      if (/^```(?:task|tell-solomon|tell-rowboat)/i.test(trimmed)) {
        inBlock = true;
        current = [trimmed];
      }
    } else {
      current.push(line);
      if (trimmed === "```") {
        blocks.push(current.join("\n"));
        inBlock = false;
        current = [];
      }
    }
  }
  if (inBlock && current.length > 0) {
    blocks.push(current.join("\n"));
  }
  return blocks;
}

/**
 * Computes a canonical signature of any headless-agent trigger directives
 * (YAML `live:` / `live_note: true` frontmatter or fenced ```task / ```tell-solomon / ```tell-rowboat blocks)
 * present in markdown content. Returns `null` if no triggers are present.
 */
function extractHeadlessTriggerSignature(text: string): string | null {
  if (!text) return null;
  let liveTrigger: unknown = undefined;
  let hasLiveTrigger = false;

  // 1. Authoritative YAML frontmatter parse (catches quoted keys `"live":`, YAML escapes,
  // and flow mappings `{ live: { objective: ... } }` that regexes miss).
  const { frontmatter } = splitFrontmatter(text);
  if (Object.prototype.hasOwnProperty.call(frontmatter, "live") && frontmatter.live !== undefined) {
    hasLiveTrigger = true;
    liveTrigger = frontmatter.live;
  }
  if (frontmatter.live_note === true) {
    hasLiveTrigger = true;
    liveTrigger = { live: liveTrigger, live_note: true };
  }

  // 2. Regex fallback for unclosed/partial frontmatter snippets
  if (
    !hasLiveTrigger &&
    /^---[\s\S]*?(?:^|\r?\n)\s*(?:["']?live["']?\s*:|["']?live_note["']?\s*:\s*true)/m.test(text)
  ) {
    hasLiveTrigger = true;
    liveTrigger = "__partial_frontmatter__";
  }

  // 3. Fenced inline-task blocks (matches inline_tasks.ts startsWith semantics: task, tell-solomon, tell-rowboat)
  const taskBlocks = extractInlineTaskBlocks(text);
  const hasInlineFence =
    taskBlocks.length > 0 ||
    text.split(/\r?\n/).some((line) => INLINE_TASK_FENCE_OPEN_RE.test(line));

  if (!hasLiveTrigger && !hasInlineFence) {
    return null;
  }
  return JSON.stringify({ live: liveTrigger ?? null, tasks: taskBlocks });
}

function simulateEditTextContent(
  existing: string,
  oldString: string,
  newString: string,
  replaceAll: boolean,
): string | null {
  if (!oldString) return null;
  if (replaceAll) {
    return existing.split(oldString).join(newString);
  }
  const idx = existing.indexOf(oldString);
  if (idx === -1) return null;
  return existing.slice(0, idx) + newString + existing.slice(idx + oldString.length);
}

function directoryContainsHeadlessTriggerMarkdown(dirPath: string, depth = 0): boolean {
  if (depth > 8) return true; // Fail closed on deep directory trees
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dirPath, { withFileTypes: true });
  } catch {
    return true; // Fail closed if unreadable
  }
  for (const entry of entries) {
    const full = path.join(dirPath, entry.name);
    if (entry.isSymbolicLink()) return true;
    if (entry.isDirectory()) {
      if (directoryContainsHeadlessTriggerMarkdown(full, depth + 1)) return true;
    } else if (entry.name.toLowerCase().endsWith(".md")) {
      try {
        const content = fs.readFileSync(full, "utf8");
        if (extractHeadlessTriggerSignature(content) !== null) return true;
      } catch {
        return true;
      }
    }
  }
  return false;
}

function inspectMcpHttpUrlWarnings(rawUrl: string): string[] {
  const warnings: string[] = [];
  try {
    const parsed = new URL(rawUrl);
    if (parsed.protocol === "http:") {
      warnings.push("Uses unencrypted HTTP (not HTTPS)");
    }
    const host = parsed.hostname.toLowerCase();
    if (isLocalOrPrivateHostname(host)) {
      warnings.push(`Targets local or private network host (${host})`);
    }
  } catch {
    warnings.push("URL could not be parsed");
  }
  return warnings;
}

function buildAddMcpServerPermission(args: Record<string, unknown>): ToolPermissionMetadataValue {
  const nameResult = McpServerName.safeParse(args.serverName);
  const serverName = nameResult.success
    ? nameResult.data
    : typeof args.serverName === "string" && args.serverName.trim()
      ? args.serverName.trim()
      : "<unknown>";
  const warnings: string[] = [];
  if (!nameResult.success) {
    warnings.push("Invalid server name");
  }

  const parsedConfig = McpServerDefinition.safeParse(args.config);
  if (parsedConfig.success) {
    const cfg = parsedConfig.data;
    if ("command" in cfg) {
      const commandArgs = cfg.args ?? [];
      const envInfo = inspectMcpEnv(cfg.env);
      const configDigest = computeStdioMcpConfigDigest(serverName, {
        command: cfg.command,
        args: commandArgs,
        env: cfg.env,
      });
      const allWarnings = [...warnings, ...envInfo.warnings];
      return {
        kind: "mcp",
        action: "install",
        serverName,
        transport: "stdio",
        command: cfg.command,
        args: commandArgs,
        envKeys: envInfo.envKeys,
        ...(envInfo.envEntries.length > 0 ? { envEntries: envInfo.envEntries } : {}),
        ...(allWarnings.length > 0 ? { warnings: allWarnings } : {}),
        configDigest,
        allowScopeGrant: false,
      };
    }

    const headerKeys = cfg.headers ? Object.keys(cfg.headers).sort() : [];
    const allWarnings = [...warnings, ...inspectMcpHttpUrlWarnings(cfg.url)];
    return {
      kind: "mcp",
      action: "install",
      serverName,
      transport: "http",
      url: cfg.url,
      headerKeys,
      ...(allWarnings.length > 0 ? { warnings: allWarnings } : {}),
      allowScopeGrant: false,
    };
  }

  // Invalid or ambiguous (e.g. dual-field) server config — still fail closed and
  // warn the user; addMcpServer.execute will also reject it.
  warnings.push(
    `Invalid MCP server configuration: ${parsedConfig.error.issues.map((i) => i.message).join("; ")}`,
  );
  return {
    kind: "mcp",
    action: "install",
    serverName,
    transport: "stdio",
    warnings,
    allowScopeGrant: false,
  };
}

async function getMcpStdioSpawnPermission(
  serverName: string,
  sessionAllowedMcpSpawns: Set<string>,
): Promise<ToolPermissionMetadataValue | null> {
  // Use the exact untrimmed serverName because listTools/executeTool look up
  // the exact key in mcp.json.
  if (!serverName) return null;

  const requirement = await getStdioMcpSpawnRequirement(serverName);
  if (!requirement) {
    return null;
  }

  if (sessionAllowedMcpSpawns.has(requirement.configDigest)) {
    return null;
  }

  const persistentGrants = getMcpServerAllowList();
  const isPersistentlyApproved = persistentGrants.some(
    (grant) =>
      grant.serverName === requirement.serverName &&
      grant.configDigest === requirement.configDigest,
  );
  if (isPersistentlyApproved) {
    return null;
  }

  const envInfo = inspectMcpEnv(requirement.env);

  return {
    kind: "mcp",
    action: "spawn",
    serverName: requirement.serverName,
    transport: "stdio",
    command: requirement.command,
    args: [...requirement.args],
    envKeys: [...requirement.envKeys],
    ...(envInfo.envEntries.length > 0 ? { envEntries: envInfo.envEntries } : {}),
    ...(envInfo.warnings.length > 0 ? { warnings: envInfo.warnings } : {}),
    configDigest: requirement.configDigest,
    allowScopeGrant: !envInfo.hasDangerousEnv,
  };
}

export async function getToolPermissionMetadata(
  toolCall: z.infer<typeof ToolCallPart>,
  underlyingTool: z.infer<typeof ToolAttachment>,
  sessionAllowedCommands: Set<string>,
  sessionAllowedFileAccess: FileAccessGrant[],
  sessionAllowedMcpSpawns: Set<string> = new Set(),
  options?: {
    codeMode?: "claude" | "codex" | null;
    agentName?: string | null;
  },
): Promise<ToolPermissionMetadataValue | null> {
  if (underlyingTool.type === "mcp") {
    return getMcpStdioSpawnPermission(underlyingTool.mcpServerName, sessionAllowedMcpSpawns);
  }

  if (underlyingTool.type !== "builtin") {
    return null;
  }

  const parsedArgs = z.record(z.string(), z.unknown()).safeParse(toolCall.arguments);
  const args: Record<string, unknown> = parsedArgs.success ? parsedArgs.data : {};

  if (underlyingTool.name === "executeCommand") {
    if (!("command" in args)) {
      return null;
    }
    const command = String(args.command);
    const cwd = typeof args.cwd === "string" ? args.cwd : undefined;
    const evaluation = evaluateCommandSecurity(command, sessionAllowedCommands, { cwd });
    if (!evaluation.blocked) {
      return null;
    }
    return {
      kind: "command",
      commandNames: evaluation.commandNames,
      cwd: resolveCommandWorkingDir(cwd),
      ...(evaluation.capabilityReasons.length > 0 ? { reasons: evaluation.capabilityReasons } : {}),
      allowScopeGrant: evaluation.allowScopeGrant,
    };
  }

  if (underlyingTool.name === "code_agent_run") {
    const requestedAgent = options?.codeMode ?? (args.agent === "codex" ? "codex" : "claude");
    const rawCwd = typeof args.cwd === "string" && args.cwd.trim() ? args.cwd.trim() : ".";
    const resolvedCwd = await resolveFilePathForPermission(rawCwd);
    const reasons: string[] = [];
    if (!options?.codeMode) {
      reasons.push(
        "Code Mode is not active on this turn — explicit approval is required to spawn a coding agent",
      );
    }
    if (
      resolvedCwd.isInsideWorkspace &&
      isProtectedWorkspacePath(resolvedCwd.canonicalPath, "write")
    ) {
      reasons.push("Coding agent working directory targets protected workspace configuration");
    } else if (isSensitiveOrBroadExternalGrantPrefix(resolvedCwd.canonicalPath)) {
      reasons.push(
        "Coding agent working directory targets a broad or sensitive system/home directory",
      );
    }
    if (reasons.length > 0) {
      return {
        kind: "command",
        commandNames: [`code_agent_run:${requestedAgent}`],
        cwd: resolvedCwd.canonicalPath,
        reasons,
        allowScopeGrant: false,
      };
    }
    return null;
  }

  if (underlyingTool.name === "save-to-memory") {
    const inboxPath = path.resolve(AGENT_NOTES_DIR, "inbox.md");
    return {
      kind: "file",
      operation: "write",
      paths: [inboxPath],
      pathPrefix: path.resolve(AGENT_NOTES_DIR),
      allowScopeGrant: false,
    };
  }

  if (
    underlyingTool.name === "run-live-note-agent" ||
    underlyingTool.name === "run-background-task-agent"
  ) {
    return {
      kind: "command",
      commandNames: [underlyingTool.name],
      cwd: path.resolve(WorkDir),
      reasons: [`Triggers headless agent execution (${underlyingTool.name})`],
      allowScopeGrant: false,
    };
  }

  if (underlyingTool.name === "rowboat-configure-integration-mcp") {
    const connector =
      typeof args.connector === "string" && args.connector.trim()
        ? args.connector.trim()
        : "<connector>";
    return {
      kind: "mcp",
      action: "install",
      serverName: `rowboat-${connector}`,
      transport: "http",
      warnings: ["Installs or updates a managed integration MCP server entry in mcp.json"],
      allowScopeGrant: false,
    };
  }

  if (
    underlyingTool.name === "create-background-task" ||
    underlyingTool.name === "patch-background-task"
  ) {
    const label =
      underlyingTool.name === "patch-background-task"
        ? typeof args.slug === "string" && args.slug.trim()
          ? args.slug.trim()
          : "<task>"
        : typeof args.name === "string" && args.name.trim()
          ? args.name.trim()
          : "<new-task>";
    const bgTasksRoot = path.resolve(WorkDir, "bg-tasks");
    const displayPath = path.join(bgTasksRoot, label, "task.yaml");
    return {
      kind: "file",
      operation: "write",
      paths: [displayPath],
      pathPrefix: bgTasksRoot,
      allowScopeGrant: false,
    };
  }

  if (underlyingTool.name === "addMcpServer") {
    return buildAddMcpServerPermission(args);
  }

  if (underlyingTool.name === "listMcpTools" || underlyingTool.name === "executeMcpTool") {
    const serverName = typeof args.serverName === "string" ? args.serverName : "";
    return getMcpStdioSpawnPermission(serverName, sessionAllowedMcpSpawns);
  }

  if (underlyingTool.name === "browser-control") {
    const action = typeof args.action === "string" ? args.action : "";
    const hasTarget = typeof args.target === "string" && args.target.trim().length > 0;
    const isMutatingBrowserAction =
      action === "navigate" ||
      action === "click" ||
      action === "type" ||
      action === "press" ||
      (action === "new-tab" && hasTarget);
    if (isMutatingBrowserAction) {
      const targetDetail = hasTarget ? ` (${String(args.target).trim().slice(0, 120)})` : "";
      return {
        kind: "command",
        commandNames: ["browser-control"],
        reasons: [
          `Browser action "${action}"${targetDetail} interacts with or navigates your authenticated embedded browser session`,
        ],
        allowScopeGrant: false,
      };
    }
    return null;
  }

  const targets = filePermissionTargets(underlyingTool.name, args);
  if (!targets) {
    return null;
  }

  const resolvedTargets = await Promise.all(
    targets.entries.map(async (entry) => ({
      operation: entry.operation,
      resolved: await resolveFilePathForPermission(entry.path),
    })),
  );

  // Planting or modifying live-note (`live:` / `live_note: true`) or inline-task
  // (```task / ```tell-solomon / ```tell-rowboat) triggers inside `knowledge/**/*.md`
  // via write, edit, copy, or rename installs persistent scheduled/event-driven
  // headless agents and requires explicit interactive approval.
  let plantsHeadlessTrigger = false;
  const knowledgeRoot = path.resolve(WorkDir, "knowledge");
  const isKnowledgeMarkdown = (canonicalPath: string): boolean =>
    canonicalPath.toLowerCase().endsWith(".md") && isPathInsideDir(knowledgeRoot, canonicalPath);

  if (underlyingTool.name === "file-writeText") {
    const dest = resolvedTargets[0]?.resolved;
    if (dest?.isInsideWorkspace && isKnowledgeMarkdown(dest.canonicalPath)) {
      const data = typeof args.data === "string" ? args.data : "";
      const afterSig = extractHeadlessTriggerSignature(data);
      if (afterSig !== null) {
        let beforeSig: string | null = null;
        try {
          if (fs.existsSync(dest.canonicalPath)) {
            beforeSig = extractHeadlessTriggerSignature(
              fs.readFileSync(dest.canonicalPath, "utf8"),
            );
          }
        } catch {
          beforeSig = null;
        }
        // Prompt whenever a trigger is newly planted or modified (or always for non-live-note agents)
        if (options?.agentName !== "live-note-agent" || beforeSig !== afterSig) {
          plantsHeadlessTrigger = true;
        }
      }
    }
  } else if (underlyingTool.name === "file-editText") {
    const dest = resolvedTargets[0]?.resolved;
    if (dest?.isInsideWorkspace && isKnowledgeMarkdown(dest.canonicalPath)) {
      const oldString = typeof args.oldString === "string" ? args.oldString : "";
      const newString = typeof args.newString === "string" ? args.newString : "";
      const replaceAll = args.replaceAll === true;
      let existingContent: string | null = null;
      try {
        existingContent = fs.readFileSync(dest.canonicalPath, "utf8");
      } catch {
        existingContent = null;
      }
      if (existingContent !== null) {
        const beforeSig = extractHeadlessTriggerSignature(existingContent);
        const simulated = simulateEditTextContent(
          existingContent,
          oldString,
          newString,
          replaceAll,
        );
        const afterSig =
          simulated !== null
            ? extractHeadlessTriggerSignature(simulated)
            : extractHeadlessTriggerSignature(newString);
        // Gate if the edit introduces a new trigger OR modifies any existing live/task directive
        if (afterSig !== null && afterSig !== beforeSig) {
          plantsHeadlessTrigger = true;
        }
      } else if (extractHeadlessTriggerSignature(newString) !== null) {
        plantsHeadlessTrigger = true;
      }
    }
  } else if (underlyingTool.name === "file-copy" || underlyingTool.name === "file-rename") {
    const source = resolvedTargets[0]?.resolved;
    const dest = resolvedTargets[1]?.resolved;
    if (source && dest?.isInsideWorkspace && isPathInsideDir(knowledgeRoot, dest.canonicalPath)) {
      try {
        const srcStat = fs.lstatSync(source.canonicalPath);
        if (srcStat.isDirectory()) {
          if (directoryContainsHeadlessTriggerMarkdown(source.canonicalPath)) {
            plantsHeadlessTrigger = true;
          }
        } else if (isKnowledgeMarkdown(dest.canonicalPath)) {
          const content = fs.readFileSync(source.canonicalPath, "utf8");
          if (extractHeadlessTriggerSignature(content) !== null) {
            plantsHeadlessTrigger = true;
          }
        }
      } catch {
        // Fail closed when moving/copying an unreadable file into knowledge/**/*.md
        if (isKnowledgeMarkdown(dest.canonicalPath)) {
          plantsHeadlessTrigger = true;
        }
      }
    }
  }

  const protectedPaths = resolvedTargets
    .filter(({ operation, resolved }) => {
      if (!resolved.isInsideWorkspace) return false;
      if (!isProtectedWorkspacePath(resolved.canonicalPath, operation)) {
        return false;
      }
      // Narrow exemption: the dedicated headless `agent_notes_agent` maintains
      // `knowledge/Agent Notes/**` and has no shell/MCP/network capabilities.
      if (
        options?.agentName === "agent_notes_agent" &&
        operation === "write" &&
        isAgentNotesWorkspacePath(resolved.canonicalPath)
      ) {
        return false;
      }
      return true;
    })
    .map(({ resolved }) => resolved.canonicalPath);
  const outsideWorkspaceTargets = resolvedTargets.filter(
    ({ resolved }) => !resolved.isInsideWorkspace,
  );
  const outsideWorkspacePaths = outsideWorkspaceTargets.map(
    ({ resolved }) => resolved.canonicalPath,
  );

  if (protectedPaths.length > 0 || targets.forceSingleApproval || plantsHeadlessTrigger) {
    const allPromptPaths = Array.from(
      new Set([
        ...protectedPaths,
        ...outsideWorkspacePaths,
        ...(targets.forceSingleApproval || plantsHeadlessTrigger
          ? resolvedTargets.map(({ resolved }) => resolved.canonicalPath)
          : []),
      ]),
    );
    return {
      kind: "file",
      operation: targets.primaryOperation,
      paths: allPromptPaths,
      pathPrefix: grantPrefixForTool(underlyingTool.name, allPromptPaths),
      allowScopeGrant: false,
    };
  }

  if (!outsideWorkspaceTargets.length) {
    return null;
  }

  const persistentGrants = getFileAccessAllowList();
  const allGrants = [...persistentGrants, ...sessionAllowedFileAccess];
  const uncoveredTargets = outsideWorkspaceTargets.filter(
    ({ operation, resolved }) =>
      !allGrants.some((grant) => fileGrantCoversPath(grant, operation, resolved.canonicalPath)),
  );
  if (!uncoveredTargets.length) {
    return null;
  }

  const uncoveredPaths = uncoveredTargets.map(({ resolved }) => resolved.canonicalPath);
  const effectiveOperation =
    uncoveredTargets.length === 1 ? uncoveredTargets[0].operation : targets.primaryOperation;
  const pathPrefix = grantPrefixForTool(underlyingTool.name, uncoveredPaths);
  const allowScopeGrant =
    !isSensitiveOrBroadExternalGrantPrefix(pathPrefix) &&
    !isProtectedWorkspacePath(pathPrefix, effectiveOperation);

  return {
    kind: "file",
    operation: effectiveOperation,
    paths: uncoveredPaths,
    pathPrefix,
    allowScopeGrant,
  };
}

function loadUserWorkDir(runId: string): string | null {
  try {
    const file = workDirConfigFile(runId);
    if (!fs.existsSync(file)) return null;
    const raw = fs.readFileSync(file, "utf-8");
    const parsed = JSON.parse(raw) as { path?: unknown };
    const value = typeof parsed.path === "string" ? parsed.path.trim() : "";
    return value || null;
  } catch {
    return null;
  }
}

function loadAgentNotesContext(): string | null {
  const sections: string[] = [];

  const userFile = path.join(AGENT_NOTES_DIR, "user.md");
  const prefsFile = path.join(AGENT_NOTES_DIR, "preferences.md");

  try {
    if (fs.existsSync(userFile)) {
      const content = fs.readFileSync(userFile, "utf-8").trim();
      if (content) {
        sections.push(
          `## About the User\nThese are notes you took about the user in previous chats.\n\n${content}`,
        );
      }
    }
  } catch {
    /* ignore */
  }

  try {
    if (fs.existsSync(prefsFile)) {
      const content = fs.readFileSync(prefsFile, "utf-8").trim();
      if (content) {
        sections.push(
          `## User Preferences\nThese are notes you took on their general preferences.\n\n${content}`,
        );
      }
    }
  } catch {
    /* ignore */
  }

  // List other Agent Notes files for on-demand access
  const otherFiles: string[] = [];
  const skipFiles = new Set(["user.md", "preferences.md", "inbox.md"]);
  try {
    if (fs.existsSync(AGENT_NOTES_DIR)) {
      function listMdFiles(dir: string, prefix: string) {
        for (const entry of fs.readdirSync(dir)) {
          const fullPath = path.join(dir, entry);
          const stat = fs.statSync(fullPath);
          if (stat.isDirectory()) {
            listMdFiles(fullPath, `${prefix}${entry}/`);
          } else if (entry.endsWith(".md") && !skipFiles.has(`${prefix}${entry}`)) {
            otherFiles.push(`${prefix}${entry}`);
          }
        }
      }
      listMdFiles(AGENT_NOTES_DIR, "");
    }
  } catch {
    /* ignore */
  }

  if (otherFiles.length > 0) {
    sections.push(
      `## More Specific Preferences\nFor more specific preferences, you can read these files using file-readText. Only read them when relevant to the current task.\n\n${otherFiles.map((f) => `- knowledge/Agent Notes/${f}`).join("\n")}`,
    );
  }

  if (sections.length === 0) return null;
  return `# Agent Memory\n\n${sections.join("\n\n")}`;
}

function isCopilotLikeAgent(agentName: string | null | undefined): boolean {
  return agentName === "copilot" || agentName === "rowboatx";
}

function formatCurrentDateTime(now: Date): string {
  return now.toLocaleString("en-US", {
    weekday: "long",
    year: "numeric",
    month: "long",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
    timeZoneName: "short",
  });
}

function toUserMessageContextMiddlePane(
  middlePaneContext: MiddlePaneContext | null,
): z.infer<typeof UserMessageContext>["middlePane"] {
  if (!middlePaneContext) {
    return { kind: "empty" };
  }
  if (middlePaneContext.kind === "note") {
    return {
      kind: "note",
      path: middlePaneContext.path,
      content: middlePaneContext.content,
    };
  }
  return {
    kind: "browser",
    url: middlePaneContext.url,
    title: middlePaneContext.title,
  };
}

function buildUserMessageContext({
  agentName,
  middlePaneContext,
}: {
  agentName: string | null | undefined;
  middlePaneContext: MiddlePaneContext | null;
}): z.infer<typeof UserMessageContext> {
  return {
    currentDateTime: formatCurrentDateTime(new Date()),
    ...(isCopilotLikeAgent(agentName)
      ? { middlePane: toUserMessageContextMiddlePane(middlePaneContext) }
      : {}),
  };
}

function formatUserMessageContextForLlm(
  userMessageContext: z.infer<typeof UserMessageContext>,
): string {
  const sections: string[] = [];

  if (userMessageContext.currentDateTime) {
    sections.push(`Current date and time: ${userMessageContext.currentDateTime}`);
  }

  if (userMessageContext.middlePane) {
    if (userMessageContext.middlePane.kind === "empty") {
      sections.push(`Middle pane:\nState: empty`);
    } else if (userMessageContext.middlePane.kind === "note") {
      sections.push(
        `Middle pane:\nState: note\nPath: ${userMessageContext.middlePane.path}\n\nContent:\n\`\`\`\n${userMessageContext.middlePane.content}\n\`\`\``,
      );
    } else {
      sections.push(
        `Middle pane:\nState: browser\nURL: ${userMessageContext.middlePane.url}\nTitle: ${userMessageContext.middlePane.title}`,
      );
    }
  }

  if (sections.length === 0) {
    return "";
  }

  return `# User Context
${sections.join("\n\n")}

# User Message
`;
}

const USER_CONTEXT_SYSTEM_INSTRUCTIONS = `# Hidden User Context
User messages may include a hidden "# User Context" section before "# User Message". Treat it as runtime metadata captured when that specific user message was sent. The actual user-authored text starts under "# User Message".

Use "Current date and time" for temporal reasoning.

If Middle pane context is present, it reflects what the user had open at the time of that specific message and overrides earlier middle-pane references. If the conversation history references a different note or browser page, the user had since closed or navigated away from it. Do not treat earlier context as current.

If Middle pane state is empty, the user was not looking at any relevant note or web page at that point. Answer the user's message on its own merits.

If Middle pane state is note, the supplied path and content are available so you can reference the note when relevant. The user may or may not be talking about this note. Do NOT assume every message is about it. Only reference or act on this note when the user's message clearly relates to it, such as "this note", "what I'm looking at", "here", "above", "below", or questions whose subject is plainly the note's content. For unrelated questions, ignore this note entirely and answer normally. Do not mention that you can see this note unless it is relevant to the answer.

If Middle pane state is browser, only the URL and page title are supplied; the page content itself is NOT included. If you need the page content to answer, use the browser tools available to you to read the page. The user may or may not be talking about this page. Only reference or act on this page when the user's message clearly relates to it, such as "this page", "this article", "what I'm looking at", "this site", or "summarize this". For unrelated questions, ignore this page entirely and answer normally. Do not mention that you can see the browser unless it is relevant to the answer.`;

export interface IAgentRuntime {
  trigger(runId: string): Promise<void>;
}

export class AgentRuntime implements IAgentRuntime {
  private runsRepo: IRunsRepo;
  private idGenerator: IMonotonicallyIncreasingIdGenerator;
  private bus: IBus;
  private messageQueue: IMessageQueue;
  private modelConfigRepo: IModelConfigRepo;
  private runsLock: IRunsLock;
  private abortRegistry: IAbortRegistry;

  constructor({
    runsRepo,
    idGenerator,
    bus,
    messageQueue,
    modelConfigRepo,
    runsLock,
    abortRegistry,
  }: {
    runsRepo: IRunsRepo;
    idGenerator: IMonotonicallyIncreasingIdGenerator;
    bus: IBus;
    messageQueue: IMessageQueue;
    modelConfigRepo: IModelConfigRepo;
    runsLock: IRunsLock;
    abortRegistry: IAbortRegistry;
  }) {
    this.runsRepo = runsRepo;
    this.idGenerator = idGenerator;
    this.bus = bus;
    this.messageQueue = messageQueue;
    this.modelConfigRepo = modelConfigRepo;
    this.runsLock = runsLock;
    this.abortRegistry = abortRegistry;
  }

  async trigger(runId: string): Promise<void> {
    if (!(await this.runsLock.lock(runId))) {
      console.log(`unable to acquire lock on run ${runId}`);
      return;
    }
    const signal = this.abortRegistry.createForRun(runId);
    try {
      await this.bus.publish({
        runId,
        type: "run-processing-start",
        subflow: [],
      });
      let pinnedAgentName: string | null = null;
      let pinnedPermissionMode: "manual" | "auto" | null = null;
      while (true) {
        // Check for abort before each iteration
        if (signal.aborted) {
          break;
        }

        let eventCount = 0;
        const run = await this.runsRepo.fetch(runId);
        if (!run) {
          throw new Error(`Run ${runId} not found`);
        }
        const state = new AgentState();
        for (const event of run.log) {
          state.ingest(event);
        }
        if (pinnedAgentName === null) {
          pinnedAgentName = state.agentName;
          pinnedPermissionMode = state.permissionMode;
        } else if (
          state.agentName !== pinnedAgentName ||
          state.permissionMode !== pinnedPermissionMode
        ) {
          throw new Error(
            `Run ${runId} metadata changed unexpectedly during execution; aborting for safety.`,
          );
        }
        try {
          for await (const event of streamAgent({
            state,
            idGenerator: this.idGenerator,
            runId,
            messageQueue: this.messageQueue,
            modelConfigRepo: this.modelConfigRepo,
            signal,
            abortRegistry: this.abortRegistry,
            bus: this.bus,
          })) {
            eventCount++;
            if (event.type !== "llm-stream-event") {
              await this.runsRepo.appendEvents(runId, [event]);
            }
            await this.bus.publish(event);
          }
        } catch (error) {
          if (error instanceof Error && error.name === "AbortError") {
            // Abort detected — exit cleanly
            break;
          }
          throw error;
        }

        // if no events, break
        if (!eventCount) {
          break;
        }
      }

      // Emit run-stopped event if aborted
      if (signal.aborted) {
        const stoppedEvent: z.infer<typeof RunEvent> = {
          runId,
          type: "run-stopped",
          reason: "user-requested",
          subflow: [],
        };
        await this.runsRepo.appendEvents(runId, [stoppedEvent]);
        await this.bus.publish(stoppedEvent);
      }
    } catch (error) {
      console.error(`Run ${runId} failed:`, error);
      // Full detail (incl. stack) goes to the console above; the event
      // carries a clean, user-facing message — never a raw stack dump or
      // an object serialization that renders as "name: ClientError".
      const message =
        error instanceof Error
          ? error.message || error.name || "The run failed unexpectedly."
          : typeof error === "string"
            ? error
            : error &&
                typeof error === "object" &&
                typeof (error as { message?: unknown }).message === "string"
              ? (error as { message: string }).message
              : "The run failed unexpectedly.";
      const errorEvent: z.infer<typeof RunEvent> = {
        runId,
        type: "error",
        error: message,
        subflow: [],
      };
      await this.runsRepo.appendEvents(runId, [errorEvent]);
      await this.bus.publish(errorEvent);
    } finally {
      this.abortRegistry.cleanup(runId);
      await this.runsLock.release(runId);
      await this.bus.publish({
        runId,
        type: "run-processing-end",
        subflow: [],
      });
    }
  }
}

export async function mapAgentTool(t: z.infer<typeof ToolAttachment>): Promise<Tool> {
  switch (t.type) {
    case "mcp":
      return tool({
        name: t.name,
        description: t.description,
        inputSchema: jsonSchema(t.inputSchema),
      });
    case "agent": {
      const agent = await loadAgent(t.name);
      if (!agent) {
        throw new Error(`Agent ${t.name} not found`);
      }
      return tool({
        name: t.name,
        description: agent.description,
        inputSchema: z.object({
          message: z.string().describe("The message to send to the workflow"),
        }),
      });
    }
    case "builtin": {
      if (t.name === "ask-human") {
        return tool({
          description:
            "Ask a human before proceeding. Optionally pass `options` (an array of short button labels) to render the question as a one-click choice; the user's response will be the chosen label verbatim.",
          inputSchema: z.object({
            question: z.string().describe("The question to ask the human"),
            options: z
              .array(z.string())
              .optional()
              .describe(
                "Optional short button labels (2-4 recommended). If provided, the user picks one with a single click instead of typing. The response you receive will be the chosen label.",
              ),
          }),
        });
      }
      const match = BuiltinTools[t.name];
      if (!match) {
        throw new Error(`Unknown builtin tool: ${t.name}`);
      }
      return tool({
        description: match.description,
        inputSchema: match.inputSchema,
      });
    }
  }
}

export class RunLogger {
  private logFile: string;
  private fileHandle: fs.WriteStream;

  ensureRunsDir() {
    const runsDir = path.join(WorkDir, "runs");
    if (!fs.existsSync(runsDir)) {
      fs.mkdirSync(runsDir, { recursive: true });
    }
  }

  /** Cleared when the stream errors; writes become no-ops rather than throwing. */
  private writable = true;

  constructor(runId: string) {
    this.ensureRunsDir();
    this.logFile = path.join(WorkDir, "runs", `${runId}.jsonl`);
    this.fileHandle = fs.createWriteStream(this.logFile, {
      flags: "a",
      encoding: "utf8",
    });
    // One of these exists per agent run. An unhandled 'error' on a write stream
    // is an uncaught exception, so a full disk — or the run file being pruned
    // or deleted underneath us — would take the whole process down rather than
    // cost us the transcript of one run.
    this.fileHandle.on("error", (error) => {
      console.error(`[RunLog] ${this.logFile} is no longer writable:`, error);
      this.writable = false;
    });
  }

  log(event: z.infer<typeof RunEvent>) {
    if (!this.writable) return;
    if (event.type !== "llm-stream-event") {
      this.fileHandle.write(JSON.stringify(event) + "\n");
    }
  }

  close() {
    this.fileHandle.close();
  }
}

export class StreamStepMessageBuilder {
  private parts: z.infer<typeof AssistantContentPart>[] = [];
  private textBuffer: string = "";
  private reasoningBuffer: string = "";
  private providerOptions: z.infer<typeof ProviderOptions> | undefined = undefined;
  private reasoningProviderOptions: z.infer<typeof ProviderOptions> | undefined = undefined;

  flushBuffers() {
    if (this.reasoningBuffer || this.reasoningProviderOptions) {
      this.parts.push({
        type: "reasoning",
        text: this.reasoningBuffer,
        providerOptions: this.reasoningProviderOptions,
      });
      this.reasoningBuffer = "";
      this.reasoningProviderOptions = undefined;
    }
    if (this.textBuffer) {
      this.parts.push({ type: "text", text: this.textBuffer });
      this.textBuffer = "";
    }
  }

  ingest(event: z.infer<typeof LlmStepStreamEvent>) {
    switch (event.type) {
      case "reasoning-start":
        break;
      case "reasoning-end":
        this.reasoningProviderOptions = event.providerOptions;
        this.flushBuffers();
        break;
      case "text-start":
      case "text-end":
        this.flushBuffers();
        break;
      case "reasoning-delta":
        this.reasoningBuffer += event.delta;
        break;
      case "text-delta":
        this.textBuffer += event.delta;
        break;
      case "tool-call":
        this.parts.push({
          type: "tool-call",
          toolCallId: event.toolCallId,
          toolName: event.toolName,
          arguments: event.input,
          providerOptions: event.providerOptions,
        });
        break;
      case "finish-step":
        this.providerOptions = event.providerOptions;
        break;
      case "error":
        this.flushBuffers();
        break;
    }
  }

  get(): z.infer<typeof AssistantMessage> {
    this.flushBuffers();
    return {
      role: "assistant",
      content: this.parts,
      providerOptions: this.providerOptions,
    };
  }
}

function formatLlmStreamError(rawError: unknown): string {
  let name: string | undefined;
  let message: string | undefined;
  let responseBody: string | undefined;
  if (rawError && typeof rawError === "object") {
    const err = rawError as Record<string, unknown>;
    const nested =
      err.error && typeof err.error === "object" ? (err.error as Record<string, unknown>) : null;
    const lastError =
      err.lastError && typeof err.lastError === "object"
        ? (err.lastError as Record<string, unknown>)
        : null;
    const retryErrors = Array.isArray(err.errors)
      ? (err.errors.filter((item) => item && typeof item === "object") as Record<string, unknown>[])
      : [];
    const pick = (key: string): string | undefined => {
      const value =
        err[key] ??
        nested?.[key] ??
        lastError?.[key] ??
        retryErrors
          .slice()
          .reverse()
          .find((item) => item[key] !== undefined)?.[key];
      return value === undefined || value === null || value === "" ? undefined : String(value);
    };
    name = pick("name");
    message = pick("message");
    responseBody = pick("responseBody");
  } else if (typeof rawError === "string") {
    message = rawError;
  }

  const billingCode = responseBody?.match(
    /\b(subscription_not_active|insufficient_credits|upgrade_required)\b/i,
  )?.[1];
  if (billingCode) {
    return billingCode;
  }

  // Compose a sentence the user can act on — a bare identifier (the old
  // "name: AI_RetryError" box) explains nothing.
  const detail = message || responseBody;
  if (detail) {
    return name && name !== "Error" && !detail.includes(name) ? `${detail} (${name})` : detail;
  }
  if (name === "AI_RetryError") {
    return "The model request failed after several retries. Check your connection and model settings, then try again.";
  }
  if (name && name !== "Error") {
    return `The model request failed (${name}). Try again.`;
  }
  return "The model request failed. Try again.";
}

export async function loadAgent(id: string): Promise<z.infer<typeof Agent>> {
  if (id === "copilot" || id === "rowboatx") {
    return buildCopilotAgent();
  }

  if (id === "live-note-agent") {
    return buildLiveNoteAgent();
  }

  if (id === "background-task-agent") {
    return buildBackgroundTaskAgent();
  }

  if (id === "note_creation") {
    const raw = getNoteCreationRaw();
    let agent: z.infer<typeof Agent> = {
      name: id,
      instructions: raw,
    };

    // Parse frontmatter if present
    if (raw.startsWith("---")) {
      const end = raw.indexOf("\n---", 3);
      if (end !== -1) {
        const fm = raw.slice(3, end).trim();
        const content = raw.slice(end + 4).trim();
        const yaml = parse(fm);
        const parsed = Agent.omit({ name: true, instructions: true }).parse(yaml);
        agent = {
          ...agent,
          ...parsed,
          instructions: content,
        };
      }
    }

    return agent;
  }

  if (id === "labeling_agent") {
    const labelingAgentRaw = getLabelingAgentRaw();
    let agent: z.infer<typeof Agent> = {
      name: id,
      instructions: labelingAgentRaw,
    };

    if (labelingAgentRaw.startsWith("---")) {
      const end = labelingAgentRaw.indexOf("\n---", 3);
      if (end !== -1) {
        const fm = labelingAgentRaw.slice(3, end).trim();
        const content = labelingAgentRaw.slice(end + 4).trim();
        const yaml = parse(fm);
        const parsed = Agent.omit({ name: true, instructions: true }).parse(yaml);
        agent = {
          ...agent,
          ...parsed,
          instructions: content,
        };
      }
    }

    return agent;
  }

  if (id === "note_tagging_agent") {
    const noteTaggingAgentRaw = getNoteTaggingAgentRaw();
    let agent: z.infer<typeof Agent> = {
      name: id,
      instructions: noteTaggingAgentRaw,
    };

    if (noteTaggingAgentRaw.startsWith("---")) {
      const end = noteTaggingAgentRaw.indexOf("\n---", 3);
      if (end !== -1) {
        const fm = noteTaggingAgentRaw.slice(3, end).trim();
        const content = noteTaggingAgentRaw.slice(end + 4).trim();
        const yaml = parse(fm);
        const parsed = Agent.omit({ name: true, instructions: true }).parse(yaml);
        agent = {
          ...agent,
          ...parsed,
          instructions: content,
        };
      }
    }

    return agent;
  }

  if (id === "inline_task_agent") {
    const inlineTaskAgentRaw = getInlineTaskAgentRaw();
    let agent: z.infer<typeof Agent> = {
      name: id,
      instructions: inlineTaskAgentRaw,
    };

    if (inlineTaskAgentRaw.startsWith("---")) {
      const end = inlineTaskAgentRaw.indexOf("\n---", 3);
      if (end !== -1) {
        const fm = inlineTaskAgentRaw.slice(3, end).trim();
        const content = inlineTaskAgentRaw.slice(end + 4).trim();
        const yaml = parse(fm);
        const parsed = Agent.omit({ name: true, instructions: true }).parse(yaml);
        agent = {
          ...agent,
          ...parsed,
          instructions: content,
        };
      }
    }

    return agent;
  }

  if (id === "agent_notes_agent") {
    const agentNotesAgentRaw = getAgentNotesAgentRaw();
    let agent: z.infer<typeof Agent> = {
      name: id,
      instructions: agentNotesAgentRaw,
    };

    if (agentNotesAgentRaw.startsWith("---")) {
      const end = agentNotesAgentRaw.indexOf("\n---", 3);
      if (end !== -1) {
        const fm = agentNotesAgentRaw.slice(3, end).trim();
        const content = agentNotesAgentRaw.slice(end + 4).trim();
        const yaml = parse(fm);
        const parsed = Agent.omit({ name: true, instructions: true }).parse(yaml);
        agent = {
          ...agent,
          ...parsed,
          instructions: content,
        };
      }
    }

    return agent;
  }

  const repo = container.resolve<IAgentsRepo>("agentsRepo");
  return await repo.fetch(id);
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export function convertFromMessages(messages: z.infer<typeof Message>[]): ModelMessage[] {
  const result: ModelMessage[] = [];
  for (const msg of messages) {
    const { providerOptions } = msg;
    switch (msg.role) {
      case "assistant":
        if (typeof msg.content === "string") {
          result.push({
            role: "assistant",
            content: msg.content,
            providerOptions,
          });
        } else {
          result.push({
            role: "assistant",
            content: msg.content.map((part) => {
              switch (part.type) {
                case "text":
                  return part;
                case "reasoning":
                  return part;
                case "tool-call":
                  return {
                    type: "tool-call",
                    toolCallId: part.toolCallId,
                    toolName: part.toolName,
                    input: part.arguments,
                    providerOptions: part.providerOptions,
                  };
              }
            }),
            providerOptions,
          });
        }
        break;
      case "system":
        result.push({
          role: "system",
          content: msg.content,
          providerOptions,
        });
        break;
      case "user": {
        const userMessageContextPrefix = msg.userMessageContext
          ? formatUserMessageContextForLlm(msg.userMessageContext)
          : "";
        if (typeof msg.content === "string") {
          // Legacy string — pass through unchanged
          result.push({
            role: "user",
            content: `${userMessageContextPrefix}${msg.content}`,
            providerOptions,
          });
        } else {
          // New content parts array — collapse to text for LLM
          const textSegments: string[] = userMessageContextPrefix ? [userMessageContextPrefix] : [];
          const attachmentLines: string[] = [];

          for (const part of msg.content) {
            if (part.type === "attachment") {
              const sizeStr = part.size ? `, ${formatBytes(part.size)}` : "";
              const lineStr = part.lineNumber ? ` (line ${part.lineNumber})` : "";
              attachmentLines.push(
                `- ${part.filename} (${part.mimeType}${sizeStr}) at ${part.path}${lineStr}`,
              );
            } else {
              textSegments.push(part.text);
            }
          }

          if (attachmentLines.length > 0) {
            if (userMessageContextPrefix) {
              textSegments.push("User has attached the following files:", ...attachmentLines, "");
            } else {
              textSegments.unshift(
                "User has attached the following files:",
                ...attachmentLines,
                "",
              );
            }
          }

          result.push({
            role: "user",
            content: textSegments.join("\n"),
            providerOptions,
          });
        }
        break;
      }
      case "tool":
        result.push({
          role: "tool",
          content: [
            {
              type: "tool-result",
              toolCallId: msg.toolCallId,
              toolName: msg.toolName,
              output: {
                type: "text",
                value: msg.content,
              },
            },
          ],
          providerOptions,
        });
        break;
    }
  }
  // doing this because: https://github.com/OpenRouterTeam/ai-sdk-provider/issues/262
  return JSON.parse(JSON.stringify(result));
}

async function buildTools(agent: z.infer<typeof Agent>): Promise<ToolSet> {
  const tools: ToolSet = {};
  for (const [name, tool] of Object.entries(agent.tools ?? {})) {
    try {
      // Skip builtin tools that declare themselves unavailable
      if (tool.type === "builtin") {
        const builtin = BuiltinTools[tool.name];
        if (builtin?.isAvailable && !(await builtin.isAvailable())) {
          continue;
        }
      }
      tools[name] = await mapAgentTool(tool);
    } catch (error) {
      console.error(`Error mapping tool ${name}:`, error);
      continue;
    }
  }
  return tools;
}

/**
 * Extract ONLY raw user-authored text messages for the auto-permission classifier.
 * Excludes `userMessageContext` (open middle-pane notes or browser page metadata)
 * and attachment blocks so untrusted page/note content cannot inject instructions
 * or evict the real user request via truncation.
 */
export function extractTrustedUserMessagesForClassifier(
  messages: z.infer<typeof MessageList>,
): ModelMessage[] {
  const result: ModelMessage[] = [];
  for (const msg of messages) {
    if (msg.role !== "user") continue;
    if (typeof msg.content === "string") {
      const text = msg.content.trim();
      if (text) {
        result.push({ role: "user", content: text });
      }
      continue;
    }
    const textParts: string[] = [];
    for (const part of msg.content) {
      if (part.type === "text" && part.text.trim()) {
        textParts.push(part.text);
      }
    }
    if (textParts.length > 0) {
      result.push({ role: "user", content: textParts.join("\n") });
    }
  }
  return result;
}

export class AgentState {
  runId: string | null = null;
  agent: z.infer<typeof Agent> | null = null;
  agentName: string | null = null;
  runModel: string | null = null;
  runProvider: string | null = null;
  permissionMode: "manual" | "auto" = "manual";
  runUseCase: UseCase | null = null;
  runSubUseCase: string | null = null;
  messages: z.infer<typeof MessageList> = [];
  lastAssistantMsg: z.infer<typeof AssistantMessage> | null = null;
  subflowStates: Record<string, AgentState> = {};
  toolCallIdMap: Record<string, z.infer<typeof ToolCallPart>> = {};
  pendingToolCalls: Record<string, true> = {};
  pendingToolPermissionRequests: Record<string, z.infer<typeof ToolPermissionRequestEvent>> = {};
  pendingAskHumanRequests: Record<string, z.infer<typeof AskHumanRequestEvent>> = {};
  allowedToolCallIds: Record<string, true> = {};
  deniedToolCallIds: Record<string, true> = {};
  autoAllowedToolCalls: Record<string, { reason: string }> = {};
  autoDeniedToolCalls: Record<string, { reason: string }> = {};
  sessionAllowedCommands: Set<string> = new Set();
  sessionAllowedFileAccess: FileAccessGrant[] = [];
  sessionAllowedMcpSpawns: Set<string> = new Set();
  approvedMcpSpawnDigests: Record<string, string> = {};
  approvedCodeAgentByToolCallId: Record<string, "claude" | "codex"> = {};

  getPendingPermissions(): z.infer<typeof ToolPermissionRequestEvent>[] {
    const response: z.infer<typeof ToolPermissionRequestEvent>[] = [];
    for (const [id, subflowState] of Object.entries(this.subflowStates)) {
      for (const perm of subflowState.getPendingPermissions()) {
        response.push({
          ...perm,
          subflow: [id, ...perm.subflow],
        });
      }
    }
    for (const perm of Object.values(this.pendingToolPermissionRequests)) {
      response.push({
        ...perm,
        subflow: [],
      });
    }
    return response;
  }

  getPendingAskHumans(): z.infer<typeof AskHumanRequestEvent>[] {
    const response: z.infer<typeof AskHumanRequestEvent>[] = [];
    for (const [id, subflowState] of Object.entries(this.subflowStates)) {
      for (const ask of subflowState.getPendingAskHumans()) {
        response.push({
          ...ask,
          subflow: [id, ...ask.subflow],
        });
      }
    }
    for (const ask of Object.values(this.pendingAskHumanRequests)) {
      response.push({
        ...ask,
        subflow: [],
      });
    }
    return response;
  }

  /**
   * Returns tool-result messages for all pending tool calls, marking them as aborted.
   * This is called when a run is stopped so the LLM knows what happened to its tool requests.
   */
  getAbortedToolResults(): z.infer<typeof ToolMessage>[] {
    const results: z.infer<typeof ToolMessage>[] = [];
    for (const toolCallId of Object.keys(this.pendingToolCalls)) {
      const toolCall = this.toolCallIdMap[toolCallId];
      if (toolCall) {
        results.push({
          role: "tool",
          content: JSON.stringify({ error: "Tool execution aborted" }),
          toolCallId,
          toolName: toolCall.toolName,
        });
      }
    }
    return results;
  }

  /**
   * Clear all pending state (permissions, ask-human, tool calls).
   * Used when a run is stopped.
   */
  clearAllPending(): void {
    this.pendingToolPermissionRequests = {};
    this.pendingAskHumanRequests = {};
    // Recursively clear subflows
    for (const subflow of Object.values(this.subflowStates)) {
      subflow.clearAllPending();
    }
  }

  finalResponse(): string {
    if (!this.lastAssistantMsg) {
      return "";
    }
    if (typeof this.lastAssistantMsg.content === "string") {
      return this.lastAssistantMsg.content;
    }
    return this.lastAssistantMsg.content.reduce((acc, part) => {
      if (part.type === "text") {
        return acc + part.text;
      }
      return acc;
    }, "");
  }

  ingest(event: z.infer<typeof RunEvent>) {
    if (event.subflow.length > 0) {
      const { subflow, ...rest } = event;
      if (!this.subflowStates[subflow[0]]) {
        this.subflowStates[subflow[0]] = new AgentState();
      }
      this.subflowStates[subflow[0]].ingest({
        ...rest,
        subflow: subflow.slice(1),
      });
      return;
    }
    switch (event.type) {
      case "start":
        this.runId = event.runId;
        this.agentName = event.agentName;
        this.runModel = event.model;
        this.runProvider = event.provider;
        this.permissionMode = event.permissionMode ?? "manual";
        this.runUseCase = event.useCase ?? null;
        this.runSubUseCase = event.subUseCase ?? null;
        break;
      case "spawn-subflow":
        // Seed the subflow state with its agent so downstream loadAgent works.
        // Subflows inherit the parent run's model+provider — there's one pair per run.
        // Subflows always use manual permission mode because their initial "user"
        // message is model-authored by the parent agent rather than directly typed by the user.
        if (!this.subflowStates[event.toolCallId]) {
          this.subflowStates[event.toolCallId] = new AgentState();
        }
        this.subflowStates[event.toolCallId].agentName = event.agentName;
        this.subflowStates[event.toolCallId].runModel = this.runModel;
        this.subflowStates[event.toolCallId].runProvider = this.runProvider;
        this.subflowStates[event.toolCallId].permissionMode = "manual";
        this.subflowStates[event.toolCallId].runUseCase = this.runUseCase;
        this.subflowStates[event.toolCallId].runSubUseCase = this.runSubUseCase;
        break;
      case "message":
        this.messages.push(event.message);
        if (event.message.content instanceof Array) {
          for (const part of event.message.content) {
            if (part.type === "tool-call") {
              // Ignore duplicate toolCallIds so a second tool-call part cannot
              // overwrite the arguments associated with an already-requested ID.
              if (!Object.prototype.hasOwnProperty.call(this.toolCallIdMap, part.toolCallId)) {
                this.toolCallIdMap[part.toolCallId] = part;
                this.pendingToolCalls[part.toolCallId] = true;
              }
            }
          }
        }
        if (event.message.role === "tool") {
          const message = event.message as z.infer<typeof ToolMessage>;
          delete this.pendingToolCalls[message.toolCallId];
          delete this.allowedToolCallIds[message.toolCallId];
          delete this.deniedToolCallIds[message.toolCallId];
          delete this.approvedMcpSpawnDigests[message.toolCallId];
          delete this.approvedCodeAgentByToolCallId[message.toolCallId];
        }
        if (event.message.role === "assistant") {
          this.lastAssistantMsg = event.message;
        }
        break;
      case "tool-permission-request":
        this.pendingToolPermissionRequests[event.toolCall.toolCallId] = event;
        break;
      case "tool-permission-response": {
        const permissionRequest = this.pendingToolPermissionRequests[event.toolCallId];
        // Ignore orphaned or replayed responses without an active pending request
        if (!permissionRequest) {
          break;
        }
        const permission = permissionRequest.permission;
        const response = event.response;
        switch (response) {
          case "approve": {
            this.allowedToolCallIds[event.toolCallId] = true;
            if (
              permission?.kind === "mcp" &&
              permission.action === "spawn" &&
              permission.configDigest
            ) {
              // Bind one-time approval strictly to this toolCallId so `scope: "once"`
              // never silently upgrades to a run-wide grant.
              this.approvedMcpSpawnDigests[event.toolCallId] = permission.configDigest;
            }
            if (
              permission?.kind === "command" &&
              permissionRequest.toolCall.toolName === "code_agent_run"
            ) {
              const approvedCmd = permission.commandNames[0];
              if (approvedCmd === "code_agent_run:claude") {
                this.approvedCodeAgentByToolCallId[event.toolCallId] = "claude";
              } else if (approvedCmd === "code_agent_run:codex") {
                this.approvedCodeAgentByToolCallId[event.toolCallId] = "codex";
              }
            }
            if (event.scope === "session" && permission?.allowScopeGrant === true) {
              switch (permission.kind) {
                case "file": {
                  if (
                    !isSensitiveOrBroadExternalGrantPrefix(permission.pathPrefix) &&
                    !isProtectedWorkspacePath(permission.pathPrefix, permission.operation)
                  ) {
                    this.sessionAllowedFileAccess.push({
                      operation: permission.operation,
                      pathPrefix: permission.pathPrefix,
                    });
                  }
                  break;
                }
                case "mcp": {
                  if (permission.action === "spawn" && permission.configDigest) {
                    this.sessionAllowedMcpSpawns.add(permission.configDigest);
                  }
                  break;
                }
                case "command": {
                  const rawNames =
                    permission.commandNames.length > 0
                      ? permission.commandNames
                      : (() => {
                          const toolCall = this.toolCallIdMap[event.toolCallId];
                          return toolCall &&
                            typeof toolCall.arguments === "object" &&
                            toolCall.arguments !== null &&
                            !Array.isArray(toolCall.arguments) &&
                            "command" in toolCall.arguments
                            ? extractCommandNames(String(toolCall.arguments.command))
                            : [];
                        })();
                  const safeNames = rawNames.filter(
                    (name) => !isAlwaysRequireApprovalCommand(name),
                  );
                  for (const name of safeNames) {
                    this.sessionAllowedCommands.add(name);
                  }
                  break;
                }
                default: {
                  const unhandled: never = permission;
                  throw new Error(`Unhandled permission kind: ${String(unhandled)}`);
                }
              }
            }
            break;
          }
          case "deny":
            this.deniedToolCallIds[event.toolCallId] = true;
            delete this.autoDeniedToolCalls[event.toolCallId];
            break;
          default: {
            const unhandled: never = response;
            throw new Error(`Unhandled permission response: ${String(unhandled)}`);
          }
        }
        delete this.pendingToolPermissionRequests[event.toolCallId];
        break;
      }
      case "tool-permission-auto-decision": {
        const decision = event.decision;
        switch (decision) {
          case "allow":
            // Defense-in-depth: never accept an auto-allow for MCP, external write/delete,
            // or non-scope-grantable calls
            if (
              event.permission?.kind === "mcp" ||
              event.permission?.allowScopeGrant !== true ||
              (event.permission?.kind === "file" &&
                (event.permission.operation === "write" || event.permission.operation === "delete"))
            ) {
              break;
            }
            this.allowedToolCallIds[event.toolCallId] = true;
            this.autoAllowedToolCalls[event.toolCallId] = { reason: event.reason };
            break;
          case "deny":
            this.autoDeniedToolCalls[event.toolCallId] = { reason: event.reason };
            break;
          default: {
            const unhandled: never = decision;
            throw new Error(`Unhandled auto-permission decision: ${String(unhandled)}`);
          }
        }
        break;
      }
      case "ask-human-request":
        this.pendingAskHumanRequests[event.toolCallId] = event;
        break;
      case "ask-human-response": {
        const ogEvent = this.pendingAskHumanRequests[event.toolCallId];
        if (!ogEvent) {
          break;
        }
        const toolCall = this.toolCallIdMap[ogEvent.toolCallId];
        this.messages.push({
          role: "tool",
          content: JSON.stringify({
            userResponse: event.response,
          }),
          toolCallId: ogEvent.toolCallId,
          toolName: toolCall?.toolName ?? "ask-human",
        });
        delete this.pendingAskHumanRequests[ogEvent.toolCallId];
        break;
      }
    }
  }
}

export async function* streamAgent({
  state,
  idGenerator,
  runId,
  messageQueue,
  modelConfigRepo,
  signal,
  abortRegistry,
  bus,
  subflowPath = [],
}: {
  state: AgentState;
  idGenerator: IMonotonicallyIncreasingIdGenerator;
  runId: string;
  messageQueue: IMessageQueue;
  modelConfigRepo: IModelConfigRepo;
  signal: AbortSignal;
  abortRegistry: IAbortRegistry;
  bus: IBus;
  subflowPath?: string[];
}): AsyncGenerator<z.infer<typeof RunEvent>, void, unknown> {
  const isSubflow = subflowPath.length > 0;
  const logger = new PrefixLogger(`run-${runId}-${state.agentName}`);

  async function* processEvent(
    event: z.infer<typeof RunEvent>,
  ): AsyncGenerator<z.infer<typeof RunEvent>, void, unknown> {
    state.ingest(event);
    yield event;
  }

  // set up agent
  const agent = await loadAgent(state.agentName!);

  // set up tools
  const tools = await buildTools(agent);

  // model+provider were resolved and frozen on the run at runs:create time.
  // Look up the named provider's current credentials from models.json and
  // instantiate the LLM client. No selection happens here.
  if (!state.runModel || !state.runProvider) {
    throw new Error(`Run ${runId} is missing model/provider on its start event`);
  }
  const modelId = state.runModel;
  const providerConfig = await resolveProviderConfig(state.runProvider);
  const provider = createProvider(providerConfig);
  const model = provider.languageModel(modelId);
  logger.log(`using model: ${modelId} (provider: ${state.runProvider})`);

  // Install use-case context for tool-internal LLM calls (e.g. parseFile)
  // so they can tag their `llm_usage` events with the parent run's category.
  enterUseCase({
    useCase: state.runUseCase ?? "copilot_chat",
    ...(state.runSubUseCase ? { subUseCase: state.runSubUseCase } : {}),
    ...(state.agentName ? { agentName: state.agentName } : {}),
  });

  let loopCounter = 0;
  let voiceInput = false;
  let voiceOutput: "summary" | "full" | null = null;
  let searchEnabled = false;
  let codeMode: "claude" | "codex" | null = null;
  let middlePaneContext:
    | { kind: "note"; path: string; content: string }
    | { kind: "browser"; url: string; title: string }
    | null = null;
  while (true) {
    // Check abort at the top of each iteration
    signal.throwIfAborted();

    loopCounter++;
    const loopLogger = logger.child(`iter-${loopCounter}`);
    loopLogger.log("starting loop iteration");

    // execute any pending tool calls
    for (const toolCallId of Object.keys(state.pendingToolCalls)) {
      const toolCall = state.toolCallIdMap[toolCallId];
      const _logger = loopLogger.child(`tc-${toolCallId}-${toolCall.toolName}`);
      _logger.log("processing");

      // if ask-human, skip
      if (toolCall.toolName === "ask-human") {
        _logger.log("skipping, reason: ask-human");
        continue;
      }

      // if tool has been denied, deny
      if (state.deniedToolCallIds[toolCallId]) {
        _logger.log("returning denied tool message, reason: tool has been denied");
        const autoDenied = state.autoDeniedToolCalls[toolCallId];
        yield* processEvent({
          runId,
          messageId: await idGenerator.next(),
          type: "message",
          message: {
            role: "tool",
            content: autoDenied
              ? JSON.stringify({
                  success: false,
                  error: `Auto-permission denied: ${autoDenied.reason}`,
                })
              : "Unable to execute this tool: Permission was denied.",
            toolCallId: toolCallId,
            toolName: toolCall.toolName,
          },
          subflow: [],
        });
        continue;
      }

      // if permission is pending on this tool call, skip execution
      if (state.pendingToolPermissionRequests[toolCallId]) {
        _logger.log("skipping, reason: permission is pending");
        continue;
      }

      const underlyingTool =
        agent.tools && Object.prototype.hasOwnProperty.call(agent.tools, toolCall.toolName)
          ? agent.tools[toolCall.toolName]
          : undefined;
      if (!underlyingTool) {
        const missingResult = {
          success: false,
          error: `Unknown tool: ${toolCall.toolName}`,
          toolName: toolCall.toolName,
        };
        yield* processEvent({
          runId,
          type: "tool-result",
          toolCallId: toolCall.toolCallId,
          toolName: toolCall.toolName,
          result: missingResult,
          subflow: [],
        });
        yield* processEvent({
          runId,
          messageId: await idGenerator.next(),
          type: "message",
          message: {
            role: "tool",
            content: JSON.stringify(missingResult),
            toolCallId: toolCall.toolCallId,
            toolName: toolCall.toolName,
          },
          subflow: [],
        });
        continue;
      }

      if (!state.allowedToolCallIds[toolCallId]) {
        // Re-check permissions right before execution so a prior tool call in
        // the same turn (e.g. addMcpServer overwriting a server with a stdio
        // command) or an external config change cannot bypass approval.
        const latePermission = await getToolPermissionMetadata(
          toolCall,
          underlyingTool,
          state.sessionAllowedCommands,
          state.sessionAllowedFileAccess,
          state.sessionAllowedMcpSpawns,
          { codeMode, agentName: state.agentName },
        );
        if (latePermission) {
          _logger.log("emitting late tool-permission-request before execution");
          yield* processEvent({
            runId,
            type: "tool-permission-request",
            toolCall,
            permission: latePermission,
            subflow: [],
          });
          continue;
        }
      }

      // execute approved tool
      // Check abort before starting tool execution
      if (signal.aborted) {
        _logger.log("skipping, reason: aborted");
        break;
      }
      _logger.log("executing tool");
      yield* processEvent({
        runId,
        type: "tool-invocation",
        toolCallId,
        toolName: toolCall.toolName,
        input: JSON.stringify(toolCall.arguments ?? {}),
        subflow: [],
      });
      let result: unknown = null;
      let subflowPaused = false;
      try {
        let mcpSpawnPolicy: McpSpawnPolicy | undefined;
        const isMcpSpawnCapableTool =
          underlyingTool.type === "mcp" ||
          (underlyingTool.type === "builtin" &&
            (underlyingTool.name === "listMcpTools" || underlyingTool.name === "executeMcpTool"));
        if (isMcpSpawnCapableTool) {
          // Default to remote-only for every MCP spawn-capable tool call so an empty
          // or unvalidated serverName can never fall through to an unrestricted spawn.
          mcpSpawnPolicy = { kind: "remote-only" };
          const mcpServerName =
            underlyingTool.type === "mcp"
              ? underlyingTool.mcpServerName
              : toolCall.arguments &&
                  typeof toolCall.arguments === "object" &&
                  !Array.isArray(toolCall.arguments) &&
                  "serverName" in toolCall.arguments &&
                  typeof toolCall.arguments.serverName === "string"
                ? toolCall.arguments.serverName
                : "";
          const expectedMcpDigest = state.approvedMcpSpawnDigests[toolCallId];
          if (expectedMcpDigest) {
            const currentReq = mcpServerName
              ? await getStdioMcpSpawnRequirement(mcpServerName)
              : null;
            if (!currentReq || currentReq.configDigest !== expectedMcpDigest) {
              throw new Error(
                "The stdio MCP server configuration changed after approval. Refusing to spawn.",
              );
            }
            mcpSpawnPolicy = { kind: "stdio", expectedDigest: expectedMcpDigest };
          } else if (mcpServerName) {
            const currentReq = await getStdioMcpSpawnRequirement(mcpServerName);
            if (currentReq) {
              const persistentGrants = getMcpServerAllowList();
              const isAuthorized =
                state.sessionAllowedMcpSpawns.has(currentReq.configDigest) ||
                persistentGrants.some(
                  (grant) =>
                    grant.serverName === currentReq.serverName &&
                    grant.configDigest === currentReq.configDigest,
                );
              if (!isAuthorized) {
                throw new Error("The stdio MCP server requires explicit approval before spawning.");
              }
              mcpSpawnPolicy = { kind: "stdio", expectedDigest: currentReq.configDigest };
            }
          }
        }
        if (underlyingTool.type === "agent") {
          const subflowState = state.subflowStates[toolCallId];
          for await (const event of streamAgent({
            state: subflowState,
            idGenerator,
            runId,
            messageQueue,
            modelConfigRepo,
            signal,
            abortRegistry,
            bus,
            subflowPath: [...subflowPath, toolCallId],
          })) {
            // subflowState already ingested `event` inside the recursive streamAgent;
            // yield directly with the outer subflow prefix to avoid double-ingestion.
            yield {
              ...event,
              subflow: [toolCallId, ...event.subflow],
            };
          }
          if (
            subflowState.getPendingAskHumans().length > 0 ||
            subflowState.getPendingPermissions().length > 0
          ) {
            subflowPaused = true;
          } else {
            result = subflowState.finalResponse();
          }
        } else {
          result = await execTool(underlyingTool, toolCall.arguments, {
            runId,
            toolCallId,
            signal,
            abortRegistry,
            publish: (event) => bus.publish(event),
            codeMode: state.approvedCodeAgentByToolCallId[toolCallId] ?? codeMode,
            mcpSpawnPolicy,
            subflow: subflowPath,
          });
        }
      } catch (error) {
        if ((error instanceof Error && error.name === "AbortError") || signal.aborted) {
          throw error;
        }
        const message = error instanceof Error ? error.message || error.name : String(error);
        _logger.log("tool failed", message);
        result = {
          success: false,
          error: message,
          toolName: toolCall.toolName,
        };
      }
      if (subflowPaused) {
        continue;
      }
      const resultPayload = result === undefined ? null : result;
      const resultMsg: z.infer<typeof ToolMessage> = {
        role: "tool",
        content: JSON.stringify(resultPayload),
        toolCallId: toolCall.toolCallId,
        toolName: toolCall.toolName,
      };
      yield* processEvent({
        runId,
        type: "tool-result",
        toolCallId: toolCall.toolCallId,
        toolName: toolCall.toolName,
        result: resultPayload,
        subflow: [],
      });
      yield* processEvent({
        runId,
        messageId: await idGenerator.next(),
        type: "message",
        message: resultMsg,
        subflow: [],
      });
    }

    // if waiting on user permission or ask-human, exit
    if (state.getPendingAskHumans().length || state.getPendingPermissions().length) {
      loopLogger.log("exiting loop, reason: pending asks or permissions");
      return;
    }

    // Only the top-level run consumes queued user messages; subflows receive their
    // input via spawn-subflow and must never steal parent messages or codeMode.
    if (!isSubflow) {
      while (true) {
        const msg = await messageQueue.dequeue(runId);
        if (!msg) {
          break;
        }
        if (msg.voiceInput) {
          voiceInput = true;
        }
        if (msg.searchEnabled) {
          searchEnabled = true;
        }
        // Code mode is per-message: latest message decides whether the assistant
        // should route coding work through the code-with-agents skill / chosen agent.
        codeMode = msg.codeMode ?? null;
        if (msg.voiceOutput) {
          voiceOutput = msg.voiceOutput;
        }
        // Middle pane is NOT sticky — it should reflect the state at the moment of the
        // latest user message. If the user closed the pane between messages, clear it.
        middlePaneContext = msg.middlePaneContext ?? null;
        loopLogger.log("dequeued user message", msg.messageId);
        const userMessageContext = buildUserMessageContext({
          agentName: state.agentName,
          middlePaneContext,
        });
        yield* processEvent({
          runId,
          type: "message",
          messageId: msg.messageId,
          message: {
            role: "user",
            content: msg.message,
            userMessageContext,
          },
          subflow: [],
        });
      }
    }

    // if last response is from assistant and text, exit
    const lastMessage = state.messages[state.messages.length - 1];
    if (
      lastMessage &&
      lastMessage.role === "assistant" &&
      (typeof lastMessage.content === "string" ||
        !lastMessage.content.some((part) => part.type === "tool-call"))
    ) {
      loopLogger.log("exiting loop, reason: last message is from assistant and text");
      return;
    }

    // run one LLM turn.
    loopLogger.log("running llm turn");
    // stream agent response and build message
    const messageBuilder = new StreamStepMessageBuilder();
    let instructionsWithDateTime = `${agent.instructions}\n\n${USER_CONTEXT_SYSTEM_INSTRUCTIONS}`;
    // Inject Agent Notes context for copilot
    if (state.agentName === "copilot" || state.agentName === "rowboatx") {
      const agentNotesContext = loadAgentNotesContext();
      if (agentNotesContext) {
        instructionsWithDateTime += `\n\n${agentNotesContext}`;
      }
      const userWorkDir = loadUserWorkDir(runId);
      if (userWorkDir) {
        loopLogger.log("injecting user work directory", userWorkDir);
        instructionsWithDateTime += `\n\n# User Work Directory
The user has chosen the following directory as their current **work directory**:

\`${userWorkDir}\`

Treat this as the **default location** for file operations whenever the user refers to files generically:
- "list the files", "show me what's in here", "what's the latest report" — list or look in the work directory.
- "save this", "export it", "write that to a file" — write the output into the work directory unless the user names another location.
- "open the file I was just working on", "the doc from earlier" — assume the work directory first.

Use absolute paths rooted at this directory with the \`file-*\` tools. For example, list with \`file-list({ path: "${userWorkDir}" })\`, read text with \`file-readText\`, and write text with \`file-writeText\`. For PDFs, Office docs, images, scanned docs, and other non-text files, use \`parseFile\` or \`LLMParse\` with the absolute path; you do NOT need to copy the file into the workspace first.

**Exceptions — these ALWAYS take precedence over the work directory default:**
1. **Knowledge base questions.** If the user asks about anything in the knowledge graph (notes, people, organizations, projects, topics) or paths starting with \`knowledge/\`, use file tools against \`knowledge/\` as documented above. Do NOT redirect those into the work directory.
2. **Explicit paths.** If the user names a different directory or gives an absolute/relative path (e.g. "in ~/Downloads", "from /tmp/foo", "the Desktop"), honor that path exactly and ignore the work-directory default for that request.
3. **Workspace-specific operations.** Anything that obviously belongs in the Oppulence workspace (config files, MCP servers, agent schedules, etc.) stays in the workspace, not the work directory.

Do not announce the work directory unless it's relevant. Just use it.`;
      }
    }
    if (voiceInput) {
      loopLogger.log("voice input enabled, injecting voice input prompt");
      instructionsWithDateTime += `\n\n# Voice Input\nThe user's message was transcribed from speech. Be aware that:\n- There may be transcription errors. Silently correct obvious ones (e.g. homophones, misheard words). If an error is genuinely ambiguous, briefly mention your interpretation (e.g. "I'm assuming you meant X").\n- Spoken messages are often long-winded. The user may ramble, repeat themselves, or correct something they said earlier in the same message. Focus on their final intent, not every word verbatim.`;
    }
    if (voiceOutput === "summary") {
      loopLogger.log("voice output enabled (summary mode), injecting voice output prompt");
      instructionsWithDateTime += `\n\n# Voice Output (MANDATORY — READ THIS FIRST)\nThe user has voice output enabled. THIS IS YOUR #1 PRIORITY: you MUST start your response with <voice></voice> tags. If your response does not begin with <voice> tags, the user will hear nothing — which is a broken experience. NEVER skip this.\n\nRules:\n1. YOUR VERY FIRST OUTPUT MUST BE A <voice> TAG. No exceptions. Do not start with markdown, headings, or any other text. The literal first characters of your response must be "<voice>".\n2. Place ALL <voice> tags at the BEGINNING of your response, before any detailed content. Do NOT intersperse <voice> tags throughout the response.\n3. Wrap EACH spoken sentence in its own separate <voice> tag so it can be spoken incrementally. Do NOT wrap everything in a single <voice> block.\n4. Use voice as a TL;DR and navigation aid — do NOT read the entire response aloud.\n5. After all <voice> tags, you may include detailed written content (markdown, tables, code, etc.) that will be shown visually but not spoken.\n\n## Examples\n\nExample 1 — User asks: "what happened in my meeting with Alex yesterday?"\n\n<voice>Your meeting with Alex covered three main things: the Q2 roadmap timeline, hiring for the backend role, and the client demo next week.</voice>\n<voice>I've pulled out the key details and action items below — the demo prep notes are at the end.</voice>\n\n## Meeting with Alex — March 11\n### Roadmap\n- Agreed to push Q2 launch to April 15...\n(detailed written content continues)\n\nExample 2 — User asks: "summarize my emails"\n\n<voice>You have five new emails since this morning.</voice>\n<voice>Two are from your team — Jordan sent the RFC you requested and Taylor flagged a contract issue.</voice>\n<voice>There's also a warm intro from a VC partner connecting you with someone at a prospective customer.</voice>\n<voice>I've drafted responses for three of them. The details and drafts are below.</voice>\n\n(email blocks, tables, and detailed content follow)\n\nExample 3 — User asks: "what's on my calendar today?"\n\n<voice>You've got a pretty packed day — seven meetings starting with standup at 9.</voice>\n<voice>The big ones are your investor call at 11, lunch with a partner from your lead VC at 12:30, and a customer call at 4.</voice>\n<voice>Your only free block for deep work is 2:30 to 4.</voice>\n\n(calendar block with full event details follows)\n\nExample 4 — User asks: "draft an email to Sam with our metrics"\n\n<voice>Done — I've drafted the email to Sam with your latest WAU and churn numbers.</voice>\n<voice>Take a look at the draft below and send it when you're ready.</voice>\n\n(email block with draft follows)\n\nREMEMBER: If you do not start with <voice> tags, the user hears silence. Always speak first, then write.`;
    } else if (voiceOutput === "full") {
      loopLogger.log("voice output enabled (full mode), injecting voice output prompt");
      instructionsWithDateTime += `\n\n# Voice Output — Full Read-Aloud (MANDATORY — READ THIS FIRST)\nThe user wants your ENTIRE response spoken aloud. THIS IS YOUR #1 PRIORITY: every single sentence must be wrapped in <voice></voice> tags. If you write anything outside <voice> tags, the user will not hear it — which is a broken experience. NEVER skip this.\n\nRules:\n1. YOUR VERY FIRST OUTPUT MUST BE A <voice> TAG. No exceptions. The literal first characters of your response must be "<voice>".\n2. Wrap EACH sentence in its own separate <voice> tag so it can be spoken incrementally.\n3. Write your response in a natural, conversational style suitable for listening — no markdown headings, bullet points, or formatting symbols. Use plain spoken language.\n4. Structure the content as if you are speaking to the user directly. Use transitions like "first", "also", "one more thing" instead of visual formatting.\n5. EVERY sentence MUST be inside a <voice> tag. Do not leave ANY content outside <voice> tags. If it's not in a <voice> tag, the user cannot hear it.\n\n## Examples\n\nExample 1 — User asks: "what happened in my meeting with Alex yesterday?"\n\n<voice>Your meeting with Alex covered three main things.</voice>\n<voice>First, you discussed the Q2 roadmap timeline and agreed to push the launch to April.</voice>\n<voice>Second, you talked about hiring for the backend role — Alex will send over two candidates by Friday.</voice>\n<voice>And lastly, the client demo is next week on Thursday at 2pm, and you're handling the intro slides.</voice>\n\nExample 2 — User asks: "summarize my emails"\n\n<voice>You've got five new emails since this morning.</voice>\n<voice>Two are from your team — Jordan sent the RFC you asked for, and Taylor flagged a contract issue that needs your sign-off.</voice>\n<voice>There's a warm intro from a VC partner connecting you with an engineering lead at a potential customer.</voice>\n<voice>And someone from a prospective client wants to confirm your API tier before your call this afternoon.</voice>\n<voice>I've drafted replies for three of them — the metrics update, the intro, and the API question.</voice>\n<voice>The only one I left for you is Taylor's contract redline, since that needs your judgment on the liability cap.</voice>\n\nExample 3 — User asks: "what's on my calendar today?"\n\n<voice>You've got a packed day — seven meetings starting with standup at 9.</voice>\n<voice>The highlights are your investor call at 11, lunch with a VC partner at 12:30, and a customer call at 4.</voice>\n<voice>Your only open block for deep work is 2:30 to 4, so plan accordingly.</voice>\n<voice>Oh, and your 1-on-1 with your co-founder is at 5:30 — that's a walking meeting.</voice>\n\nExample 4 — User asks: "how are our metrics looking?"\n\n<voice>Metrics are looking strong this week.</voice>\n<voice>You hit 2,573 weekly active users, which is up 12% week over week.</voice>\n<voice>That means you've crossed the 2,500 milestone — worth calling out in your next investor update.</voice>\n<voice>Churn is down to 4.1%, improving month over month.</voice>\n<voice>The trailing 8-week compound growth rate is about 10%.</voice>\n\nREMEMBER: Start with <voice> immediately. No preamble, no markdown before it. Speak first.`;
    }
    if (searchEnabled) {
      loopLogger.log("search enabled, injecting search prompt");
      instructionsWithDateTime += `\n\n# Search\nThe user has requested a search. Use the web-search tool to answer their query.`;
    }
    if (codeMode) {
      loopLogger.log("code mode enabled, injecting coding-agent context", codeMode);
      const agentDisplay = codeMode === "claude" ? "Claude Code" : "Codex";
      instructionsWithDateTime += `\n\n# Code Mode (Active) — Agent: ${agentDisplay}
The user has turned on **code mode** and the composer chip is set to **${agentDisplay}** (\`${codeMode}\`). For EVERY coding task this turn, use **${agentDisplay}**, and narrate that agent ("Using ${agentDisplay} to …").

The chip is the single source of truth for which agent runs:
- Do NOT carry over a different agent from earlier in this thread — even if a previous run used the other agent, use **${agentDisplay}** now.
- Do NOT switch agents based on an in-chat text request ("use codex", "switch to claude"). The agent only changes when the user toggles the chip; if they ask in chat, tell them to toggle the chip.

**How to run coding work — call the \`code_agent_run\` tool** with:
- \`agent\`: \`${codeMode}\` (always — match the chip).
- \`cwd\`: the absolute project/working directory (resolve it per the code-with-agents skill — a path the user named, the "# User Work Directory" block, or ask once).
- \`prompt\`: a clear, self-contained coding instruction.

The tool runs the agent on-device and streams its tool calls, file diffs, and plan into the chat; any action needing approval surfaces as an inline permission card, so you do NOT pre-confirm with an in-chat "reply yes". This chat keeps ONE persistent agent session, so follow-up coding requests automatically resume with full context — just call \`code_agent_run\` again. Do NOT shell out to \`acpx\` or \`executeCommand\` for coding, and do NOT fall back to your own file tools.

If the user's message is clearly NOT a coding request (small talk, an unrelated question), answer directly without invoking the coding agent. Code mode signals readiness, not that every message must route through the agent.`;
    }
    let streamError: string | null = null;
    for await (const event of streamLlm(
      model,
      state.messages,
      instructionsWithDateTime,
      tools,
      signal,
      {
        useCase: state.runUseCase ?? "copilot_chat",
        ...(state.runSubUseCase ? { subUseCase: state.runSubUseCase } : {}),
        agentName: state.agentName ?? undefined,
        modelId,
        providerName: state.runProvider!,
      },
    )) {
      messageBuilder.ingest(event);
      yield* processEvent({
        runId,
        type: "llm-stream-event",
        event: event,
        subflow: [],
      });
      if (event.type === "error") {
        streamError = event.error;
        yield* processEvent({
          runId,
          type: "error",
          error: streamError,
          subflow: [],
        });
        break;
      }
    }

    // build and emit final message from agent response
    const message = messageBuilder.get();
    yield* processEvent({
      runId,
      messageId: await idGenerator.next(),
      type: "message",
      message,
      subflow: [],
    });

    if (streamError) {
      return;
    }

    // if there were any ask-human calls, emit those events
    if (message.content instanceof Array) {
      const permissionCandidates: AutoPermissionCandidate[] = [];
      for (const part of message.content) {
        if (part.type === "tool-call") {
          const underlyingTool =
            agent.tools && Object.prototype.hasOwnProperty.call(agent.tools, part.toolName)
              ? agent.tools[part.toolName]
              : undefined;
          if (!underlyingTool) {
            continue;
          }
          if (underlyingTool.type === "builtin" && underlyingTool.name === "ask-human") {
            loopLogger.log("emitting ask-human-request, toolCallId:", part.toolCallId);
            const rawOptions = (part.arguments as { options?: unknown }).options;
            const options = Array.isArray(rawOptions)
              ? rawOptions.filter((o): o is string => typeof o === "string" && o.trim().length > 0)
              : undefined;
            yield* processEvent({
              runId,
              type: "ask-human-request",
              toolCallId: part.toolCallId,
              query: part.arguments.question,
              ...(options && options.length > 0 ? { options } : {}),
              subflow: [],
            });
          }
          const permission = await getToolPermissionMetadata(
            part,
            underlyingTool,
            state.sessionAllowedCommands,
            state.sessionAllowedFileAccess,
            state.sessionAllowedMcpSpawns,
            { codeMode, agentName: state.agentName },
          );
          if (permission) {
            permissionCandidates.push({ toolCall: part, permission });
          }
          if (underlyingTool.type === "agent" && underlyingTool.name) {
            loopLogger.log("emitting spawn-subflow, toolCallId:", part.toolCallId);
            yield* processEvent({
              runId,
              type: "spawn-subflow",
              agentName: underlyingTool.name,
              toolCallId: part.toolCallId,
              subflow: [],
            });
            yield* processEvent({
              runId,
              messageId: await idGenerator.next(),
              type: "message",
              message: {
                role: "user",
                content: part.arguments.message,
              },
              subflow: [part.toolCallId],
            });
          }
        }
      }

      if (permissionCandidates.length > 0) {
        if (state.permissionMode === "auto") {
          // High-risk actions (interpreters, shell metacharacters, protected workspace
          // paths, outside-workspace writes/deletes, code_agent_run outside code mode,
          // and ALL MCP install/spawn calls) ALWAYS require interactive human approval
          // and bypass the LLM classifier.
          const mustPromptHuman: AutoPermissionCandidate[] = [];
          const classifiableCandidates: AutoPermissionCandidate[] = [];
          for (const candidate of permissionCandidates) {
            const isExternalFileMutation =
              candidate.permission.kind === "file" &&
              (candidate.permission.operation === "write" ||
                candidate.permission.operation === "delete");
            if (
              candidate.permission.allowScopeGrant !== true ||
              candidate.permission.kind === "mcp" ||
              isExternalFileMutation
            ) {
              mustPromptHuman.push(candidate);
            } else {
              classifiableCandidates.push(candidate);
            }
          }

          for (const candidate of mustPromptHuman) {
            loopLogger.log(
              "high-risk permission candidate bypassing auto-classifier, prompting human:",
              candidate.toolCall.toolCallId,
            );
            yield* processEvent({
              runId,
              type: "tool-permission-request",
              toolCall: candidate.toolCall,
              permission: candidate.permission,
              subflow: [],
            });
          }

          if (classifiableCandidates.length > 0) {
            let decisionsByToolCallId = new Map<
              string,
              { decision: "allow" | "deny"; reason: string }
            >();
            try {
              const decisions = await classifyToolPermissions({
                runId,
                agentName: state.agentName,
                messages: extractTrustedUserMessagesForClassifier(state.messages),
                candidates: classifiableCandidates,
                useCase: state.runUseCase ?? "copilot_chat",
                subUseCase: state.runSubUseCase,
              });
              decisionsByToolCallId = new Map(
                decisions.map((decision) => [
                  decision.toolCallId,
                  { decision: decision.decision, reason: decision.reason },
                ]),
              );
            } catch (error) {
              loopLogger.log(
                "auto-permission classifier failed:",
                error instanceof Error ? error.message : String(error),
              );
            }

            for (const candidate of classifiableCandidates) {
              const decision = decisionsByToolCallId.get(candidate.toolCall.toolCallId);
              if (!decision) {
                loopLogger.log(
                  "auto-permission missing decision, falling back to prompt:",
                  candidate.toolCall.toolCallId,
                );
                yield* processEvent({
                  runId,
                  type: "tool-permission-request",
                  toolCall: candidate.toolCall,
                  permission: candidate.permission,
                  subflow: [],
                });
                continue;
              }

              loopLogger.log(
                "emitting tool-permission-auto-decision, toolCallId:",
                candidate.toolCall.toolCallId,
                "decision:",
                decision.decision,
              );
              yield* processEvent({
                runId,
                type: "tool-permission-auto-decision",
                toolCallId: candidate.toolCall.toolCallId,
                toolCall: candidate.toolCall,
                permission: candidate.permission,
                decision: decision.decision,
                reason: decision.reason,
                subflow: [],
              });
              if (decision.decision === "deny") {
                loopLogger.log(
                  "auto-permission denied, falling back to prompt:",
                  candidate.toolCall.toolCallId,
                );
                yield* processEvent({
                  runId,
                  type: "tool-permission-request",
                  toolCall: candidate.toolCall,
                  permission: candidate.permission,
                  subflow: [],
                });
              }
            }
          }
        } else {
          for (const candidate of permissionCandidates) {
            loopLogger.log(
              "emitting tool-permission-request, toolCallId:",
              candidate.toolCall.toolCallId,
            );
            yield* processEvent({
              runId,
              type: "tool-permission-request",
              toolCall: candidate.toolCall,
              permission: candidate.permission,
              subflow: [],
            });
          }
        }
      }
    }
  }
}

interface StreamLlmAnalytics {
  useCase: UseCase;
  subUseCase?: string;
  agentName?: string;
  modelId: string;
  providerName: string;
}

async function* streamLlm(
  model: LanguageModel,
  messages: z.infer<typeof MessageList>,
  instructions: string,
  tools: ToolSet,
  signal?: AbortSignal,
  analytics?: StreamLlmAnalytics,
): AsyncGenerator<z.infer<typeof LlmStepStreamEvent>, void, unknown> {
  const converted = withPromptCaching(convertFromMessages(messages));
  // The payload carries whole email bodies and note contents. Dumping it on
  // every step wrote that to disk in the clear and cost hundreds of MB of log
  // churn per session; the shape is what is useful when debugging, not the
  // contents.
  if (process.env.OPPULENCE_LOG_LLM_PAYLOAD === "1") {
    console.log(`! SENDING payload to model: `, JSON.stringify(converted));
  } else {
    console.log(
      `! SENDING payload to model: ${converted.length} messages, ~${JSON.stringify(converted).length} bytes`,
    );
  }
  const streamResult = analytics
    ? withUseCase(
        {
          useCase: analytics.useCase,
          ...(analytics.subUseCase ? { subUseCase: analytics.subUseCase } : {}),
          ...(analytics.agentName ? { agentName: analytics.agentName } : {}),
        },
        () =>
          streamText({
            model,
            messages: converted,
            system: instructions,
            tools,
            stopWhen: stepCountIs(1),
            abortSignal: signal,
          }),
      )
    : streamText({
        model,
        messages: converted,
        system: instructions,
        tools,
        stopWhen: stepCountIs(1),
        abortSignal: signal,
      });
  const { fullStream } = streamResult;
  for await (const event of fullStream) {
    // Check abort on every chunk for responsiveness
    signal?.throwIfAborted();
    // One line per stream chunk, each carrying the model's text. Same reason as
    // the payload dump above: this is the model's output written to disk in the
    // clear, thousands of lines per run, behind the same opt-in flag.
    if (process.env.OPPULENCE_LOG_LLM_PAYLOAD === "1") {
      console.log("-> \t\tstream event", JSON.stringify(event));
    }
    switch (event.type) {
      case "start":
      case "start-step":
      case "finish":
        break;
      case "error":
        yield {
          type: "error",
          error: formatLlmStreamError((event as { error?: unknown }).error ?? event),
        };
        return;
      case "reasoning-start":
        yield {
          type: "reasoning-start",
          providerOptions: event.providerMetadata,
        };
        break;
      case "reasoning-delta":
        yield {
          type: "reasoning-delta",
          delta: event.text,
          providerOptions: event.providerMetadata,
        };
        break;
      case "reasoning-end":
        yield {
          type: "reasoning-end",
          providerOptions: event.providerMetadata,
        };
        break;
      case "text-start":
        yield {
          type: "text-start",
          providerOptions: event.providerMetadata,
        };
        break;
      case "text-end":
        yield {
          type: "text-end",
          providerOptions: event.providerMetadata,
        };
        break;
      case "text-delta":
        yield {
          type: "text-delta",
          delta: event.text,
          providerOptions: event.providerMetadata,
        };
        break;
      case "tool-call":
        yield {
          type: "tool-call",
          toolCallId: event.toolCallId,
          toolName: event.toolName,
          input: event.input,
          providerOptions: event.providerMetadata,
        };
        break;
      case "finish-step":
        if (analytics) {
          captureLlmUsage({
            useCase: analytics.useCase,
            ...(analytics.subUseCase ? { subUseCase: analytics.subUseCase } : {}),
            ...(analytics.agentName ? { agentName: analytics.agentName } : {}),
            model: analytics.modelId,
            provider: analytics.providerName,
            usage: event.usage,
          });
        }
        yield {
          type: "finish-step",
          usage: event.usage,
          finishReason: event.finishReason,
          providerOptions: event.providerMetadata,
        };
        break;
      default:
        console.log("unknown stream event:", JSON.stringify(event));
        continue;
    }
  }
}
export const MappedToolCall = z.object({
  toolCall: ToolCallPart,
  agentTool: ToolAttachment,
});
