import { withFileLock } from '../knowledge/file-lock.js';
import { writeJsonAtomic, writeJsonAtomicSync } from "../filesystem/atomic_write.js";
import os from "os";
import path from "path";
import fs from "fs";
import fsPromises from "fs/promises";
import {
    FileAccessOperationSchema,
    FileAccessGrantSchema,
    McpServerGrantSchema,
    ParsedSecurityConfigSchema,
    type FileAccessOperation,
    type FileAccessGrant,
    type McpServerGrant,
    type ParsedSecurityConfig,
} from "@x/shared/security";
import { WorkDir } from "./config.js";

export {
    FileAccessOperationSchema,
    FileAccessGrantSchema,
    McpServerGrantSchema,
    ParsedSecurityConfigSchema,
    type FileAccessOperation,
    type FileAccessGrant,
    type McpServerGrant,
    type ParsedSecurityConfig,
};

export const SECURITY_CONFIG_PATH = path.join(WorkDir, "config", "security.json");
const OWNER_ONLY_FILE_MODE = 0o600;

// Read-only, non-executing utilities allowed inside the workspace without prompting.
// Interpreters (awk), environment dumpers (env, printenv), execution-capable
// search/query tools (find, jq, yq), and any command with dangerous arguments,
// shell expansions, redirections, or outside-workspace/protected-config paths
// always require approval in command-executor.ts.
const DEFAULT_ALLOW_LIST = [
    "agent-slack",
    "basename",
    "cat",
    "cut",
    "date",
    "df",
    "diff",
    "dirname",
    "du",
    "echo",
    "file",
    "grep",
    "head",
    "hostname",
    "ls",
    "printf",
    "pwd",
    "readlink",
    "realpath",
    "sort",
    "stat",
    "tail",
    "tree",
    "uname",
    "uniq",
    "wc",
    "which",
    "whoami",
];

// Non-secret config files under WorkDir/config/ that agents legitimately read.
// All other files under WorkDir/config/ (oauth.json, models.json, security.json,
// mcp.json, exa-search.json, code-mode.json, etc.) require explicit approval.
const AGENT_READABLE_CONFIG_FILES = new Set(["slack.json"]);

// Top-level directories under WorkDir whose contents are always protected across
// all operations (reads, lists, searches, writes, deletes).
const ALWAYS_PROTECTED_WORKSPACE_DIRS = new Set([
    "runs",
    ".trash",
    "code-mode",
    "runtime",
    "models",
    "cache",
    "index",
    "events",
    "logs",
]);

const MAX_SYMLINK_HOPS = 40;

let cachedConfig: ParsedSecurityConfig | null = null;
let cachedStatKey: string | null = null;

function isCaseInsensitivePlatform(platform: NodeJS.Platform = process.platform): boolean {
    return platform === "darwin" || platform === "win32";
}

export function isWindowsDeviceNamespacePath(inputPath: string): boolean {
    const normalized = inputPath.replace(/\\/g, "/");
    if (/^\/\/\.\//i.test(normalized)) {
        return true;
    }
    if (/^\/\/\?\//i.test(normalized)) {
        return !/^\/\/\?\/(?:unc\/|[a-z]:\/)/i.test(normalized);
    }
    return false;
}

export function isWindowsUncPath(inputPath: string): boolean {
    const normalized = inputPath.replace(/\\/g, "/");
    if (/^\/\/\?\/unc\//i.test(normalized)) {
        return true;
    }
    if (/^\/\/[^/?.\s][^/]*/i.test(normalized)) {
        return true;
    }
    return false;
}

export function hasWindowsUnsafePathSegment(inputPath: string): boolean {
    const normalized = stripWindowsExtendedPathPrefix(inputPath.replace(/\\/g, "/"));
    const withoutDrive = normalized.replace(/^[a-z]:/i, "");
    const segments = withoutDrive.split("/");
    for (const seg of segments) {
        if (!seg || seg === "." || seg === "..") continue;
        if (seg.includes(":")) return true;
        if (/[. ]$/.test(seg)) return true;
    }
    return false;
}

function stripWindowsExtendedPathPrefix(slashPath: string): string {
    if (/^\/\/\?\/unc\//i.test(slashPath)) {
        return `//${slashPath.slice(8)}`;
    }
    if (/^\/\/[?.]\/[a-z]:\//i.test(slashPath)) {
        return slashPath.slice(4);
    }
    return slashPath;
}

function normalizePathForComparison(
    inputPath: string,
    platform: NodeJS.Platform = process.platform,
): string {
    let resolved: string;
    if (platform === "win32") {
        const stripped = stripWindowsExtendedPathPrefix(inputPath.replace(/\\/g, "/"));
        resolved = path.win32.resolve(stripped).replace(/\\/g, "/");
    } else {
        resolved = path.resolve(inputPath).replace(/\\/g, "/");
    }
    const nfc = resolved.normalize("NFC");
    return isCaseInsensitivePlatform(platform) ? nfc.toLowerCase() : nfc;
}

export function isSameNormalizedPath(
    a: string,
    b: string,
    platform: NodeJS.Platform = process.platform,
): boolean {
    return normalizePathForComparison(a, platform) === normalizePathForComparison(b, platform);
}

export function isPathInsideDir(
    parent: string,
    child: string,
    platform: NodeJS.Platform = process.platform,
): boolean {
    const normParent = normalizePathForComparison(parent, platform).replace(/\/+$/, "") || "/";
    const normChild = normalizePathForComparison(child, platform).replace(/\/+$/, "") || "/";
    if (normParent === normChild) return true;
    const prefix = normParent === "/" ? "/" : `${normParent}/`;
    return normChild.startsWith(prefix);
}

/**
 * Synchronously canonicalize a path, resolving symlinks including dangling symlinks
 * by walking up ancestors and following `readlinkSync` targets (bounded by MAX_SYMLINK_HOPS).
 */
export function canonicalizePathSync(
    inputPath: string,
    platform: NodeJS.Platform = process.platform,
    depth = 0,
): string {
    if (platform !== process.platform) {
        if (platform === "win32") {
            const stripped = stripWindowsExtendedPathPrefix(inputPath.replace(/\\/g, "/"));
            return path.win32.resolve(stripped);
        }
        return path.posix.resolve(inputPath);
    }

    const resolved = path.resolve(inputPath);
    if (depth >= MAX_SYMLINK_HOPS) {
        return resolved;
    }

    try {
        return fs.realpathSync.native(resolved);
    } catch {
        try {
            return fs.realpathSync(resolved);
        } catch {
            const parsed = path.parse(resolved);
            const missingParts: string[] = [];
            let current = resolved;
            while (current !== parsed.root) {
                try {
                    const st = fs.lstatSync(current);
                    if (st.isSymbolicLink()) {
                        const linkTarget = fs.readlinkSync(current);
                        const nextPath = path.resolve(
                            path.dirname(current),
                            linkTarget,
                            ...missingParts.slice().reverse(),
                        );
                        return canonicalizePathSync(nextPath, platform, depth + 1);
                    }
                    const canonicalParent = fs.realpathSync.native(current);
                    return path.join(canonicalParent, ...missingParts.slice().reverse());
                } catch {
                    missingParts.push(path.basename(current));
                    current = path.dirname(current);
                }
            }
            return resolved;
        }
    }
}

/**
 * Asynchronously canonicalize a path, resolving symlinks including dangling symlinks
 * by walking up ancestors and following `readlink` targets (bounded by MAX_SYMLINK_HOPS).
 */
export async function canonicalizePath(
    inputPath: string,
    depth = 0,
): Promise<string> {
    const resolved = path.resolve(inputPath);
    if (depth >= MAX_SYMLINK_HOPS) {
        return resolved;
    }

    try {
        return await fsPromises.realpath(resolved);
    } catch {
        const parsed = path.parse(resolved);
        const missingParts: string[] = [];
        let current = resolved;
        while (current !== parsed.root) {
            try {
                const st = await fsPromises.lstat(current);
                if (st.isSymbolicLink()) {
                    const linkTarget = await fsPromises.readlink(current);
                    const nextPath = path.resolve(
                        path.dirname(current),
                        linkTarget,
                        ...missingParts.slice().reverse(),
                    );
                    return canonicalizePath(nextPath, depth + 1);
                }
                const canonicalParent = await fsPromises.realpath(current);
                return path.join(canonicalParent, ...missingParts.slice().reverse());
            } catch {
                missingParts.push(path.basename(current));
                current = path.dirname(current);
            }
        }
        return resolved;
    }
}

function canonicalizeRootSync(
    dirPath: string,
    platform: NodeJS.Platform = process.platform,
): string {
    return canonicalizePathSync(dirPath, platform);
}

function relativeNormalized(
    parent: string,
    child: string,
    platform: NodeJS.Platform = process.platform,
): string {
    const normParent = normalizePathForComparison(parent, platform).replace(/\/+$/, "");
    const normChild = normalizePathForComparison(child, platform).replace(/\/+$/, "");
    if (normParent === normChild) return "";
    const prefix = `${normParent}/`;
    return normChild.startsWith(prefix) ? normChild.slice(prefix.length) : normChild;
}

function normalizeWorkspaceSegment(segment: string, platform: NodeJS.Platform): string {
    const lower = segment.toLowerCase();
    if (platform !== "win32") {
        return lower;
    }
    return lower.replace(/:.*$/, "").replace(/[. ]+$/, "");
}

/**
 * Returns true if `canonicalPath` targets `WorkDir/knowledge/Agent Notes/**`.
 * Used to apply a narrow write exemption for the dedicated `agent_notes_agent`
 * while requiring explicit approval for all other agents.
 */
export function isAgentNotesWorkspacePath(
    canonicalPath: string,
    workspaceRoot?: string,
    platform: NodeJS.Platform = process.platform,
): boolean {
    const canonicalRoot = canonicalizeRootSync(workspaceRoot ?? WorkDir, platform);
    const resolvedTarget = canonicalizePathSync(canonicalPath, platform);
    if (!isPathInsideDir(canonicalRoot, resolvedTarget, platform)) {
        return false;
    }
    const relToWorkspace = relativeNormalized(canonicalRoot, resolvedTarget, platform);
    if (!relToWorkspace) return false;
    const lowerSegments = relToWorkspace
        .split("/")
        .filter(Boolean)
        .map((s) => normalizeWorkspaceSegment(s, platform));
    return lowerSegments[0] === "knowledge" && lowerSegments[1] === "agent notes";
}

/**
 * Returns true if `canonicalPath` targets a security-sensitive subtree inside
 * `WorkDir`:
 * - `WorkDir` root itself (write/delete): prevents deleting/renaming the workspace
 * - `WorkDir/config/**`: credentials, allowlists, MCP definitions, API keys
 *   (read-only `config/slack.json` is exempted for the Slack skill)
 * - `WorkDir/runs/**`, `.trash/**`, `code-mode/**`, `runtime/**`, `models/**`, `cache/**`,
 *   `index/**`, `events/**`, `logs/**`
 * - `WorkDir/agents/**` (write/delete): custom agent definitions & tool attachments
 * - `WorkDir/bg-tasks/**` (write/delete): task folders, `task.yaml`, `runs.log`, sidecars
 *   (exempting direct `bg-tasks/<slug>/index.md` artifact writes)
 * - `WorkDir/knowledge/Agent Notes/**` (write/delete): injected into Copilot system prompt
 * - `WorkDir/**\/.git/**`: git config & hooks inside the workspace
 *
 * Uses case-insensitive & NFC-normalized comparison on macOS/Windows to prevent
 * `Config/oauth.json`, NFD/NFC, and Windows NTFS ADS / trailing-dot bypasses.
 */
export function isProtectedWorkspacePath(
    canonicalPath: string,
    operation: FileAccessOperation,
    workspaceRoot?: string,
    platform: NodeJS.Platform = process.platform,
): boolean {
    const canonicalRoot = canonicalizeRootSync(workspaceRoot ?? WorkDir, platform);
    const resolvedTarget = canonicalizePathSync(canonicalPath, platform);

    if (!isPathInsideDir(canonicalRoot, resolvedTarget, platform)) {
        return false;
    }

    const relToWorkspace = relativeNormalized(canonicalRoot, resolvedTarget, platform);
    if (!relToWorkspace) {
        return operation === "write" || operation === "delete";
    }

    const segments = relToWorkspace.split("/").filter(Boolean);
    if (
        platform === "win32"
        && segments.some((s) => s.includes(":") || /[. ]$/.test(s))
    ) {
        return true;
    }

    const lowerSegments = segments.map((s) => normalizeWorkspaceSegment(s, platform));
    const topDir = lowerSegments[0];

    // Any `.git` directory or file inside the workspace (e.g. knowledge/.git/config)
    if (lowerSegments.includes(".git")) {
        return true;
    }

    // `runs/`, `.trash/`, `code-mode/`, `runtime/`, `models/`, `cache/`, `index/`, `events/`, `logs/`
    if (topDir && ALWAYS_PROTECTED_WORKSPACE_DIRS.has(topDir)) {
        return true;
    }

    // `config/` is protected for all operations except read-only `config/slack.json`
    if (topDir === "config") {
        const relInConfig = lowerSegments.slice(1).join("/");
        if (operation === "read" && AGENT_READABLE_CONFIG_FILES.has(relInConfig)) {
            return false;
        }
        return true;
    }

    // Writing or deleting custom agent definitions requires approval
    if (topDir === "agents" && (operation === "write" || operation === "delete")) {
        return true;
    }

    // Writing or deleting background task directories, task.yaml, runs.log, or sidecars
    // requires approval; direct updates to `bg-tasks/<slug>/index.md` remain permitted.
    if (topDir === "bg-tasks" && (operation === "write" || operation === "delete")) {
        const isDirectIndexWrite =
            operation === "write"
            && lowerSegments.length === 3
            && lowerSegments[2] === "index.md";
        if (!isDirectIndexWrite) {
            return true;
        }
    }

    // Writing or deleting `knowledge/Agent Notes/**` requires approval because these
    // files are injected directly into the Copilot system prompt on every chat.
    if (
        topDir === "knowledge"
        && lowerSegments[1] === "agent notes"
        && (operation === "write" || operation === "delete")
    ) {
        return true;
    }

    return false;
}

function serializeSecurityConfig(config: ParsedSecurityConfig): Record<string, unknown> {
    return {
        allowedCommands: config.allowedCommands,
        allowedFileAccess: config.allowedFileAccess,
        ...(config.allowedMcpServers.length > 0
            ? { allowedMcpServers: config.allowedMcpServers }
            : {}),
    };
}

function isFilesystemRoot(
    resolvedPath: string,
    platform: NodeJS.Platform = process.platform,
): boolean {
    const norm = normalizePathForComparison(resolvedPath, platform).replace(/\/+$/, "") || "/";
    if (norm === "/") return true;
    if (platform === "win32" && /^[a-z]:$/i.test(norm)) return true;
    return false;
}

const SENSITIVE_HOME_SUBDIRS = [
    ".ssh",
    ".aws",
    ".gnupg",
    ".kube",
    ".config",
    ".docker",
    ".npmrc",
    ".netrc",
    ".git-credentials",
    ".claude",
    ".cursor",
    ".codex",
    ".local",
    ".bashrc",
    ".bash_profile",
    ".zshrc",
    ".zprofile",
    ".zshenv",
    ".profile",
    ".gitconfig",
    ".pypirc",
    ".azure",
    ".gcloud",
    ".cargo",
    ".npm",
    "Library/Keychains",
    "Library/LaunchAgents",
    "Library/Application Support",
    "Library/Preferences",
    "Library/Cookies",
    "Library/Safari",
    "Library/Mail",
    "Library/Messages",
    "AppData/Roaming",
    "AppData/Local",
] as const;

const POSIX_SENSITIVE_SYSTEM_DIRS = [
    "/etc",
    "/private/etc",
    "/System",
    "/usr",
    "/bin",
    "/sbin",
    "/proc",
    "/sys",
    "/Library/LaunchDaemons",
    "/Library/LaunchAgents",
] as const;

const WINDOWS_SENSITIVE_SYSTEM_DIRS = [
    "C:/Windows",
    "C:/ProgramData",
] as const;

/**
 * Returns true if `pathPrefix` is too broad (filesystem root, `$HOME`, or any
 * ancestor of `$HOME` / `WorkDir`), is a Windows device/UNC/ADS/trailing-dot path,
 * or targets (or is an ancestor of) a sensitive credential/system directory where
 * persistent "Always allow" grants must never be persisted.
 */
export function isSensitiveOrBroadExternalGrantPrefix(
    pathPrefix: string,
    platform: NodeJS.Platform = process.platform,
    homeDir: string = os.homedir(),
): boolean {
    if (
        platform === "win32"
        && (
            isWindowsDeviceNamespacePath(pathPrefix)
            || isWindowsUncPath(pathPrefix)
            || hasWindowsUnsafePathSegment(pathPrefix)
        )
    ) {
        return true;
    }

    const canonicalPrefix = canonicalizeRootSync(pathPrefix, platform);
    if (platform === "win32" && hasWindowsUnsafePathSegment(canonicalPrefix)) {
        return true;
    }
    if (isFilesystemRoot(canonicalPrefix, platform)) {
        return true;
    }

    const canonicalHome = canonicalizeRootSync(homeDir, platform);
    // Reject `$HOME` itself and any ancestor of `$HOME` (e.g. `/Users`, `/home`, `C:\Users`)
    if (isPathInsideDir(canonicalPrefix, canonicalHome, platform)) {
        return true;
    }

    const canonicalWorkDir = canonicalizeRootSync(WorkDir, platform);
    // Reject `WorkDir` itself or any ancestor of `WorkDir`
    if (isPathInsideDir(canonicalPrefix, canonicalWorkDir, platform)) {
        return true;
    }

    const joinImpl = platform === "win32" ? path.win32.join : path.join;
    for (const subdir of SENSITIVE_HOME_SUBDIRS) {
        const sensitivePath = canonicalizeRootSync(joinImpl(canonicalHome, subdir), platform);
        if (
            isPathInsideDir(sensitivePath, canonicalPrefix, platform)
            || isPathInsideDir(canonicalPrefix, sensitivePath, platform)
        ) {
            return true;
        }
    }

    const systemDirs: string[] = platform === "win32"
        ? [...WINDOWS_SENSITIVE_SYSTEM_DIRS]
        : [...POSIX_SENSITIVE_SYSTEM_DIRS];
    if (platform === "win32") {
        if (process.env.SystemRoot) systemDirs.push(process.env.SystemRoot);
        if (process.env.ProgramData) systemDirs.push(process.env.ProgramData);
    }
    for (const sysDir of systemDirs) {
        if (
            isPathInsideDir(sysDir, canonicalPrefix, platform)
            || isPathInsideDir(canonicalPrefix, sysDir, platform)
        ) {
            return true;
        }
    }

    return false;
}

export async function addToSecurityConfig(commands: string[]): Promise<void> {
    // Locked, because all mutators here rewrite the WHOLE file from a value
    // they read first. A single assistant turn can raise several permission
    // prompts at once, the renderer fires each approval as its own
    // runs:authorizePermission, and that handler awaits a full run-log fetch
    // before reaching this write — so two grants interleaving is the ordinary
    // case, not a corner one. Unlocked, the second write carried the first's
    // pre-image and silently dropped its grant; the user saw "Always allow"
    // succeed and got re-prompted anyway. auth/repo.ts already does this for
    // the sibling oauth.json.
    await withFileLock(SECURITY_CONFIG_PATH, async () => {
        ensureSecurityConfigSync();
        const current = readSecurityConfig();
        const merged = new Set(current.allowedCommands);
        for (const cmd of commands) {
            const normalized = cmd.trim().toLowerCase();
            // Never allow programmatic grants to persist a wildcard "*" allow-all rule
            if (!normalized || normalized === "*") continue;
            merged.add(normalized);
        }
        // Atomic: a torn security.json reads as empty — every grant lost.
        await writeJsonAtomic(
            SECURITY_CONFIG_PATH,
            serializeSecurityConfig({
                allowedCommands: Array.from(merged).sort(),
                allowedFileAccess: current.allowedFileAccess,
                allowedMcpServers: current.allowedMcpServers,
            }),
            2,
            OWNER_ONLY_FILE_MODE,
        );
        // Reset cache so next read picks up the new file
        resetSecurityAllowListCache();
    });
}

export async function addFileAccessGrant(grant: FileAccessGrant): Promise<void> {
    const normalizedGrant = normalizeFileAccessGrant(grant);
    // Refuse filesystem-wide root grants ("/", "C:\"), $HOME / sensitive dirs, and protected workspace grants
    if (
        isSensitiveOrBroadExternalGrantPrefix(normalizedGrant.pathPrefix)
        || isProtectedWorkspacePath(normalizedGrant.pathPrefix, normalizedGrant.operation)
    ) {
        return;
    }

    // Same lock, same file: this writes back allowedCommands verbatim, so
    // racing a command grant loses it (and vice versa).
    await withFileLock(SECURITY_CONFIG_PATH, async () => {
        ensureSecurityConfigSync();
        const current = readSecurityConfig();
        const exists = current.allowedFileAccess.some(existing =>
            existing.operation === normalizedGrant.operation
            && existing.pathPrefix === normalizedGrant.pathPrefix
        );
        const allowedFileAccess = exists
            ? current.allowedFileAccess
            : [...current.allowedFileAccess, normalizedGrant].sort((a, b) =>
                `${a.operation}:${a.pathPrefix}`.localeCompare(`${b.operation}:${b.pathPrefix}`)
            );
        await writeJsonAtomic(
            SECURITY_CONFIG_PATH,
            serializeSecurityConfig({
                allowedCommands: current.allowedCommands,
                allowedFileAccess,
                allowedMcpServers: current.allowedMcpServers,
            }),
            2,
            OWNER_ONLY_FILE_MODE,
        );
        resetSecurityAllowListCache();
    });
}

export async function addMcpServerGrant(grant: McpServerGrant): Promise<void> {
    const parsed = McpServerGrantSchema.parse({
        serverName: grant.serverName.trim(),
        configDigest: grant.configDigest.trim(),
        command: grant.command.trim(),
        ...(grant.args && grant.args.length > 0 ? { args: grant.args } : {}),
    });

    await withFileLock(SECURITY_CONFIG_PATH, async () => {
        ensureSecurityConfigSync();
        const current = readSecurityConfig();
        const exists = current.allowedMcpServers.some(
            (existing) =>
                existing.serverName === parsed.serverName
                && existing.configDigest === parsed.configDigest,
        );
        const allowedMcpServers = exists
            ? current.allowedMcpServers
            : [...current.allowedMcpServers, parsed].sort((a, b) =>
                `${a.serverName}:${a.configDigest}`.localeCompare(
                    `${b.serverName}:${b.configDigest}`,
                ),
            );
        await writeJsonAtomic(
            SECURITY_CONFIG_PATH,
            serializeSecurityConfig({
                allowedCommands: current.allowedCommands,
                allowedFileAccess: current.allowedFileAccess,
                allowedMcpServers,
            }),
            2,
            OWNER_ONLY_FILE_MODE,
        );
        resetSecurityAllowListCache();
    });
}

/**
 * Async function to ensure security config file exists.
 * Called explicitly at app startup via initConfigs().
 */
export async function ensureSecurityConfig(): Promise<void> {
    try {
        await fsPromises.access(SECURITY_CONFIG_PATH);
    } catch {
        await writeJsonAtomic(SECURITY_CONFIG_PATH, DEFAULT_ALLOW_LIST, 2, OWNER_ONLY_FILE_MODE);
    }
}

/**
 * Sync version for internal use by getSecurityAllowList() and readSecurityConfig().
 */
function ensureSecurityConfigSync(): void {
    if (!fs.existsSync(SECURITY_CONFIG_PATH)) {
        writeJsonAtomicSync(SECURITY_CONFIG_PATH, DEFAULT_ALLOW_LIST, 2, OWNER_ONLY_FILE_MODE);
    }
}

function normalizeList(commands: unknown[]): string[] {
    const seen = new Set<string>();
    for (const entry of commands) {
        if (typeof entry !== "string") continue;
        const normalized = entry.trim().toLowerCase();
        if (!normalized) continue;
        seen.add(normalized);
    }

    return Array.from(seen);
}

function normalizeFileAccessGrant(grant: FileAccessGrant): FileAccessGrant {
    return {
        operation: grant.operation,
        pathPrefix: canonicalizeRootSync(grant.pathPrefix),
    };
}

function normalizeFileAccessList(grants: unknown[]): FileAccessGrant[] {
    const seen = new Set<string>();
    const normalized: FileAccessGrant[] = [];
    for (const entry of grants) {
        const parsed = FileAccessGrantSchema.safeParse(entry);
        if (!parsed.success || !parsed.data.pathPrefix.trim()) continue;
        const grant = normalizeFileAccessGrant(parsed.data);
        if (
            isSensitiveOrBroadExternalGrantPrefix(grant.pathPrefix)
            || isProtectedWorkspacePath(grant.pathPrefix, grant.operation)
        ) {
            continue;
        }
        const key = `${grant.operation}:${grant.pathPrefix}`;
        if (seen.has(key)) continue;
        seen.add(key);
        normalized.push(grant);
    }
    return normalized;
}

function normalizeMcpServerList(grants: unknown[]): McpServerGrant[] {
    const seen = new Set<string>();
    const normalized: McpServerGrant[] = [];
    for (const entry of grants) {
        const parsed = McpServerGrantSchema.safeParse(entry);
        if (!parsed.success) continue;
        const grant: McpServerGrant = {
            serverName: parsed.data.serverName.trim(),
            configDigest: parsed.data.configDigest.trim(),
            command: parsed.data.command.trim(),
            ...(parsed.data.args && parsed.data.args.length > 0 ? { args: parsed.data.args } : {}),
        };
        if (!grant.serverName || !grant.configDigest || !grant.command) continue;
        const key = `${grant.serverName}:${grant.configDigest}`;
        if (seen.has(key)) continue;
        seen.add(key);
        normalized.push(grant);
    }
    return normalized;
}

function parseSecurityPayload(payload: unknown): ParsedSecurityConfig {
    if (Array.isArray(payload)) {
        return {
            allowedCommands: normalizeList(payload),
            allowedFileAccess: [],
            allowedMcpServers: [],
        };
    }

    if (payload && typeof payload === "object") {
        const entries = Object.entries(payload);
        const maybeObject = Object.fromEntries(entries);
        const allowedFileAccess = Array.isArray(maybeObject.allowedFileAccess)
            ? normalizeFileAccessList(maybeObject.allowedFileAccess)
            : [];
        const allowedMcpServers = Array.isArray(maybeObject.allowedMcpServers)
            ? normalizeMcpServerList(maybeObject.allowedMcpServers)
            : [];

        if (
            Array.isArray(maybeObject.allowedCommands)
            || Array.isArray(maybeObject.allowedFileAccess)
            || Array.isArray(maybeObject.allowedMcpServers)
        ) {
            return {
                allowedCommands: Array.isArray(maybeObject.allowedCommands)
                    ? normalizeList(maybeObject.allowedCommands)
                    : [],
                allowedFileAccess,
                allowedMcpServers,
            };
        }
    }

    // Fail closed on unrecognized / malformed object shapes rather than turning
    // arbitrary JSON keys into allowed commands.
    return { allowedCommands: [], allowedFileAccess: [], allowedMcpServers: [] };
}

function readSecurityConfig(): ParsedSecurityConfig {
    ensureSecurityConfigSync();

    try {
        const configContent = fs.readFileSync(SECURITY_CONFIG_PATH, "utf8");
        const parsed: unknown = JSON.parse(configContent);
        return ParsedSecurityConfigSchema.parse(parseSecurityPayload(parsed));
    } catch (error) {
        console.warn(`Failed to read security config at ${SECURITY_CONFIG_PATH}: ${error instanceof Error ? error.message : error}`);
        // Fail closed on corrupt/unreadable existing security.json rather than
        // silently restoring a permissive allow-list.
        return {
            allowedCommands: [],
            allowedFileAccess: [],
            allowedMcpServers: [],
        };
    }
}

function getCachedSecurityConfig(): ParsedSecurityConfig {
    ensureSecurityConfigSync();
    try {
        const stats = fs.statSync(SECURITY_CONFIG_PATH);
        const statKey = `${stats.ino}:${stats.size}:${stats.mtimeMs}:${stats.ctimeMs}`;
        if (cachedConfig && cachedStatKey === statKey) {
            return cachedConfig;
        }
        const configContent = fs.readFileSync(SECURITY_CONFIG_PATH, "utf8");
        const parsed: unknown = JSON.parse(configContent);
        const validated = ParsedSecurityConfigSchema.parse(parseSecurityPayload(parsed));
        cachedConfig = validated;
        cachedStatKey = statKey;
        return cachedConfig;
    } catch (error) {
        console.warn(`Failed to read security config at ${SECURITY_CONFIG_PATH}: ${error instanceof Error ? error.message : error}`);
        cachedConfig = null;
        cachedStatKey = null;
        return {
            allowedCommands: [],
            allowedFileAccess: [],
            allowedMcpServers: [],
        };
    }
}

export function getSecurityAllowList(): string[] {
    return getCachedSecurityConfig().allowedCommands;
}

export function getFileAccessAllowList(): FileAccessGrant[] {
    return getCachedSecurityConfig().allowedFileAccess;
}

export function getMcpServerAllowList(): McpServerGrant[] {
    return getCachedSecurityConfig().allowedMcpServers;
}

export function resetSecurityAllowListCache(): void {
    cachedConfig = null;
    cachedStatKey = null;
}
