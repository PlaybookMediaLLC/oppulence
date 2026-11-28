import fs from "node:fs/promises";
import type { Stats } from "node:fs";
import path from "node:path";
import { workspace } from "@x/shared";
import { z } from "zod";
import { WorkDir } from "../config/config.js";
import {
  canonicalizePath,
  isPathInsideDir,
  isSameNormalizedPath,
  resetSecurityAllowListCache,
  SECURITY_CONFIG_PATH,
} from "../config/security.js";
import { rewriteWikiLinksForRenamedKnowledgeFile } from "./wiki-link-rewrite.js";
import { commitAll } from "../knowledge/version_history.js";
import { withFileLock } from "../knowledge/file-lock.js";

// ============================================================================
// Path Utilities
// ============================================================================

/**
 * Assert that a relative path is safe (no traversal, no absolute paths)
 */
export function assertSafeRelPath(relPath: string): void {
  if (path.isAbsolute(relPath)) {
    throw new Error("Absolute paths are not allowed");
  }
  if (relPath.includes("..")) {
    throw new Error("Path traversal (..) is not allowed");
  }
  // Normalize and check again after normalization
  const normalized = path.normalize(relPath);
  if (normalized.includes("..") || path.isAbsolute(normalized)) {
    throw new Error("Invalid path");
  }
}

/**
 * Resolve a workspace-relative path to an absolute path
 * Ensures the resolved path stays within the workspace boundary
 * Empty string represents the root directory
 */
export function resolveWorkspacePath(relPath: string): string {
  // Empty string means root directory
  if (relPath === "") {
    return WorkDir;
  }
  assertSafeRelPath(relPath);
  const resolved = path.resolve(WorkDir, relPath);
  if (!resolved.startsWith(WorkDir + path.sep) && resolved !== WorkDir) {
    throw new Error("Path outside workspace boundary");
  }
  return resolved;
}

/**
 * Convert absolute path to workspace-relative POSIX path
 * Returns null if path is outside workspace boundary
 */
export function absToRelPosix(absPath: string): string | null {
  const normalized = path.normalize(absPath);
  if (!normalized.startsWith(WorkDir + path.sep) && normalized !== WorkDir) {
    return null;
  }
  const relPath = path.relative(WorkDir, normalized);
  return relPath.split(path.sep).join("/");
}

function isKnowledgeMarkdownRelPath(relPath: string): boolean {
  const normalized = relPath.replace(/\\/g, "/").replace(/^\/+/, "").toLowerCase();
  return normalized.startsWith("knowledge/") && normalized.endsWith(".md");
}

// ============================================================================
// File System Utilities
// ============================================================================

/**
 * Compute ETag from file stats: `${size}:${mtimeMs}`
 */
export function computeEtag(size: number, mtimeMs: number): string {
  return `${size}:${mtimeMs}`;
}

/**
 * Convert fs.Stats to Stat schema
 */
export function statToSchema(
  stats: Stats,
  kind: z.infer<typeof workspace.NodeKind>,
): z.infer<typeof workspace.Stat> {
  return {
    kind,
    size: stats.size,
    mtimeMs: stats.mtimeMs,
    ctimeMs: stats.ctimeMs,
    isSymlink: stats.isSymbolicLink() ? true : undefined,
  };
}

/**
 * Ensure workspace root exists
 */
export async function ensureWorkspaceRoot(): Promise<void> {
  await fs.mkdir(WorkDir, { recursive: true });
}

// ============================================================================
// Workspace Operations
// ============================================================================

export async function getRoot(): Promise<{ root: string }> {
  await ensureWorkspaceRoot();
  return { root: WorkDir };
}

export async function exists(relPath: string): Promise<{ exists: boolean }> {
  const filePath = resolveWorkspacePath(relPath);
  try {
    await assertCanonicalInsideWorkspace(filePath);
    await fs.access(filePath);
    return { exists: true };
  } catch {
    return { exists: false };
  }
}

export async function stat(relPath: string): Promise<z.infer<typeof workspace.Stat>> {
  const filePath = resolveWorkspacePath(relPath);
  const stats = await fs.lstat(filePath);
  if (stats.isSymbolicLink()) {
    await assertCanonicalInsideWorkspace(path.dirname(filePath));
  } else {
    await assertCanonicalInsideWorkspace(filePath);
  }
  const kind = stats.isDirectory() ? "dir" : "file";
  return statToSchema(stats, kind);
}

export async function readdir(
  relPath: string,
  opts?: z.infer<typeof workspace.ReaddirOptions>,
): Promise<Array<z.infer<typeof workspace.DirEntry>>> {
  const dirPath = resolveWorkspacePath(relPath);
  await assertCanonicalInsideWorkspace(dirPath);
  const entries: Array<z.infer<typeof workspace.DirEntry>> = [];

  async function readDir(currentPath: string, currentRelPath: string): Promise<void> {
    await assertCanonicalInsideWorkspace(currentPath);
    const items = await fs.readdir(currentPath, { withFileTypes: true });

    await Promise.all(
      items.map(async (item) => {
        // Skip hidden files unless includeHidden is true
        if (!opts?.includeHidden && item.name.startsWith(".")) {
          return;
        }

        const itemPath = path.join(currentPath, item.name);
        const itemRelPath = path.posix.join(currentRelPath, item.name);

        // Filter by extension if specified
        if (opts?.allowedExtensions && opts.allowedExtensions.length > 0) {
          const ext = path.extname(item.name);
          if (!opts.allowedExtensions.includes(ext)) {
            return;
          }
        }

        let itemKind: z.infer<typeof workspace.NodeKind>;
        let itemStat: { size: number; mtimeMs: number } | undefined;

        if (item.isDirectory()) {
          itemKind = "dir";
          if (opts?.includeStats) {
            const stats = await fs.lstat(itemPath);
            itemStat = { size: stats.size, mtimeMs: stats.mtimeMs };
          }
          entries.push({ name: item.name, path: itemRelPath, kind: itemKind, stat: itemStat });

          // Recurse if recursive is true
          if (opts?.recursive) {
            await readDir(itemPath, itemRelPath);
          }
        } else if (item.isFile()) {
          itemKind = "file";
          if (opts?.includeStats) {
            const stats = await fs.lstat(itemPath);
            itemStat = { size: stats.size, mtimeMs: stats.mtimeMs };
          }
          entries.push({ name: item.name, path: itemRelPath, kind: itemKind, stat: itemStat });
        }
      }),
    );
  }

  await readDir(dirPath, relPath);

  // Sort: directories first, then by name (localeCompare)
  entries.sort((a, b) => {
    if (a.kind !== b.kind) {
      return a.kind === "dir" ? -1 : 1;
    }
    return a.name.localeCompare(b.name);
  });

  return entries;
}

async function assertCanonicalInsideWorkspace(targetPath: string): Promise<string> {
  const canonicalRoot = await fs.realpath(WorkDir).catch(() => path.resolve(WorkDir));
  const canonicalTarget = await canonicalizePath(targetPath);
  if (!isPathInsideDir(canonicalRoot, canonicalTarget)) {
    throw new Error("Path resolves outside workspace boundary");
  }
  return canonicalTarget;
}

function maybeResetSecurityCache(targetPaths: readonly string[]): void {
  const configDir = path.join(WorkDir, "config");
  for (const p of targetPaths) {
    if (isSameNormalizedPath(p, SECURITY_CONFIG_PATH) || isSameNormalizedPath(p, configDir)) {
      resetSecurityAllowListCache();
      return;
    }
  }
}

export async function readFile(
  relPath: string,
  encoding: z.infer<typeof workspace.Encoding> = "utf8",
): Promise<z.infer<typeof workspace.ReadFileResult>> {
  const filePath = resolveWorkspacePath(relPath);
  await assertCanonicalInsideWorkspace(filePath);
  const stats = await fs.lstat(filePath);

  let data: string;
  if (encoding === "utf8") {
    data = await fs.readFile(filePath, "utf8");
  } else if (encoding === "base64") {
    const buffer = await fs.readFile(filePath);
    data = buffer.toString("base64");
  } else {
    // binary: return as base64-encoded binary data
    const buffer = await fs.readFile(filePath);
    data = buffer.toString("base64");
  }

  const stat = statToSchema(stats, "file");
  const etag = computeEtag(stats.size, stats.mtimeMs);

  return {
    path: relPath,
    encoding,
    data,
    stat,
    etag,
  };
}

// Debounced commit for knowledge file edits
let knowledgeCommitTimer: ReturnType<typeof setTimeout> | null = null;

function scheduleKnowledgeCommit(filename: string): void {
  if (knowledgeCommitTimer) {
    clearTimeout(knowledgeCommitTimer);
  }
  knowledgeCommitTimer = setTimeout(
    () => {
      knowledgeCommitTimer = null;
      commitAll(`Edit ${filename}`, "You").catch((err) => {
        console.error("[VersionHistory] Failed to commit after edit:", err);
      });
    },
    3 * 60 * 1000,
  );
}

export async function writeFile(
  relPath: string,
  data: string,
  opts?: z.infer<typeof workspace.WriteFileOptions>,
): Promise<z.infer<typeof workspace.WriteFileResult>> {
  const filePath = resolveWorkspacePath(relPath);
  await assertCanonicalInsideWorkspace(filePath);
  const encoding = opts?.encoding || "utf8";
  const atomic = opts?.atomic !== false; // default true
  const mkdirp = opts?.mkdirp !== false; // default true
  const isConfigWrite = isPathInsideDir(path.join(WorkDir, "config"), filePath);

  // Create parent directory if needed
  if (mkdirp) {
    await fs.mkdir(path.dirname(filePath), { recursive: true });
  }

  const result = await withFileLock(filePath, async () => {
    // Check expectedEtag if provided (conflict detection)
    if (opts?.expectedEtag) {
      const existingStats = await fs.lstat(filePath);
      const existingEtag = computeEtag(existingStats.size, existingStats.mtimeMs);
      if (existingEtag !== opts.expectedEtag) {
        throw new Error("File was modified (ETag mismatch)");
      }
    }

    // Convert data to buffer based on encoding
    let buffer: Buffer;
    if (encoding === "utf8") {
      buffer = Buffer.from(data, "utf8");
    } else if (encoding === "base64") {
      buffer = Buffer.from(data, "base64");
    } else {
      // binary: assume data is base64-encoded
      buffer = Buffer.from(data, "base64");
    }

    const writeOpts = isConfigWrite ? { mode: 0o600 } : undefined;
    if (atomic) {
      // Atomic write: write to temp file, then rename
      const tempPath = filePath + ".tmp." + Date.now() + Math.random().toString(36).slice(2);
      await fs.writeFile(tempPath, buffer, writeOpts);
      if (isConfigWrite && process.platform !== "win32") {
        await fs.chmod(tempPath, 0o600);
      }
      await fs.rename(tempPath, filePath);
    } else {
      const existingStat = await fs.lstat(filePath).catch(() => null);
      if (existingStat?.isSymbolicLink()) {
        throw new Error("Refusing non-atomic write through symbolic link");
      }
      await fs.writeFile(filePath, buffer, writeOpts);
      if (isConfigWrite && process.platform !== "win32") {
        await fs.chmod(filePath, 0o600);
      }
    }

    const stats = await fs.lstat(filePath);
    const stat = statToSchema(stats, "file");
    const etag = computeEtag(stats.size, stats.mtimeMs);

    return { stat, etag };
  });

  // Invalidate cached security allowlist whenever security.json is updated via workspace IPC
  maybeResetSecurityCache([filePath]);

  // Schedule a debounced version history commit for knowledge files
  if (relPath.startsWith("knowledge/") && relPath.endsWith(".md")) {
    scheduleKnowledgeCommit(path.basename(relPath));
  }

  return {
    path: relPath,
    stat: result.stat,
    etag: result.etag,
  };
}

export async function mkdir(relPath: string, recursive: boolean = true): Promise<{ ok: true }> {
  const dirPath = resolveWorkspacePath(relPath);
  await assertCanonicalInsideWorkspace(dirPath);
  await fs.mkdir(dirPath, { recursive });
  return { ok: true as const };
}

export async function rename(
  from: string,
  to: string,
  overwrite: boolean = false,
): Promise<{ ok: true }> {
  const fromPath = resolveWorkspacePath(from);
  const toPath = resolveWorkspacePath(to);
  await assertCanonicalInsideWorkspace(fromPath);
  await assertCanonicalInsideWorkspace(toPath);

  // Check if source exists
  await fs.access(fromPath);
  const fromStats = await fs.lstat(fromPath);

  // Check if destination exists (only if overwrite is false). Use lstat so
  // dangling symlinks are detected instead of being treated as ENOENT.
  if (!overwrite) {
    try {
      await fs.lstat(toPath);
      throw new Error("Destination already exists");
    } catch (err: unknown) {
      if (err && typeof err === "object" && "code" in err && err.code !== "ENOENT") {
        throw err;
      }
      if (err instanceof Error && err.message === "Destination already exists") {
        throw err;
      }
    }
  }

  // Create parent directory for destination
  await fs.mkdir(path.dirname(toPath), { recursive: true });

  await fs.rename(fromPath, toPath);
  const canonicalTo = await canonicalizePath(toPath);
  const canonicalConfigDir = await canonicalizePath(path.join(WorkDir, "config"));
  if (isPathInsideDir(canonicalConfigDir, canonicalTo) && process.platform !== "win32") {
    await fs.chmod(toPath, 0o600).catch(() => undefined);
  }
  maybeResetSecurityCache([fromPath, toPath]);

  if (fromStats.isFile() && isKnowledgeMarkdownRelPath(from) && isKnowledgeMarkdownRelPath(to)) {
    try {
      await rewriteWikiLinksForRenamedKnowledgeFile(WorkDir, from, to);
    } catch (error) {
      console.error("Failed to rewrite wiki backlinks after file rename:", error);
    }
  }

  return { ok: true as const };
}

export async function copy(
  from: string,
  to: string,
  overwrite: boolean = false,
): Promise<{ ok: true }> {
  const fromPath = resolveWorkspacePath(from);
  const toPath = resolveWorkspacePath(to);
  await assertCanonicalInsideWorkspace(fromPath);
  await assertCanonicalInsideWorkspace(toPath);

  // Check if source is a file (no recursive dir copy)
  const fromStats = await fs.lstat(fromPath);
  if (fromStats.isDirectory()) {
    throw new Error("Copying directories is not supported");
  }

  // Use lstat so dangling symlinks are detected and never followed by copyFile.
  const destStats = await fs.lstat(toPath).catch((err: unknown) => {
    if (err && typeof err === "object" && "code" in err && err.code === "ENOENT") {
      return null;
    }
    throw err;
  });
  if (destStats?.isSymbolicLink()) {
    throw new Error("Refusing to copy onto a symbolic link");
  }
  if (!overwrite && destStats) {
    throw new Error("Destination already exists");
  }

  // Create parent directory for destination
  await fs.mkdir(path.dirname(toPath), { recursive: true });

  await fs.copyFile(fromPath, toPath);
  if (isPathInsideDir(path.join(WorkDir, "config"), toPath) && process.platform !== "win32") {
    await fs.chmod(toPath, 0o600);
  }
  maybeResetSecurityCache([toPath]);
  return { ok: true as const };
}

export async function remove(
  relPath: string,
  opts?: z.infer<typeof workspace.RemoveOptions>,
): Promise<{ ok: true }> {
  const filePath = resolveWorkspacePath(relPath);
  const trash = opts?.trash !== false; // default true

  const stats = await fs.lstat(filePath);
  if (stats.isSymbolicLink()) {
    await assertCanonicalInsideWorkspace(path.dirname(filePath));
  } else {
    await assertCanonicalInsideWorkspace(filePath);
  }

  if (trash) {
    // Move to trash: ~/.workspace/.trash/<timestamp>-<name>
    const trashDir = path.join(WorkDir, ".trash");
    await fs.mkdir(trashDir, { recursive: true });

    const timestamp = Date.now();
    const basename = path.basename(filePath);
    const trashPath = path.join(trashDir, `${timestamp}-${basename}`);

    // Handle name conflicts in trash
    let finalTrashPath = trashPath;
    let counter = 1;
    while (true) {
      try {
        await fs.access(finalTrashPath);
        finalTrashPath = path.join(trashDir, `${timestamp}-${counter}-${basename}`);
        counter++;
      } catch {
        break;
      }
    }

    await fs.rename(filePath, finalTrashPath);
  } else {
    // Permanent delete
    if (stats.isDirectory()) {
      if (!opts?.recursive) {
        throw new Error("Cannot remove directory without recursive=true");
      }
      await fs.rm(filePath, { recursive: true });
    } else {
      await fs.unlink(filePath);
    }
  }

  maybeResetSecurityCache([filePath]);
  return { ok: true as const };
}
