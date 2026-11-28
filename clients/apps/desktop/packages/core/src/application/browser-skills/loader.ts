import { writeJsonAtomic } from "../../filesystem/atomic_write.js";
import * as path from 'node:path';
import * as fs from 'node:fs/promises';
import { z } from 'zod';
import { WorkDir } from '../../config/config.js';
import { isPathInsideDir, isSameNormalizedPath } from '../../config/security.js';

const REPO_OWNER = 'browser-use';
const REPO_NAME = 'browser-harness';
const REPO_BRANCH = 'main';
const DOMAIN_SKILLS_PREFIX = 'domain-skills/';

const MANIFEST_TTL_MS = 24 * 60 * 60 * 1000;
const FETCH_TIMEOUT_MS = 20_000;

const SkillEntrySchema = z.object({
  id: z.string().min(1),
  site: z.string().min(1),
  fileName: z.string().min(1),
  title: z.string(),
  path: z.string().min(1),
  localPath: z.string().min(1),
});
export type SkillEntry = z.infer<typeof SkillEntrySchema>;

const SkillsIndexSchema = z.object({
  fetchedAt: z.number(),
  treeSha: z.string(),
  entries: z.array(SkillEntrySchema),
});
export type SkillsIndex = z.infer<typeof SkillsIndexSchema>;

export type LoaderStatus =
  | { status: 'ready'; index: SkillsIndex }
  | { status: 'stale'; index: SkillsIndex; refreshing: boolean }
  | { status: 'empty' }
  | { status: 'error'; error: string };

const cacheRoot = () => path.join(WorkDir, 'cache', 'browser-skills');
const skillsDir = () => path.join(cacheRoot(), 'domain-skills');
const manifestPath = () => path.join(cacheRoot(), 'manifest.json');

function isSafeRelativeSegmentPath(value: string): boolean {
  const trimmed = value.trim();
  if (
    !trimmed
    || trimmed.includes('\0')
    || path.isAbsolute(trimmed)
    || /^[A-Za-z]:/.test(trimmed)
    || trimmed.startsWith('~')
  ) {
    return false;
  }
  const segments = trimmed.replace(/\\/g, '/').split('/');
  return segments.every((segment) => segment.length > 0 && segment !== '.' && segment !== '..');
}

async function resolveSafeSkillFilePath(site: string, fileName: string): Promise<string | null> {
  if (!isSafeRelativeSegmentPath(site) || !isSafeRelativeSegmentPath(fileName)) {
    return null;
  }
  const baseDir = path.resolve(skillsDir());
  const candidate = path.resolve(baseDir, site, fileName);
  if (!isPathInsideDir(baseDir, candidate) || isSameNormalizedPath(candidate, baseDir)) {
    return null;
  }
  const canonicalBase = await fs.realpath(baseDir).catch(() => baseDir);
  const canonicalTarget = await fs.realpath(candidate).catch(() => null);
  if (!canonicalTarget) {
    return null;
  }
  if (!isPathInsideDir(canonicalBase, canonicalTarget) || isSameNormalizedPath(canonicalTarget, canonicalBase)) {
    return null;
  }
  return canonicalTarget;
}

async function ensureCacheDir(): Promise<void> {
  await fs.mkdir(skillsDir(), { recursive: true });
}

async function readManifest(): Promise<SkillsIndex | null> {
  try {
    const raw = await fs.readFile(manifestPath(), 'utf8');
    const parsed = SkillsIndexSchema.safeParse(JSON.parse(raw));
    if (!parsed.success) return null;
    return parsed.data;
  } catch {
    return null;
  }
}

async function writeManifest(index: SkillsIndex): Promise<void> {
  await ensureCacheDir();
  await writeJsonAtomic(manifestPath(), index);
}

function extractTitle(markdown: string, fallback: string): string {
  const match = markdown.match(/^#\s+(.+?)\s*$/m);
  if (match?.[1]) return match[1].trim();
  return fallback;
}

async function fetchWithTimeout(url: string, init?: RequestInit): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    return await fetch(url, {
      ...init,
      signal: controller.signal,
      headers: {
        'User-Agent': 'solomon-ai-browser-skills',
        Accept: 'application/vnd.github+json',
        ...(init?.headers ?? {}),
      },
    });
  } finally {
    clearTimeout(timer);
  }
}

type GithubTreeNode = { path: string; type: string; sha: string };

async function fetchRepoTree(): Promise<{ treeSha: string; skillPaths: string[] }> {
  const branchUrl = `https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/branches/${REPO_BRANCH}`;
  const branchRes = await fetchWithTimeout(branchUrl);
  if (!branchRes.ok) {
    throw new Error(`GitHub branch fetch failed: ${branchRes.status} ${branchRes.statusText}`);
  }
  const branch = (await branchRes.json()) as { commit: { commit: { tree: { sha: string } } } };
  const treeSha = branch.commit?.commit?.tree?.sha;
  if (!treeSha) throw new Error('Could not resolve tree SHA from branch response.');

  const treeUrl = `https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/git/trees/${treeSha}?recursive=1`;
  const treeRes = await fetchWithTimeout(treeUrl);
  if (!treeRes.ok) {
    throw new Error(`GitHub tree fetch failed: ${treeRes.status} ${treeRes.statusText}`);
  }
  const tree = (await treeRes.json()) as { tree: GithubTreeNode[]; truncated: boolean };

  const skillPaths = tree.tree
    .filter((n) => n.type === 'blob' && n.path.startsWith(DOMAIN_SKILLS_PREFIX) && n.path.endsWith('.md'))
    .map((n) => n.path);

  return { treeSha, skillPaths };
}

async function fetchRawFile(repoPath: string): Promise<string> {
  const url = `https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/${REPO_BRANCH}/${repoPath}`;
  const res = await fetchWithTimeout(url, { headers: { Accept: 'text/plain' } });
  if (!res.ok) {
    throw new Error(`Raw file fetch failed for ${repoPath}: ${res.status} ${res.statusText}`);
  }
  return res.text();
}

function parseRepoPath(repoPath: string): { id: string; site: string; fileName: string } | null {
  const rel = repoPath.slice(DOMAIN_SKILLS_PREFIX.length);
  const parts = rel.split('/');
  if (parts.length < 2) return null;
  const site = parts[0];
  const fileName = parts.slice(1).join('/');
  if (!isSafeRelativeSegmentPath(site) || !isSafeRelativeSegmentPath(fileName)) {
    return null;
  }
  const id = rel.replace(/\.md$/, '');
  return { id, site, fileName };
}

export async function refreshFromRemote(): Promise<SkillsIndex> {
  await ensureCacheDir();
  const baseDir = path.resolve(skillsDir());
  const canonicalSkillsDir = await fs.realpath(baseDir).catch(() => baseDir);
  const { treeSha, skillPaths } = await fetchRepoTree();

  const entries: SkillEntry[] = [];
  await Promise.all(skillPaths.map(async (repoPath) => {
    const parsed = parseRepoPath(repoPath);
    if (!parsed) return;
    try {
      const content = await fetchRawFile(repoPath);
      const localRel = path.join(parsed.site, parsed.fileName);
      const localPath = path.resolve(baseDir, localRel);
      if (!isPathInsideDir(baseDir, localPath) || isSameNormalizedPath(localPath, baseDir)) {
        return;
      }
      await fs.mkdir(path.dirname(localPath), { recursive: true });
      const canonicalParent = await fs.realpath(path.dirname(localPath));
      if (!isPathInsideDir(canonicalSkillsDir, canonicalParent)) {
        return;
      }
      const existingStat = await fs.lstat(localPath).catch(() => null);
      if (existingStat?.isSymbolicLink()) {
        return;
      }
      const safeTarget = path.join(canonicalParent, path.basename(localPath));
      await fs.writeFile(safeTarget, content, 'utf8');
      entries.push({
        id: parsed.id,
        site: parsed.site,
        fileName: parsed.fileName,
        title: extractTitle(content, parsed.id),
        path: repoPath,
        localPath: safeTarget,
      });
    } catch (err) {
      console.warn(`[browser-skills] Failed to fetch ${repoPath}:`, err);
    }
  }));

  entries.sort((a, b) => a.id.localeCompare(b.id));

  const index: SkillsIndex = {
    fetchedAt: Date.now(),
    treeSha,
    entries,
  };
  await writeManifest(index);
  return index;
}

let inFlightRefresh: Promise<SkillsIndex> | null = null;

export async function ensureLoaded(options?: { forceRefresh?: boolean }): Promise<LoaderStatus> {
  try {
    const existing = await readManifest();
    const fresh = existing && Date.now() - existing.fetchedAt < MANIFEST_TTL_MS;

    if (existing && fresh && !options?.forceRefresh) {
      return { status: 'ready', index: existing };
    }

    if (existing && !options?.forceRefresh) {
      if (!inFlightRefresh) {
        inFlightRefresh = refreshFromRemote()
          .catch((err) => {
            console.warn('[browser-skills] Background refresh failed:', err);
            return existing;
          })
          .finally(() => { inFlightRefresh = null; });
      }
      return { status: 'stale', index: existing, refreshing: true };
    }

    if (!inFlightRefresh) {
      inFlightRefresh = refreshFromRemote().finally(() => { inFlightRefresh = null; });
    }
    try {
      const index = await inFlightRefresh;
      return { status: 'ready', index };
    } catch (err) {
      return { status: 'error', error: err instanceof Error ? err.message : 'Failed to load skills.' };
    }
  } catch (err) {
    return { status: 'error', error: err instanceof Error ? err.message : 'Skill loader failed.' };
  }
}

export async function readSkillContent(id: string): Promise<{ ok: true; content: string; entry: SkillEntry } | { ok: false; error: string }> {
  const status = await ensureLoaded();
  if (status.status === 'error' || status.status === 'empty') {
    return { ok: false, error: status.status === 'error' ? status.error : 'No skills cached yet.' };
  }
  const entry = status.index.entries.find((e) => e.id === id);
  if (!entry) return { ok: false, error: `Skill '${id}' not found.` };
  // Never trust `entry.localPath` from manifest.json directly; derive and
  // canonicalize strictly inside `skillsDir()` so a tampered manifest cannot
  // turn `load-browser-skill` into an arbitrary file read primitive.
  const safePath = await resolveSafeSkillFilePath(entry.site, entry.fileName);
  if (!safePath) {
    return { ok: false, error: `Skill '${id}' points outside the browser-skills cache directory.` };
  }
  try {
    const content = await fs.readFile(safePath, 'utf8');
    return { ok: true, content, entry: { ...entry, localPath: safePath } };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : 'Failed to read skill file.' };
  }
}
