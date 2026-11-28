import { WorkDir } from "../config/config.js";
import { canonicalizePath, isPathInsideDir, isSameNormalizedPath } from "../config/security.js";
import fs from "fs/promises";
import { glob } from "node:fs/promises";
import path from "path";
import z from "zod";
import { Agent } from "@x/shared/agent";
import { stringify } from "yaml";
import { parseFrontmatter } from "../application/lib/parse-frontmatter.js";

// eslint-disable-next-line @typescript-eslint/no-unused-vars
const UpdateAgentSchema = Agent.omit({ name: true });

export interface IAgentsRepo {
    list(): Promise<z.infer<typeof Agent>[]>;
    fetch(id: string): Promise<z.infer<typeof Agent>>;
    create(agent: z.infer<typeof Agent>): Promise<void>;
    update(id: string, agent: z.infer<typeof Agent>): Promise<void>;
    delete(id: string): Promise<void>;
}

export class FSAgentsRepo implements IAgentsRepo {
    private readonly agentsDir = path.join(WorkDir, "agents");

    private resolveAgentFilePath(id: string): string {
        const trimmed = id.trim();
        if (
            !trimmed
            || trimmed.includes("\0")
            || path.isAbsolute(trimmed)
            || /^[A-Za-z]:/.test(trimmed)
            || trimmed.startsWith("~")
            || trimmed.replace(/\\/g, "/").split("/").includes("..")
        ) {
            throw new Error(`Invalid agent identifier: ${id}`);
        }
        const resolvedDir = path.resolve(this.agentsDir);
        const resolvedFile = path.resolve(resolvedDir, `${trimmed}.md`);
        if (!isPathInsideDir(resolvedDir, resolvedFile) || isSameNormalizedPath(resolvedFile, resolvedDir)) {
            throw new Error(`Agent path escapes agents directory: ${id}`);
        }
        return resolvedFile;
    }

    private async assertCanonicalInsideAgentsDir(filePath: string): Promise<string> {
        const canonicalDir = await fs.realpath(this.agentsDir).catch(() => path.resolve(this.agentsDir));
        const canonicalFile = await fs.realpath(filePath);
        if (!isPathInsideDir(canonicalDir, canonicalFile) || isSameNormalizedPath(canonicalFile, canonicalDir)) {
            throw new Error("Agent file resolves outside agents directory");
        }
        return canonicalFile;
    }

    async list(): Promise<z.infer<typeof Agent>[]> {
        const result: z.infer<typeof Agent>[] = [];

        // list all md files in workdir/agents/
        // const matches = await Array.fromAsync(glob("**/*.md", { cwd: this.agentsDir }));
        const matches: string[] = [];
        const results = glob("**/*.md", { cwd: this.agentsDir });
        for await (const file of results) {
            matches.push(file);
        }
        for (const file of matches) {
            try {
                const candidate = path.join(this.agentsDir, file);
                await this.assertCanonicalInsideAgentsDir(candidate);
                const agent = await this.parseAgentMd(candidate);
                result.push({
                    ...agent,
                    name: file.replace(/\.md$/, ""),
                });
            } catch (error) {
                console.error(`Error parsing agent ${file}: ${error instanceof Error ? error.message : String(error)}`);
                continue;
            }
        }
        return result;
    }

    private async parseAgentMd(filepath: string): Promise<z.infer<typeof Agent>> {
        const raw = await fs.readFile(filepath, "utf8");

        const { frontmatter, content } = parseFrontmatter(raw);
        if (frontmatter) {
            const parsed = Agent
                .omit({ instructions: true })
                .parse(frontmatter);

            return {
                ...parsed,
                instructions: content,
            };
        }

        return {
            name: filepath,
            instructions: raw,
        };
    }

    async fetch(id: string): Promise<z.infer<typeof Agent>> {
        const filePath = this.resolveAgentFilePath(id);
        await this.assertCanonicalInsideAgentsDir(filePath);
        const agent = await this.parseAgentMd(filePath);
        return {
            ...agent,
            name: id,
        };
    }

    private async assertSafeWritePath(filePath: string): Promise<string> {
        const canonicalDir = await fs.realpath(this.agentsDir).catch(() => path.resolve(this.agentsDir));
        const canonicalTarget = await canonicalizePath(filePath);
        if (!isPathInsideDir(canonicalDir, canonicalTarget) || isSameNormalizedPath(canonicalTarget, canonicalDir)) {
            throw new Error("Agent file write resolves outside agents directory");
        }
        const existingStat = await fs.lstat(filePath).catch(() => null);
        if (existingStat?.isSymbolicLink()) {
            throw new Error("Refusing to write agent file through symbolic link");
        }
        return canonicalTarget;
    }

    async create(agent: z.infer<typeof Agent>): Promise<void> {
        const filePath = this.resolveAgentFilePath(agent.name);
        const safePath = await this.assertSafeWritePath(filePath);
        const { instructions, ...rest } = agent;
        const contents = `---\n${stringify(rest)}\n---\n${instructions}`;
        await fs.writeFile(safePath, contents);
    }

    async update(id: string, agent: z.infer<typeof UpdateAgentSchema>): Promise<void> {
        const filePath = this.resolveAgentFilePath(id);
        const safePath = await this.assertSafeWritePath(filePath);
        const { instructions, ...rest } = agent;
        const contents = `---\n${stringify(rest)}\n---\n${instructions}`;
        await fs.writeFile(safePath, contents);
    }

    async delete(id: string): Promise<void> {
        const filePath = this.resolveAgentFilePath(id);
        await this.assertCanonicalInsideAgentsDir(filePath);
        await fs.unlink(filePath);
    }
}