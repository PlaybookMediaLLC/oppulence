import { writeJsonAtomic } from "../filesystem/atomic_write.js";
import { withFileLock } from "../knowledge/file-lock.js";
import fs from 'fs/promises';
import path from 'path';
import { WorkDir } from '../config/config.js';
import { CodeModeConfig } from './types.js';
import { checkCodeModeAgentStatus } from './status.js';

export interface ICodeModeConfigRepo {
    getConfig(): Promise<CodeModeConfig>;
    setConfig(config: CodeModeConfig): Promise<void>;
}

export class FSCodeModeConfigRepo implements ICodeModeConfigRepo {
    private readonly configPath = path.join(WorkDir, 'config', 'code-mode.json');
    private agentReadyPromise: Promise<boolean> | null = null;

    // Reuse the existing agent check (Claude Code / Codex installed + signed in),
    // cached for the process lifetime so we probe (shell + keychain) at most once
    // per session rather than on every getConfig call.
    private agentReady(): Promise<boolean> {
        if (!this.agentReadyPromise) {
            this.agentReadyPromise = checkCodeModeAgentStatus()
                .then((s) =>
                    (s.claude.installed && s.claude.signedIn)
                    || (s.codex.installed && s.codex.signedIn))
                .catch(() => false);
        }
        return this.agentReadyPromise;
    }

    async getConfig(): Promise<CodeModeConfig> {
        try {
            // The file only exists once the user has explicitly toggled code mode
            // in settings — always honor that choice.
            const content = await fs.readFile(this.configPath, 'utf8');
            return CodeModeConfig.parse(JSON.parse(content));
        } catch (error) {
            if (error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT') {
                // No explicit choice yet: enable automatically when a coding agent is ready.
                return { enabled: await this.agentReady() };
            }
            // Corrupt/unreadable existing config fails closed rather than silently enabling Code Mode.
            return { enabled: false };
        }
    }

    async setConfig(config: CodeModeConfig): Promise<void> {
        const validated = CodeModeConfig.parse(config);
        await withFileLock(this.configPath, async () => {
            await fs.mkdir(path.dirname(this.configPath), { recursive: true });
            // Atomic: a torn file reverts an explicit opt-out to auto-detection.
            await writeJsonAtomic(this.configPath, validated, 2, 0o600);
        });
    }
}
