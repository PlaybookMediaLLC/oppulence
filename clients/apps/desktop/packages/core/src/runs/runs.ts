import z from "zod";
import container from "../di/container.js";
import { IMessageQueue, UserMessageContentType, VoiceOutputMode, MiddlePaneContext } from "../application/lib/message-queue.js";
import { AskHumanResponseEvent, ToolPermissionRequestEvent, ToolPermissionResponseEvent, CreateRunOptions, Run, ListRunsOptions, ListRunsResponse, ToolPermissionAuthorizePayload, AskHumanResponsePayload } from "@x/shared/runs";
import { IRunsRepo } from "./repo.js";
import { IAgentRuntime } from "../agents/runtime.js";
import { IBus } from "../application/lib/bus.js";
import { IAbortRegistry } from "./abort-registry.js";
import { IRunsLock } from "./lock.js";
import { forceCloseAllMcpClients } from "../mcp/mcp.js";
import {
    extractCommandNames,
    isAlwaysRequireApprovalCommand,
} from "../application/lib/command-executor.js";
import {
    addFileAccessGrant,
    addMcpServerGrant,
    addToSecurityConfig,
} from "../config/security.js";
import { withFileLock } from "../knowledge/file-lock.js";
import { loadAgent } from "../agents/runtime.js";
import { getDefaultModelAndProvider } from "../models/defaults.js";

export async function createRun(opts: z.infer<typeof CreateRunOptions>): Promise<z.infer<typeof Run>> {
    const repo = container.resolve<IRunsRepo>('runsRepo');
    const bus = container.resolve<IBus>('bus');

    // Resolve model+provider once at creation: opts > agent declaration > defaults.
    // Both fields are plain strings (provider is a name, looked up at runtime).
    // Use `||` (not `??`) so an empty-string override — what an LLM tool call
    // sometimes synthesizes for "I'm not setting this" — falls through to the
    // next link in the chain instead of being treated as a real value.
    const agent = await loadAgent(opts.agentId);
    const defaults = await getDefaultModelAndProvider();
    const model = opts.model || agent.model || defaults.model;
    const provider = opts.provider || agent.provider || defaults.provider;
    const useCase = opts.useCase ?? "copilot_chat";

    const run = await repo.create({
        agentId: opts.agentId,
        model,
        provider,
        permissionMode: opts.permissionMode ?? "manual",
        useCase,
        ...(opts.subUseCase ? { subUseCase: opts.subUseCase } : {}),
    });
    await bus.publish(run.log[0]);
    return run;
}

export async function createMessage(runId: string, message: UserMessageContentType, voiceInput?: boolean, voiceOutput?: VoiceOutputMode, searchEnabled?: boolean, middlePaneContext?: MiddlePaneContext, codeMode?: 'claude' | 'codex'): Promise<string> {
    const queue = container.resolve<IMessageQueue>('messageQueue');
    const id = await queue.enqueue(runId, message, voiceInput, voiceOutput, searchEnabled, middlePaneContext, codeMode);
    const runtime = container.resolve<IAgentRuntime>('agentRuntime');
    runtime.trigger(runId);
    return id;
}

export async function authorizePermission(runId: string, ev: z.infer<typeof ToolPermissionAuthorizePayload>): Promise<void> {
    const { scope, ...rest } = ev;
    const repo = container.resolve<IRunsRepo>('runsRepo');
    const targetSubflow = JSON.stringify(rest.subflow);

    const committed = await withFileLock(`run-permission:${runId}`, async () => {
        const run = await repo.fetch(runId);
        const permReqEvent = run.log.find(
            (e): e is z.infer<typeof ToolPermissionRequestEvent> =>
                e.type === "tool-permission-request"
                && e.toolCall.toolCallId === rest.toolCallId
                && JSON.stringify(e.subflow) === targetSubflow
        );
        if (!permReqEvent) {
            throw new Error(`No matching permission request found for toolCallId ${rest.toolCallId}`);
        }

        const alreadyResponded = run.log.some(
            (e) =>
                e.type === "tool-permission-response"
                && e.toolCallId === rest.toolCallId
                && JSON.stringify(e.subflow) === targetSubflow
        );
        if (alreadyResponded) {
            return null;
        }

        const permission = permReqEvent.permission;
        const canGrantScope = permission?.allowScopeGrant === true;
        const effectiveScope = canGrantScope ? scope : "once";

        // Commit the run log response FIRST while holding the per-run lock so a
        // racing deny/approve pair can never persist an "always" grant after deny won.
        const event: z.infer<typeof ToolPermissionResponseEvent> = {
            ...rest,
            runId,
            type: "tool-permission-response",
            scope: effectiveScope,
        };
        await repo.appendEvents(runId, [event]);

        return { permReqEvent, permission, effectiveScope };
    });

    if (!committed) {
        return;
    }

    // For "always" scope, derive grant from the verified request metadata and persist to security config
    if (rest.response === "approve" && committed.effectiveScope === "always" && committed.permission) {
        const { permission, permReqEvent } = committed;
        switch (permission.kind) {
            case "file": {
                await addFileAccessGrant({
                    operation: permission.operation,
                    pathPrefix: permission.pathPrefix,
                });
                break;
            }
            case "mcp": {
                if (
                    permission.action === "spawn"
                    && permission.configDigest
                    && permission.command
                ) {
                    await addMcpServerGrant({
                        serverName: permission.serverName,
                        configDigest: permission.configDigest,
                        command: permission.command,
                        args: permission.args,
                    });
                }
                break;
            }
            case "command": {
                const rawNames = permission.commandNames.length > 0
                    ? permission.commandNames
                    : (typeof permReqEvent.toolCall.arguments === 'object'
                        && permReqEvent.toolCall.arguments !== null
                        && 'command' in permReqEvent.toolCall.arguments
                        ? extractCommandNames(String(permReqEvent.toolCall.arguments.command))
                        : []);
                const commandNames = rawNames.filter((name) => !isAlwaysRequireApprovalCommand(name));
                if (commandNames.length > 0) {
                    await addToSecurityConfig(commandNames);
                }
                break;
            }
            default: {
                const unhandled: never = permission;
                throw new Error(`Unhandled permission kind: ${String(unhandled)}`);
            }
        }
    }

    const runtime = container.resolve<IAgentRuntime>('agentRuntime');
    runtime.trigger(runId);
}

export async function replyToHumanInputRequest(runId: string, ev: z.infer<typeof AskHumanResponsePayload>): Promise<void> {
    const repo = container.resolve<IRunsRepo>('runsRepo');
    const targetSubflow = JSON.stringify(ev.subflow);
    const appended = await withFileLock(`run-ask-human:${runId}`, async () => {
        const run = await repo.fetch(runId);
        const matchingRequest = run.log.some(
            (e) =>
                e.type === "ask-human-request"
                && e.toolCallId === ev.toolCallId
                && JSON.stringify(e.subflow) === targetSubflow
        );
        if (!matchingRequest) {
            throw new Error(`No matching ask-human request found for toolCallId ${ev.toolCallId}`);
        }
        const alreadyResponded = run.log.some(
            (e) =>
                e.type === "ask-human-response"
                && e.toolCallId === ev.toolCallId
                && JSON.stringify(e.subflow) === targetSubflow
        );
        if (alreadyResponded) {
            return false;
        }
        const event: z.infer<typeof AskHumanResponseEvent> = {
            ...ev,
            runId,
            type: "ask-human-response",
        };
        await repo.appendEvents(runId, [event]);
        return true;
    });
    if (!appended) {
        return;
    }
    const runtime = container.resolve<IAgentRuntime>('agentRuntime');
    runtime.trigger(runId);
}

export async function stop(runId: string, force: boolean = false): Promise<void> {
    const abortRegistry = container.resolve<IAbortRegistry>('abortRegistry');

    if (force && abortRegistry.isAborted(runId)) {
        // Second click: aggressive cleanup — SIGKILL + force close MCP clients
        console.log(`Force stopping run ${runId}`);
        abortRegistry.forceAbort(runId);
        await forceCloseAllMcpClients();
    } else {
        // First click: graceful — fires AbortSignal + SIGTERM
        console.log(`Gracefully stopping run ${runId}`);
        abortRegistry.abort(runId);
    }
    // Note: The run-stopped event is emitted by AgentRuntime.trigger() when it detects the abort.
    // This avoids duplicate events and ensures proper sequencing.
}

export async function deleteRun(runId: string): Promise<void> {
    const runsLock = container.resolve<IRunsLock>('runsLock');
    if (!await runsLock.lock(runId)) {
        throw new Error(`Cannot delete run ${runId}: run is currently active`);
    }
    try {
        const repo = container.resolve<IRunsRepo>('runsRepo');
        await repo.delete(runId);
    } finally {
        await runsLock.release(runId);
    }
}

export async function fetchRun(runId: string): Promise<z.infer<typeof Run>> {
    const repo = container.resolve<IRunsRepo>('runsRepo');
    return repo.fetch(runId);
}

export async function listRuns(opts?: z.infer<typeof ListRunsOptions>): Promise<z.infer<typeof ListRunsResponse>> {
    const repo = container.resolve<IRunsRepo>('runsRepo');
    return repo.list(opts);
}
