import { generateObject, type ModelMessage } from "ai";
import z from "zod";
import { ToolPermissionMetadata } from "@x/shared/runs";
import { ToolCallPart } from "@x/shared/message";
import { captureLlmUsage } from "../analytics/usage.js";
import { withUseCase, type UseCase } from "../analytics/use_case.js";
import { getAutoPermissionDecisionModel, getDefaultModelAndProvider, resolveProviderConfig } from "../models/defaults.js";
import { createProvider } from "../models/models.js";

const DecisionSchema = z.object({
    decisions: z.array(z.object({
        toolCallId: z.string(),
        decision: z.enum(["allow", "deny"]),
        reason: z.string().min(1),
    })),
});

export type AutoPermissionCandidate = {
    readonly toolCall: z.infer<typeof ToolCallPart>;
    readonly permission: z.infer<typeof ToolPermissionMetadata>;
};

export type AutoPermissionDecision = z.infer<typeof DecisionSchema>["decisions"][number];

const SYSTEM_PROMPT = `You decide whether a personal productivity app may run tool calls without interrupting the user.

You only receive tool calls that already require permission under deterministic rules.

Allow a tool call only when it is clearly consistent with the user's request and low risk.
Deny tool calls that are destructive, credential-sensitive, privacy-sensitive, broad in scope, likely irreversible, or not clearly requested.

Command examples to deny unless explicitly requested: deleting data, force pushing, deploying, running migrations, changing permissions, reading secrets, dumping environment variables (env, printenv), running interpreters or shells (awk, sh, bash, python, node), using command substitution or file redirections, exfiltrating tokens, or accessing/modifying files outside the user's workspace or inside workspace config/.
File examples to deny unless explicitly requested: deleting paths, writing outside the workspace, reading or editing workspace config/ files (oauth.json, models.json, security.json, mcp.json), reading secrets or credentials, or broad access to private directories.
MCP examples to deny unless explicitly requested: installing or updating MCP servers (addMcpServer), or spawning local stdio MCP server processes.

Return one decision for every toolCallId. Use the exact toolCallId values provided.`;

function compact(value: unknown, max = 8_000): string {
    const text = typeof value === "string" ? value : JSON.stringify(value, null, 2);
    if (text.length <= max) return text;
    return `${text.slice(0, max)}\n...<truncated>`;
}

export function extractUserOnlyContext(messages: ModelMessage[]): unknown[] {
    // Only include user-authored messages in the permission classifier context.
    // Assistant turns can echo or summarize prompt injections from tool outputs,
    // and slicing all messages by -8 could evict the real user request after a
    // few tool turns.
    const userMessages = messages.filter((message) => message.role === "user");
    return userMessages.slice(-6).map((message) => {
        if (typeof message.content === "string") {
            return { role: message.role, content: compact(message.content, 2_000) };
        }
        return { role: message.role, content: compact(message.content, 3_000) };
    });
}

function recentContext(messages: ModelMessage[]): unknown[] {
    return extractUserOnlyContext(messages);
}

function buildPrompt(input: {
    agentName: string | null;
    messages: ModelMessage[];
    candidates: AutoPermissionCandidate[];
}) {
    return compact({
        agentName: input.agentName,
        recentConversation: recentContext(input.messages),
        toolCalls: input.candidates.map(({ toolCall, permission }) => ({
            toolCallId: toolCall.toolCallId,
            toolName: toolCall.toolName,
            arguments: toolCall.arguments,
            permission,
        })),
    }, 24_000);
}

export async function classifyToolPermissions(input: {
    runId: string;
    agentName: string | null;
    messages: ModelMessage[];
    candidates: AutoPermissionCandidate[];
    useCase: UseCase;
    subUseCase?: string | null;
}): Promise<AutoPermissionDecision[]> {
    if (input.candidates.length === 0) return [];

    const modelId = await getAutoPermissionDecisionModel();
    const { provider: providerName } = await getDefaultModelAndProvider();
    const providerConfig = await resolveProviderConfig(providerName);
    const model = createProvider(providerConfig).languageModel(modelId);

    const result = await withUseCase(
        {
            useCase: input.useCase,
            subUseCase: "auto_permission_classifier",
            ...(input.agentName ? { agentName: input.agentName } : {}),
        },
        () => generateObject({
            model,
            system: SYSTEM_PROMPT,
            prompt: buildPrompt(input),
            schema: DecisionSchema,
        }),
    );

    captureLlmUsage({
        useCase: input.useCase,
        subUseCase: "auto_permission_classifier",
        model: modelId,
        provider: providerName,
        usage: result.usage,
    });

    const allowedIds = new Set(input.candidates.map((candidate) => candidate.toolCall.toolCallId));
    return result.object.decisions.filter((decision) => allowedIds.has(decision.toolCallId));
}
