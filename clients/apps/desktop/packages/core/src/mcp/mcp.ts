import container from "../di/container.js";
import { lookup as dnsLookup } from "node:dns/promises";
import net from "node:net";
import { Client } from "@modelcontextprotocol/sdk/client";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import z from "zod";
import { IMcpConfigRepo } from "./repo.js";
import { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { connectionState, ListToolsResponse, McpServerList, McpServerName } from "@x/shared/mcp";
import {
  awaitApprovalAndRetry,
  cancelPendingMcpApprovals,
  canonicalArgumentsDigest,
  snapshotMcpArguments,
} from "./product-approval.js";
import {
  createObservedMcpFetch,
  createOneShotApprovalFetch,
  mcpAuthorizationSessionFingerprint,
  mcpHeadersDigest,
  normalizeMcpEndpoint,
  sameMcpEndpoint,
  type McpApprovalRequestBinding,
  type McpConfigApprovalSnapshot,
  type ObservedMcpToolCallRequest,
} from "./approval-request.js";
import { isCloudMetadataHostOrIp, isPrivateOrLocalIpAddress } from "../security/network-safety.js";

export { isCloudMetadataHostOrIp, isPrivateOrLocalIpAddress };

type McpClientState = {
  state: z.infer<typeof connectionState>;
  client: Client | null;
  error: string | null;
  configDigest?: string;
  isStdio?: boolean;
};
const clients = new Map<string, McpClientState>();
const serverConnectQueues = new Map<string, Promise<unknown>>();
const serverEpochs = new Map<string, number>();
let globalCloseEpoch = 0;

function bumpServerEpoch(serverName: string): void {
  serverEpochs.set(serverName, (serverEpochs.get(serverName) ?? 0) + 1);
}

async function withServerConnectLock<T>(serverName: string, fn: () => Promise<T>): Promise<T> {
  const previous = serverConnectQueues.get(serverName) ?? Promise.resolve();
  let release!: () => void;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const tail = previous.then(
    () => gate,
    () => gate,
  );
  serverConnectQueues.set(serverName, tail);
  await previous.catch(() => undefined);
  try {
    return await fn();
  } finally {
    release();
    if (serverConnectQueues.get(serverName) === tail) {
      serverConnectQueues.delete(serverName);
    }
  }
}

export async function assertSafeRemoteMcpUrl(rawUrl: string): Promise<URL> {
  const parsed = new URL(rawUrl);
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new Error(`Unsupported MCP URL protocol "${parsed.protocol}"`);
  }
  const host = parsed.hostname
    .toLowerCase()
    .replace(/^\[|\]$/g, "")
    .replace(/\.+$/, "");
  if (isCloudMetadataHostOrIp(host)) {
    throw new Error(`Refusing to connect MCP client to cloud metadata address "${host}"`);
  }
  const isLiteralIp = net.isIP(host) !== 0;
  const isExplicitLocalhost = host === "localhost" || host.endsWith(".localhost");
  if (!isLiteralIp && !isExplicitLocalhost) {
    let resolved: Array<{ address: string }>;
    try {
      resolved = await dnsLookup(host, { all: true });
    } catch (err) {
      throw new Error(`Refusing to connect MCP client: DNS lookup failed for "${host}"`, {
        cause: err,
      });
    }
    if (!resolved.length) {
      throw new Error(`Refusing to connect MCP client: hostname "${host}" returned no DNS records`);
    }
    for (const entry of resolved) {
      if (isCloudMetadataHostOrIp(entry.address) || isPrivateOrLocalIpAddress(entry.address)) {
        throw new Error(
          `Refusing to connect MCP client: hostname "${host}" resolved to local or private IP "${entry.address}"`,
        );
      }
    }
  }
  return parsed;
}

export type McpSpawnPolicy =
  { readonly kind: "stdio"; readonly expectedDigest: string } | { readonly kind: "remote-only" };

export type StdioMcpSpawnRequirement = {
  readonly serverName: string;
  readonly command: string;
  readonly args: readonly string[];
  readonly env: Readonly<Record<string, string>>;
  readonly envKeys: readonly string[];
  readonly configDigest: string;
  readonly alreadyConnectedWithSameConfig: boolean;
};

export function computeStdioMcpConfigDigest(
  serverName: string,
  config: { command: string; args?: string[]; env?: Record<string, string> },
): string {
  return canonicalArgumentsDigest({
    serverName,
    command: config.command,
    args: config.args ?? [],
    env: config.env ?? {},
  });
}

type ClientApprovalContext = {
  config: Readonly<McpConfigApprovalSnapshot>;
  repo: IMcpConfigRepo;
  observedToolCalls: Map<string, ObservedMcpToolCallRequest[]>;
};

const clientApprovalContexts = new WeakMap<Client, ClientApprovalContext>();
const clientConfigMeta = new WeakMap<Client, { configDigest: string; isStdio: boolean }>();
const configGenerations = new Map<string, { digest: string; generation: number }>();
let nextConfigGeneration = 1;

function toolCallKey(toolName: string, argumentsDigest: string): string {
  return `${toolName}\0${argumentsDigest}`;
}

function snapshotRemoteConfig(
  serverName: string,
  config: { url: string; headers?: Record<string, string>; connectionId?: string },
  repositoryGeneration?: number,
): Readonly<McpConfigApprovalSnapshot> {
  const configDigest = canonicalArgumentsDigest(config);
  const previous = configGenerations.get(serverName);
  const generation =
    repositoryGeneration ??
    (previous?.digest === configDigest ? previous.generation : nextConfigGeneration++);
  configGenerations.set(serverName, { digest: configDigest, generation });
  return Object.freeze({
    serverName,
    configuredEndpoint: normalizeMcpEndpoint(config.url),
    connectionId: config.connectionId,
    configGeneration: generation,
    configDigest,
    configuredHeadersDigest: mcpHeadersDigest(config.headers),
    credentialFingerprint: mcpAuthorizationSessionFingerprint(config.headers),
  });
}

function assertSameApprovalConfig(
  expected: Readonly<McpApprovalRequestBinding>,
  actual: Readonly<McpConfigApprovalSnapshot>,
): void {
  if (
    expected.serverName !== actual.serverName ||
    !sameMcpEndpoint(expected.configuredEndpoint, actual.configuredEndpoint) ||
    expected.connectionId !== actual.connectionId ||
    expected.configGeneration !== actual.configGeneration ||
    expected.configDigest !== actual.configDigest ||
    expected.configuredHeadersDigest !== actual.configuredHeadersDigest ||
    expected.credentialFingerprint !== actual.credentialFingerprint
  )
    throw new Error(
      "The MCP endpoint, credential, connection, or configuration changed after approval.",
    );
}

async function assertApprovalConfigCurrent(
  repo: IMcpConfigRepo,
  serverName: string,
  binding: Readonly<McpApprovalRequestBinding>,
): Promise<void> {
  const { mcpServers } = await repo.getConfig();
  const config = mcpServers[serverName];
  if (!config || "command" in config)
    throw new Error("The approved remote MCP connection is no longer configured.");
  assertSameApprovalConfig(
    binding,
    snapshotRemoteConfig(serverName, config, repo.getGeneration?.(serverName, config)),
  );
}

async function redeemApprovalCode(
  repo: IMcpConfigRepo,
  serverName: string,
  code: string,
  verifier: string,
  productOrigin: string,
  binding: Readonly<McpApprovalRequestBinding & { actor?: string; action?: string }>,
): Promise<{ approvalToken: string }> {
  const { mcpServers } = await repo.getConfig();
  const config = mcpServers[serverName];
  if (!config || "command" in config)
    throw new Error("The approved product is no longer configured.");
  await assertApprovalConfigCurrent(repo, serverName, binding);
  if (new URL(config.url).origin !== productOrigin || binding.endpoint.origin !== productOrigin)
    throw new Error("The approval redemption origin did not match the bound product origin.");
  const redeemUrl = new URL("/v1/approvals/redeem", productOrigin);
  await assertSafeRemoteMcpUrl(redeemUrl.toString());
  const response = await fetch(redeemUrl, {
    method: "POST",
    redirect: "error",
    headers: { ...(config.headers ?? {}), "content-type": "application/json" },
    body: JSON.stringify({
      code,
      code_verifier: verifier,
      desktop_challenge_id: binding.desktopChallengeId,
      connection_id: binding.connectionId,
      tool: binding.toolName,
      arguments_digest: binding.argumentsDigest,
      actor: binding.actor,
      action: binding.action,
    }),
  });
  if (!response.ok) throw new Error(`Approval code redemption failed (${response.status}).`);
  const body = (await response.json()) as Record<string, unknown>;
  if (typeof body.approval_token !== "string")
    throw new Error("The product returned an invalid approval redemption response.");
  return { approvalToken: body.approval_token };
}

function takeObservedToolCall(
  client: Client,
  toolName: string,
  input: Readonly<Record<string, unknown>>,
): { binding: McpApprovalRequestBinding; repo: IMcpConfigRepo } | undefined {
  const context = clientApprovalContexts.get(client);
  if (!context) return undefined;
  const argumentsDigest = canonicalArgumentsDigest(input);
  const key = toolCallKey(toolName, argumentsDigest);
  const requests = context.observedToolCalls.get(key);
  const request = requests?.pop();
  if (!request) return undefined;
  if (!requests?.length) context.observedToolCalls.delete(key);
  return { binding: Object.freeze({ ...context.config, ...request }), repo: context.repo };
}

function enforceSpawnPolicyForStdio(
  serverName: string,
  actualDigest: string,
  spawnPolicy?: McpSpawnPolicy,
): void {
  if (!spawnPolicy) {
    throw new Error(
      `MCP server "${serverName}" is a local stdio command and requires an explicit spawn policy.`,
    );
  }
  switch (spawnPolicy.kind) {
    case "remote-only":
      throw new Error(
        `MCP server "${serverName}" changed to a local stdio command after permission check — refusing to spawn.`,
      );
    case "stdio":
      if (spawnPolicy.expectedDigest !== actualDigest) {
        throw new Error(
          `MCP server "${serverName}" configuration changed after approval — refusing to spawn unapproved command.`,
        );
      }
      return;
    default: {
      const unhandled: never = spawnPolicy;
      throw new Error(`Unhandled MCP spawn policy: ${String(unhandled)}`);
    }
  }
}

function getMcpConfigRepo(): IMcpConfigRepo {
  return container.resolve<IMcpConfigRepo>("mcpConfigRepo");
}

async function createClient(
  serverName: string,
  approval?: { token: string; binding: Readonly<McpApprovalRequestBinding> },
  spawnPolicy?: McpSpawnPolicy,
): Promise<Client> {
  if (!McpServerName.safeParse(serverName).success) {
    throw new Error(`Invalid MCP server name "${serverName}"`);
  }
  const repo = getMcpConfigRepo();
  const { mcpServers } = await repo.getConfig();
  const config = Object.prototype.hasOwnProperty.call(mcpServers, serverName)
    ? mcpServers[serverName]
    : undefined;
  if (!config) throw new Error(`MCP server ${serverName} not found`);
  let transport: Transport | undefined;
  try {
    const client = new Client({ name: "rowboatx", version: "1.0.0" });
    if ("command" in config) {
      if (approval) throw new Error("Approval tokens are only supported by remote MCP servers.");
      const configDigest = computeStdioMcpConfigDigest(serverName, config);
      enforceSpawnPolicyForStdio(serverName, configDigest, spawnPolicy);
      transport = new StdioClientTransport({
        command: config.command,
        args: config.args,
        env: config.env,
      });
      await client.connect(transport);
      clientConfigMeta.set(client, { configDigest, isStdio: true });
    } else {
      const safeUrl = await assertSafeRemoteMcpUrl(config.url);
      const headers = { ...(config.headers ?? {}) };
      if (Object.keys(headers).some((name) => name.toLowerCase() === "x-approval-token"))
        throw new Error("X-Approval-Token is reserved for one-time approved MCP requests.");
      const configSnapshot = snapshotRemoteConfig(
        serverName,
        config,
        repo.getGeneration?.(serverName, config),
      );
      if (approval) assertSameApprovalConfig(approval.binding, configSnapshot);
      const observedToolCalls = new Map<string, ObservedMcpToolCallRequest[]>();
      const rawFetch = globalThis.fetch.bind(globalThis);
      const baseFetch: typeof fetch = async (input, init) => {
        const reqUrl =
          typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
        await assertSafeRemoteMcpUrl(reqUrl);
        return rawFetch(input, init);
      };
      const observedFetch = createObservedMcpFetch(
        baseFetch,
        canonicalArgumentsDigest,
        (request) => {
          const key = toolCallKey(request.toolName, request.argumentsDigest);
          const requests = observedToolCalls.get(key) ?? [];
          requests.push(request);
          observedToolCalls.set(key, requests);
        },
      );
      const transportFetch = approval
        ? createOneShotApprovalFetch({
            fetchImpl: baseFetch,
            token: approval.token,
            binding: approval.binding,
            argumentsDigest: canonicalArgumentsDigest,
            validateCurrent: () => assertApprovalConfigCurrent(repo, serverName, approval.binding),
          })
        : observedFetch;
      clientApprovalContexts.set(client, { config: configSnapshot, repo, observedToolCalls });
      const requestInit = Object.keys(headers).length ? { headers } : undefined;
      try {
        transport = new StreamableHTTPClientTransport(safeUrl, {
          ...(requestInit ? { requestInit } : {}),
          fetch: transportFetch,
          ...(approval?.binding.sessionId ? { sessionId: approval.binding.sessionId } : {}),
        });
        await client.connect(transport);
      } catch (error) {
        // Approval credentials never enter fallback setup or a second transport.
        if (approval) throw error;
        try {
          await transport?.close();
        } catch {
          // Ignore close errors from the failed HTTP transport.
        }
        transport = new SSEClientTransport(safeUrl, {
          ...(requestInit ? { requestInit } : {}),
          fetch: transportFetch,
        });
        await client.connect(transport);
      }
      clientConfigMeta.set(client, { configDigest: configSnapshot.configDigest, isStdio: false });
    }
    const clearIfCurrent = () => {
      if (clients.get(serverName)?.client === client) {
        clients.delete(serverName);
      }
    };
    const prevTransportClose = transport?.onclose;
    if (transport) {
      transport.onclose = () => {
        clearIfCurrent();
        prevTransportClose?.();
      };
    }
    const prevClientClose = client.onclose;
    client.onclose = () => {
      clearIfCurrent();
      prevClientClose?.();
    };
    return client;
  } catch (error) {
    await transport?.close().catch(() => undefined);
    throw error;
  }
}

async function getCurrentServerConfigMeta(
  serverName: string,
): Promise<{ configDigest: string; isStdio: boolean } | null> {
  if (!McpServerName.safeParse(serverName).success) {
    return null;
  }
  const repo = getMcpConfigRepo();
  const { mcpServers } = await repo.getConfig();
  const config = Object.prototype.hasOwnProperty.call(mcpServers, serverName)
    ? mcpServers[serverName]
    : undefined;
  if (!config) return null;
  if ("command" in config) {
    return { configDigest: computeStdioMcpConfigDigest(serverName, config), isStdio: true };
  }
  return { configDigest: canonicalArgumentsDigest(config), isStdio: false };
}

async function closeStoredClientLocked(serverName: string): Promise<void> {
  const existing = clients.get(serverName);
  if (!existing) return;
  clients.delete(serverName);
  if (existing.client) {
    await existing.client.transport?.close().catch(() => undefined);
    await existing.client.close().catch(() => undefined);
  }
}

async function getClient(serverName: string, spawnPolicy?: McpSpawnPolicy): Promise<Client> {
  if (!McpServerName.safeParse(serverName).success) {
    throw new Error(`Invalid MCP server name "${serverName}"`);
  }

  return withServerConnectLock(serverName, async () => {
    const currentMeta = await getCurrentServerConfigMeta(serverName);
    if (!currentMeta) {
      bumpServerEpoch(serverName);
      await closeStoredClientLocked(serverName);
      throw new Error(`MCP server ${serverName} not found`);
    }
    if (currentMeta.isStdio) {
      enforceSpawnPolicyForStdio(serverName, currentMeta.configDigest, spawnPolicy);
    }

    const existing = clients.get(serverName);
    if (existing && existing.state === "connected" && existing.client) {
      if (
        existing.configDigest === currentMeta.configDigest &&
        existing.isStdio === currentMeta.isStdio
      ) {
        return existing.client;
      }
      bumpServerEpoch(serverName);
      await closeStoredClientLocked(serverName);
    }

    const startGlobalEpoch = globalCloseEpoch;
    const startServerEpoch = serverEpochs.get(serverName) ?? 0;
    try {
      const client = await createClient(serverName, undefined, spawnPolicy);
      const invalidated =
        globalCloseEpoch !== startGlobalEpoch ||
        (serverEpochs.get(serverName) ?? 0) !== startServerEpoch;
      if (invalidated) {
        await client.close().catch(() => undefined);
        throw new Error(`MCP server "${serverName}" was closed while connecting.`);
      }
      const prev = clients.get(serverName);
      if (prev?.client && prev.client !== client) {
        await prev.client.transport?.close().catch(() => undefined);
        await prev.client.close().catch(() => undefined);
      }
      const meta = clientConfigMeta.get(client);
      clients.set(serverName, {
        state: "connected",
        client,
        error: null,
        configDigest: meta?.configDigest,
        isStdio: meta?.isStdio,
      });
      return client;
    } catch (error) {
      const invalidated =
        globalCloseEpoch !== startGlobalEpoch ||
        (serverEpochs.get(serverName) ?? 0) !== startServerEpoch;
      if (!invalidated) {
        clients.set(serverName, {
          state: "error",
          client: null,
          error: error instanceof Error ? error.message : "Unknown error",
        });
      }
      throw error;
    }
  });
}

export async function cleanup() {
  cancelPendingMcpApprovals("MCP connections were closed before approval completed.");
  globalCloseEpoch += 1;
  for (const [serverName, { client }] of Array.from(clients.entries())) {
    await client?.transport?.close().catch(() => undefined);
    await client?.close().catch(() => undefined);
    clients.delete(serverName);
  }
}

/**
 * Force-close all MCP client connections.
 * Used during force abort to immediately reject any pending MCP tool calls.
 * Clients will be lazily reconnected on next use.
 */
export async function forceCloseAllMcpClients(): Promise<void> {
  cancelPendingMcpApprovals("The product action was cancelled.");
  globalCloseEpoch += 1;
  for (const [serverName, { client }] of Array.from(clients.entries())) {
    try {
      await client?.close();
    } catch {
      // Ignore errors during force close
    }
    clients.delete(serverName);
  }
}

export async function closeMcpClient(serverName: string): Promise<void> {
  bumpServerEpoch(serverName);
  await closeStoredClientLocked(serverName);
}

export async function listServers(): Promise<z.infer<typeof McpServerList>> {
  const repo = getMcpConfigRepo();
  const { mcpServers } = await repo.getConfig();
  const result: z.infer<typeof McpServerList> = {
    mcpServers: {},
  };
  for (const [serverName, config] of Object.entries(mcpServers)) {
    const state = clients.get(serverName);
    result.mcpServers[serverName] = {
      config,
      state: state ? state.state : "disconnected",
      error: state ? state.error : null,
    };
  }
  return result;
}

export async function getStdioMcpSpawnRequirement(
  serverName: string,
): Promise<StdioMcpSpawnRequirement | null> {
  if (!McpServerName.safeParse(serverName).success) {
    return null;
  }
  const { mcpServers } = await listServers();
  const entry = Object.prototype.hasOwnProperty.call(mcpServers, serverName)
    ? mcpServers[serverName]
    : undefined;
  if (!entry || !("command" in entry.config)) {
    return null;
  }
  const config = entry.config;
  const args = config.args ?? [];
  const env = config.env ? { ...config.env } : {};
  const envKeys = Object.keys(env).sort();
  const configDigest = computeStdioMcpConfigDigest(serverName, config);
  const existing = clients.get(serverName);
  const alreadyConnectedWithSameConfig =
    existing?.state === "connected" &&
    existing.isStdio === true &&
    existing.configDigest === configDigest;
  return {
    serverName,
    command: config.command,
    args,
    env,
    envKeys,
    configDigest,
    alreadyConnectedWithSameConfig,
  };
}

export async function listTools(
  serverName: string,
  cursor?: string,
  options?: { spawnPolicy?: McpSpawnPolicy },
): Promise<z.infer<typeof ListToolsResponse>> {
  const client = await getClient(serverName, options?.spawnPolicy);
  const { tools, nextCursor } = await client.listTools({
    cursor,
  });
  return {
    tools,
    nextCursor,
  };
}

export async function executeTool(
  serverName: string,
  toolName: string,
  input: Record<string, unknown>,
  options?: { spawnPolicy?: McpSpawnPolicy },
): Promise<unknown> {
  return executeToolAttempt(
    serverName,
    toolName,
    snapshotMcpArguments(input),
    undefined,
    options?.spawnPolicy,
  );
}

async function executeToolAttempt(
  serverName: string,
  toolName: string,
  input: Readonly<Record<string, unknown>>,
  approval?: { token: string; binding: Readonly<McpApprovalRequestBinding> },
  spawnPolicy?: McpSpawnPolicy,
): Promise<unknown> {
  const client = approval
    ? await createClient(serverName, approval, spawnPolicy)
    : await getClient(serverName, spawnPolicy);
  let succeeded = false;
  try {
    const result = await client.callTool({ name: toolName, arguments: input });
    succeeded = true;
    return result;
  } catch (error) {
    if (approval) throw error;
    const approvalContext = takeObservedToolCall(client, toolName, input);
    const requestBinding = approvalContext?.binding;
    return await awaitApprovalAndRetry(
      serverName,
      toolName,
      input,
      error,
      requestBinding,
      (token, binding) =>
        executeToolAttempt(
          serverName,
          toolName,
          input,
          {
            token,
            binding,
          },
          spawnPolicy,
        ),
      (code, verifier, productOrigin, binding) => {
        if (!approvalContext)
          throw new Error("The approval-required MCP request had no repository context.");
        return redeemApprovalCode(
          approvalContext.repo,
          serverName,
          code,
          verifier,
          productOrigin,
          binding,
        );
      },
    );
  } finally {
    if (succeeded && !approval) {
      takeObservedToolCall(client, toolName, input);
    }
    // One-time approval credentials must never remain on a pooled transport.
    if (approval) await client.close();
  }
}
