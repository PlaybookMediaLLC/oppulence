"use client";

import { Badge } from "@oppulence/ui/components/badge";
import { cn } from "@/lib/utils";
import { CheckCircle2Icon, ShieldAlertIcon, Terminal } from "@/lib/icons";
import { useState, type ComponentProps } from "react";
import { ToolCallPart } from "@x/shared/message";
import { ToolPermissionMetadata } from "@x/shared/runs";
import { sanitizeDisplayText } from "@/lib/sanitize-display";
import z from "zod";

export type AutoPermissionDecisionProps = ComponentProps<"div"> & {
  toolCall: z.infer<typeof ToolCallPart>;
  decision: "allow" | "deny";
  reason: string;
  permission?: z.infer<typeof ToolPermissionMetadata>;
};

const fileActionLabels: Record<string, string> = {
  read: "Read file",
  list: "List folder",
  search: "Search files",
  write: "Write files",
  delete: "Delete path",
};

function getRecordArgs(raw: unknown): Record<string, unknown> | null {
  const parsed = z.record(z.string(), z.unknown()).safeParse(raw);
  return parsed.success ? parsed.data : null;
}

export function AutoPermissionDecision({
  className,
  toolCall,
  decision,
  reason,
  permission,
  ...props
}: AutoPermissionDecisionProps) {
  const argObj = getRecordArgs(toolCall.arguments);
  const isCodeAgentRun = toolCall.toolName === "code_agent_run";
  const command =
    !isCodeAgentRun && (permission?.kind === "command" || toolCall.toolName === "executeCommand")
      ? argObj && "command" in argObj
        ? String(argObj.command)
        : JSON.stringify(toolCall.arguments)
      : null;
  const commandPermission = permission?.kind === "command" ? permission : null;
  const filePermission = permission?.kind === "file" ? permission : null;
  const mcpPermission = permission?.kind === "mcp" ? permission : null;
  const allowed = decision === "allow";

  let hasHiddenChars = false;
  const safe = (value: string): string => {
    const res = sanitizeDisplayText(value);
    if (res.hasHiddenChars) hasHiddenChars = true;
    return res.text;
  };

  const safeToolName = safe(toolCall.toolName);
  const safeReason = safe(reason);
  const safeCommand = command ? safe(command) : null;
  const safeCommandCwd = commandPermission?.cwd ? safe(commandPermission.cwd) : null;
  const safeCommandReasons = commandPermission?.reasons?.map((item: string) => safe(item)) ?? [];
  const safeCodeAgent = isCodeAgentRun
    ? safe(
        commandPermission?.commandNames[0]?.replace(/^code_agent_run:/, "") ||
          (typeof argObj?.agent === "string" ? argObj.agent : "claude"),
      )
    : null;
  const safeCodeCwd = isCodeAgentRun
    ? safe(commandPermission?.cwd || (typeof argObj?.cwd === "string" ? argObj.cwd : "."))
    : null;
  const [showFullCodePrompt, setShowFullCodePrompt] = useState(false);
  const safeCodePromptFull =
    isCodeAgentRun && typeof argObj?.prompt === "string"
      ? safe(argObj.prompt)
      : null;
  const codePromptTruncated = Boolean(safeCodePromptFull && safeCodePromptFull.length > 600);
  const safeCodePrompt =
    safeCodePromptFull && !showFullCodePrompt && codePromptTruncated
      ? `${safeCodePromptFull.slice(0, 600)}…`
      : safeCodePromptFull;
  const safeFilePaths = filePermission ? safe(filePermission.paths.join("\n")) : null;
  const safeFilePrefix =
    filePermission && filePermission.allowScopeGrant === true
      ? safe(filePermission.pathPrefix)
      : null;
  const safeMcpServerName = mcpPermission ? safe(mcpPermission.serverName) : null;
  const safeMcpCommand = mcpPermission?.command ? safe(mcpPermission.command) : null;
  const safeMcpArgs =
    mcpPermission?.args && mcpPermission.args.length > 0
      ? safe(JSON.stringify(mcpPermission.args))
      : null;
  const safeMcpUrl = mcpPermission?.url ? safe(mcpPermission.url) : null;
  const safeMcpEnvEntries:
    | Array<{ key: string; value: string; dangerous: boolean }>
    | undefined = mcpPermission?.envEntries?.map(
    (entry: { key: string; value: string; dangerous: boolean }) => ({
      key: safe(entry.key),
      value: safe(entry.value),
      dangerous: entry.dangerous,
    }),
  );
  const safeMcpEnvKeys =
    mcpPermission?.envKeys && mcpPermission.envKeys.length > 0
      ? safe(mcpPermission.envKeys.join(", "))
      : null;
  const safeMcpHeaderKeys =
    mcpPermission?.headerKeys && mcpPermission.headerKeys.length > 0
      ? safe(mcpPermission.headerKeys.join(", "))
      : null;
  const safeMcpWarnings = mcpPermission?.warnings?.map((w: string) => safe(w)) ?? [];
  const safeRawFallback =
    ((!isCodeAgentRun && !safeCommand && !filePermission && !mcpPermission) ||
      (mcpPermission && !safeMcpCommand && !safeMcpUrl)) &&
    toolCall.arguments
      ? safe(JSON.stringify(toolCall.arguments, null, 2))
      : null;

  return (
    <div
      className={cn(
        "not-prose mb-4 w-full rounded-none border",
        allowed
          ? "border-green-500/50 bg-green-50/80 dark:border-green-500/35 dark:bg-green-950/30"
          : "border-destructive/60 bg-destructive/15 dark:border-destructive/50 dark:bg-destructive/20",
        className,
      )}
      {...props}
    >
      <div className="space-y-3 p-4">
        <div className="flex items-start gap-3">
          {allowed ? (
            <CheckCircle2Icon className="mt-0.5 size-5 shrink-0 text-green-600 dark:text-green-400" />
          ) : (
            <ShieldAlertIcon className="mt-0.5 size-5 shrink-0 text-destructive" />
          )}
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <h3 className="text-sm font-semibold text-foreground">
                {allowed ? "Auto Allowed" : "Auto Denied"}
              </h3>
              <Badge variant="secondary" className="bg-secondary text-foreground">
                <Terminal className="mr-1 size-3" />
                {safeToolName}
              </Badge>
            </div>
            <p className="mt-1 text-sm text-muted-foreground">{safeReason}</p>
          </div>
        </div>
        {hasHiddenChars && (
          <div className="rounded-none border border-destructive/60 bg-destructive/10 px-3 py-2 text-xs text-destructive">
            Warning: Contains hidden, control, or bidirectional Unicode characters (escaped as{" "}
            <code className="font-mono">[U+XXXX]</code>).
          </div>
        )}
        {isCodeAgentRun && (
          <div className="space-y-3 rounded-none border bg-background/50 p-3">
            <div>
              <p className="mb-1.5 text-xs font-medium uppercase tracking-wide text-muted-foreground">Coding Agent</p>
              <pre className="whitespace-pre-wrap break-all font-mono text-xs text-foreground">{safeCodeAgent}</pre>
            </div>
            {safeCodeCwd && (
              <div>
                <p className="mb-1.5 text-xs font-medium uppercase tracking-wide text-muted-foreground">Working Directory</p>
                <pre className="whitespace-pre-wrap break-all font-mono text-xs text-foreground">{safeCodeCwd}</pre>
              </div>
            )}
            {safeCodePrompt && (
              <div>
                <div className="mb-1.5 flex items-center justify-between gap-2">
                  <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Prompt</p>
                  {codePromptTruncated && (
                    <button
                      type="button"
                      onClick={() => setShowFullCodePrompt((v) => !v)}
                      className="text-xs text-muted-foreground underline hover:text-foreground"
                    >
                      {showFullCodePrompt ? "Collapse" : "Show full content"}
                    </button>
                  )}
                </div>
                <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-all font-mono text-xs text-foreground">{safeCodePrompt}</pre>
              </div>
            )}
          </div>
        )}
        {safeCommand && (
          <div className="space-y-3 rounded-none border bg-background/50 p-3">
            <div>
              <p className="mb-1.5 text-xs font-medium uppercase tracking-wide text-muted-foreground">Command</p>
              <pre className="whitespace-pre-wrap break-all font-mono text-xs text-foreground">{safeCommand}</pre>
            </div>
            {safeCommandCwd && (
              <div>
                <p className="mb-1.5 text-xs font-medium uppercase tracking-wide text-muted-foreground">Working Directory</p>
                <pre className="whitespace-pre-wrap break-all font-mono text-xs text-foreground">{safeCommandCwd}</pre>
              </div>
            )}
            {safeCommandReasons.length > 0 && (
              <div>
                <p className="mb-1.5 text-xs font-medium uppercase tracking-wide text-muted-foreground">Reasons</p>
                <ul className="list-disc pl-4 space-y-1 text-xs text-foreground">
                  {safeCommandReasons.map((item: string, idx: number) => (
                    <li key={idx}>{item}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}
        {filePermission && (
          <div className="space-y-3 rounded-none border bg-background/50 p-3">
            <div>
              <p className="mb-1.5 text-xs font-medium uppercase tracking-wide text-muted-foreground">Action</p>
              <p className="text-xs font-medium text-foreground">
                {fileActionLabels[filePermission.operation] ?? filePermission.operation}
              </p>
            </div>
            <div>
              <p className="mb-1.5 text-xs font-medium uppercase tracking-wide text-muted-foreground">
                Path{filePermission.paths.length === 1 ? "" : "s"}
              </p>
              <pre className="whitespace-pre-wrap break-all font-mono text-xs text-foreground">
                {safeFilePaths}
              </pre>
            </div>
            {safeFilePrefix && (
              <div>
                <p className="mb-1.5 text-xs font-medium uppercase tracking-wide text-muted-foreground">Approval Scope</p>
                <pre className="whitespace-pre-wrap break-all font-mono text-xs text-foreground">
                  {safeFilePrefix}
                </pre>
              </div>
            )}
          </div>
        )}
        {mcpPermission && (
          <div className="space-y-3 rounded-none border bg-background/50 p-3">
            <div>
              <p className="mb-1.5 text-xs font-medium uppercase tracking-wide text-muted-foreground">Action</p>
              <p className="text-xs font-medium text-foreground">
                {mcpPermission.action === "install"
                  ? `Install MCP server (${mcpPermission.transport})`
                  : "Start local MCP server process"}
              </p>
            </div>
            <div>
              <p className="mb-1.5 text-xs font-medium uppercase tracking-wide text-muted-foreground">Server</p>
              <pre className="whitespace-pre-wrap break-all font-mono text-xs text-foreground">
                {safeMcpServerName}
              </pre>
            </div>
            {safeMcpCommand && (
              <div>
                <p className="mb-1.5 text-xs font-medium uppercase tracking-wide text-muted-foreground">Command</p>
                <pre className="whitespace-pre-wrap break-all font-mono text-xs text-foreground">
                  {safeMcpCommand}
                </pre>
              </div>
            )}
            {safeMcpArgs && (
              <div>
                <p className="mb-1.5 text-xs font-medium uppercase tracking-wide text-muted-foreground">Arguments</p>
                <pre className="whitespace-pre-wrap break-all font-mono text-xs text-foreground">
                  {safeMcpArgs}
                </pre>
              </div>
            )}
            {safeMcpUrl && (
              <div>
                <p className="mb-1.5 text-xs font-medium uppercase tracking-wide text-muted-foreground">Endpoint URL</p>
                <pre className="whitespace-pre-wrap break-all font-mono text-xs text-foreground">
                  {safeMcpUrl}
                </pre>
              </div>
            )}
            {safeMcpEnvEntries && safeMcpEnvEntries.length > 0 ? (
              <div>
                <p className="mb-1.5 text-xs font-medium uppercase tracking-wide text-muted-foreground">Environment Variables</p>
                <div className="space-y-1">
                  {safeMcpEnvEntries.map((entry, idx) => (
                    <div key={idx} className="flex flex-wrap items-center gap-1.5 font-mono text-xs">
                      {entry.dangerous && (
                        <Badge variant="destructive" className="text-[10px] px-1 py-0">
                          Exec override
                        </Badge>
                      )}
                      <span className="break-all text-foreground">
                        {entry.key}={entry.value}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            ) : safeMcpEnvKeys ? (
              <div>
                <p className="mb-1.5 text-xs font-medium uppercase tracking-wide text-muted-foreground">Environment Variables</p>
                <pre className="whitespace-pre-wrap break-all font-mono text-xs text-foreground">
                  {safeMcpEnvKeys}
                </pre>
              </div>
            ) : null}
            {safeMcpHeaderKeys && (
              <div>
                <p className="mb-1.5 text-xs font-medium uppercase tracking-wide text-muted-foreground">Headers</p>
                <pre className="whitespace-pre-wrap break-all font-mono text-xs text-foreground">
                  {safeMcpHeaderKeys}
                </pre>
              </div>
            )}
            {safeMcpWarnings.length > 0 && (
              <div>
                <p className="mb-1.5 text-xs font-medium uppercase tracking-wide text-destructive">Security Warnings</p>
                <ul className="list-disc pl-4 space-y-1 text-xs text-destructive">
                  {safeMcpWarnings.map((warning: string, idx: number) => (
                    <li key={idx}>{warning}</li>
                  ))}
                </ul>
              </div>
            )}
            {!safeMcpCommand && !safeMcpUrl && safeRawFallback && (
              <div>
                <p className="mb-1.5 text-xs font-medium uppercase tracking-wide text-muted-foreground">Raw Arguments</p>
                <pre className="whitespace-pre-wrap break-all font-mono text-xs text-foreground">
                  {safeRawFallback}
                </pre>
              </div>
            )}
          </div>
        )}
        {!isCodeAgentRun && !safeCommand && !filePermission && !mcpPermission && safeRawFallback && (
          <div className="rounded-none border bg-background/50 p-3">
            <p className="mb-1.5 text-xs font-medium uppercase tracking-wide text-muted-foreground">Arguments</p>
            <pre className="whitespace-pre-wrap break-all font-mono text-xs text-foreground">
              {safeRawFallback}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
}
