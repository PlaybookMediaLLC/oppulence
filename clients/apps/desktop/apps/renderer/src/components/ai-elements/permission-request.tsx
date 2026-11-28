"use client";

import { Badge } from "@oppulence/ui/components/badge";
import { Button } from "@oppulence/ui/components/button";
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem,
} from "@oppulence/ui/components/dropdown-menu";
import { cn } from "@/lib/utils";
import {
  AlertTriangleIcon,
  CheckIcon,
  ChevronDownIcon,
  RefreshCwIcon,
  Terminal,
  XIcon,
} from "@/lib/icons";
import { useState, type ComponentProps } from "react";
import { ToolCallPart } from "@x/shared/message";
import { ToolPermissionMetadata } from "@x/shared/runs";
import { sanitizeDisplayText } from "@/lib/sanitize-display";
import z from "zod";

export type PermissionRequestProps = ComponentProps<"div"> & {
  toolCall: z.infer<typeof ToolCallPart>;
  onApprove?: () => void;
  onApproveSession?: () => void;
  onApproveAlways?: () => void;
  onDeny?: () => void;
  onSwitchAgent?: (newAgent: "claude" | "codex") => void;
  isProcessing?: boolean;
  response?: "approve" | "deny" | null;
  permission?: z.infer<typeof ToolPermissionMetadata>;
};

const fileActionLabels: Record<string, string> = {
  read: "Read file",
  list: "List folder",
  search: "Search files",
  write: "Write files",
  delete: "Delete path",
};

function truncatePreview(value: string, max = 400): { preview: string; truncated: boolean } {
  if (value.length <= max) {
    return { preview: value, truncated: false };
  }
  return {
    preview: `${value.slice(0, max)}… (${value.length} chars)`,
    truncated: true,
  };
}

function getRecordArgs(raw: unknown): Record<string, unknown> | null {
  const parsed = z.record(z.string(), z.unknown()).safeParse(raw);
  return parsed.success ? parsed.data : null;
}

export const PermissionRequest = ({
  className,
  toolCall,
  onApprove,
  onApproveSession,
  onApproveAlways,
  onDeny,
  onSwitchAgent,
  isProcessing = false,
  response = null,
  permission,
  ...props
}: PermissionRequestProps) => {
  const argObj = getRecordArgs(toolCall.arguments);
  const isCodeAgentRun = toolCall.toolName === "code_agent_run";
  const isBackgroundTaskTool =
    toolCall.toolName === "create-background-task" || toolCall.toolName === "patch-background-task";
  const isSaveToMemory = toolCall.toolName === "save-to-memory";

  // Extract command ONLY for executeCommand (or generic command tools other than code_agent_run)
  // so a spoofed extra `arguments.command` on code_agent_run can never hide real agent/cwd/prompt.
  const command =
    !isCodeAgentRun && (permission?.kind === "command" || toolCall.toolName === "executeCommand")
      ? argObj && "command" in argObj
        ? String(argObj.command)
        : JSON.stringify(toolCall.arguments)
      : null;

  const commandPermission = permission?.kind === "command" ? permission : null;
  const filePermission = permission?.kind === "file" ? permission : null;
  const mcpPermission = permission?.kind === "mcp" ? permission : null;
  const canGrantScope =
    permission?.allowScopeGrant === true &&
    (Boolean(commandPermission) || Boolean(filePermission) || mcpPermission?.action === "spawn");

  // Detect pure, single-command `acpx <agent> exec` invocations (no chained commands,
  // no capability reasons) so chained payloads cannot spoof the Claude Code / Codex badge.
  const acpxAgent: "claude" | "codex" | null = (() => {
    if (toolCall.toolName !== "executeCommand" || !command) return null;
    if (
      !commandPermission ||
      commandPermission.commandNames.length !== 1 ||
      commandPermission.commandNames[0] !== "acpx" ||
      (commandPermission.reasons && commandPermission.reasons.length > 0)
    ) {
      return null;
    }
    const tokens = command.trim().split(/\s+/);
    if (tokens[0] !== "acpx") return null;
    let idx = 1;
    while (idx < tokens.length && tokens[idx].startsWith("-")) {
      idx += 1;
    }
    if (tokens[idx + 1] !== "exec") return null;
    const agent = tokens[idx];
    return agent === "claude" ? "claude" : agent === "codex" ? "codex" : null;
  })();
  const otherAgent: "claude" | "codex" | null =
    acpxAgent === "claude" ? "codex" : acpxAgent === "codex" ? "claude" : null;
  const agentDisplay =
    acpxAgent === "claude" ? "Claude Code" : acpxAgent === "codex" ? "Codex" : null;
  const otherDisplay =
    otherAgent === "claude" ? "Claude Code" : otherAgent === "codex" ? "Codex" : null;

  let hasHiddenChars = false;
  const safe = (value: string): string => {
    const res = sanitizeDisplayText(value);
    if (res.hasHiddenChars) hasHiddenChars = true;
    return res.text;
  };
  const safeExpandable = (
    raw: string,
    max = 400,
  ): { full: string; preview: string; truncated: boolean } => {
    // Always sanitize the FULL payload before truncating so hidden/bidi chars
    // beyond the initial preview cutoff still trigger `hasHiddenChars`.
    const full = safe(raw);
    const { preview, truncated } = truncatePreview(full, max);
    return { full, preview, truncated };
  };

  // Pre-sanitize displayed values so `hasHiddenChars` reflects every visible field
  const safeToolName = safe(toolCall.toolName);
  const safeCommand = command ? safe(command) : null;
  const safeCommandCwd = commandPermission?.cwd ? safe(commandPermission.cwd) : null;
  const safeCommandReasons = commandPermission?.reasons?.map((r: string) => safe(r)) ?? [];
  const safeCommandNames = commandPermission?.commandNames.map((n: string) => safe(n)) ?? [];
  const safeCodeAgent = isCodeAgentRun
    ? safe(
        commandPermission?.commandNames[0]?.replace(/^code_agent_run:/, "") ||
          (typeof argObj?.agent === "string" ? argObj.agent : "claude"),
      )
    : null;
  const safeCodeCwd = isCodeAgentRun
    ? safe(commandPermission?.cwd || (typeof argObj?.cwd === "string" ? argObj.cwd : "."))
    : null;
  const safeCodePrompt =
    isCodeAgentRun && typeof argObj?.prompt === "string"
      ? safeExpandable(argObj.prompt, 600)
      : null;
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
  const safeMcpEnvEntries: Array<{ key: string; value: string; dangerous: boolean }> | undefined =
    mcpPermission?.envEntries?.map((entry: { key: string; value: string; dangerous: boolean }) => ({
      key: safe(entry.key),
      value: safe(entry.value),
      dangerous: entry.dangerous,
    }));
  const safeMcpEnvKeys =
    mcpPermission?.envKeys && mcpPermission.envKeys.length > 0
      ? safe(mcpPermission.envKeys.join(", "))
      : null;
  const safeMcpHeaderKeys =
    mcpPermission?.headerKeys && mcpPermission.headerKeys.length > 0
      ? safe(mcpPermission.headerKeys.join(", "))
      : null;
  const safeMcpWarnings = mcpPermission?.warnings?.map((w: string) => safe(w)) ?? [];

  // Contextual previews for file, memory & background-task operations
  const fileExtraDetails: Array<{
    label: string;
    full: string;
    preview: string;
    truncated: boolean;
  }> = [];
  const pushDetail = (label: string, raw: string, max = 400) => {
    const item = safeExpandable(raw, max);
    fileExtraDetails.push({ label, ...item });
  };
  if (filePermission && argObj) {
    if (
      (toolCall.toolName === "file-copy" || toolCall.toolName === "file-rename") &&
      typeof argObj.from === "string" &&
      typeof argObj.to === "string"
    ) {
      pushDetail("Transfer", `${argObj.from} → ${argObj.to}`, 600);
    }
    if (toolCall.toolName === "file-glob" && typeof argObj.pattern === "string") {
      pushDetail("Glob Pattern", argObj.pattern, 600);
    }
    if (toolCall.toolName === "file-grep") {
      if (typeof argObj.pattern === "string") {
        pushDetail("Search Pattern", argObj.pattern, 600);
      }
      if (typeof argObj.fileGlob === "string") {
        pushDetail("File Glob", argObj.fileGlob, 600);
      }
    }
    if (toolCall.toolName === "file-writeText" && typeof argObj.data === "string") {
      pushDetail("Content Preview", argObj.data, 400);
    }
    if (toolCall.toolName === "file-editText") {
      const oldText =
        typeof argObj.oldString === "string"
          ? argObj.oldString
          : typeof argObj.oldText === "string"
            ? argObj.oldText
            : null;
      const newText =
        typeof argObj.newString === "string"
          ? argObj.newString
          : typeof argObj.newText === "string"
            ? argObj.newText
            : null;
      if (oldText !== null || newText !== null) {
        pushDetail("Replacement Preview", `-${oldText ?? ""}\n+${newText ?? ""}`, 400);
      } else if (Array.isArray(argObj.edits)) {
        pushDetail("Edits", JSON.stringify(argObj.edits, null, 2), 400);
      }
    }
    if (isSaveToMemory && typeof argObj.note === "string") {
      pushDetail("Memory Entry", argObj.note, 400);
    }
    if (isBackgroundTaskTool) {
      if (typeof argObj.name === "string") {
        pushDetail("Task Name", argObj.name, 400);
      }
      if (typeof argObj.slug === "string") {
        pushDetail("Task Slug", argObj.slug, 400);
      }
      if (typeof argObj.instructions === "string") {
        pushDetail("Instructions", argObj.instructions, 400);
      }
      if (argObj.triggers !== undefined) {
        pushDetail("Triggers", JSON.stringify(argObj.triggers, null, 2), 300);
      }
    }
  }

  const safeRawFallback =
    ((!isCodeAgentRun && !safeCommand && !filePermission && !mcpPermission) ||
      (mcpPermission && !safeMcpCommand && !safeMcpUrl)) &&
    toolCall.arguments
      ? safe(JSON.stringify(toolCall.arguments, null, 2))
      : null;

  const isResponded = response !== null;
  const isApproved = response === "approve";

  // Once a response is chosen, collapse the details to just the header.
  // Users can click the header to expand them again.
  const [expanded, setExpanded] = useState(false);
  const [expandedPreviews, setExpandedPreviews] = useState<Record<string, boolean>>({});
  const togglePreview = (key: string) =>
    setExpandedPreviews((prev) => ({ ...prev, [key]: !prev[key] }));
  const showDetails = !isResponded || expanded;

  return (
    <div
      className={cn(
        "not-prose mb-4 w-full rounded-none border",
        isResponded
          ? isApproved
            ? "border-green-500/60 bg-green-200/80 dark:border-green-500/40 dark:bg-green-900/40"
            : "border-destructive/70 bg-destructive/30 dark:border-destructive/60 dark:bg-destructive/30"
          : "border-amber-500/50 bg-amber-50/50 dark:border-amber-950/20 dark:bg-amber-950/20",
        className,
      )}
      {...props}
    >
      <div className="p-4 space-y-4">
        <div className="flex items-start gap-3">
          {!isResponded && (
            <AlertTriangleIcon className="size-5 text-amber-600 dark:text-amber-500 shrink-0 mt-0.5" />
          )}
          <div className="flex-1 space-y-2">
            <div
              className={cn("flex items-center gap-2", isResponded && "cursor-pointer select-none")}
              onClick={isResponded ? () => setExpanded((v) => !v) : undefined}
            >
              <div className="flex-1">
                <h3 className="font-semibold text-sm text-foreground">
                  {isResponded
                    ? isApproved
                      ? "Permission Granted"
                      : "Permission Denied"
                    : "Permission Required"}
                </h3>
                <p className="text-sm text-muted-foreground mt-1">
                  {isResponded ? "Requested:" : "The agent wants to execute:"}{" "}
                  <span className="font-mono font-medium">{safeToolName}</span>
                  {agentDisplay && (
                    <Badge
                      variant="secondary"
                      className="ml-2 align-middle bg-secondary text-foreground"
                    >
                      <Terminal className="size-3 mr-1" />
                      {agentDisplay}
                    </Badge>
                  )}
                </p>
              </div>
              {isResponded && (
                <ChevronDownIcon
                  className={cn(
                    "size-4 shrink-0 text-muted-foreground transition-transform",
                    expanded ? "rotate-180" : "rotate-0",
                  )}
                />
              )}
            </div>
            {showDetails && hasHiddenChars && (
              <div className="rounded-none border border-destructive/60 bg-destructive/10 px-3 py-2 text-xs text-destructive">
                Warning: This request contains hidden, control, or bidirectional Unicode characters
                (escaped as <code className="font-mono">[U+XXXX]</code>). Review carefully before
                approving.
              </div>
            )}
            {showDetails && isCodeAgentRun && (
              <div className="rounded-none border bg-background/50 p-3 mt-3 space-y-3">
                <div>
                  <p className="text-xs font-medium text-muted-foreground mb-1.5 uppercase tracking-wide">
                    Coding Agent
                  </p>
                  <pre className="whitespace-pre-wrap text-xs font-mono text-foreground break-all">
                    {safeCodeAgent}
                  </pre>
                </div>
                {safeCodeCwd && (
                  <div>
                    <p className="text-xs font-medium text-muted-foreground mb-1.5 uppercase tracking-wide">
                      Working Directory
                    </p>
                    <pre className="whitespace-pre-wrap text-xs font-mono text-foreground break-all">
                      {safeCodeCwd}
                    </pre>
                  </div>
                )}
                {safeCodePrompt && (
                  <div>
                    <div className="flex items-center justify-between mb-1.5">
                      <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
                        Prompt
                      </p>
                      {safeCodePrompt.truncated && (
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            togglePreview("code_prompt");
                          }}
                          className="text-xs font-medium text-primary hover:underline"
                        >
                          {expandedPreviews.code_prompt ? "Collapse" : "Show full content"}
                        </button>
                      )}
                    </div>
                    <pre
                      className={cn(
                        "whitespace-pre-wrap text-xs font-mono text-foreground break-all",
                        expandedPreviews.code_prompt && "max-h-96 overflow-auto",
                      )}
                    >
                      {expandedPreviews.code_prompt ? safeCodePrompt.full : safeCodePrompt.preview}
                    </pre>
                  </div>
                )}
                {safeCommandReasons.length > 0 && (
                  <div>
                    <p className="text-xs font-medium text-muted-foreground mb-1.5 uppercase tracking-wide">
                      Why approval is required
                    </p>
                    <ul className="list-disc pl-4 space-y-1 text-xs text-foreground">
                      {safeCommandReasons.map((reason: string, idx: number) => (
                        <li key={idx}>{reason}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}
            {showDetails && safeCommand && (
              <div className="rounded-none border bg-background/50 p-3 mt-3 space-y-3">
                <div>
                  <p className="text-xs font-medium text-muted-foreground mb-1.5 uppercase tracking-wide">
                    Command
                  </p>
                  <pre className="whitespace-pre-wrap text-xs font-mono text-foreground break-all">
                    {safeCommand}
                  </pre>
                </div>
                {safeCommandCwd && (
                  <div>
                    <p className="text-xs font-medium text-muted-foreground mb-1.5 uppercase tracking-wide">
                      Working Directory
                    </p>
                    <pre className="whitespace-pre-wrap text-xs font-mono text-foreground break-all">
                      {safeCommandCwd}
                    </pre>
                  </div>
                )}
                {safeCommandReasons.length > 0 && (
                  <div>
                    <p className="text-xs font-medium text-muted-foreground mb-1.5 uppercase tracking-wide">
                      Why approval is required
                    </p>
                    <ul className="list-disc pl-4 space-y-1 text-xs text-foreground">
                      {safeCommandReasons.map((reason: string, idx: number) => (
                        <li key={idx}>{reason}</li>
                      ))}
                    </ul>
                  </div>
                )}
                {canGrantScope && safeCommandNames.length > 0 && (
                  <div>
                    <p className="text-xs font-medium text-muted-foreground mb-1.5 uppercase tracking-wide">
                      Approval Scope
                    </p>
                    <pre className="whitespace-pre-wrap text-xs font-mono text-foreground break-all">
                      {safeCommandNames.join(", ")}
                    </pre>
                  </div>
                )}
              </div>
            )}
            {showDetails && filePermission && (
              <div className="rounded-none border bg-background/50 p-3 mt-3 space-y-3">
                <div>
                  <p className="text-xs font-medium text-muted-foreground mb-1.5 uppercase tracking-wide">
                    Action
                  </p>
                  <p className="text-xs font-medium text-foreground">
                    {isSaveToMemory
                      ? "Save note to Agent Notes memory"
                      : isBackgroundTaskTool
                        ? toolCall.toolName === "create-background-task"
                          ? "Create scheduled background task"
                          : "Update scheduled background task"
                        : (fileActionLabels[filePermission.operation] ?? filePermission.operation)}
                  </p>
                </div>
                <div>
                  <p className="text-xs font-medium text-muted-foreground mb-1.5 uppercase tracking-wide">
                    Path{filePermission.paths.length === 1 ? "" : "s"}
                  </p>
                  <pre className="whitespace-pre-wrap text-xs font-mono text-foreground break-all">
                    {safeFilePaths}
                  </pre>
                </div>
                {fileExtraDetails.map((detail) => {
                  const isOpen = Boolean(expandedPreviews[detail.label]);
                  return (
                    <div key={detail.label}>
                      <div className="flex items-center justify-between mb-1.5">
                        <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
                          {detail.label}
                        </p>
                        {detail.truncated && (
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              togglePreview(detail.label);
                            }}
                            className="text-xs font-medium text-primary hover:underline"
                          >
                            {isOpen ? "Collapse" : "Show full content"}
                          </button>
                        )}
                      </div>
                      <pre
                        className={cn(
                          "whitespace-pre-wrap text-xs font-mono text-foreground break-all",
                          isOpen && "max-h-96 overflow-auto",
                        )}
                      >
                        {isOpen ? detail.full : detail.preview}
                      </pre>
                    </div>
                  );
                })}
                {safeFilePrefix && (
                  <div>
                    <p className="text-xs font-medium text-muted-foreground mb-1.5 uppercase tracking-wide">
                      Approval Scope
                    </p>
                    <pre className="whitespace-pre-wrap text-xs font-mono text-foreground break-all">
                      {safeFilePrefix}
                    </pre>
                  </div>
                )}
              </div>
            )}
            {showDetails && mcpPermission && (
              <div className="rounded-none border bg-background/50 p-3 mt-3 space-y-3">
                <div>
                  <p className="text-xs font-medium text-muted-foreground mb-1.5 uppercase tracking-wide">
                    Action
                  </p>
                  <p className="text-xs font-medium text-foreground">
                    {mcpPermission.action === "install"
                      ? `Install MCP server (${mcpPermission.transport})`
                      : "Start local MCP server process"}
                  </p>
                </div>
                <div>
                  <p className="text-xs font-medium text-muted-foreground mb-1.5 uppercase tracking-wide">
                    Server
                  </p>
                  <pre className="whitespace-pre-wrap text-xs font-mono text-foreground break-all">
                    {safeMcpServerName}
                  </pre>
                </div>
                {safeMcpCommand && (
                  <div>
                    <p className="text-xs font-medium text-muted-foreground mb-1.5 uppercase tracking-wide">
                      Command
                    </p>
                    <pre className="whitespace-pre-wrap text-xs font-mono text-foreground break-all">
                      {safeMcpCommand}
                    </pre>
                  </div>
                )}
                {safeMcpArgs && (
                  <div>
                    <p className="text-xs font-medium text-muted-foreground mb-1.5 uppercase tracking-wide">
                      Arguments
                    </p>
                    <pre className="whitespace-pre-wrap text-xs font-mono text-foreground break-all">
                      {safeMcpArgs}
                    </pre>
                  </div>
                )}
                {safeMcpUrl && (
                  <div>
                    <p className="text-xs font-medium text-muted-foreground mb-1.5 uppercase tracking-wide">
                      Endpoint URL
                    </p>
                    <pre className="whitespace-pre-wrap text-xs font-mono text-foreground break-all">
                      {safeMcpUrl}
                    </pre>
                  </div>
                )}
                {safeMcpEnvEntries && safeMcpEnvEntries.length > 0 ? (
                  <div>
                    <p className="text-xs font-medium text-muted-foreground mb-1.5 uppercase tracking-wide">
                      Environment Variables
                    </p>
                    <div className="space-y-1">
                      {safeMcpEnvEntries.map((entry, idx) => (
                        <div
                          key={idx}
                          className="flex flex-wrap items-center gap-1.5 text-xs font-mono"
                        >
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
                    <p className="text-xs font-medium text-muted-foreground mb-1.5 uppercase tracking-wide">
                      Environment Variables
                    </p>
                    <pre className="whitespace-pre-wrap text-xs font-mono text-foreground break-all">
                      {safeMcpEnvKeys}
                    </pre>
                  </div>
                ) : null}
                {safeMcpHeaderKeys && (
                  <div>
                    <p className="text-xs font-medium text-muted-foreground mb-1.5 uppercase tracking-wide">
                      Headers
                    </p>
                    <pre className="whitespace-pre-wrap text-xs font-mono text-foreground break-all">
                      {safeMcpHeaderKeys}
                    </pre>
                  </div>
                )}
                {safeMcpWarnings.length > 0 && (
                  <div>
                    <p className="text-xs font-medium text-destructive mb-1.5 uppercase tracking-wide">
                      Security Warnings
                    </p>
                    <ul className="list-disc pl-4 space-y-1 text-xs text-destructive">
                      {safeMcpWarnings.map((warning: string, idx: number) => (
                        <li key={idx}>{warning}</li>
                      ))}
                    </ul>
                  </div>
                )}
                {!safeMcpCommand && !safeMcpUrl && safeRawFallback && (
                  <div>
                    <p className="text-xs font-medium text-muted-foreground mb-1.5 uppercase tracking-wide">
                      Raw Arguments
                    </p>
                    <pre className="whitespace-pre-wrap text-xs font-mono text-foreground break-all">
                      {safeRawFallback}
                    </pre>
                  </div>
                )}
                {canGrantScope && mcpPermission.configDigest && (
                  <div>
                    <p className="text-xs font-medium text-muted-foreground mb-1.5 uppercase tracking-wide">
                      Approval Scope
                    </p>
                    <p className="text-xs text-foreground">
                      Pinned to this exact server command, arguments, and environment (
                      {mcpPermission.configDigest.slice(0, 12)}…)
                    </p>
                  </div>
                )}
              </div>
            )}
            {showDetails &&
              !isCodeAgentRun &&
              !safeCommand &&
              !filePermission &&
              !mcpPermission &&
              safeRawFallback && (
                <div className="rounded-none border bg-background/50 p-3 mt-3">
                  <p className="text-xs font-medium text-muted-foreground mb-1.5 uppercase tracking-wide">
                    Arguments
                  </p>
                  <pre className="whitespace-pre-wrap text-xs font-mono text-foreground break-all">
                    {safeRawFallback}
                  </pre>
                </div>
              )}
          </div>
        </div>
        {!isResponded && (
          <div className="flex items-center gap-2 pt-2">
            <div className="flex flex-1 items-center">
              <Button
                variant="default"
                size="sm"
                onClick={onApprove}
                disabled={isProcessing}
                className={cn("flex-1", canGrantScope && "rounded-r-none")}
              >
                <CheckIcon className="size-4" />
                Approve
              </Button>
              {canGrantScope && (
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button
                      variant="default"
                      size="sm"
                      disabled={isProcessing}
                      className="rounded-l-none border-l border-l-primary-foreground/20 px-1.5"
                    >
                      <ChevronDownIcon className="size-3.5" />
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="end">
                    <DropdownMenuItem onClick={onApproveSession}>
                      Allow for Session
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={onApproveAlways}>Always Allow</DropdownMenuItem>
                  </DropdownMenuContent>
                </DropdownMenu>
              )}
            </div>
            <Button
              variant="destructive"
              size="sm"
              onClick={onDeny}
              disabled={isProcessing}
              className="flex-1"
            >
              <XIcon className="size-4" />
              Deny
            </Button>
            {otherAgent && otherDisplay && onSwitchAgent && (
              <Button
                variant="secondary"
                size="sm"
                onClick={() => onSwitchAgent(otherAgent)}
                disabled={isProcessing}
                className="flex-1"
              >
                <RefreshCwIcon className="size-4" />
                Use {otherDisplay} instead
              </Button>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
