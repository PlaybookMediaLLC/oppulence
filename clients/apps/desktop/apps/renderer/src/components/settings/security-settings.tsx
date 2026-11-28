import * as React from "react";
import { Plus, Trash2, ShieldCheck, CodeIcon, Loader2, AlertTriangleIcon } from "@/lib/icons";
import { Button } from "@oppulence/ui/components/button";
import { Input } from "@oppulence/ui/components/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@oppulence/ui/components/select";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@oppulence/ui/components/collapsible";
import {
  FileAccessGrantSchema,
  FileAccessOperationSchema,
  McpServerGrantSchema,
  type FileAccessGrant,
  type McpServerGrant,
} from "@x/shared/security";
import { sanitizeDisplayText } from "@/lib/sanitize-display";
import { z } from "zod";
import { SettingsSection, StringListRows } from "./settings-ui";

/**
 * Security settings — a real form over `config/security.json`.
 * The file has two accepted shapes (the core parser handles both): a legacy
 * `string[]` of allowed commands, or `{ allowedCommands, allowedFileAccess, allowedMcpServers }`.
 * We read either and always save the richer object form (forward-compatible).
 */

const SECURITY_PATH = "config/security.json";
const FILE_OPS = FileAccessOperationSchema.options;

const SecurityFileShapeSchema = z.union([
  z.array(z.string()),
  z
    .object({
      allowedCommands: z.array(z.string()).optional(),
      allowedFileAccess: z.array(FileAccessGrantSchema).optional(),
      allowedMcpServers: z.array(McpServerGrantSchema).optional(),
    })
    .refine(
      (obj) =>
        obj.allowedCommands !== undefined ||
        obj.allowedFileAccess !== undefined ||
        obj.allowedMcpServers !== undefined,
      { message: "Must include at least one security allow-list field" },
    ),
]);

function isUnsafeOrBroadPrefix(prefix: string): boolean {
  const trimmed = prefix.trim();
  if (!trimmed) return false;
  const normalized = trimmed.replace(/\\/g, "/");
  if (
    /^\/+$/.test(normalized) ||
    /^[A-Za-z]:\/*$/.test(normalized) ||
    normalized === "~" ||
    normalized === "~/" ||
    /^\/\/[?.]\//.test(normalized) ||
    normalized.split("/").includes("..")
  ) {
    return true;
  }
  return false;
}

function parse(raw: string): {
  commands: string[];
  access: FileAccessGrant[];
  mcpServers: McpServerGrant[];
  valid: boolean;
} {
  let data: unknown;
  try {
    data = JSON.parse(raw || "[]");
  } catch {
    return { commands: [], access: [], mcpServers: [], valid: false };
  }
  const parsed = SecurityFileShapeSchema.safeParse(data);
  if (!parsed.success) {
    return { commands: [], access: [], mcpServers: [], valid: false };
  }
  if (Array.isArray(parsed.data)) {
    return {
      commands: parsed.data,
      access: [],
      mcpServers: [],
      valid: true,
    };
  }
  return {
    commands: parsed.data.allowedCommands ?? [],
    access: parsed.data.allowedFileAccess ?? [],
    mcpServers: parsed.data.allowedMcpServers ?? [],
    valid: true,
  };
}

function toConfig(commands: string[], access: FileAccessGrant[], mcpServers: McpServerGrant[]) {
  return {
    allowedCommands: commands.map((c) => c.trim()).filter(Boolean),
    allowedFileAccess: access
      .map((g) => ({ operation: g.operation, pathPrefix: g.pathPrefix.trim() }))
      .filter((g) => g.pathPrefix !== ""),
    ...(mcpServers.length > 0 ? { allowedMcpServers: mcpServers } : {}),
  };
}

export function SecuritySettings({ dialogOpen }: { dialogOpen: boolean }) {
  const [commands, setCommands] = React.useState<string[]>([]);
  const [access, setAccess] = React.useState<FileAccessGrant[]>([]);
  const [mcpServers, setMcpServers] = React.useState<McpServerGrant[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [saving, setSaving] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const [loadFailed, setLoadFailed] = React.useState(false);
  const [saved, setSaved] = React.useState(false);
  const [jsonOpen, setJsonOpen] = React.useState(false);
  const [rawJson, setRawJson] = React.useState("");

  React.useEffect(() => {
    if (!dialogOpen) return;
    setLoading(true);
    setError(null);
    setLoadFailed(false);
    setSaved(false);
    window.ipc
      .invoke("workspace:readFile", { path: SECURITY_PATH })
      .then((r) => {
        const raw = r.data || "";
        setRawJson(raw);
        const parsed = parse(raw);
        if (raw.trim() && !parsed.valid) {
          setError(
            "Existing config/security.json is invalid — switched to raw JSON so you can repair it.",
          );
          setJsonOpen(true);
          return;
        }
        setCommands(parsed.commands);
        setAccess(parsed.access);
        setMcpServers(parsed.mcpServers);
      })
      .catch((err: unknown) => {
        const msg = err instanceof Error ? err.message : String(err);
        if (msg.includes("ENOENT") || msg.toLowerCase().includes("no such file")) {
          setCommands([]);
          setAccess([]);
          setMcpServers([]);
        } else {
          setLoadFailed(true);
          setError(`Failed to read config/security.json: ${msg}`);
        }
      })
      .finally(() => setLoading(false));
  }, [dialogOpen]);

  const handleJsonOpenChange = (open: boolean) => {
    if (open) {
      setError(null);
      setRawJson(JSON.stringify(toConfig(commands, access, mcpServers), null, 2));
      setJsonOpen(true);
      return;
    }
    const parsed = parse(rawJson);
    if (!parsed.valid) {
      setError("Fix invalid JSON before switching back to form view.");
      return;
    }
    setError(null);
    setCommands(parsed.commands);
    setAccess(parsed.access);
    setMcpServers(parsed.mcpServers);
    setJsonOpen(false);
  };

  const save = async () => {
    setSaving(true);
    setError(null);
    setSaved(false);
    try {
      let configToSave: ReturnType<typeof toConfig>;
      if (jsonOpen) {
        // Validate syntax first so SyntaxError reports cleanly
        JSON.parse(rawJson || "[]");
        const parsed = parse(rawJson || "[]");
        if (!parsed.valid) {
          setError(
            'Security config must be an array of command names or an object with valid "allowedCommands", "allowedFileAccess", or "allowedMcpServers".',
          );
          return;
        }
        configToSave = toConfig(parsed.commands, parsed.access, parsed.mcpServers);
      } else {
        configToSave = toConfig(commands, access, mcpServers);
      }
      const unsafeGrant = configToSave.allowedFileAccess.find((g) =>
        isUnsafeOrBroadPrefix(g.pathPrefix),
      );
      if (unsafeGrant) {
        setError(
          `Refusing overly broad or unsafe file access grant ("${unsafeGrant.pathPrefix}"). Grant access to a specific non-sensitive folder instead.`,
        );
        return;
      }
      const data = JSON.stringify(configToSave, null, 2);
      await window.ipc.invoke("workspace:writeFile", { path: SECURITY_PATH, data });
      setCommands(configToSave.allowedCommands);
      setAccess(configToSave.allowedFileAccess);
      setMcpServers(configToSave.allowedMcpServers ?? []);
      setRawJson(data);
      setSaved(true);
    } catch (e) {
      setError(
        e instanceof SyntaxError
          ? "Invalid JSON syntax"
          : e instanceof Error
            ? e.message
            : "Failed to save security config",
      );
    } finally {
      setSaving(false);
    }
  };

  const effectiveCommands = React.useMemo(() => {
    if (!jsonOpen) return commands;
    const parsed = parse(rawJson);
    return parsed.valid ? parsed.commands : commands;
  }, [jsonOpen, rawJson, commands]);

  const hasWildcardCommand = effectiveCommands.some((cmd) => cmd.trim() === "*");

  if (loading) {
    return (
      <div className="flex h-full items-center justify-center text-sm text-muted-foreground">
        <Loader2 className="mr-2 size-4 animate-spin" />
        Loading…
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {hasWildcardCommand && (
        <div className="flex items-start gap-2.5 rounded-none border border-amber-500/60 bg-amber-50/70 px-3.5 py-3 text-xs leading-relaxed text-amber-950 dark:bg-amber-950/30 dark:text-amber-200">
          <AlertTriangleIcon className="mt-0.5 size-4 shrink-0 text-amber-600 dark:text-amber-400" />
          <p>
            Wildcard <code className="font-mono font-semibold">*</code> is enabled in Allowed commands.
            This disables all command approval prompts and safety checks. Remove{" "}
            <code className="font-mono font-semibold">*</code> unless you intentionally want unrestricted
            shell execution.
          </p>
        </div>
      )}
      {!jsonOpen && (
        <>
          <div className="flex items-start gap-2.5 rounded-none border bg-muted/40 px-3.5 py-3 text-xs leading-relaxed text-muted-foreground">
            <ShieldCheck className="mt-0.5 size-4 shrink-0" />
            <p>
              These rules let the assistant act without asking each time. Grant the minimum it needs
              — anything not listed here still prompts for your approval.
            </p>
          </div>
          <SettingsSection
            title="Allowed commands"
            description="Shell commands the assistant may run without asking each time."
          >
            <StringListRows
              values={commands}
              onChange={setCommands}
              placeholder="ls"
              addLabel="Add command"
              itemLabel="Allowed command"
            />
          </SettingsSection>

          <SettingsSection
            title="File access"
            description="Grant read/write access under specific path prefixes."
            action={
              <Button
                variant="outline"
                size="sm"
                className="gap-1.5"
                onClick={() => setAccess((p) => [...p, { operation: "read", pathPrefix: "" }])}
              >
                <Plus className="size-3.5" />
                Add grant
              </Button>
            }
          >
            {access.length === 0 ? (
              <p className="rounded-none border border-dashed px-3.5 py-6 text-center text-xs text-muted-foreground">
                No file-access grants.
              </p>
            ) : (
              <div className="space-y-2">
                {access.map((grant, i) => (
                  <div key={i} className="flex items-center gap-2">
                    <Select
                      value={grant.operation}
                      onValueChange={(operation) => {
                        const parsedOp = FileAccessOperationSchema.safeParse(operation);
                        if (!parsedOp.success) return;
                        setAccess((p) =>
                          p.map((g, j) => (j === i ? { ...g, operation: parsedOp.data } : g)),
                        );
                      }}
                    >
                      <SelectTrigger
                        className="h-8 w-28 shrink-0"
                        aria-label={`File access operation ${i + 1}`}
                      >
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {FILE_OPS.map((op) => (
                          <SelectItem key={op} value={op}>
                            {op}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <Input
                      value={grant.pathPrefix}
                      placeholder="/path/to/folder"
                      className="h-8 flex-1 font-mono text-xs"
                      aria-label={`File access path ${i + 1}`}
                      onChange={(e) =>
                        setAccess((p) =>
                          p.map((g, j) => (j === i ? { ...g, pathPrefix: e.target.value } : g)),
                        )
                      }
                    />
                    <Button
                      variant="ghost"
                      size="icon-sm"
                      className="shrink-0 text-muted-foreground hover:text-destructive"
                      onClick={() => setAccess((p) => p.filter((_, j) => j !== i))}
                      aria-label="Remove grant"
                    >
                      <Trash2 className="size-4" />
                    </Button>
                  </div>
                ))}
              </div>
            )}
          </SettingsSection>

          <SettingsSection
            title="Allowed MCP servers"
            description="Local stdio MCP servers pinned by exact command, arguments, and environment digest."
          >
            {mcpServers.length === 0 ? (
              <p className="rounded-none border border-dashed px-3.5 py-6 text-center text-xs text-muted-foreground">
                No permanently allowed local MCP servers.
              </p>
            ) : (
              <div className="space-y-2">
                {mcpServers.map((grant, i) => (
                  <div
                    key={`${grant.serverName}:${grant.configDigest}`}
                    className="flex items-start justify-between gap-2 rounded-none border bg-muted/30 px-3 py-2"
                  >
                    <div className="min-w-0 flex-1 space-y-0.5">
                      <p className="text-xs font-medium text-foreground">
                        {sanitizeDisplayText(grant.serverName).text}
                      </p>
                      <p className="truncate font-mono text-xs text-muted-foreground">
                        {sanitizeDisplayText(grant.command).text}{" "}
                        {grant.args?.length ? sanitizeDisplayText(JSON.stringify(grant.args)).text : ""}
                      </p>
                      <p className="font-mono text-[11px] text-muted-foreground">
                        Digest: {grant.configDigest.slice(0, 16)}…
                      </p>
                    </div>
                    <Button
                      variant="ghost"
                      size="icon-sm"
                      className="shrink-0 text-muted-foreground hover:text-destructive"
                      onClick={() => setMcpServers((p) => p.filter((_, j) => j !== i))}
                      aria-label={`Revoke MCP grant for ${grant.serverName}`}
                    >
                      <Trash2 className="size-4" />
                    </Button>
                  </div>
                ))}
              </div>
            )}
          </SettingsSection>
        </>
      )}

      {/* Raw JSON escape hatch */}
      <Collapsible open={jsonOpen} onOpenChange={handleJsonOpenChange}>
        <CollapsibleTrigger asChild>
          <button className="flex items-center gap-1.5 text-xs font-medium text-muted-foreground hover:text-foreground">
            <CodeIcon className="size-3.5" />
            {jsonOpen ? "Hide raw JSON" : "Edit as JSON"}
          </button>
        </CollapsibleTrigger>
        <CollapsibleContent className="pt-2">
          <textarea
            value={jsonOpen ? rawJson : JSON.stringify(toConfig(commands, access, mcpServers), null, 2)}
            onChange={(e) => setRawJson(e.target.value)}
            className="h-64 w-full resize-none rounded-none border bg-muted/40 p-3 font-mono text-xs focus:outline-none focus:ring-1 focus:ring-ring"
            spellCheck={false}
            aria-label="Security configuration JSON"
          />
        </CollapsibleContent>
      </Collapsible>

      <div className="flex items-center justify-between gap-2 border-t pt-3">
        <span className="text-xs">
          {error ? (
            <span className="text-destructive">{error}</span>
          ) : saved ? (
            <span className="text-green-600 dark:text-green-400">Saved</span>
          ) : null}
        </span>
        <Button size="sm" onClick={save} disabled={saving || (loadFailed && !jsonOpen)}>
          {saving ? "Saving…" : "Save"}
        </Button>
      </div>
    </div>
  );
}
