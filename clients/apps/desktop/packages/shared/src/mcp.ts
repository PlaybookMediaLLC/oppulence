import z from "zod";

const FORBIDDEN_MCP_SERVER_NAMES = new Set(["__proto__", "constructor", "prototype"]);

export const McpServerName = z
    .string()
    .min(1, "Server name is required")
    .refine((name) => name.trim() === name && name.trim().length > 0, {
        message: "Server name must not be empty or have leading/trailing whitespace",
    })
    .refine((name) => !FORBIDDEN_MCP_SERVER_NAMES.has(name), {
        message: "Server name uses a reserved identifier",
    });

export const StdioMcpServerConfig = z
    .object({
        type: z.literal("stdio").optional(),
        command: z.string().min(1, "Command is required"),
        args: z.array(z.string()).optional(),
        env: z.record(z.string(), z.string()).optional(),
    })
    .strict();

export const HttpMcpServerConfig = z
    .object({
        type: z.literal("http").optional(),
        url: z
            .string()
            .url("URL must be a valid http(s) URL")
            .refine((raw) => {
                try {
                    const parsed = new URL(raw);
                    return parsed.protocol === "https:" || parsed.protocol === "http:";
                } catch {
                    return false;
                }
            }, { message: "MCP server URL must use http:// or https://" }),
        headers: z.record(z.string(), z.string()).optional(),
        /** Stable broker connection identity, when the MCP credential issuer provides one. */
        connectionId: z.string().optional(),
    })
    .strict();

export const McpServerDefinition = z.union([StdioMcpServerConfig, HttpMcpServerConfig]);

export const McpServerConfig = z.object({
    mcpServers: z.record(McpServerName, McpServerDefinition),
});

export const connectionState = z.enum(["disconnected", "connected", "error"]);

export const McpServerList = z.object({
    mcpServers: z.record(McpServerName, z.object({
        config: McpServerDefinition,
        state: connectionState,
        error: z.string().nullable(),
    })),
});

export const Tool = z.object({
    name: z.string(),
    description: z.string().optional(),
    inputSchema: z.object({
        type: z.literal("object"),
        properties: z.record(z.string(), z.any()).optional(),
        required: z.array(z.string()).optional(),
    }),
    outputSchema: z.object({
        type: z.literal("object"),
        properties: z.record(z.string(), z.any()).optional(),
        required: z.array(z.string()).optional(),
    }).optional(),
});

export const ListToolsResponse = z.object({
    tools: z.array(Tool),
    nextCursor: z.string().optional(),
});
