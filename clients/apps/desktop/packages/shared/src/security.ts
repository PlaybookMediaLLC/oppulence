import z from "zod";

export const FileAccessOperationSchema = z.enum(["read", "list", "search", "write", "delete"]);
export type FileAccessOperation = z.infer<typeof FileAccessOperationSchema>;

export const FileAccessGrantSchema = z.object({
  operation: FileAccessOperationSchema,
  pathPrefix: z.string().min(1),
});
export type FileAccessGrant = z.infer<typeof FileAccessGrantSchema>;

export const McpServerGrantSchema = z.object({
  serverName: z.string().min(1),
  configDigest: z.string().min(1),
  command: z.string().min(1),
  args: z.array(z.string()).optional(),
});
export type McpServerGrant = z.infer<typeof McpServerGrantSchema>;

export const ParsedSecurityConfigSchema = z.object({
  allowedCommands: z.array(z.string()),
  allowedFileAccess: z.array(FileAccessGrantSchema),
  allowedMcpServers: z.array(McpServerGrantSchema),
});
export type ParsedSecurityConfig = z.infer<typeof ParsedSecurityConfigSchema>;

export const SecurityConfigFileSchema = z.object({
  allowedCommands: z.array(z.string()).optional(),
  allowedFileAccess: z.array(FileAccessGrantSchema).optional(),
  allowedMcpServers: z.array(McpServerGrantSchema).optional(),
});
export type SecurityConfigFile = z.infer<typeof SecurityConfigFileSchema>;
