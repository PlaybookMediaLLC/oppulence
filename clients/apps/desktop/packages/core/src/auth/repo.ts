import { WorkDir } from "../config/config.js";
import fs from "fs/promises";
import path from "path";
import { withFileLock } from "../knowledge/file-lock.js";
import { writeJsonAtomic } from "../filesystem/atomic_write.js";
import { OAuthTokens } from "./types.js";
import z from "zod";
import {
  LEGACY_PRODUCT_PROVIDER_ID,
  PRODUCT_PROVIDER_ID,
  isProductProvider,
} from "@x/shared/branding";

const RESERVED_PROVIDER_KEYS = new Set(["__proto__", "constructor", "prototype"]);

function assertSafeOAuthProviderKey(provider: string): void {
  if (!provider || RESERVED_PROVIDER_KEYS.has(provider)) {
    throw new Error(`Invalid OAuth provider key: ${provider}`);
  }
}

const ProviderConnectionSchema = z.object({
  tokens: OAuthTokens.nullable().optional(),
  clientId: z.string().nullable().optional(),
  clientSecret: z.string().nullable().optional(),
  /**
   * `byok` (default for absent) — user provides their own client_id+secret;
   * tokens stored locally; refresh handled locally via openid-client.
   * `solomon` — signed-in user; client_id+secret never on the desktop;
   * tokens stored locally but refresh goes through the api.
   */
  mode: z.enum(["byok", PRODUCT_PROVIDER_ID, LEGACY_PRODUCT_PROVIDER_ID]).optional(),
  error: z.string().nullable().optional(),
});

const OAuthConfigSchema = z.object({
  version: z.number().optional(),
  providers: z.record(z.string(), ProviderConnectionSchema),
});

const ClientFacingConfigSchema = z.record(
  z.string(),
  z.object({
    connected: z.boolean(),
    error: z.string().nullable().optional(),
    clientId: z.string().nullable().optional(),
  }),
);

const LegacyOauthConfigSchema = z.record(z.string(), OAuthTokens);

function createDefaultConfig(): z.infer<typeof OAuthConfigSchema> {
  return {
    version: 2,
    providers: Object.create(null) as Record<string, ProviderConnection>,
  };
}

export function isManagedAuthMode(mode: string | null | undefined): boolean {
  return mode === PRODUCT_PROVIDER_ID || mode === LEGACY_PRODUCT_PROVIDER_ID;
}

export type ProviderConnection = z.infer<typeof ProviderConnectionSchema>;

export interface IOAuthRepo {
  read(provider: string): Promise<ProviderConnection>;
  upsert(provider: string, connection: Partial<ProviderConnection>): Promise<void>;
  delete(provider: string): Promise<void>;
  getClientFacingConfig(): Promise<z.infer<typeof ClientFacingConfigSchema>>;
  /**
   * Atomically merge `connection` into the provider entry, but only if the
   * stored refresh_token still equals `expectedRefreshToken` (null = no token).
   * Returns whether the write happened and the entry now on disk — refresh
   * flows use this so a racing writer's rotated token is never clobbered.
   */
  compareAndSwapTokens(
    provider: string,
    expectedRefreshToken: string | null,
    connection: Partial<ProviderConnection>,
  ): Promise<{ written: boolean; current: ProviderConnection }>;
}

export class FSOAuthRepo implements IOAuthRepo {
  private readonly configPath = path.join(WorkDir, "config", "oauth.json");

  private normalizeConfig(payload: unknown): {
    config: z.infer<typeof OAuthConfigSchema>;
    migrated: boolean;
  } {
    // check if payload conforms to updated schema
    const result = OAuthConfigSchema.safeParse(payload);
    if (result.success) {
      const safeProviders: Record<string, ProviderConnection> = Object.create(null) as Record<
        string,
        ProviderConnection
      >;
      for (const [provider, conn] of Object.entries(result.data.providers)) {
        if (!RESERVED_PROVIDER_KEYS.has(provider)) {
          safeProviders[provider] = conn;
        }
      }
      return this.migrateProductProvider(
        { version: result.data.version, providers: safeProviders },
        false,
      );
    }

    // otherwise attempt to parse as legacy schema
    const legacyConfig = LegacyOauthConfigSchema.parse(payload);
    const updatedConfig = createDefaultConfig();
    for (const [provider, tokens] of Object.entries(legacyConfig)) {
      if (!RESERVED_PROVIDER_KEYS.has(provider)) {
        updatedConfig.providers[provider] = {
          tokens,
        };
      }
    }
    return this.migrateProductProvider(updatedConfig, true);
  }

  private migrateProductProvider(
    config: z.infer<typeof OAuthConfigSchema>,
    migrated: boolean,
  ): { config: z.infer<typeof OAuthConfigSchema>; migrated: boolean } {
    const legacy = config.providers[LEGACY_PRODUCT_PROVIDER_ID];
    if (legacy && !config.providers[PRODUCT_PROVIDER_ID]) {
      config.providers[PRODUCT_PROVIDER_ID] = legacy;
      migrated = true;
    }
    return { config, migrated };
  }

  private async readConfig(
    allowMigrationWrite = false,
  ): Promise<z.infer<typeof OAuthConfigSchema>> {
    try {
      const content = await fs.readFile(this.configPath, "utf8");
      const parsed = JSON.parse(content);
      const { config, migrated } = this.normalizeConfig(parsed);
      if (migrated && allowMigrationWrite) {
        await this.writeConfig(config);
      }
      return config;
    } catch {
      return createDefaultConfig();
    }
  }

  private async writeConfig(config: z.infer<typeof OAuthConfigSchema>): Promise<void> {
    // Crash-atomic: a write interrupted mid-flight must never leave a torn
    // oauth.json (it holds the only copy of rotating refresh tokens).
    await fs.mkdir(path.dirname(this.configPath), { recursive: true, mode: 0o700 });
    await writeJsonAtomic(this.configPath, config, 2, 0o600);
  }

  async read(provider: string): Promise<ProviderConnection> {
    assertSafeOAuthProviderKey(provider);
    const config = await this.readConfig();
    if (isProductProvider(provider)) {
      return (
        config.providers[PRODUCT_PROVIDER_ID] ?? config.providers[LEGACY_PRODUCT_PROVIDER_ID] ?? {}
      );
    }
    return config.providers[provider] ?? {};
  }

  // NOTE: withFileLock is a non-reentrant promise queue — never call a locked
  // method from inside another locked section on the same path. readConfig
  // stays lock-free (its rare migration write is idempotent and every locked
  // writer re-derives the migrated shape from disk before writing).
  async upsert(provider: string, connection: Partial<ProviderConnection>): Promise<void> {
    assertSafeOAuthProviderKey(provider);
    await withFileLock(this.configPath, async () => {
      const config = await this.readConfig(true);
      const providerKey = isProductProvider(provider) ? PRODUCT_PROVIDER_ID : provider;
      config.providers[providerKey] = { ...(config.providers[providerKey] ?? {}), ...connection };
      await this.writeConfig(config);
    });
  }

  async delete(provider: string): Promise<void> {
    assertSafeOAuthProviderKey(provider);
    await withFileLock(this.configPath, async () => {
      const config = await this.readConfig(true);
      if (isProductProvider(provider)) {
        delete config.providers[PRODUCT_PROVIDER_ID];
        delete config.providers[LEGACY_PRODUCT_PROVIDER_ID];
        await this.writeConfig(config);
        return;
      }
      delete config.providers[provider];
      await this.writeConfig(config);
    });
  }

  async compareAndSwapTokens(
    provider: string,
    expectedRefreshToken: string | null,
    connection: Partial<ProviderConnection>,
  ): Promise<{ written: boolean; current: ProviderConnection }> {
    assertSafeOAuthProviderKey(provider);
    return withFileLock(this.configPath, async () => {
      const config = await this.readConfig(true);
      const providerKey = isProductProvider(provider) ? PRODUCT_PROVIDER_ID : provider;
      const existing =
        config.providers[providerKey] ??
        (isProductProvider(provider) ? config.providers[LEGACY_PRODUCT_PROVIDER_ID] : undefined) ??
        {};
      const storedRt = existing.tokens?.refresh_token ?? null;
      if (storedRt !== expectedRefreshToken) {
        return { written: false, current: existing };
      }
      const merged = { ...existing, ...connection };
      config.providers[providerKey] = merged;
      await this.writeConfig(config);
      return { written: true, current: merged };
    });
  }

  async getClientFacingConfig(): Promise<z.infer<typeof ClientFacingConfigSchema>> {
    const config = await this.readConfig();
    const clientFacingConfig: z.infer<typeof ClientFacingConfigSchema> = {};
    for (const [provider, providerConfig] of Object.entries(config.providers)) {
      clientFacingConfig[provider] = {
        connected: !!providerConfig.tokens,
        error: providerConfig.error,
        clientId: providerConfig.clientId ?? null,
      };
    }
    const productState =
      clientFacingConfig[PRODUCT_PROVIDER_ID] ?? clientFacingConfig[LEGACY_PRODUCT_PROVIDER_ID];
    if (productState) {
      clientFacingConfig[PRODUCT_PROVIDER_ID] = productState;
      clientFacingConfig[LEGACY_PRODUCT_PROVIDER_ID] = productState;
    }
    return ClientFacingConfigSchema.parse(clientFacingConfig);
  }
}
