import { withFileLock } from '../knowledge/file-lock.js';
import { writeJsonAtomic } from "../filesystem/atomic_write.js";
import { WorkDir } from '../config/config.js';
import fs from 'fs/promises';
import path from 'path';
import { z } from 'zod';
import { ClientRegistrationResponse } from './types.js';

export const DEFAULT_CALLBACK_PORT = 8080;

const RESERVED_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

const StoredEntrySchema = z.record(z.string(), z.unknown());
const ClientRegistrationStorageSchema = z.record(z.string(), StoredEntrySchema);

function assertSafeProviderKey(provider: string): string {
  const trimmed = provider.trim();
  if (!trimmed || RESERVED_KEYS.has(trimmed)) {
    throw new Error(`Invalid OAuth provider key "${provider}"`);
  }
  return trimmed;
}

export interface IClientRegistrationRepo {
  getClientRegistration(provider: string): Promise<ClientRegistrationResponse | null>;
  /** Returns the port that was used when DCR-registering this provider, or DEFAULT_CALLBACK_PORT if not stored. */
  getRegisteredPort(provider: string): Promise<number>;
  saveClientRegistration(provider: string, registration: ClientRegistrationResponse, port: number): Promise<void>;
  clearClientRegistration(provider: string): Promise<void>;
}

type ClientRegistrationStorage = z.infer<typeof ClientRegistrationStorageSchema>;

export class FSClientRegistrationRepo implements IClientRegistrationRepo {
  private readonly configPath = path.join(WorkDir, 'config', 'oauth-clients.json');

  private async readConfig(): Promise<ClientRegistrationStorage> {
    try {
      const content = await fs.readFile(this.configPath, 'utf8');
      const parsed = ClientRegistrationStorageSchema.safeParse(JSON.parse(content));
      if (!parsed.success) {
        return Object.create(null) as ClientRegistrationStorage;
      }
      const safe: ClientRegistrationStorage = Object.create(null) as ClientRegistrationStorage;
      for (const [key, value] of Object.entries(parsed.data)) {
        if (!RESERVED_KEYS.has(key)) {
          safe[key] = value;
        }
      }
      return safe;
    } catch {
      return Object.create(null) as ClientRegistrationStorage;
    }
  }

  private async writeConfig(config: ClientRegistrationStorage): Promise<void> {
    // Atomic, like the sibling oauth.json repo already is — these are the
    // dynamically-registered client credentials.
    await writeJsonAtomic(this.configPath, config, 2, 0o600);
  }

  async getClientRegistration(provider: string): Promise<ClientRegistrationResponse | null> {
    const key = assertSafeProviderKey(provider);
    const config = await this.readConfig();
    const entry = Object.prototype.hasOwnProperty.call(config, key) ? config[key] : undefined;
    if (!entry) {
      return null;
    }

    // Validate registration structure (Zod strips unknown fields like _registeredPort)
    try {
      return ClientRegistrationResponse.parse(entry);
    } catch {
      // Invalid registration, remove it
      await this.clearClientRegistration(key);
      return null;
    }
  }

  async getRegisteredPort(provider: string): Promise<number> {
    const key = assertSafeProviderKey(provider);
    const config = await this.readConfig();
    const entry = Object.prototype.hasOwnProperty.call(config, key) ? config[key] : undefined;
    const port = entry?._registeredPort;
    return typeof port === 'number' && Number.isInteger(port) && port > 0
      ? port
      : DEFAULT_CALLBACK_PORT;
  }

  // Locked, like the sibling oauth.json repo: two OAuth flows can register
  // concurrently, and each of these rewrites the whole provider map from a
  // value it read first — so one provider's registration was lost.
  async saveClientRegistration(provider: string, registration: ClientRegistrationResponse, port: number): Promise<void> {
    const key = assertSafeProviderKey(provider);
    return withFileLock(this.configPath, async () => {
      const config = await this.readConfig();
      config[key] = { ...registration, _registeredPort: port };
      await this.writeConfig(config);
    });
  }

  async clearClientRegistration(provider: string): Promise<void> {
    const key = assertSafeProviderKey(provider);
    return withFileLock(this.configPath, async () => {
      const config = await this.readConfig();
      delete config[key];
      await this.writeConfig(config);
    });
  }
}

