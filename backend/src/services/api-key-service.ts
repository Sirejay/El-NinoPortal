/**
 * API key service backed by the shared SQLite database and audit log stream.
 *
 * The runtime only needs the methods exercised by the auth and controller layers;
 * the rest of the project can keep its richer migration/test-only helpers without
 * affecting the app startup path.
 */
import crypto from "node:crypto";
import { ApiKeyError } from "../errors/api-key-error";
import { db, type DbApiKey } from "../db/database";
import {
  type ApiKey,
  type ApiKeyWithPlaintext,
  type RevokedApiKey,
  type ApiKeyCreateInput,
  generateApiKey,
  hashApiKey,
  timingSafeCompare,
} from "../models/api-key";
import { auditLogService } from "./audit-log";
import { SystemClock, type Clock } from "./clock";

export type CreateApiKeyInput = ApiKeyCreateInput;

function decodeScopes(raw: string | null | undefined): string[] {
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed.filter((s): s is string => typeof s === "string") : [];
  } catch {
    return [];
  }
}

export class ApiKeyService {
  constructor(
    protected readonly store = db,
    protected readonly clock: Clock = new SystemClock(),
    private readonly audit = auditLogService,
  ) {}

  private decode(row: DbApiKey): ApiKey {
    const scopes = decodeScopes(row.scopes);
    const revoked = row.revoked !== 0;
    const expired = row.expires_at != null && Date.parse(row.expires_at) <= this.clock.now();
    const version = row.version ?? 1;
    const status: ApiKey["status"] = revoked ? "revoked" : expired ? "expired" : "active";

    return {
      id: row.id,
      prefix: row.prefix,
      scopes,
      created_by: row.created_by,
      created_at: row.created_at,
      last_used_at: row.last_used_at,
      expires_at: row.expires_at,
      revoked,
      signing_secret_hash: row.signing_secret_hash,
      prev_signing_secret_hash: row.prev_signing_secret_hash,
      prev_secret_expires_at: row.prev_secret_expires_at,
      name: row.name,
      ownerId: row.created_by,
      permissions: scopes,
      status,
      version,
      createdAt: Date.parse(row.created_at),
      revokedAt: row.revoked_at ?? null,
      revokedBy: row.revoked_by ?? null,
    };
  }

  private validateCreateInput(input: ApiKeyCreateInput): void {
    if (!input.name || !input.name.trim()) {
      throw new ApiKeyError("VALIDATION_ERROR", "API key name is required.", { action: "createApiKey" });
    }
    if (!input.created_by || !input.created_by.trim()) {
      throw new ApiKeyError("VALIDATION_ERROR", "created_by is required.", { action: "createApiKey" });
    }
    if (!Array.isArray(input.scopes)) {
      throw new ApiKeyError("VALIDATION_ERROR", "scopes must be an array.", { action: "createApiKey" });
    }
    if (input.scopes.some((scope) => typeof scope !== "string" || scope.trim().length === 0)) {
      throw new ApiKeyError("VALIDATION_ERROR", "scopes contain invalid entries.", { action: "createApiKey" });
    }
    if (input.expires_at != null) {
      const parsed = Date.parse(input.expires_at);
      if (!Number.isFinite(parsed) || parsed <= this.clock.now()) {
        throw new ApiKeyError("VALIDATION_ERROR", "expires_at must be a future ISO timestamp.", { action: "createApiKey" });
      }
    }
  }

  async createApiKey(input: ApiKeyCreateInput, ip?: string): Promise<ApiKeyWithPlaintext> {
    this.validateCreateInput(input);
    const credential = generateApiKey();
    const signingSecret = crypto.randomBytes(32).toString("base64url");
    const nowIso = new Date(this.clock.now()).toISOString();
    const row: DbApiKey = {
      id: crypto.randomUUID(),
      prefix: credential.prefix,
      name: input.name,
      key_hash: credential.hash,
      scopes: JSON.stringify(input.scopes),
      created_by: input.created_by,
      created_at: nowIso,
      last_used_at: null,
      expires_at: input.expires_at ?? null,
      revoked: 0,
      signing_secret_hash: hashApiKey(signingSecret),
      prev_signing_secret_hash: null,
      prev_secret_expires_at: null,
      version: 1,
      revoked_at: null,
      revoked_by: null,
    };

    this.store.createApiKey(row);
    await this.audit.logCreated(row.id, input.created_by, ip);

    return {
      ...this.decode(row),
      plaintext_key: credential.key,
      plaintext_signing_secret: signingSecret,
    };
  }

  async verifyApiKey(plaintext: string): Promise<ApiKey | null> {
    if (typeof plaintext !== "string" || !plaintext.startsWith("qlx_") || plaintext.length < 20) {
      return null;
    }

    const prefix = plaintext.slice(0, 15);
    const row = this.store.getApiKeyByPrefix(prefix);
    if (!row) {
      return null;
    }

    if (!timingSafeCompare(hashApiKey(plaintext), row.key_hash)) {
      return null;
    }

    const key = this.decode(row);
    return key.status === "active" ? key : null;
  }

  async getApiKeyById(id: string): Promise<ApiKey | null> {
    const row = this.store.getApiKeyById(id);
    return row ? this.decode(row) : null;
  }

  async getApiKey(id: string): Promise<ApiKey | null> {
    return this.getApiKeyById(id);
  }

  async listApiKeys(filters: { created_by?: string; revoked?: boolean } = {}): Promise<ApiKey[]> {
    return this.store.listApiKeys(filters).map((row) => this.decode(row));
  }

  async updateLastUsed(id: string, endpoint: string, ip?: string): Promise<void> {
    const row = this.store.getApiKeyById(id);
    if (!row) return;
    this.store.updateApiKey(id, {
      last_used_at: new Date(this.clock.now()).toISOString(),
    });
    await this.audit.logUsed(id, row.created_by, endpoint, ip);
  }

  async revokeApiKey(id: string, revokedBy: string, expectedVersion?: number): Promise<RevokedApiKey> {
    let changed = false;
    const result = this.store.transaction(() => {
      const existing = this.store.getApiKeyById(id);
      if (!existing) {
        throw new ApiKeyError("NOT_FOUND", "The requested API key was not found.", {
          action: "revokeApiKey",
          apiKeyId: id,
          actorId: revokedBy,
        });
      }

      const currentVersion = existing.version ?? 1;
      if (expectedVersion !== undefined && expectedVersion !== currentVersion) {
        throw new ApiKeyError("CONFLICT", "API key version changed; re-read and retry.", {
          action: "revokeApiKey",
          apiKeyId: id,
          actorId: revokedBy,
          cause: { expectedVersion, actualVersion: currentVersion },
        });
      }

      if (existing.revoked !== 0) return this.decode(existing) as RevokedApiKey;

      this.store.updateApiKey(id, {
        revoked: 1,
        version: currentVersion + 1,
        revoked_at: this.clock.now(),
        revoked_by: revokedBy,
      });

      const updated = this.store.getApiKeyById(id);
      if (!updated) {
        throw new ApiKeyError("SYSTEM_ERROR", "API key disappeared while revoking.", {
          action: "revokeApiKey",
          apiKeyId: id,
          actorId: revokedBy,
        });
      }

      changed = true;
      return this.decode(updated) as RevokedApiKey;
    });

    if (changed) await this.audit.logRevoked(id, revokedBy);
    return result;
  }

  async rotateApiKey(id: string, actor: string, ip?: string): Promise<ApiKeyWithPlaintext> {
    const existing = this.store.getApiKeyById(id);
    if (!existing) {
      throw new ApiKeyError("NOT_FOUND", "The requested API key was not found.", {
        action: "rotateApiKey",
        apiKeyId: id,
        actorId: actor,
      });
    }

    const current = this.decode(existing);
    if (current.status !== "active") {
      throw new ApiKeyError("FORBIDDEN", "API key is revoked or expired.", {
        action: "rotateApiKey",
        apiKeyId: id,
        actorId: actor,
      });
    }

    const credential = generateApiKey();
    const signingSecret = crypto.randomBytes(32).toString("base64url");
    const newRow: DbApiKey = {
      id: crypto.randomUUID(),
      prefix: credential.prefix,
      name: current.name,
      key_hash: credential.hash,
      scopes: JSON.stringify(current.scopes),
      created_by: current.created_by,
      created_at: new Date(this.clock.now()).toISOString(),
      last_used_at: null,
      expires_at: current.expires_at,
      revoked: 0,
      signing_secret_hash: hashApiKey(signingSecret),
      prev_signing_secret_hash: null,
      prev_secret_expires_at: null,
      version: 1,
      revoked_at: null,
      revoked_by: null,
    };

    this.store.createApiKey(newRow);
    this.store.updateApiKey(id, {
      revoked: 1,
      version: (existing.version ?? 1) + 1,
      revoked_at: this.clock.now(),
      revoked_by: actor,
    });

    await this.audit.logRotated(id, newRow.id, actor, ip);
    return {
      ...this.decode(newRow),
      plaintext_key: credential.key,
      plaintext_signing_secret: signingSecret,
    };
  }

  async rotateSigningSecret(id: string, actor: string, ip?: string, graceHours = 24): Promise<ApiKey & { plaintext_signing_secret: string }> {
    if (!Number.isFinite(graceHours) || graceHours < 0 || graceHours > 168) {
      throw new ApiKeyError("VALIDATION_ERROR", "Grace hours must be between 0 and 168.", { action: "rotateSigningSecret" });
    }

    const existing = this.store.getApiKeyById(id);
    if (!existing) {
      throw new ApiKeyError("NOT_FOUND", "The requested API key was not found.", {
        action: "rotateSigningSecret",
        apiKeyId: id,
        actorId: actor,
      });
    }

    const current = this.decode(existing);
    if (current.status !== "active") {
      throw new ApiKeyError("FORBIDDEN", "API key is revoked or expired.", {
        action: "rotateSigningSecret",
        apiKeyId: id,
        actorId: actor,
      });
    }

    const nextSecret = crypto.randomBytes(32).toString("base64url");
    const update = {
      signing_secret_hash: hashApiKey(nextSecret),
      prev_signing_secret_hash: existing.signing_secret_hash,
      prev_secret_expires_at: new Date(this.clock.now() + graceHours * 60 * 60 * 1000).toISOString(),
      version: (existing.version ?? 1) + 1,
    };

    this.store.updateApiKey(id, update);
    const updated = this.store.getApiKeyById(id);
    if (!updated) {
      throw new ApiKeyError("SYSTEM_ERROR", "API key disappeared while rotating the signing secret.", {
        action: "rotateSigningSecret",
        apiKeyId: id,
        actorId: actor,
      });
    }

    await this.audit.logRotated(id, id, actor, ip);
    return {
      ...this.decode(updated),
      plaintext_signing_secret: nextSecret,
    };
  }
}

export class InMemoryApiKeyService {
  private readonly keys = new Map<string, ApiKey>();

  constructor(private readonly clock: Clock = new SystemClock()) {}

  create(input: {
    id: string;
    name: string;
    ownerId: string;
    permissions?: readonly string[];
    status?: "active" | "expired";
    createdAt?: number;
  }): void {
    const now = input.createdAt ?? this.clock.now();
    const status: ApiKey["status"] = input.status ?? "active";
    const key: ApiKey = {
      id: input.id,
      prefix: `qlx_${input.id.slice(0, 8)}`,
      scopes: [...(input.permissions ?? [])],
      created_by: input.ownerId,
      created_at: new Date(now).toISOString(),
      last_used_at: null,
      expires_at: null,
      revoked: status !== "active",
      signing_secret_hash: null,
      prev_signing_secret_hash: null,
      prev_secret_expires_at: null,
      name: input.name,
      ownerId: input.ownerId,
      permissions: [...(input.permissions ?? [])],
      status,
      version: 1,
      createdAt: now,
      revokedAt: status === "active" ? null : now,
      revokedBy: status === "active" ? null : input.ownerId,
    };

    this.keys.set(input.id, key);
  }

  async getApiKey(id: string): Promise<ApiKey | null> {
    const key = this.keys.get(id);
    return key ? { ...key } : null;
  }

  async revokeApiKey(id: string, revokedBy: string, expectedVersion?: number): Promise<RevokedApiKey> {
    const existing = this.keys.get(id);
    if (!existing) {
      throw new ApiKeyError("NOT_FOUND", "The requested API key was not found.", {
        action: "revokeApiKey",
        apiKeyId: id,
        actorId: revokedBy,
      });
    }

    if (expectedVersion !== undefined && existing.version !== expectedVersion) {
      throw new ApiKeyError("CONFLICT", "API key version changed; re-read and retry.", {
        action: "revokeApiKey",
        apiKeyId: id,
        actorId: revokedBy,
        cause: { expectedVersion, actualVersion: existing.version },
      });
    }

    const updated: ApiKey = {
      ...existing,
      revoked: true,
      status: "revoked",
      version: existing.version + 1,
      revokedAt: this.clock.now(),
      revokedBy,
    };

    this.keys.set(id, updated);
    return updated as RevokedApiKey;
  }

  async verifyApiKey(plaintext: string): Promise<ApiKey | null> {
    if (!plaintext || !plaintext.startsWith("qlx_")) return null;
    for (const key of this.keys.values()) {
      if (key.prefix === plaintext.slice(0, 15) && key.status === "active") {
        return { ...key };
      }
    }
    return null;
  }

  get size(): number {
    return this.keys.size;
  }
}

export const apiKeyService = new ApiKeyService();
