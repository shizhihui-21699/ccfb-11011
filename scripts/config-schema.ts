#!/usr/bin/env node
/**
 * Generates the JSON Schema for config files, so editors validate them.
 * Run with: npm run config:schema
 */
import fs from 'node:fs';
import path from 'node:path';

const ROOT = path.resolve(import.meta.dirname, '..');

const versionFloor = {
  oneOf: [
    { type: 'string', pattern: '^v?\\d+(\\.\\d+)*$' },
    {
      type: 'object',
      additionalProperties: false,
      properties: {
        macos: { type: 'string', pattern: '^v?\\d+(\\.\\d+)*$' },
        windows: { type: 'string', pattern: '^v?\\d+(\\.\\d+)*$' },
        linux: { type: 'string', pattern: '^v?\\d+(\\.\\d+)*$' },
      },
    },
  ],
};

const configSchema = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  title: 'Zero Trust Access Proxy configuration',
  type: 'object',
  required: ['apps'],
  additionalProperties: false,
  properties: {
    host: { type: 'string', default: '127.0.0.1' },
    port: { type: 'integer', minimum: 0, maximum: 65535, default: 8443 },
    publicOrigin: { type: 'string', format: 'uri' },
    sessionTtlSeconds: { type: 'integer', minimum: 60 },
    grantTtlSeconds: { type: 'integer', minimum: 60 },
    trustProxy: { type: 'boolean', default: false },
    thresholds: {
      type: 'object',
      additionalProperties: false,
      properties: {
        postureMaxAgeSeconds: { type: 'integer', minimum: 10 },
        minOsVersion: versionFloor,
        revalidateIntervalMs: { type: 'integer', minimum: 100 },
        revokeWithinMs: { type: 'integer', minimum: 1000 },
      },
    },
    postureService: {
      type: 'object',
      additionalProperties: false,
      properties: {
        host: { type: 'string' },
        port: { type: 'integer', minimum: 0, maximum: 65535 },
      },
    },
    apps: {
      type: 'array',
      minItems: 1,
      items: {
        type: 'object',
        required: ['id', 'name', 'upstream'],
        additionalProperties: false,
        properties: {
          id: { type: 'string', pattern: '^[a-z0-9][a-z0-9-]{0,63}$' },
          name: { type: 'string', minLength: 1 },
          description: { type: 'string' },
          upstream: { type: 'string', format: 'uri', pattern: '^https?://' },
          pathHint: { type: 'string' },
        },
      },
    },
    seedUsers: {
      type: 'array',
      items: {
        type: 'object',
        required: ['username', 'displayName', 'password'],
        additionalProperties: false,
        properties: {
          id: { type: 'string' },
          username: { type: 'string', pattern: '^[a-z0-9][a-z0-9._-]{0,63}$' },
          displayName: { type: 'string' },
          password: { type: 'string', minLength: 8 },
          roles: { type: 'array', items: { enum: ['admin', 'employee'] } },
          group: { type: 'string' },
        },
      },
    },
  },
};

const policySchema = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  title: 'Zero Trust access policy',
  type: 'object',
  required: ['rules'],
  additionalProperties: false,
  properties: {
    version: { type: 'integer' },
    defaultDenyReason: { type: 'string' },
    rules: {
      type: 'array',
      items: {
        type: 'object',
        required: ['effect', 'apps'],
        additionalProperties: false,
        properties: {
          id: { type: 'string' },
          effect: { enum: ['allow', 'deny'] },
          description: { type: 'string' },
          apps: { type: 'array', minItems: 1, items: { type: 'string' } },
          users: { type: 'array', items: { type: 'string' } },
          groups: { type: 'array', items: { type: 'string' } },
          roles: { type: 'array', items: { type: 'string' } },
          deviceGroups: { type: 'array', items: { type: 'string' } },
          deviceIds: { type: 'array', items: { type: 'string' } },
          requireDiskEncrypted: { type: 'boolean' },
          requireEdrOnline: { type: 'boolean' },
          requireFirewall: { type: 'boolean' },
          osFamilies: { type: 'array', items: { enum: ['macos', 'windows', 'linux'] } },
          minOsVersion: versionFloor,
          maxPostureAgeSeconds: { type: 'integer', minimum: 1 },
          allowMissingPosture: { type: 'boolean' },
        },
      },
    },
  },
};

function write(file: string, value: unknown): void {
  const target = path.join(ROOT, file);
  fs.writeFileSync(target, `${JSON.stringify(value, null, 2)}\n`);
  console.log(`wrote ${file}`);
}

write('config/schema.json', configSchema);
write('config/policy.schema.json', policySchema);
