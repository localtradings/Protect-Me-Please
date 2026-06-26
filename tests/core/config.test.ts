import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { describe, expect, test } from 'vitest';
import { createDefaultScopeConfig, loadScopeConfig, scopeConfigFile, writeScopeConfig } from '../../src/core/config.js';
import { approveScope, isPathAllowed, isUrlAllowed } from '../../src/core/scope.js';
import { appendAuditEvent, redactSensitiveText } from '../../src/core/audit.js';
import { initializeStateStore, recordRun } from '../../src/core/state.js';

async function tempWorkspace(): Promise<string> {
  return mkdtemp(path.join(tmpdir(), 'pmp-config-'));
}

describe('scope config and approval', () => {
  test('writes and loads the default local scope config', async () => {
    const workspace = await tempWorkspace();
    try {
      const config = createDefaultScopeConfig(workspace);
      await writeScopeConfig(workspace, config);

      const loaded = await loadScopeConfig(workspace);

      expect(loaded.mode).toBe('local');
      expect(loaded.workspace).toBe(workspace);
      expect(loaded.allowedPaths).toContain('.');
      expect(scopeConfigFile).toBe('breachproof.scope.yml');
      expect(loaded.product).toBe('BreachProof');
      expect(loaded.stateDir).toBe('.breachproof');
      expect(loaded.autofix.enabled).toBe(false);
      expect(loaded.autofix.apply).toBe(false);
      expect(loaded.ci.failOnSeverity).toBe('critical');
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  });

  test('persists one-time approval with a stable scope hash', async () => {
    const workspace = await tempWorkspace();
    try {
      const config = createDefaultScopeConfig(workspace);
      const approval = await approveScope(workspace, config, 'test-operator');

      expect(approval.product).toBe('BreachProof');
      expect(approval.mode).toBe('local');
      expect(approval.scopeHash).toHaveLength(64);
      expect(approval.approvedBy).toBe('test-operator');
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  });

  test('enforces local path and staging URL scope boundaries', async () => {
    const workspace = await tempWorkspace();
    try {
      const config = {
        ...createDefaultScopeConfig(workspace),
        mode: 'staging' as const,
        stagingTargets: ['https://staging.example.test'],
        allowedPaths: ['src', 'package.json']
      };

      expect(isPathAllowed(workspace, path.join(workspace, 'src/index.ts'), config)).toBe(true);
      expect(isPathAllowed(workspace, path.join(workspace, '..', 'outside.txt'), config)).toBe(false);
      expect(isUrlAllowed('https://staging.example.test/api/health', config)).toBe(true);
      expect(isUrlAllowed('https://example.com/api/health', config)).toBe(false);
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  });
});

describe('audit and local state', () => {
  test('redacts sensitive values in audit text', () => {
    const redacted = redactSensitiveText('token=abc123 SECRET_KEY=super-secret sk-live-1234567890abcdef');

    expect(redacted).not.toContain('super-secret');
    expect(redacted).not.toContain('sk-live-1234567890abcdef');
    expect(redacted).toContain('[REDACTED]');
  });

  test('initializes SQLite state and records a run event', async () => {
    const workspace = await tempWorkspace();
    try {
      const db = initializeStateStore(workspace);
      recordRun(db, { command: 'map', mode: 'local', status: 'completed' });
      db.close();

      const event = await appendAuditEvent(workspace, {
        action: 'map',
        actor: 'cli',
        mode: 'local',
        status: 'completed',
        message: 'Mapped local workspace with token=abc123'
      });

      expect(event.message).toContain('[REDACTED]');
      expect(event.status).toBe('completed');
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  });
});
