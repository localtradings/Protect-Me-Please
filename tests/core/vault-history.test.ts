import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { describe, expect, test } from 'vitest';
import { initializeStateStore, recordRun } from '../../src/core/state.js';
import { currentLifecycleByFingerprint, projectLifecycle } from '../../src/vault/history.js';
import { appendVaultSnapshot, readVaultHistory } from '../../src/vault/store.js';
import { vaultRunSnapshotSchema, type VaultRunSnapshot } from '../../src/vault/types.js';
import { makeSnapshot } from '../helpers/vault-fixtures.js';

function makeEmptySnapshot(runId: string): VaultRunSnapshot {
  const startedAt = '2026-06-06T09:59:00.000Z';
  const completedAt = '2026-06-06T10:00:00.000Z';

  return vaultRunSnapshotSchema.parse({
    run: {
      id: runId,
      mode: 'local',
      scopeHash: 'a'.repeat(64),
      startedAt,
      completedAt,
      reportPath: 'reports/vault/index.html'
    },
    findings: [],
    patches: [],
    replays: []
  });
}

describe('Vault append-only history store', () => {
  test('creates additive vault tables and preserves the existing runs table', async () => {
    const workspace = await mkdtemp(path.join(tmpdir(), 'bp-vault-history-'));
    const db = initializeStateStore(workspace);
    try {
      const names = db
        .prepare(
          `
            SELECT name
            FROM sqlite_master
            WHERE type IN ('table', 'index')
              AND name IN (
                'runs',
                'findings',
                'vault_runs',
                'vault_finding_events',
                'vault_patch_events',
                'vault_replay_events',
                'idx_vault_finding_fingerprint'
              )
            ORDER BY name
          `
        )
        .all()
        .map((row) => (row as { name: string }).name);

      expect(names).toEqual([
        'findings',
        'idx_vault_finding_fingerprint',
        'runs',
        'vault_finding_events',
        'vault_patch_events',
        'vault_replay_events',
        'vault_runs'
      ]);

      recordRun(db, { command: 'map', mode: 'local', status: 'completed' });
      expect(db.prepare('SELECT count(*) AS count FROM runs').get()).toEqual({ count: 1 });
    } finally {
      db.close();
      await rm(workspace, { recursive: true, force: true });
    }
  });

  test('appends snapshots idempotently and projects lifecycle changes in order', async () => {
    const workspace = await mkdtemp(path.join(tmpdir(), 'bp-vault-history-'));
    const db = initializeStateStore(workspace);
    try {
      appendVaultSnapshot(db, makeSnapshot('day-1', 'observed'));
      appendVaultSnapshot(db, makeSnapshot('day-2-repeat', 'observed'));
      appendVaultSnapshot(db, makeSnapshot('day-2-fixed', 'verified_fixed'));
      appendVaultSnapshot(db, makeSnapshot('day-5', 'observed'));
      appendVaultSnapshot(db, makeSnapshot('day-5', 'observed'));

      const history = readVaultHistory(db);
      expect(history.runs.map((run) => run.id)).toEqual([
        'day-1',
        'day-2-repeat',
        'day-2-fixed',
        'day-5'
      ]);
      expect(history.findings.map((finding) => finding.runId)).toEqual([
        'day-1',
        'day-2-repeat',
        'day-2-fixed',
        'day-5'
      ]);
      expect(projectLifecycle(history).map((event) => event.lifecycle)).toEqual([
        'new',
        'repeated',
        'fixed',
        'reopened'
      ]);
      expect(currentLifecycleByFingerprint(history).get('invoice-fingerprint')).toBe('reopened');
      expect(db.prepare('SELECT count(*) AS count FROM vault_runs').get()).toEqual({ count: 4 });
      expect(db.prepare('SELECT count(*) AS count FROM vault_finding_events').get()).toEqual({ count: 4 });
      expect(db.prepare('SELECT count(*) AS count FROM vault_patch_events').get()).toEqual({ count: 4 });
      expect(db.prepare('SELECT count(*) AS count FROM vault_replay_events').get()).toEqual({ count: 4 });
    } finally {
      db.close();
      await rm(workspace, { recursive: true, force: true });
    }
  });

  test('sorts history deterministically despite insertion order', async () => {
    const workspace = await mkdtemp(path.join(tmpdir(), 'bp-vault-history-'));
    const db = initializeStateStore(workspace);
    try {
      appendVaultSnapshot(db, makeSnapshot('day-5', 'observed'));
      appendVaultSnapshot(db, makeSnapshot('day-1', 'observed'));
      appendVaultSnapshot(db, makeSnapshot('day-2-fixed', 'verified_fixed'));
      appendVaultSnapshot(db, makeSnapshot('day-2-repeat', 'observed'));

      const history = readVaultHistory(db);
      expect(history.runs.map((run) => run.id)).toEqual([
        'day-1',
        'day-2-repeat',
        'day-2-fixed',
        'day-5'
      ]);
      expect(history.findings.map((finding) => finding.runId)).toEqual([
        'day-1',
        'day-2-repeat',
        'day-2-fixed',
        'day-5'
      ]);
      expect(projectLifecycle(history).map((event) => event.lifecycle)).toEqual([
        'new',
        'repeated',
        'fixed',
        'reopened'
      ]);
    } finally {
      db.close();
      await rm(workspace, { recursive: true, force: true });
    }
  });

  test('projects not_observed for an empty later run when absence is visible', async () => {
    const workspace = await mkdtemp(path.join(tmpdir(), 'bp-vault-history-'));
    const db = initializeStateStore(workspace);
    try {
      appendVaultSnapshot(db, makeSnapshot('day-1', 'observed'));
      appendVaultSnapshot(db, makeSnapshot('day-2-fixed', 'verified_fixed'));
      appendVaultSnapshot(db, makeEmptySnapshot('day-6-empty'));

      const history = readVaultHistory(db);
      expect(projectLifecycle(history).map((event) => event.lifecycle)).toEqual([
        'new',
        'fixed',
        'not_observed'
      ]);
      expect(currentLifecycleByFingerprint(history).get('invoice-fingerprint')).toBe('not_observed');
    } finally {
      db.close();
      await rm(workspace, { recursive: true, force: true });
    }
  });

  test('throws contextual errors for corrupt JSON without mutating stored rows', async () => {
    const workspace = await mkdtemp(path.join(tmpdir(), 'bp-vault-history-'));
    const db = initializeStateStore(workspace);
    try {
      appendVaultSnapshot(db, makeSnapshot('day-1', 'observed'));
      db.prepare(
        `
          INSERT OR IGNORE INTO vault_finding_events (
            id,
            run_id,
            fingerprint,
            lifecycle_input,
            rule_id,
            finding_json,
            verification_status,
            observed_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `
      ).run(
        'corrupt-finding-event',
        'day-1',
        'invoice-fingerprint',
        'observed',
        'BP-BOLA-002',
        '{not valid json',
        'not_run',
        '2026-06-01T10:00:00.000Z'
      );

      const before = db.prepare('SELECT count(*) AS count FROM vault_finding_events').get() as {
        count: number;
      };
      expect(before.count).toBe(2);

      expect(() => readVaultHistory(db)).toThrow(/vault_finding_events|corrupt-finding-event/i);

      const after = db.prepare('SELECT count(*) AS count FROM vault_finding_events').get() as {
        count: number;
      };
      expect(after.count).toBe(2);
    } finally {
      db.close();
      await rm(workspace, { recursive: true, force: true });
    }
  });
});
