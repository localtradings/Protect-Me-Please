import { createHash } from 'node:crypto';
import type Database from 'better-sqlite3';
import { z } from 'zod';
import { findingSchema, modeSchema } from '../core/types.js';
import {
  vaultFindingEventSchema,
  vaultHistorySchema,
  vaultPatchEventSchema,
  vaultReplayEventSchema,
  vaultRunEventSchema,
  vaultRunSnapshotSchema,
  vaultLifecycleInputSchema,
  type VaultFindingEvent,
  type VaultHistory,
  type VaultPatchEvent,
  type VaultReplayEvent,
  type VaultRunEvent,
  type VaultRunSnapshot
} from './types.js';

export type StateDatabase = Database.Database;

const vaultRunRowSchema = z
  .object({
    id: z.string().min(1),
    mode: modeSchema,
    scope_hash: z.string().min(1),
    started_at: z.string().datetime(),
    completed_at: z.string().datetime(),
    report_path: z.string().min(1)
  })
  .strict();

const vaultFindingRowSchema = z
  .object({
    id: z.string().min(1),
    run_id: z.string().min(1),
    fingerprint: z.string().min(1),
    lifecycle_input: vaultLifecycleInputSchema,
    rule_id: z.string().min(1),
    finding_json: z.string().min(1),
    verification_status: z.enum(['not_run', 'passed', 'failed', 'manual_review', 'verified_fixed']),
    observed_at: z.string().datetime()
  })
  .strict();

const vaultPatchRowSchema = z
  .object({
    id: z.string().min(1),
    run_id: z.string().min(1),
    finding_fingerprint: z.string().min(1),
    pattern_id: z.string().min(1),
    rule_id: z.string().min(1),
    framework: z.string().min(1),
    file_role: z.string().min(1),
    strategy: z.string().min(1),
    change_pattern: z.string().min(1),
    outcome: z.string().min(1),
    patch_json: z.string().min(1),
    observed_at: z.string().datetime()
  })
  .strict();

const vaultReplayRowSchema = z
  .object({
    id: z.string().min(1),
    run_id: z.string().min(1),
    finding_fingerprint: z.string().min(1),
    replay_id: z.string().min(1),
    status: z.enum(['passed', 'failed', 'not_run', 'manual_review']),
    replay_json: z.string().min(1),
    observed_at: z.string().datetime()
  })
  .strict();

function sha256(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

function sortByTimestampThenId<T extends { id: string }>(items: T[], getTimestamp: (item: T) => string): T[] {
  return [...items].sort(
    (left, right) => getTimestamp(left).localeCompare(getTimestamp(right)) || left.id.localeCompare(right.id)
  );
}

function contextualRowError(table: string, rowId: string, reason: unknown): Error {
  const message = reason instanceof Error ? reason.message : String(reason);
  return new Error(`Invalid ${table} row ${rowId}: ${message}`);
}

function contextualJsonError(table: string, rowId: string, column: string, reason: unknown): Error {
  const message = reason instanceof Error ? reason.message : String(reason);
  return new Error(`Invalid ${table} ${column} for row ${rowId}: ${message}`);
}

function parseStoredJson<T>(table: string, rowId: string, column: string, raw: string, schema: z.ZodType<T>): T {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw) as unknown;
  } catch (error) {
    throw contextualJsonError(table, rowId, column, error);
  }

  try {
    return schema.parse(parsed);
  } catch (error) {
    throw contextualJsonError(table, rowId, column, error);
  }
}

function parseRun(row: unknown): VaultRunEvent {
  try {
    const parsedRow = vaultRunRowSchema.parse(row);
    return vaultRunEventSchema.parse({
      id: parsedRow.id,
      mode: parsedRow.mode,
      scopeHash: parsedRow.scope_hash,
      startedAt: parsedRow.started_at,
      completedAt: parsedRow.completed_at,
      reportPath: parsedRow.report_path
    });
  } catch (error) {
    const rowId = typeof row === 'object' && row !== null && 'id' in row ? String((row as { id?: unknown }).id ?? 'unknown') : 'unknown';
    throw contextualRowError('vault_runs', rowId, error);
  }
}

function parseFinding(row: unknown): VaultFindingEvent {
  try {
    const parsedRow = vaultFindingRowSchema.parse(row);
    const finding = parseStoredJson('vault_finding_events', parsedRow.id, 'finding_json', parsedRow.finding_json, findingSchema);
    return vaultFindingEventSchema.parse({
      id: parsedRow.id,
      runId: parsedRow.run_id,
      fingerprint: parsedRow.fingerprint,
      lifecycleInput: parsedRow.lifecycle_input,
      ruleId: parsedRow.rule_id,
      finding,
      verificationStatus: parsedRow.verification_status,
      observedAt: parsedRow.observed_at
    });
  } catch (error) {
    const rowId = typeof row === 'object' && row !== null && 'id' in row ? String((row as { id?: unknown }).id ?? 'unknown') : 'unknown';
    throw contextualRowError('vault_finding_events', rowId, error);
  }
}

function parsePatch(row: unknown): VaultPatchEvent {
  try {
    const parsedRow = vaultPatchRowSchema.parse(row);
    const patch = parseStoredJson('vault_patch_events', parsedRow.id, 'patch_json', parsedRow.patch_json, vaultPatchEventSchema);
    return vaultPatchEventSchema.parse({
      ...patch,
      id: parsedRow.id,
      runId: parsedRow.run_id,
      findingFingerprint: parsedRow.finding_fingerprint,
      patternId: parsedRow.pattern_id,
      ruleId: parsedRow.rule_id,
      framework: parsedRow.framework,
      fileRole: parsedRow.file_role,
      strategy: parsedRow.strategy,
      changePattern: parsedRow.change_pattern,
      outcome: parsedRow.outcome,
      observedAt: parsedRow.observed_at
    });
  } catch (error) {
    const rowId = typeof row === 'object' && row !== null && 'id' in row ? String((row as { id?: unknown }).id ?? 'unknown') : 'unknown';
    throw contextualRowError('vault_patch_events', rowId, error);
  }
}

function parseReplay(row: unknown): VaultReplayEvent {
  try {
    const parsedRow = vaultReplayRowSchema.parse(row);
    const replay = parseStoredJson('vault_replay_events', parsedRow.id, 'replay_json', parsedRow.replay_json, vaultReplayEventSchema);
    return vaultReplayEventSchema.parse({
      ...replay,
      id: parsedRow.id,
      runId: parsedRow.run_id,
      findingFingerprint: parsedRow.finding_fingerprint,
      replayId: parsedRow.replay_id,
      status: parsedRow.status,
      observedAt: parsedRow.observed_at
    });
  } catch (error) {
    const rowId = typeof row === 'object' && row !== null && 'id' in row ? String((row as { id?: unknown }).id ?? 'unknown') : 'unknown';
    throw contextualRowError('vault_replay_events', rowId, error);
  }
}

function findingEventId(runId: string, fingerprint: string, lifecycleInput: string): string {
  return `vault_finding_event_${sha256(`${runId}\u0000${fingerprint}\u0000${lifecycleInput}`)}`;
}

export function appendVaultSnapshot(db: StateDatabase, snapshot: VaultRunSnapshot): void {
  const parsedSnapshot = vaultRunSnapshotSchema.parse(snapshot);
  const insertRun = db.prepare(`
    INSERT OR IGNORE INTO vault_runs (
      id,
      mode,
      scope_hash,
      started_at,
      completed_at,
      report_path
    ) VALUES (?, ?, ?, ?, ?, ?)
  `);
  const insertFinding = db.prepare(`
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
  `);
  const insertPatch = db.prepare(`
    INSERT OR IGNORE INTO vault_patch_events (
      id,
      run_id,
      finding_fingerprint,
      pattern_id,
      rule_id,
      framework,
      file_role,
      strategy,
      change_pattern,
      outcome,
      patch_json,
      observed_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  const insertReplay = db.prepare(`
    INSERT OR IGNORE INTO vault_replay_events (
      id,
      run_id,
      finding_fingerprint,
      replay_id,
      status,
      replay_json,
      observed_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?)
  `);

  const transaction = db.transaction((currentSnapshot: VaultRunSnapshot) => {
    insertRun.run(
      currentSnapshot.run.id,
      currentSnapshot.run.mode,
      currentSnapshot.run.scopeHash,
      currentSnapshot.run.startedAt,
      currentSnapshot.run.completedAt,
      currentSnapshot.run.reportPath
    );

    for (const findingEntry of currentSnapshot.findings) {
      const verificationStatus =
        findingEntry.lifecycleInput === 'verified_fixed'
          ? 'verified_fixed'
          : findingEntry.finding.verificationStatus;
      insertFinding.run(
        findingEventId(currentSnapshot.run.id, findingEntry.fingerprint, findingEntry.lifecycleInput),
        currentSnapshot.run.id,
        findingEntry.fingerprint,
        findingEntry.lifecycleInput,
        findingEntry.finding.ruleId,
        JSON.stringify(findingEntry.finding),
        verificationStatus,
        currentSnapshot.run.completedAt
      );
    }

    for (const patch of currentSnapshot.patches) {
      insertPatch.run(
        patch.id,
        patch.runId,
        patch.findingFingerprint,
        patch.patternId,
        patch.ruleId,
        patch.framework,
        patch.fileRole,
        patch.strategy,
        patch.changePattern,
        patch.outcome,
        JSON.stringify(patch),
        patch.observedAt
      );
    }

    for (const replay of currentSnapshot.replays) {
      insertReplay.run(
        replay.id,
        replay.runId,
        replay.findingFingerprint,
        replay.replayId,
        replay.status,
        JSON.stringify(replay),
        replay.observedAt
      );
    }
  });

  transaction(parsedSnapshot);
}

export function readVaultHistory(db: StateDatabase): VaultHistory {
  const runs = sortByTimestampThenId(
    db
    .prepare('SELECT id, mode, scope_hash, started_at, completed_at, report_path FROM vault_runs')
    .all()
    .map(parseRun),
    (run) => run.startedAt
  );

  const findings = sortByTimestampThenId(
    db
    .prepare(
      'SELECT id, run_id, fingerprint, lifecycle_input, rule_id, finding_json, verification_status, observed_at FROM vault_finding_events'
    )
    .all()
    .map(parseFinding),
    (finding) => finding.observedAt
  );

  const patches = sortByTimestampThenId(
    db
    .prepare(
      'SELECT id, run_id, finding_fingerprint, pattern_id, rule_id, framework, file_role, strategy, change_pattern, outcome, patch_json, observed_at FROM vault_patch_events'
    )
    .all()
    .map(parsePatch),
    (patch) => patch.observedAt
  );

  const replays = sortByTimestampThenId(
    db
    .prepare(
      'SELECT id, run_id, finding_fingerprint, replay_id, status, replay_json, observed_at FROM vault_replay_events'
    )
    .all()
    .map(parseReplay),
    (replay) => replay.observedAt
  );

  return vaultHistorySchema.parse({
    runs,
    findings,
    patches,
    replays
  });
}
