import { mkdirSync } from 'node:fs';
import path from 'node:path';
import Database from 'better-sqlite3';
import type { ProtectMode } from './types.js';

export type StateDatabase = Database.Database;

export function initializeStateStore(workspace: string): StateDatabase {
  const stateDir = path.join(workspace, '.breachproof');
  mkdirSync(stateDir, { recursive: true });
  const db = new Database(path.join(stateDir, 'state.sqlite'));
  db.pragma('journal_mode = WAL');
  db.exec(`
    CREATE TABLE IF NOT EXISTS runs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      command TEXT NOT NULL,
      mode TEXT NOT NULL,
      status TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS findings (
      id TEXT PRIMARY KEY,
      rule_id TEXT NOT NULL,
      severity TEXT NOT NULL,
      status TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS vault_runs (
      id TEXT PRIMARY KEY,
      mode TEXT NOT NULL,
      scope_hash TEXT NOT NULL,
      started_at TEXT NOT NULL,
      completed_at TEXT NOT NULL,
      report_path TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS vault_finding_events (
      id TEXT PRIMARY KEY,
      run_id TEXT NOT NULL,
      fingerprint TEXT NOT NULL,
      lifecycle_input TEXT NOT NULL,
      rule_id TEXT NOT NULL,
      finding_json TEXT NOT NULL,
      verification_status TEXT NOT NULL,
      observed_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_vault_finding_fingerprint
      ON vault_finding_events(fingerprint, observed_at);
    CREATE TABLE IF NOT EXISTS vault_patch_events (
      id TEXT PRIMARY KEY,
      run_id TEXT NOT NULL,
      finding_fingerprint TEXT NOT NULL,
      pattern_id TEXT NOT NULL,
      rule_id TEXT NOT NULL,
      framework TEXT NOT NULL,
      file_role TEXT NOT NULL,
      strategy TEXT NOT NULL,
      change_pattern TEXT NOT NULL,
      outcome TEXT NOT NULL,
      patch_json TEXT NOT NULL,
      observed_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS vault_replay_events (
      id TEXT PRIMARY KEY,
      run_id TEXT NOT NULL,
      finding_fingerprint TEXT NOT NULL,
      replay_id TEXT NOT NULL,
      status TEXT NOT NULL,
      replay_json TEXT NOT NULL,
      observed_at TEXT NOT NULL
    );
  `);
  return db;
}

export function recordRun(db: StateDatabase, run: { command: string; mode: ProtectMode; status: string }): void {
  db.prepare('INSERT INTO runs (command, mode, status, created_at) VALUES (?, ?, ?, ?)').run(
    run.command,
    run.mode,
    run.status,
    new Date().toISOString()
  );
}
