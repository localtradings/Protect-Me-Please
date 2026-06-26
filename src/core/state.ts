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
