import crypto from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { approvalRecordSchema, productName, type ApprovalRecord, type ScopeConfig } from './types.js';

export const stateDirectory = '.breachproof';
export const approvalFile = 'approval.json';

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(',')}]`;
  }
  const object = value as Record<string, unknown>;
  return `{${Object.keys(object)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stableStringify(object[key])}`)
    .join(',')}}`;
}

export function computeScopeHash(config: ScopeConfig): string {
  const scoped = {
    mode: config.mode,
    workspace: path.resolve(config.workspace),
    allowedPaths: [...config.allowedPaths].sort(),
    stagingTargets: [...config.stagingTargets].sort(),
    autofix: config.autofix
  };
  return crypto.createHash('sha256').update(stableStringify(scoped)).digest('hex');
}

export async function approveScope(workspace: string, config: ScopeConfig, approvedBy = 'local-operator'): Promise<ApprovalRecord> {
  const stateDir = path.join(workspace, stateDirectory);
  await mkdir(stateDir, { recursive: true });
  const approval = approvalRecordSchema.parse({
    product: productName,
    approvedAt: new Date().toISOString(),
    approvedBy,
    mode: config.mode,
    workspace: path.resolve(workspace),
    scopeHash: computeScopeHash(config),
    scopeSummary: {
      allowedPaths: config.allowedPaths,
      stagingTargets: config.stagingTargets,
      autofixEnabled: config.autofix.enabled,
      applyEnabled: config.autofix.apply
    }
  });
  await writeFile(path.join(stateDir, approvalFile), `${JSON.stringify(approval, null, 2)}\n`, 'utf8');
  return approval;
}

export async function loadApproval(workspace: string): Promise<ApprovalRecord | undefined> {
  try {
    const raw = await readFile(path.join(workspace, stateDirectory, approvalFile), 'utf8');
    return approvalRecordSchema.parse(JSON.parse(raw));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return undefined;
    }
    throw error;
  }
}

export function approvalMatchesConfig(approval: ApprovalRecord | undefined, config: ScopeConfig): boolean {
  return Boolean(approval && approval.scopeHash === computeScopeHash(config) && approval.mode === config.mode);
}

function isInside(parent: string, child: string): boolean {
  const relative = path.relative(parent, child);
  return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
}

export function isPathAllowed(workspace: string, targetPath: string, config: ScopeConfig): boolean {
  const root = path.resolve(workspace);
  const target = path.resolve(targetPath);
  if (!isInside(root, target)) {
    return false;
  }
  return config.allowedPaths.some((allowedPath) => {
    const allowedRoot = path.resolve(root, allowedPath);
    return isInside(allowedRoot, target);
  });
}

export function isUrlAllowed(rawUrl: string, config: ScopeConfig): boolean {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return false;
  }

  if (config.mode === 'local' || config.mode === 'audit' || config.mode === 'validate' || config.mode === 'fix' || config.mode === 'auto') {
    return ['localhost', '127.0.0.1', '::1'].includes(parsed.hostname);
  }

  if (config.mode === 'staging' || config.mode === 'ci') {
    return config.stagingTargets.some((target) => {
      const allowed = new URL(target);
      return parsed.origin === allowed.origin && parsed.pathname.startsWith(allowed.pathname.replace(/\/$/, ''));
    });
  }

  return false;
}
