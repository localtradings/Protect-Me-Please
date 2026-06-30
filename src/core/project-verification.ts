import { spawn } from 'node:child_process';
import { access, mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import {
  projectVerificationSummarySchema,
  type ProjectVerificationCheck,
  type ProjectVerificationSummary
} from './types.js';
import { redactVaultText, safeSlug } from '../vault/redaction.js';

const DEFAULT_TIMEOUT_MS = 10 * 60 * 1000;
const MAX_LOG_BYTES = 1024 * 1024;

interface PlannedCheck {
  name: string;
  ecosystem: ProjectVerificationCheck['ecosystem'];
  executable: string;
  args: string[];
}

export interface RunProjectVerificationInput {
  workspace: string;
  reportsDir: string;
  timeoutMs?: number;
  env?: NodeJS.ProcessEnv;
}

async function exists(file: string): Promise<boolean> {
  try {
    await access(file);
    return true;
  } catch {
    return false;
  }
}

async function readOptional(file: string): Promise<string | undefined> {
  try {
    return await readFile(file, 'utf8');
  } catch {
    return undefined;
  }
}

async function nodeChecks(workspace: string): Promise<PlannedCheck[]> {
  const source = await readOptional(path.join(workspace, 'package.json'));
  if (!source) return [];
  let scripts: Record<string, string> = {};
  try {
    const parsed = JSON.parse(source) as { scripts?: Record<string, string> };
    scripts = parsed.scripts ?? {};
  } catch {
    return [];
  }
  const manager =
    (await exists(path.join(workspace, 'pnpm-lock.yaml'))) ? 'pnpm' :
    (await exists(path.join(workspace, 'yarn.lock'))) ? 'yarn' :
    (await exists(path.join(workspace, 'bun.lock'))) || (await exists(path.join(workspace, 'bun.lockb'))) ? 'bun' :
    'npm';
  return ['typecheck', 'lint', 'test', 'build']
    .filter((name) => Boolean(scripts[name]))
    .map((name) => ({
      name: `node:${name}`,
      ecosystem: 'node' as const,
      executable: manager,
      args: ['run', name]
    }));
}

async function pythonChecks(workspace: string): Promise<PlannedCheck[]> {
  const source = await readOptional(path.join(workspace, 'pyproject.toml'));
  if (!source) return [];
  const checks: PlannedCheck[] = [];
  if (/pytest|\[tool\.pytest/i.test(source)) checks.push({ name: 'python:pytest', ecosystem: 'python', executable: 'python3', args: ['-m', 'pytest'] });
  if (/ruff|\[tool\.ruff/i.test(source)) checks.push({ name: 'python:ruff', ecosystem: 'python', executable: 'python3', args: ['-m', 'ruff', 'check', '.', '--no-fix'] });
  if (/mypy|\[tool\.mypy/i.test(source)) checks.push({ name: 'python:mypy', ecosystem: 'python', executable: 'python3', args: ['-m', 'mypy', '.'] });
  if (/\[build-system\]/i.test(source)) checks.push({ name: 'python:build', ecosystem: 'python', executable: 'python3', args: ['-m', 'build'] });
  return checks;
}

async function plannedChecks(workspace: string): Promise<PlannedCheck[]> {
  const checks = [...await nodeChecks(workspace), ...await pythonChecks(workspace)];
  if (await exists(path.join(workspace, 'go.mod'))) {
    checks.push(
      { name: 'go:test', ecosystem: 'go', executable: 'go', args: ['test', './...'] },
      { name: 'go:vet', ecosystem: 'go', executable: 'go', args: ['vet', './...'] },
      { name: 'go:build', ecosystem: 'go', executable: 'go', args: ['build', './...'] }
    );
  }
  if (await exists(path.join(workspace, 'Cargo.toml'))) {
    checks.push(
      { name: 'rust:test', ecosystem: 'rust', executable: 'cargo', args: ['test', '--all-targets'] },
      { name: 'rust:clippy', ecosystem: 'rust', executable: 'cargo', args: ['clippy', '--all-targets', '--', '-D', 'warnings'] },
      { name: 'rust:build', ecosystem: 'rust', executable: 'cargo', args: ['build'] }
    );
  }
  return checks;
}

async function runCheck(
  check: PlannedCheck,
  input: RunProjectVerificationInput,
  logsDir: string
): Promise<ProjectVerificationCheck> {
  const startedAt = Date.now();
  const command = [check.executable, ...check.args];
  const logPath = path.join(input.reportsDir, 'verification', `${safeSlug(check.name)}.log`).split(path.sep).join('/');
  const absoluteLog = path.join(input.workspace, logPath);
  let output = '';
  let timedOut = false;

  const result = await new Promise<{ code: number | null; missing: boolean }>((resolve) => {
    const child = spawn(check.executable, check.args, {
      cwd: input.workspace,
      env: input.env ?? process.env,
      shell: false,
      stdio: ['ignore', 'pipe', 'pipe']
    });
    const append = (chunk: Buffer): void => {
      if (Buffer.byteLength(output) < MAX_LOG_BYTES) output += chunk.toString('utf8');
    };
    child.stdout.on('data', append);
    child.stderr.on('data', append);
    child.once('error', (error: NodeJS.ErrnoException) => resolve({ code: null, missing: error.code === 'ENOENT' }));
    child.once('close', (code) => resolve({ code, missing: false }));
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGTERM');
    }, input.timeoutMs ?? DEFAULT_TIMEOUT_MS);
    timer.unref();
    child.once('close', () => clearTimeout(timer));
    child.once('error', () => clearTimeout(timer));
  });

  const missingPythonModule = check.ecosystem === 'python' && /No module named|ModuleNotFoundError/i.test(output);
  const status: ProjectVerificationCheck['status'] = result.missing || missingPythonModule
    ? 'skipped'
    : timedOut
      ? 'timed_out'
      : result.code === 0
        ? 'passed'
        : 'failed';
  const summary = result.missing || missingPythonModule
    ? result.missing ? `${check.executable} is unavailable.` : `Configured Python module for ${check.name} is unavailable.`
    : timedOut
      ? `Timed out after ${input.timeoutMs ?? DEFAULT_TIMEOUT_MS} ms.`
      : `Exited with code ${result.code ?? 'unknown'}.`;
  const redacted = redactVaultText(output, input.workspace);
  await mkdir(logsDir, { recursive: true });
  await writeFile(absoluteLog, Buffer.from(redacted).subarray(0, MAX_LOG_BYTES), 'utf8');
  return {
    name: check.name,
    ecosystem: check.ecosystem,
    command,
    status,
    exitCode: result.code,
    durationMs: Date.now() - startedAt,
    logPath,
    summary
  };
}

export async function runProjectVerification(input: RunProjectVerificationInput): Promise<ProjectVerificationSummary> {
  const logsDir = path.join(input.workspace, input.reportsDir, 'verification');
  const checks: ProjectVerificationCheck[] = [];
  for (const check of await plannedChecks(input.workspace)) {
    checks.push(await runCheck(check, input, logsDir));
  }
  return projectVerificationSummarySchema.parse({
    generatedAt: new Date().toISOString(),
    checks,
    summary: {
      passed: checks.filter((check) => check.status === 'passed').length,
      failed: checks.filter((check) => check.status === 'failed').length,
      skipped: checks.filter((check) => check.status === 'skipped').length,
      timedOut: checks.filter((check) => check.status === 'timed_out').length
    }
  });
}
