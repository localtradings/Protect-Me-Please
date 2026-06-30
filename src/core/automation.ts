import { spawn } from 'node:child_process';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import {
  automationSummarySchema,
  type AutomationSummary,
  type ProjectVerificationSummary,
  type ProtectMode,
  type ScopeConfig
} from './types.js';
import { runAutonomousWorkflow, type RunAutonomousWorkflowResult } from './workflow.js';

function outputPath(reportsDir: string, name: string): string {
  return path.posix.join(reportsDir.split(path.sep).join('/'), name);
}

export function createAutomationSummary(
  result: RunAutonomousWorkflowResult,
  reportsDir: string
): AutomationSummary {
  const currentEvents = result.vaultGraph.timeline.filter((event) => event.runId === result.vaultGraph.currentRunId);
  const lifecycleCount = (status: typeof currentEvents[number]['lifecycle']): number => currentEvents.filter((event) => event.lifecycle === status).length;
  const projectChecks = result.projectVerification?.summary ?? { passed: 0, failed: 0, skipped: 0, timedOut: 0 };
  return automationSummarySchema.parse({
    generatedAt: new Date().toISOString(),
    systemMap: {
      routes: result.systemMap.routes.length,
      models: result.systemMap.dataModels.length,
      authGates: result.systemMap.authBoundaries.length,
      webhooks: result.systemMap.routes.filter((route) => /webhook/i.test(route.path)).length,
      uploads: result.systemMap.routes.filter((route) => /upload/i.test(route.path)).length,
      aiTools: result.systemMap.aiToolCalls.length
    },
    fixes: {
      autoFixed: result.fixDispositions.filter((item) => item.disposition === 'auto_fixed').length,
      reviewPatches: result.fixDispositions.filter((item) => item.disposition === 'review_patch').length,
      manualReview: result.fixDispositions.filter((item) => item.disposition === 'manual_review').length
    },
    findingVerification: {
      verifiedFixed: result.verification.items.filter((item) => item.status === 'verified_fixed').length,
      notVerified: result.verification.items.filter((item) => item.status !== 'verified_fixed').length
    },
    lifecycle: {
      new: lifecycleCount('new'), repeated: lifecycleCount('repeated'), fixed: lifecycleCount('fixed'),
      reopened: lifecycleCount('reopened'), notObserved: lifecycleCount('not_observed')
    },
    projectChecks,
    outputs: {
      markdown: outputPath(reportsDir, 'final-report.md'), html: outputPath(reportsDir, 'final-report.html'),
      json: outputPath(reportsDir, 'final-report.json'), sarif: outputPath(reportsDir, 'final-report.sarif'),
      summary: outputPath(reportsDir, 'automation-summary.json'), vault: outputPath(reportsDir, 'vault/index.html')
    },
    rescan: { status: 'skipped', reason: 'Generated-artifact-only policy made no analyzed source changes.' }
  });
}

export function automationExitCode(projectVerification?: ProjectVerificationSummary): number {
  return projectVerification && (projectVerification.summary.failed > 0 || projectVerification.summary.timedOut > 0) ? 1 : 0;
}

export interface RunAutomaticWorkflowInput {
  workspace: string;
  config: ScopeConfig;
  yes?: boolean;
  apply?: boolean;
  mode?: ProtectMode;
  verifyProject?: boolean;
  open?: boolean;
}

export interface RunAutomaticWorkflowResult {
  workflow: RunAutonomousWorkflowResult;
  summary: AutomationSummary;
  exitCode: number;
}

async function openLocalFile(target: string): Promise<void> {
  const executable = process.platform === 'darwin' ? 'open' : process.platform === 'win32' ? 'explorer.exe' : 'xdg-open';
  await new Promise<void>((resolve, reject) => {
    const child = spawn(executable, [target], { detached: true, stdio: 'ignore', shell: false });
    child.once('error', reject);
    child.once('spawn', () => { child.unref(); resolve(); });
  });
}

export async function runAutomaticWorkflow(input: RunAutomaticWorkflowInput): Promise<RunAutomaticWorkflowResult> {
  const workflow = await runAutonomousWorkflow({
    workspace: input.workspace,
    config: input.config,
    yes: input.yes,
    apply: input.apply ?? false,
    mode: input.mode,
    verifyProject: input.verifyProject ?? true
  });
  const summary = createAutomationSummary(workflow, input.config.reportsDir);
  const summaryFile = path.join(input.workspace, summary.outputs.summary);
  await mkdir(path.dirname(summaryFile), { recursive: true });
  await writeFile(summaryFile, `${JSON.stringify(summary, null, 2)}\n`, 'utf8');
  if (input.open) await openLocalFile(path.join(input.workspace, summary.outputs.vault));
  return { workflow, summary, exitCode: automationExitCode(workflow.projectVerification) };
}

export function renderAutomationSummary(summary: AutomationSummary): string {
  return `BreachProof automatic run complete
System map: ${summary.systemMap.routes} routes, ${summary.systemMap.models} models, ${summary.systemMap.authGates} auth gates, ${summary.systemMap.webhooks} webhooks, ${summary.systemMap.uploads} uploads, ${summary.systemMap.aiTools} AI tools
Fixes: ${summary.fixes.autoFixed} auto-fixed, ${summary.fixes.reviewPatches} review patches, ${summary.fixes.manualReview} manual review
Finding verification: ${summary.findingVerification.verifiedFixed} verified fixed, ${summary.findingVerification.notVerified} not verified
Lifecycle: ${summary.lifecycle.new} new, ${summary.lifecycle.repeated} repeated, ${summary.lifecycle.fixed} fixed, ${summary.lifecycle.reopened} reopened, ${summary.lifecycle.notObserved} not observed
Project checks: ${summary.projectChecks.passed} passed, ${summary.projectChecks.failed} failed, ${summary.projectChecks.skipped} skipped, ${summary.projectChecks.timedOut} timed out
Rescan: ${summary.rescan.status} - ${summary.rescan.reason}
Reports: ${summary.outputs.markdown}, ${summary.outputs.html}, ${summary.outputs.json}, ${summary.outputs.sarif}
Summary: ${summary.outputs.summary}
Vault: ${summary.outputs.vault}`;
}
