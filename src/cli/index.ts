#!/usr/bin/env node
import { spawn } from 'node:child_process';
import { access, mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { createInterface } from 'node:readline/promises';
import { Command } from 'commander';
import { buildAttackGraph } from '../agents/attack-graph.js';
import { createEvidenceBundle, createValidationPlan } from '../agents/attack-planner.js';
import { runAiLab, renderAiLabMarkdown } from '../agents/ai-lab.js';
import { analyzeBola } from '../agents/bola.js';
import { generatePatchArtifacts } from '../agents/fix-agent.js';
import { generatePatchTournament } from '../agents/patch-tournament.js';
import { buildReachabilityGraph } from '../agents/reachability.js';
import { mapRepository } from '../agents/repo-mapper.js';
import { validateSystemMap } from '../agents/safe-validation.js';
import { runVibeAudit, renderVibeAuditMarkdown } from '../agents/vibe-audit.js';
import { createVerification } from '../agents/verification-agent.js';
import { buildLocalVulnerabilityCorpus, importVulnerabilityCorpusFromFiles, matchRelevantVulnerabilities, summarizeVulnerabilityCorpus } from '../agents/vulnerability-corpus.js';
import { appendAuditEvent } from '../core/audit.js';
import { createDefaultScopeConfig, loadScopeConfig, scopeConfigFile, writeScopeConfig } from '../core/config.js';
import { approveScope, approvalMatchesConfig, loadApproval } from '../core/scope.js';
import { initializeStateStore, recordRun } from '../core/state.js';
import { type Finding, type ProtectMode, type ScopeConfig, type SystemMap } from '../core/types.js';
import { runAutonomousWorkflow } from '../core/workflow.js';
import { renderAutomationSummary, runAutomaticWorkflow } from '../core/automation.js';
import { replayFindingEvidence } from '../proof/evidence.js';
import { evaluateInvariants, writeDefaultInvariants } from '../proof/invariants.js';
import { composeLocalCyberRange } from '../proof/range.js';
import { renderHtmlReport } from '../reporting/html-report.js';
import { createReportModel, renderJsonReport, renderMarkdownReport, renderSarifReport } from '../reporting/report-generator.js';
import { exportCodexSkill } from '../skills/exporter.js';
import { projectLifecycle } from '../vault/history.js';
import { rebuildVaultFromReports } from '../vault/report.js';
import { readVaultHistory } from '../vault/store.js';

interface RuntimeContext {
  workspace: string;
  config: ScopeConfig;
}

async function ensureDirectories(workspace: string, config: ScopeConfig): Promise<void> {
  await mkdir(path.join(workspace, config.reportsDir), { recursive: true });
  await mkdir(path.join(workspace, config.stateDir), { recursive: true });
}

async function loadContext(options: { scope?: string; mode?: ProtectMode; apply?: boolean } = {}): Promise<RuntimeContext> {
  const workspace = process.cwd();
  const loaded = await loadScopeConfig(workspace, options.scope);
  const config = {
    ...loaded,
    mode: options.mode ?? loaded.mode,
    autofix: {
      ...loaded.autofix,
      apply: options.apply ?? loaded.autofix.apply
    }
  };
  await ensureDirectories(workspace, config);
  return { workspace, config };
}

async function writeJson(file: string, value: unknown): Promise<void> {
  await mkdir(path.dirname(file), { recursive: true });
  await writeFile(file, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

async function writeText(file: string, value: string): Promise<void> {
  await mkdir(path.dirname(file), { recursive: true });
  await writeFile(file, value, 'utf8');
}

async function runMap(context: RuntimeContext): Promise<SystemMap> {
  const systemMap = await mapRepository(context.workspace);
  await writeJson(path.join(context.workspace, context.config.reportsDir, 'system-map.json'), systemMap);
  await appendAuditEvent(context.workspace, {
    action: 'map',
    actor: 'cli',
    mode: context.config.mode,
    status: 'completed',
    message: `System map generated for ${context.workspace}`
  });
  return systemMap;
}

function dedupeFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  const result: Finding[] = [];
  for (const finding of findings) {
    if (seen.has(finding.id)) continue;
    seen.add(finding.id);
    result.push(finding);
  }
  return result;
}

async function buildAnalysis(context: RuntimeContext) {
  const systemMap = await runMap(context);
  const reachabilityGraph = await buildReachabilityGraph(context.workspace, systemMap);
  const localCorpus = buildLocalVulnerabilityCorpus();
  const attackGraph = buildAttackGraph(systemMap, localCorpus, reachabilityGraph);
  const bolaAnalysis = await analyzeBola(context.workspace, systemMap, reachabilityGraph);
  const findings = dedupeFindings([...validateSystemMap(systemMap, attackGraph, localCorpus, reachabilityGraph), ...bolaAnalysis.findings]);
  const validationPlan = createValidationPlan(findings, reachabilityGraph);
  const evidence = createEvidenceBundle(findings);
  const corpusSummary = summarizeVulnerabilityCorpus(localCorpus, {
    matchedComponents: matchRelevantVulnerabilities(systemMap, localCorpus).length,
    possiblyReachableIssues: findings.length,
    safelyValidatedIssues: findings.filter((finding) => finding.status === 'validated').length,
    manualReviewIssues: findings.filter((finding) => finding.status === 'manual_review').length
  });
  return { systemMap, reachabilityGraph, localCorpus, attackGraph, bolaAnalysis, findings, validationPlan, evidence, corpusSummary };
}

function configureCommonOptions(command: Command): Command {
  return command.option('--scope <file>', 'scope config file', scopeConfigFile).option('--mode <mode>', 'execution mode');
}

async function authorizeAutomaticRun(context: RuntimeContext, yes = false): Promise<boolean> {
  if (approvalMatchesConfig(await loadApproval(context.workspace), context.config)) return false;
  if (yes) return true;
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    throw new Error('Scope is not approved. Rerun with --yes after confirming you own or are authorized to test this workspace.');
  }
  const terminal = createInterface({ input: process.stdin, output: process.stdout });
  try {
    const answer = await terminal.question('Do you own or have explicit authorization to test this workspace? [y/N] ');
    if (!/^(y|yes)$/i.test(answer.trim())) throw new Error('Authorization declined. No BreachProof run was started.');
    return true;
  } finally {
    terminal.close();
  }
}

const program = new Command();

program
  .name('breachproof')
  .description('Local autonomous breach-path proof and fix verification for authorized repositories.')
  .version('0.3.0');

configureCommonOptions(
  program.command('init').description('Create scope config and one-time project approval.').option('--yes', 'confirm the one-time authorized scope gate')
).action(async (options: { yes?: boolean; scope?: string; mode?: ProtectMode }) => {
  const workspace = process.cwd();
  const config = { ...createDefaultScopeConfig(workspace), mode: options.mode ?? 'local' };
  await writeScopeConfig(workspace, config);
  await ensureDirectories(workspace, config);
  if (!options.yes) {
    console.log('Review the authorization scope, then rerun with --yes to confirm you own or are authorized to test this workspace.');
    return;
  }
  await approveScope(workspace, config);
  const db = initializeStateStore(workspace);
  recordRun(db, { command: 'init', mode: config.mode, status: 'completed' });
  db.close();
  await appendAuditEvent(workspace, {
    action: 'init',
    actor: 'cli',
    mode: config.mode,
    status: 'completed',
    message: 'Scope approved and local state initialized'
  });
  console.log('Scope approved for BreachProof.');
});

configureCommonOptions(
  program
    .command('run', { isDefault: true })
    .description('Run the autonomous proof, fix-artifact, verification, and report workflow.')
    .option('--auto', 'run map, corpus, reachability, validate, fix artifacts, verify, and reports')
    .option('--yes', 'approve scope if missing')
    .option('--apply', 'explicitly allow source changes where implemented')
    .option('--open', 'open the generated local Vault dashboard')
    .option('--no-verify', 'skip detected project build, lint, and test checks')
).action(async (options: { auto?: boolean; yes?: boolean; apply?: boolean; open?: boolean; verify?: boolean; scope?: string; mode?: ProtectMode }) => {
  const context = await loadContext({ scope: options.scope, mode: options.mode ?? 'auto', apply: options.apply });
  const approved = await authorizeAutomaticRun(context, options.yes);
  const result = await runAutomaticWorkflow({
    workspace: context.workspace,
    config: context.config,
    yes: approved,
    apply: options.apply ?? false,
    mode: context.config.mode,
    verifyProject: options.verify !== false,
    open: options.open
  });
  console.log(renderAutomationSummary(result.summary));
  if (result.exitCode !== 0) process.exitCode = result.exitCode;
});

const proof = program.command('proof').description('Proof Mode commands for replayable local evidence.');
configureCommonOptions(
  proof
    .command('run')
    .description('Run Proof Mode and generate replayable evidence artifacts.')
    .option('--yes', 'approve scope if missing')
    .option('--apply', 'explicitly allow source changes where implemented')
).action(async (options: { yes?: boolean; apply?: boolean; scope?: string; mode?: ProtectMode }) => {
  const context = await loadContext({ scope: options.scope, mode: options.mode ?? 'auto', apply: options.apply });
  const result = await runAutonomousWorkflow({
    workspace: context.workspace,
    config: context.config,
    yes: options.yes,
    apply: options.apply ?? false,
    mode: context.config.mode
  });
  console.log(`Proof Mode completed with ${result.findingsCount} findings. Replay evidence is in ${context.config.reportsDir}/evidence.`);
});

configureCommonOptions(proof.command('replay').description('Validate and explain replay evidence for a finding.').argument('<findingId>', 'finding id')).action(
  async (findingId: string, options: { scope?: string; mode?: ProtectMode }) => {
    const context = await loadContext({ scope: options.scope, mode: options.mode ?? 'validate' });
    const replay = await replayFindingEvidence(context.workspace, context.config.reportsDir, findingId);
    if (!replay.valid) {
      console.log(`Replay evidence for ${findingId} is incomplete. Missing: ${replay.missingFiles.join(', ')}`);
      return;
    }
    console.log(`Replay evidence for ${findingId} is valid in ${replay.directory}.`);
    console.log(replay.steps.join('\n'));
  }
);

const range = program.command('range').description('Local cyber range commands.');
configureCommonOptions(range.command('init').description('Create local cyber range Docker and fake seed artifacts.')).action(
  async (options: { scope?: string; mode?: ProtectMode }) => {
    const context = await loadContext({ scope: options.scope, mode: options.mode ?? 'local' });
    const systemMap = await runMap(context);
    const summary = await composeLocalCyberRange(context.workspace, systemMap, context.config.stateDir);
    await writeJson(path.join(context.workspace, context.config.reportsDir, 'range-summary.json'), summary);
    console.log(`Local cyber range written to ${summary.directory}. Fake data only.`);
  }
);

configureCommonOptions(range.command('seed').description('Regenerate fake seed data for the local cyber range.')).action(
  async (options: { scope?: string; mode?: ProtectMode }) => {
    const context = await loadContext({ scope: options.scope, mode: options.mode ?? 'local' });
    const systemMap = await runMap(context);
    const summary = await composeLocalCyberRange(context.workspace, systemMap, context.config.stateDir);
    await writeJson(path.join(context.workspace, context.config.reportsDir, 'range-summary.json'), summary);
    console.log(`Range seed artifacts refreshed in ${summary.directory}.`);
  }
);

const invariants = program.command('invariants').description('Security invariant DSL commands.');
invariants.command('init').description('Create breachproof.invariants.yml with default security invariants.').action(async () => {
  const file = await writeDefaultInvariants(process.cwd());
  console.log(`Invariant file ready: ${path.relative(process.cwd(), file)}`);
});

configureCommonOptions(invariants.command('test').description('Evaluate security invariants against current BreachProof artifacts.')).action(
  async (options: { scope?: string; mode?: ProtectMode }) => {
    const context = await loadContext({ scope: options.scope, mode: options.mode ?? 'validate' });
    const analysis = await buildAnalysis(context);
    const results = await evaluateInvariants({
      workspace: context.workspace,
      systemMap: analysis.systemMap,
      reachabilityGraph: analysis.reachabilityGraph,
      attackGraph: analysis.attackGraph,
      validationPlan: analysis.validationPlan,
      findings: analysis.findings
    });
    await writeJson(path.join(context.workspace, context.config.reportsDir, 'invariant-results.json'), results);
    console.log(`Invariant test completed: ${results.summary.failed} failed, ${results.summary.manualReview} manual review.`);
  }
);

configureCommonOptions(program.command('graph').description('Graph utilities.').command('view').description('Print a text summary of the local attack graph.')).action(
  async (options: { scope?: string; mode?: ProtectMode }) => {
    const context = await loadContext({ scope: options.scope, mode: options.mode ?? 'audit' });
    const analysis = await buildAnalysis(context);
    await writeJson(path.join(context.workspace, context.config.reportsDir, 'attack-graph.json'), analysis.attackGraph);
    console.log(`Attack graph: ${analysis.attackGraph.nodes.length} nodes, ${analysis.attackGraph.edges.length} edges.`);
    console.log(`Reachability: ${analysis.reachabilityGraph.summary.reachableRoutes} routes, ${analysis.reachabilityGraph.summary.reachableModels.length} models.`);
  }
);

configureCommonOptions(program.command('map').description('Map the repository into a local system graph.')).action(
  async (options: { scope?: string; mode?: ProtectMode }) => {
    const context = await loadContext({ scope: options.scope, mode: options.mode });
    const db = initializeStateStore(context.workspace);
    recordRun(db, { command: 'map', mode: context.config.mode, status: 'completed' });
    db.close();
    const map = await runMap(context);
    console.log(`System map written with ${map.routes.length} routes and ${map.dataModels.length} data models.`);
  }
);

const corpus = program.command('corpus').description('Vulnerability corpus commands.');
corpus
  .command('import')
  .description('Import local OSV, NVD/CVE, GitHub advisory, KEV, EPSS, or rule-pack files.')
  .argument('[files...]', 'files to import')
  .option('--file <file...>', 'file paths to import')
  .option('--fetch', 'reserved for explicit online fetching')
  .option('--url <url>', 'reserved for explicit URL import')
  .action(async (files: string[], options: { file?: string[]; fetch?: boolean; url?: string }) => {
    if (options.fetch || options.url) {
      throw new Error('Online corpus fetching is not enabled in this foundation. Import local files explicitly.');
    }
    const selected = [...(files ?? []), ...(options.file ?? [])].map((file) => path.resolve(process.cwd(), file));
    const imported = await importVulnerabilityCorpusFromFiles(selected);
    const summary = summarizeVulnerabilityCorpus(imported);
    await writeJson(path.join(process.cwd(), 'reports', 'vulnerability-corpus-summary.json'), summary);
    console.log(`Imported ${summary.recordsLoaded} vulnerability records from ${summary.sources.join(', ')}.`);
  });

configureCommonOptions(program.command('reachability').description('Build route-to-code-to-dependency reachability graph.')).action(
  async (options: { scope?: string; mode?: ProtectMode }) => {
    const context = await loadContext({ scope: options.scope, mode: options.mode ?? 'audit' });
    const systemMap = await runMap(context);
    const reachabilityGraph = await buildReachabilityGraph(context.workspace, systemMap);
    await writeJson(path.join(context.workspace, context.config.reportsDir, 'reachability-graph.json'), reachabilityGraph);
    console.log(`Reachability graph written with ${reachabilityGraph.nodes.length} nodes and ${reachabilityGraph.edges.length} edges.`);
  }
);

program.command('agents').description('List built-in deterministic agents.').action(() => {
  console.log(
    [
      'Mapper Agent',
      'Vulnerability Intelligence Agent',
      'Reachability Agent',
      'Business Logic Agent',
      'Attack Planner Agent',
      'Local Validation Agent',
      'Fix Agent',
      'Regression Test Agent',
      'Verification Agent',
      'Report Agent'
    ].join('\n')
  );
});

configureCommonOptions(program.command('validate').description('Run safe validation.').option('--focus <area>', 'validation focus')).action(
  async (options: { scope?: string; mode?: ProtectMode; focus?: string }) => {
    const context = await loadContext({ scope: options.scope, mode: options.mode ?? 'validate' });
    const analysis = await buildAnalysis(context);
    await writeJson(path.join(context.workspace, context.config.reportsDir, 'validation-plan.json'), analysis.validationPlan);
    await writeJson(path.join(context.workspace, context.config.reportsDir, 'evidence.json'), analysis.evidence);
    await writeJson(path.join(context.workspace, context.config.reportsDir, 'bola-map.json'), analysis.bolaAnalysis.bolaMap);
    await writeJson(path.join(context.workspace, context.config.reportsDir, 'ownership-traces.json'), analysis.bolaAnalysis.ownershipTraces);
    console.log(`Safe validation completed with ${analysis.findings.length} findings${options.focus ? ` for ${options.focus}` : ''}.`);
  }
);

configureCommonOptions(
  program
    .command('fix')
    .description('Generate safe patch and regression-test artifacts.')
    .option('--apply', 'explicitly allow source changes where implemented')
    .option('--tournament', 'generate multiple competing patch candidates')
).action(
  async (options: { scope?: string; mode?: ProtectMode; apply?: boolean; tournament?: boolean }) => {
    const context = await loadContext({ scope: options.scope, mode: options.mode ?? 'fix', apply: options.apply });
    const analysis = await buildAnalysis(context);
    const patchSummary = await generatePatchArtifacts({
      workspace: context.workspace,
      reportsDir: context.config.reportsDir,
      findings: analysis.findings,
      apply: options.apply ?? false
    });
    await writeJson(path.join(context.workspace, context.config.reportsDir, 'patch-summary.json'), patchSummary);
    if (options.tournament) {
      const tournament = await generatePatchTournament({ workspace: context.workspace, reportsDir: context.config.reportsDir, findings: analysis.findings });
      await writeJson(path.join(context.workspace, context.config.reportsDir, 'patch-tournament.json'), tournament);
      console.log(`Patch tournament written for ${tournament.items.length} findings. Source files were not modified.`);
      return;
    }
    console.log(`Patch artifacts written for ${patchSummary.items.length} findings. Source files were not modified by default.`);
  }
);

configureCommonOptions(program.command('verify').description('Create verification records for generated patch artifacts.').option('--rerun-failed', 'rerun failed validations')).action(
  async (options: { scope?: string; mode?: ProtectMode; rerunFailed?: boolean }) => {
    const context = await loadContext({ scope: options.scope, mode: options.mode ?? 'validate' });
    const analysis = await buildAnalysis(context);
    const patchSummary = await generatePatchArtifacts({ workspace: context.workspace, reportsDir: context.config.reportsDir, findings: analysis.findings, apply: false });
    const verification = createVerification(analysis.findings, patchSummary);
    await writeJson(path.join(context.workspace, context.config.reportsDir, 'verification.json'), verification);
    console.log(`Verification records written for ${verification.items.length} findings${options.rerunFailed ? ' including failed validations' : ''}.`);
  }
);

configureCommonOptions(program.command('report').description('Render reports.').option('--format <format>', 'markdown, json, sarif, or html', 'markdown')).action(
  async (options: { scope?: string; mode?: ProtectMode; format: string }) => {
    const context = await loadContext({ scope: options.scope, mode: options.mode ?? 'audit' });
    const analysis = await buildAnalysis(context);
    const patchSummary = await generatePatchArtifacts({ workspace: context.workspace, reportsDir: context.config.reportsDir, findings: analysis.findings, apply: false });
    const verification = createVerification(analysis.findings, patchSummary);
    const report = createReportModel({
      workspace: context.workspace,
      mode: context.config.mode,
      systemMap: analysis.systemMap,
      reachabilityGraph: analysis.reachabilityGraph,
      attackGraph: analysis.attackGraph,
      findings: analysis.findings,
      corpusSummary: analysis.corpusSummary,
      validationPlan: analysis.validationPlan,
      evidence: analysis.evidence,
      patchSummary,
      verification
    });
    if (options.format === 'json') console.log(renderJsonReport(report));
    else if (options.format === 'sarif') console.log(JSON.stringify(renderSarifReport(report), null, 2));
    else if (options.format === 'html') {
      const invariantResults = await evaluateInvariants({
        workspace: context.workspace,
        systemMap: analysis.systemMap,
        reachabilityGraph: analysis.reachabilityGraph,
        attackGraph: analysis.attackGraph,
        validationPlan: analysis.validationPlan,
        findings: analysis.findings
      });
      const patchTournament = await generatePatchTournament({ workspace: context.workspace, reportsDir: context.config.reportsDir, findings: analysis.findings });
      const html = renderHtmlReport(report, {
        invariantResults,
        bolaMap: analysis.bolaAnalysis.bolaMap,
        ownershipTraces: analysis.bolaAnalysis.ownershipTraces,
        patchTournament
      });
      const target = path.join(context.workspace, context.config.reportsDir, 'final-report.html');
      await writeText(target, html);
      console.log(`HTML report written to ${path.relative(context.workspace, target)}`);
    } else console.log(renderMarkdownReport(report));
  }
);

const vibe = program.command('vibe').description('Security checks for fast AI-generated application code.');
configureCommonOptions(vibe.command('audit').description('Run Vibe-Code Security Mode.')).action(async (options: { scope?: string; mode?: ProtectMode }) => {
  const context = await loadContext({ scope: options.scope, mode: options.mode ?? 'audit' });
  const analysis = await buildAnalysis(context);
  const result = await runVibeAudit(context.workspace, analysis.systemMap, analysis.findings);
  await writeJson(path.join(context.workspace, context.config.reportsDir, 'vibe-audit.json'), result);
  await writeText(path.join(context.workspace, context.config.reportsDir, 'vibe-audit.md'), renderVibeAuditMarkdown(result));
  console.log(`Vibe-Code audit completed: ${result.summary.failed} failed checks. See ${context.config.reportsDir}/vibe-audit.md.`);
});

const aiLab = program.command('ai-lab').description('Defensive AI-agent security lab.');
configureCommonOptions(aiLab.command('run').description('Inspect AI-agent tool calls and policy guardrails.')).action(
  async (options: { scope?: string; mode?: ProtectMode }) => {
    const context = await loadContext({ scope: options.scope, mode: options.mode ?? 'audit' });
    const systemMap = await runMap(context);
    const result = await runAiLab(context.workspace, systemMap);
    await writeJson(path.join(context.workspace, context.config.reportsDir, 'ai-lab.json'), result);
    await writeText(path.join(context.workspace, context.config.reportsDir, 'ai-lab.md'), renderAiLabMarkdown(result));
    console.log(`AI-agent security lab completed: ${result.issues.length} issues. See ${context.config.reportsDir}/ai-lab.md.`);
  }
);

async function buildVaultCommand(options: {
  scope?: string;
  mode?: ProtectMode;
}): Promise<void> {
  const context = await loadContext({ scope: options.scope, mode: options.mode });
  const output = await rebuildVaultFromReports(
    context.workspace,
    context.config.reportsDir
  );
  console.log(
    `Vault built: ${path.relative(context.workspace, output.indexFile).split(path.sep).join('/')}`
  );
}

function assertLocalVaultReport(workspace: string, reportsDir: string): string {
  const root = path.resolve(workspace);
  const target = path.resolve(root, reportsDir, 'vault', 'index.html');
  const relative = path.relative(root, target);
  if (relative.startsWith('..') || path.isAbsolute(relative)) {
    throw new Error('Vault report path must remain inside the local workspace.');
  }
  return target;
}

async function openLocalFile(target: string): Promise<void> {
  const command =
    process.platform === 'darwin'
      ? 'open'
      : process.platform === 'win32'
        ? 'explorer.exe'
        : 'xdg-open';
  await new Promise<void>((resolve, reject) => {
    const child = spawn(command, [target], {
      detached: true,
      stdio: 'ignore',
      shell: false
    });
    child.once('error', reject);
    child.once('spawn', () => {
      child.unref();
      resolve();
    });
  });
}

async function viewVaultCommand(options: {
  scope?: string;
  mode?: ProtectMode;
  open?: boolean;
}): Promise<void> {
  const context = await loadContext({ scope: options.scope, mode: options.mode });
  const target = assertLocalVaultReport(
    context.workspace,
    context.config.reportsDir
  );
  await access(target);
  console.log(path.relative(context.workspace, target).split(path.sep).join('/'));
  if (options.open) await openLocalFile(target);
}

async function printVaultTimelineCommand(options: {
  scope?: string;
  mode?: ProtectMode;
}): Promise<void> {
  const context = await loadContext({ scope: options.scope, mode: options.mode });
  const db = initializeStateStore(context.workspace);
  try {
    const timeline = projectLifecycle(readVaultHistory(db));
    if (timeline.length === 0) {
      console.log('Vault timeline is empty. Run breachproof run --auto first.');
      return;
    }
    console.log(
      timeline
        .map(
          (event) =>
            `${event.timestamp} ${event.lifecycle} ${event.ruleId} ${event.title}`
        )
        .join('\n')
    );
  } finally {
    db.close();
  }
}

const vault = program
  .command('vault')
  .description('Build and inspect the local security memory graph.');
configureCommonOptions(vault.command('build')).action(buildVaultCommand);
configureCommonOptions(
  vault.command('view').option('--open', 'open the generated local report')
).action(viewVaultCommand);
configureCommonOptions(vault.command('timeline')).action(printVaultTimelineCommand);

program.command('doctor').description('Check local runtime prerequisites.').action(() => {
  console.log(`BreachProof doctor
Node.js: ${process.version}
Platform: ${process.platform}
Workspace: ${process.cwd()}
Paid services: not required
Source upload: disabled by default`);
});

program.command('plugins').description('List plugin directories and manifest requirements.').action(() => {
  console.log('Plugins are loaded from ./plugins by manifest. Required fields: name, version, type, supportedFrameworks, inputs, outputs, permissionsNeeded, entrypoint.');
});

program
  .command('skill')
  .description('Skill utilities.')
  .command('export')
  .description('Export an AI-agent skill pack.')
  .option('--codex', 'export Codex-compatible skill pack')
  .action(async (options: { codex?: boolean }) => {
    if (!options.codex) throw new Error('Only --codex export is supported in this foundation.');
    const target = await exportCodexSkill(process.cwd());
    console.log(`Codex skill exported to ${target}`);
  });

configureCommonOptions(program.command('ci').description('Run CI-safe audit and SARIF generation.')).action(
  async (options: { scope?: string; mode?: ProtectMode }) => {
    const context = await loadContext({ scope: options.scope, mode: options.mode ?? 'ci' });
    const result = await runAutonomousWorkflow({ workspace: context.workspace, config: context.config, yes: true, apply: false, mode: 'ci' });
    console.log(`CI report written with ${result.findingsCount} findings.`);
  }
);

program.parseAsync(process.argv).catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
