#!/usr/bin/env node
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { Command } from 'commander';
import { buildAttackGraph } from '../agents/attack-graph.js';
import { createEvidenceBundle, createValidationPlan } from '../agents/attack-planner.js';
import { generatePatchArtifacts } from '../agents/fix-agent.js';
import { buildReachabilityGraph } from '../agents/reachability.js';
import { mapRepository } from '../agents/repo-mapper.js';
import { validateSystemMap } from '../agents/safe-validation.js';
import { createVerification } from '../agents/verification-agent.js';
import { buildLocalVulnerabilityCorpus, importVulnerabilityCorpusFromFiles, matchRelevantVulnerabilities, summarizeVulnerabilityCorpus } from '../agents/vulnerability-corpus.js';
import { appendAuditEvent } from '../core/audit.js';
import { createDefaultScopeConfig, loadScopeConfig, scopeConfigFile, writeScopeConfig } from '../core/config.js';
import { approveScope } from '../core/scope.js';
import { initializeStateStore, recordRun } from '../core/state.js';
import { type ProtectMode, type ScopeConfig, type SystemMap } from '../core/types.js';
import { runAutonomousWorkflow } from '../core/workflow.js';
import { createReportModel, renderJsonReport, renderMarkdownReport, renderSarifReport } from '../reporting/report-generator.js';
import { exportCodexSkill } from '../skills/exporter.js';

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

function configureCommonOptions(command: Command): Command {
  return command.option('--scope <file>', 'scope config file', scopeConfigFile).option('--mode <mode>', 'execution mode');
}

const program = new Command();

program
  .name('breachproof')
  .description('Local autonomous breach-path proof and fix verification for authorized repositories.')
  .version('0.2.0');

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
    .command('run')
    .description('Run the autonomous proof, fix-artifact, verification, and report workflow.')
    .option('--auto', 'run map, corpus, reachability, validate, fix artifacts, verify, and reports')
    .option('--yes', 'approve scope if missing')
    .option('--apply', 'explicitly allow source changes where implemented')
).action(async (options: { auto?: boolean; yes?: boolean; apply?: boolean; scope?: string; mode?: ProtectMode }) => {
  const context = await loadContext({ scope: options.scope, mode: options.mode ?? (options.auto ? 'auto' : undefined), apply: options.apply });
  const result = await runAutonomousWorkflow({
    workspace: context.workspace,
    config: context.config,
    yes: options.yes,
    apply: options.apply ?? false,
    mode: context.config.mode
  });
  console.log(`BreachProof run completed with ${result.findingsCount} findings. Artifacts written to ${context.config.reportsDir}.`);
});

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
    const systemMap = await runMap(context);
    const reachabilityGraph = await buildReachabilityGraph(context.workspace, systemMap);
    const localCorpus = buildLocalVulnerabilityCorpus();
    const attackGraph = buildAttackGraph(systemMap, localCorpus, reachabilityGraph);
    const findings = validateSystemMap(systemMap, attackGraph, localCorpus, reachabilityGraph);
    const validationPlan = createValidationPlan(findings, reachabilityGraph);
    const evidence = createEvidenceBundle(findings);
    await writeJson(path.join(context.workspace, context.config.reportsDir, 'validation-plan.json'), validationPlan);
    await writeJson(path.join(context.workspace, context.config.reportsDir, 'evidence.json'), evidence);
    console.log(`Safe validation completed with ${findings.length} findings${options.focus ? ` for ${options.focus}` : ''}.`);
  }
);

configureCommonOptions(program.command('fix').description('Generate safe patch and regression-test artifacts.').option('--apply', 'explicitly allow source changes where implemented')).action(
  async (options: { scope?: string; mode?: ProtectMode; apply?: boolean }) => {
    const context = await loadContext({ scope: options.scope, mode: options.mode ?? 'fix', apply: options.apply });
    const systemMap = await runMap(context);
    const reachabilityGraph = await buildReachabilityGraph(context.workspace, systemMap);
    const localCorpus = buildLocalVulnerabilityCorpus();
    const attackGraph = buildAttackGraph(systemMap, localCorpus, reachabilityGraph);
    const findings = validateSystemMap(systemMap, attackGraph, localCorpus, reachabilityGraph);
    const patchSummary = await generatePatchArtifacts({ workspace: context.workspace, reportsDir: context.config.reportsDir, findings, apply: options.apply ?? false });
    await writeJson(path.join(context.workspace, context.config.reportsDir, 'patch-summary.json'), patchSummary);
    console.log(`Patch artifacts written for ${patchSummary.items.length} findings. Source files were not modified by default.`);
  }
);

configureCommonOptions(program.command('verify').description('Create verification records for generated patch artifacts.').option('--rerun-failed', 'rerun failed validations')).action(
  async (options: { scope?: string; mode?: ProtectMode; rerunFailed?: boolean }) => {
    const context = await loadContext({ scope: options.scope, mode: options.mode ?? 'validate' });
    const systemMap = await runMap(context);
    const reachabilityGraph = await buildReachabilityGraph(context.workspace, systemMap);
    const localCorpus = buildLocalVulnerabilityCorpus();
    const attackGraph = buildAttackGraph(systemMap, localCorpus, reachabilityGraph);
    const findings = validateSystemMap(systemMap, attackGraph, localCorpus, reachabilityGraph);
    const patchSummary = await generatePatchArtifacts({ workspace: context.workspace, reportsDir: context.config.reportsDir, findings, apply: false });
    const verification = createVerification(findings, patchSummary);
    await writeJson(path.join(context.workspace, context.config.reportsDir, 'verification.json'), verification);
    console.log(`Verification records written for ${verification.items.length} findings${options.rerunFailed ? ' including failed validations' : ''}.`);
  }
);

configureCommonOptions(program.command('report').description('Render reports.').option('--format <format>', 'markdown, json, or sarif', 'markdown')).action(
  async (options: { scope?: string; mode?: ProtectMode; format: string }) => {
    const context = await loadContext({ scope: options.scope, mode: options.mode ?? 'audit' });
    const systemMap = await runMap(context);
    const reachabilityGraph = await buildReachabilityGraph(context.workspace, systemMap);
    const localCorpus = buildLocalVulnerabilityCorpus();
    const attackGraph = buildAttackGraph(systemMap, localCorpus, reachabilityGraph);
    const findings = validateSystemMap(systemMap, attackGraph, localCorpus, reachabilityGraph);
    const corpusSummary = summarizeVulnerabilityCorpus(localCorpus, {
      matchedComponents: matchRelevantVulnerabilities(systemMap, localCorpus).length,
      possiblyReachableIssues: findings.length,
      safelyValidatedIssues: findings.filter((finding) => finding.status === 'validated').length,
      manualReviewIssues: findings.filter((finding) => finding.status === 'manual_review').length
    });
    const report = createReportModel({ workspace: context.workspace, mode: context.config.mode, systemMap, reachabilityGraph, attackGraph, findings, corpusSummary });
    if (options.format === 'json') console.log(renderJsonReport(report));
    else if (options.format === 'sarif') console.log(JSON.stringify(renderSarifReport(report), null, 2));
    else console.log(renderMarkdownReport(report));
  }
);

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
