import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { buildAttackGraph } from '../agents/attack-graph.js';
import { createEvidenceBundle, createValidationPlan } from '../agents/attack-planner.js';
import { runAiLab, renderAiLabMarkdown } from '../agents/ai-lab.js';
import { analyzeBola } from '../agents/bola.js';
import { generatePatchArtifacts } from '../agents/fix-agent.js';
import { generatePatchTournament } from '../agents/patch-tournament.js';
import { buildReachabilityGraph, matchReachableVulnerabilities } from '../agents/reachability.js';
import { mapRepository } from '../agents/repo-mapper.js';
import { validateSystemMap } from '../agents/safe-validation.js';
import { runVibeAudit, renderVibeAuditMarkdown } from '../agents/vibe-audit.js';
import { createVerification } from '../agents/verification-agent.js';
import { buildLocalVulnerabilityCorpus, matchRelevantVulnerabilities, summarizeVulnerabilityCorpus } from '../agents/vulnerability-corpus.js';
import { writeReplayableEvidenceArtifacts } from '../proof/evidence.js';
import { evaluateInvariants } from '../proof/invariants.js';
import { composeLocalCyberRange } from '../proof/range.js';
import { generateRequestSequences } from '../proof/request-sequences.js';
import { renderHtmlReport } from '../reporting/html-report.js';
import { createReportModel, renderJsonReport, renderMarkdownReport, renderSarifReport } from '../reporting/report-generator.js';
import { appendAuditEvent } from './audit.js';
import { writeScopeConfig } from './config.js';
import { approveScope, approvalMatchesConfig, computeScopeHash, loadApproval } from './scope.js';
import { initializeStateStore, recordRun } from './state.js';
import type { Finding, PatchSummary, ProtectMode, ScopeConfig, Verification } from './types.js';
import { recordAndBuildVault } from '../vault/report.js';

export interface RunAutonomousWorkflowInput {
  workspace: string;
  config: ScopeConfig;
  yes?: boolean;
  apply?: boolean;
  mode?: ProtectMode;
}

export interface RunAutonomousWorkflowResult {
  artifacts: string[];
  patchSummary: PatchSummary;
  verification: Verification;
  findingsCount: number;
}

async function writeJson(file: string, value: unknown): Promise<string> {
  await mkdir(path.dirname(file), { recursive: true });
  await writeFile(file, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
  return file;
}

async function writeText(file: string, value: string): Promise<string> {
  await mkdir(path.dirname(file), { recursive: true });
  await writeFile(file, value, 'utf8');
  return file;
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

export async function ensureWorkflowApproval(workspace: string, config: ScopeConfig, yes = false): Promise<void> {
  const approval = await loadApproval(workspace);
  if (approvalMatchesConfig(approval, config)) return;
  if (!yes) {
    throw new Error('Scope is not approved. Run `breachproof init --yes` after confirming you own or are authorized to test this workspace.');
  }
  await writeScopeConfig(workspace, config);
  await approveScope(workspace, config);
}

export async function runAutonomousWorkflow(input: RunAutonomousWorkflowInput): Promise<RunAutonomousWorkflowResult> {
  const workspace = path.resolve(input.workspace);
  const mode = input.mode ?? input.config.mode;
  const config: ScopeConfig = {
    ...input.config,
    mode,
    workspace,
    autofix: {
      ...input.config.autofix,
      apply: input.apply ?? input.config.autofix.apply
    }
  };
  const reportsDir = path.join(workspace, config.reportsDir);
  await mkdir(reportsDir, { recursive: true });
  await ensureWorkflowApproval(workspace, config, input.yes);

  const db = initializeStateStore(workspace);
  recordRun(db, { command: 'run', mode: config.mode, status: 'started' });

  const systemMap = await mapRepository(workspace);
  const corpus = buildLocalVulnerabilityCorpus();
  const reachabilityGraph = await buildReachabilityGraph(workspace, systemMap);
  const reachableVulnerabilities = matchReachableVulnerabilities(systemMap, reachabilityGraph, corpus);
  const relevantVulnerabilities = matchRelevantVulnerabilities(systemMap, corpus);
  const attackGraph = buildAttackGraph(systemMap, corpus, reachabilityGraph);
  const bolaAnalysis = await analyzeBola(workspace, systemMap, reachabilityGraph);
  const findings = dedupeFindings([...validateSystemMap(systemMap, attackGraph, corpus, reachabilityGraph), ...bolaAnalysis.findings]);
  const validationPlan = createValidationPlan(findings, reachabilityGraph);
  const evidence = createEvidenceBundle(findings);
  const invariantResults = await evaluateInvariants({ workspace, systemMap, reachabilityGraph, attackGraph, validationPlan, findings });
  const requestSequences = await generateRequestSequences(workspace, systemMap, findings);
  const rangeSummary = await composeLocalCyberRange(workspace, systemMap, config.stateDir);
  const patchSummary = await generatePatchArtifacts({
    workspace,
    reportsDir: config.reportsDir,
    findings,
    apply: config.autofix.apply
  });
  const patchTournament = await generatePatchTournament({ workspace, reportsDir: config.reportsDir, findings });
  const verification = createVerification(findings, patchSummary);
  const evidenceArtifacts = await writeReplayableEvidenceArtifacts({
    workspace,
    reportsDir: config.reportsDir,
    findings,
    requestSequences,
    verification
  });
  const vibeAudit = await runVibeAudit(workspace, systemMap, findings);
  const aiLab = await runAiLab(workspace, systemMap);
  const corpusSummary = summarizeVulnerabilityCorpus(corpus, {
    matchedComponents: relevantVulnerabilities.length,
    possiblyReachableIssues: reachableVulnerabilities.length + findings.filter((finding) => finding.ruleId !== 'BP-DEP-001').length,
    safelyValidatedIssues: findings.filter((finding) => finding.status === 'validated').length,
    autoFixedIssues: patchSummary.items.filter((item) => item.status === 'verified_fixed').length,
    manualReviewIssues: verification.items.filter((item) => item.status === 'needs_human_review').length
  });
  const report = createReportModel({
    workspace,
    mode: config.mode,
    systemMap,
    reachabilityGraph,
    attackGraph,
    findings,
    corpusSummary,
    validationPlan,
    evidence,
    patchSummary,
    verification,
    scopeApproved: true
  });

  const artifacts = [
    await writeJson(path.join(reportsDir, 'system-map.json'), systemMap),
    await writeJson(path.join(reportsDir, 'vulnerability-corpus-summary.json'), corpusSummary),
    await writeJson(path.join(reportsDir, 'reachability-graph.json'), reachabilityGraph),
    await writeJson(path.join(reportsDir, 'attack-graph.json'), attackGraph),
    await writeJson(path.join(reportsDir, 'bola-map.json'), bolaAnalysis.bolaMap),
    await writeJson(path.join(reportsDir, 'ownership-traces.json'), bolaAnalysis.ownershipTraces),
    await writeJson(path.join(reportsDir, 'validation-plan.json'), validationPlan),
    await writeJson(path.join(reportsDir, 'invariant-results.json'), invariantResults),
    await writeJson(path.join(reportsDir, 'request-sequences.json'), requestSequences),
    await writeJson(path.join(reportsDir, 'evidence.json'), evidence),
    await writeJson(path.join(reportsDir, 'evidence-summary.json'), evidenceArtifacts),
    await writeJson(path.join(reportsDir, 'patch-summary.json'), patchSummary),
    await writeJson(path.join(reportsDir, 'patch-tournament.json'), patchTournament),
    await writeJson(path.join(reportsDir, 'verification.json'), verification),
    await writeJson(path.join(reportsDir, 'range-summary.json'), rangeSummary),
    await writeJson(path.join(reportsDir, 'vibe-audit.json'), vibeAudit),
    await writeText(path.join(reportsDir, 'vibe-audit.md'), renderVibeAuditMarkdown(vibeAudit)),
    await writeJson(path.join(reportsDir, 'ai-lab.json'), aiLab),
    await writeText(path.join(reportsDir, 'ai-lab.md'), renderAiLabMarkdown(aiLab)),
    await writeText(path.join(reportsDir, 'final-report.md'), renderMarkdownReport(report)),
    await writeJson(path.join(reportsDir, 'final-report.json'), JSON.parse(renderJsonReport(report))),
    await writeJson(path.join(reportsDir, 'final-report.sarif'), renderSarifReport(report)),
    await writeText(
      path.join(reportsDir, 'final-report.html'),
      renderHtmlReport(report, {
        invariantResults,
        bolaMap: bolaAnalysis.bolaMap,
        ownershipTraces: bolaAnalysis.ownershipTraces,
        patchTournament
      })
    )
  ];

  try {
    const vault = await recordAndBuildVault({
      workspace,
      reportsDir: config.reportsDir,
      mode: config.mode,
      scopeHash: computeScopeHash(config),
      systemMap,
      findings,
      invariantResults,
      patchSummary,
      patchTournament,
      verification,
      evidence: evidenceArtifacts,
      startedAt: systemMap.generatedAt,
      completedAt: report.generatedAt
    });
    artifacts.push(...vault.paths);
    recordRun(db, { command: 'run', mode: config.mode, status: 'completed' });
  } finally {
    db.close();
  }
  await appendAuditEvent(workspace, {
    action: 'run',
    actor: 'cli',
    mode: config.mode,
    status: 'completed',
    message: `BreachProof autonomous workflow completed with ${findings.length} findings`
  });

  return { artifacts, patchSummary, verification, findingsCount: findings.length };
}
