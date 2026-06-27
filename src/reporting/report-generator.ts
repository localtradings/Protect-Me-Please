import { productName, productTagline, reportSchema, type AttackGraph, type EvidenceBundle, type Finding, type PatchSummary, type ProtectMode, type ProtectReport, type ReachabilityGraph, type SystemMap, type ValidationPlan, type Verification, type VulnerabilityCorpusSummary } from '../core/types.js';
import { createEvidenceBundle, createValidationPlan } from '../agents/attack-planner.js';
import { generateEmptyReachabilityGraph } from './report-helpers.js';

export interface ReportInput {
  workspace: string;
  mode: ProtectMode;
  systemMap: SystemMap;
  reachabilityGraph?: ReachabilityGraph;
  attackGraph: AttackGraph;
  findings: Finding[];
  corpusSummary?: VulnerabilityCorpusSummary;
  validationPlan?: ValidationPlan;
  evidence?: EvidenceBundle;
  patchSummary?: PatchSummary;
  verification?: Verification;
  scopeApproved?: boolean;
}

function defaultCorpusSummary(findings: Finding[]): VulnerabilityCorpusSummary {
  return {
    generatedAt: new Date().toISOString(),
    sources: ['local-rule-pack'],
    recordsLoaded: findings.filter((finding) => finding.ruleId === 'BP-DEP-001').length,
    matchedComponents: findings.filter((finding) => finding.ruleId === 'BP-DEP-001').length,
    possiblyReachableIssues: findings.length,
    highExploitLikelihoodIssues: findings.filter((finding) => ['high', 'critical'].includes(finding.severity)).length,
    safelyValidatedIssues: findings.filter((finding) => finding.status === 'validated').length,
    autoFixedIssues: findings.filter((finding) => finding.fixStatus === 'verified_fixed').length,
    manualReviewIssues: findings.filter((finding) => finding.status === 'manual_review').length
  };
}

function defaultPatchSummary(findings: Finding[]): PatchSummary {
  return {
    generatedAt: new Date().toISOString(),
    apply: false,
    items: findings.map((finding) => ({
      findingId: finding.id,
      status: finding.status === 'manual_review' ? 'needs_human_review' : 'suggested',
      summary: finding.recommendation
    }))
  };
}

function defaultVerification(findings: Finding[]): Verification {
  return {
    generatedAt: new Date().toISOString(),
    items: findings.map((finding) => ({
      findingId: finding.id,
      status: finding.status === 'manual_review' ? 'needs_human_review' : 'unverified',
      proofMode: finding.proofMode,
      productionTouched: false,
      destructive: false,
      summary: 'Verification has not run.'
    }))
  };
}

export function createReportModel(input: ReportInput): ProtectReport {
  const reachabilityGraph = input.reachabilityGraph ?? generateEmptyReachabilityGraph();
  const validationPlan = input.validationPlan ?? createValidationPlan(input.findings, reachabilityGraph);
  const evidence = input.evidence ?? createEvidenceBundle(input.findings);
  const patchSummary = input.patchSummary ?? defaultPatchSummary(input.findings);
  const verification = input.verification ?? defaultVerification(input.findings);
  return reportSchema.parse({
    product: productName,
    tagline: productTagline,
    project: input.systemMap.projectName,
    mode: input.mode,
    scopeApproved: input.scopeApproved ?? true,
    productionTouched: false,
    generatedAt: new Date().toISOString(),
    summary: input.corpusSummary ?? defaultCorpusSummary(input.findings),
    systemMap: input.systemMap,
    reachabilityGraph,
    attackGraph: input.attackGraph,
    validationPlan,
    evidence,
    patchSummary,
    verification,
    findings: input.findings
  });
}

export function renderMarkdownReport(report: ProtectReport): string {
  const confirmed = report.findings.filter((finding) => finding.status === 'validated');
  const manual = report.findings.filter((finding) => finding.status === 'manual_review');
  const findingSections = report.findings
    .map(
      (finding) => `## Finding: ${finding.title}

Status: ${finding.fixStatus}
Severity: ${finding.severity}
Proof mode: ${finding.proofMode}
Rule: ${finding.ruleId}
Path: ${finding.attackPath.join(' -> ')}

Proof:
${finding.evidence}

Fix:
${finding.recommendation}

Regression test:
${report.patchSummary.items.find((item) => item.findingId === finding.id)?.testFile ?? 'not generated'}

Verification:
${report.verification.items.find((item) => item.findingId === finding.id)?.summary ?? 'not run'}
`
    )
    .join('\n');

  return `# BreachProof Final Report

${report.tagline}

Project: ${report.project}
Mode: ${report.mode}
Scope approved: ${report.scopeApproved ? 'yes' : 'no'}
Production touched: ${report.productionTouched ? 'yes' : 'no'}

## Executive summary

- Vulnerability corpus loaded: ${report.summary.recordsLoaded}
- Relevant matches: ${report.summary.matchedComponents}
- Possibly reachable issues: ${report.summary.possiblyReachableIssues}
- High exploit-likelihood issues: ${report.summary.highExploitLikelihoodIssues}
- Safely validated issues: ${report.summary.safelyValidatedIssues}
- Auto-fixed issues: ${report.summary.autoFixedIssues}
- Manual review issues: ${report.summary.manualReviewIssues}

## Vulnerability corpus loaded

Sources: ${report.summary.sources.join(', ') || 'none'}

## Reachability analysis

- Routes: ${report.reachabilityGraph.summary.reachableRoutes}
- Dependencies: ${report.reachabilityGraph.summary.reachableDependencies.join(', ') || 'none'}
- Data models: ${report.reachabilityGraph.summary.reachableModels.join(', ') || 'none'}
- AI tool flows: ${report.reachabilityGraph.summary.aiToolFlows}

## Confirmed breach paths

${confirmed.length > 0 ? confirmed.map((finding) => `- ${finding.attackPath.join(' -> ')}`).join('\n') : '- none confirmed by safe validation'}

## Generated fixes

${report.patchSummary.items.map((item) => `- ${item.findingId}: ${item.status}${item.patchFile ? ` (${item.patchFile})` : ''}`).join('\n') || '- none'}

## Verification results

${report.verification.items.map((item) => `- ${item.findingId}: ${item.status} - ${item.summary}`).join('\n') || '- none'}

## Remaining risk and manual review

${manual.length > 0 ? manual.map((finding) => `- ${finding.title}: ${finding.recommendation}`).join('\n') : '- no manual review items'}

## Attack graph

- Nodes: ${report.attackGraph.nodes.length}
- Edges: ${report.attackGraph.edges.length}

${findingSections || 'No findings.'}
`;
}

export function renderJsonReport(report: ProtectReport): string {
  return `${JSON.stringify(report, null, 2)}\n`;
}

export interface SarifReport {
  version: '2.1.0';
  $schema: string;
  runs: Array<{
    tool: { driver: { name: string; informationUri: string; rules: Array<{ id: string; name: string; shortDescription: { text: string } }> } };
    results: Array<{
      ruleId: string;
      level: 'note' | 'warning' | 'error';
      message: { text: string };
      locations: Array<{ physicalLocation: { artifactLocation: { uri: string } } }>;
    }>;
  }>;
}

function sarifLevel(severity: Finding['severity']): 'note' | 'warning' | 'error' {
  if (severity === 'critical' || severity === 'high') return 'error';
  if (severity === 'medium') return 'warning';
  return 'note';
}

export function renderSarifReport(report: ProtectReport): SarifReport {
  const rules = new Map(report.findings.map((finding) => [finding.ruleId, finding]));
  return {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [
      {
        tool: {
          driver: {
            name: productName,
            informationUri: 'https://github.com/localtradings/breachproof',
            rules: [...rules.values()].map((finding) => ({
              id: finding.ruleId,
              name: finding.title,
              shortDescription: { text: finding.title }
            }))
          }
        },
        results: report.findings.map((finding) => ({
          ruleId: finding.ruleId,
          level: sarifLevel(finding.severity),
          message: { text: `${finding.title}: ${finding.evidence}` },
          locations: finding.affectedFiles.map((file) => ({
            physicalLocation: {
              artifactLocation: { uri: file }
            }
          }))
        }))
      }
    ]
  };
}
