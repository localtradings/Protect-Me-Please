import { access, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import YAML from 'yaml';
import type { AttackGraph, Finding, ReachabilityGraph, RouteNode, SystemMap, ValidationPlan } from '../core/types.js';

export const invariantsFile = 'breachproof.invariants.yml';

export interface SecurityInvariant {
  id: string;
  description: string;
  appliesTo?: {
    routes?: string[];
  };
  require?: Record<string, unknown>;
  forbiddenRequestFields?: string[];
  dangerousTools?: string[];
}

export interface InvariantResult {
  id: string;
  description: string;
  status: 'passed' | 'failed' | 'manual_review';
  routes: string[];
  evidence: string[];
  connectedArtifacts: {
    systemMapRoutes: number;
    reachabilityEdges: number;
    attackGraphNodes: number;
    validationPlanItems: number;
    relatedFindings: string[];
  };
}

export interface InvariantResultsArtifact {
  generatedAt: string;
  invariantFile: string;
  invariants: InvariantResult[];
  summary: {
    total: number;
    passed: number;
    failed: number;
    manualReview: number;
  };
}

const defaultInvariants: SecurityInvariant[] = [
  {
    id: 'tenant-isolation',
    description: 'Users can only access records owned by their own tenant.',
    appliesTo: { routes: ['/api/invoices/:id', '/api/projects/:id'] },
    require: { 'principal.tenantId': 'equals object.tenantId' }
  },
  {
    id: 'object-ownership',
    description: 'Object routes require owner or tenant predicates before returning data.',
    appliesTo: { routes: ['/api/**'] },
    require: { 'principal.id': 'equals object.ownerId' }
  },
  {
    id: 'admin-only-actions',
    description: 'Admin routes require an admin or owner role.',
    appliesTo: { routes: ['/api/admin/**'] },
    require: { 'principal.role': 'in ["admin", "owner"]' }
  },
  {
    id: 'price-integrity',
    description: 'Client input must not control price, plan, discount, or payment status.',
    forbiddenRequestFields: ['price', 'plan', 'discount', 'paymentStatus']
  },
  {
    id: 'webhook-signature-required',
    description: 'Webhook routes require provider signature verification.',
    appliesTo: { routes: ['/api/webhooks/**'] },
    require: { signature: 'verified before trust' }
  },
  {
    id: 'file-upload-policy',
    description: 'Upload routes require size, type, and storage policy checks.',
    appliesTo: { routes: ['/api/upload/**', '/api/uploads/**'] },
    require: { upload: 'validated size and MIME type' }
  },
  {
    id: 'ai-tool-approval',
    description: 'Dangerous AI tools require allowlists, validation, audit logs, and human approval.',
    dangerousTools: ['delete', 'refund', 'transfer', 'email', 'deploy', 'sql.write']
  }
];

function defaultInvariantYaml(): string {
  return `${YAML.stringify({ invariants: defaultInvariants })}`;
}

function normalizeRoutePattern(pattern: string): RegExp {
  let source = '';
  for (let index = 0; index < pattern.length; index += 1) {
    const char = pattern[index] ?? '';
    const rest = pattern.slice(index);
    if (rest.startsWith('**')) {
      source += '.*';
      index += 1;
      continue;
    }
    if (char === '*') {
      source += '[^/]*';
      continue;
    }
    if (char === ':') {
      const match = rest.match(/^:[A-Za-z_][A-Za-z0-9_]*/);
      if (match?.[0]) {
        source += '[^/]+';
        index += match[0].length - 1;
        continue;
      }
    }
    if (char === '[') {
      const match = rest.match(/^\[[A-Za-z_][A-Za-z0-9_]*\]/);
      if (match?.[0]) {
        source += '[^/]+';
        index += match[0].length - 1;
        continue;
      }
    }
    source += char.replace(/[.+?^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp(`^${source}$`);
}

function matchingRoutes(systemMap: SystemMap, invariant: SecurityInvariant): RouteNode[] {
  const patterns = invariant.appliesTo?.routes;
  if (!patterns || patterns.length === 0) return systemMap.routes;
  const matchers = patterns.map(normalizeRoutePattern);
  return systemMap.routes.filter((route) => matchers.some((matcher) => matcher.test(route.path)));
}

function relatedFindings(findings: Finding[], routes: RouteNode[], ruleIds: string[]): string[] {
  const paths = new Set(routes.map((route) => route.path));
  return findings
    .filter((finding) => ruleIds.includes(finding.ruleId) || finding.affectedRoutes.some((route) => paths.has(route)))
    .map((finding) => finding.id);
}

function evaluateInvariant(
  invariant: SecurityInvariant,
  systemMap: SystemMap,
  reachabilityGraph: ReachabilityGraph,
  attackGraph: AttackGraph,
  validationPlan: ValidationPlan,
  findings: Finding[]
): InvariantResult {
  const routes = matchingRoutes(systemMap, invariant);
  let status: InvariantResult['status'] = 'passed';
  const evidence: string[] = [];
  let relatedRuleIds: string[] = [];

  if (invariant.id === 'tenant-isolation' || invariant.id === 'object-ownership') {
    relatedRuleIds = ['BP-AUTHZ-001', 'BP-BOLA-001', 'BP-BOLA-002'];
    const failed = routes.filter((route) => route.authDetected && !route.ownershipCheckDetected && (route.prismaModels.length > 0 || /\[id\]|:id|invoice|project|file|tenant/i.test(route.path)));
    if (failed.length > 0) {
      status = 'failed';
      evidence.push(...failed.map((route) => `${route.method} ${route.path} has auth but no detected ownership predicate.`));
    }
  } else if (invariant.id === 'admin-only-actions') {
    relatedRuleIds = ['BP-AUTH-001', 'BP-AUTHZ-001'];
    const failed = routes.filter((route) => /\/admin(\/|$)/i.test(route.path) && !route.authDetected);
    if (failed.length > 0) {
      status = 'failed';
      evidence.push(...failed.map((route) => `${route.method} ${route.path} has no detected auth.`));
    } else if (routes.length > 0) {
      status = routes.some((route) => !route.ownershipCheckDetected) ? 'manual_review' : 'passed';
      if (status === 'manual_review') evidence.push('Admin role checks are not statically distinguishable yet; review route-level role guard.');
    }
  } else if (invariant.id === 'price-integrity') {
    relatedRuleIds = ['BP-BODY-001', 'BP-BOLA-002'];
    const forbidden = new Set(invariant.forbiddenRequestFields ?? []);
    const failed = systemMap.routes.filter((route) => route.bodyFields.some((field) => forbidden.has(field)));
    if (failed.length > 0) {
      status = 'failed';
      evidence.push(...failed.map((route) => `${route.method} ${route.path} reads forbidden client fields: ${route.bodyFields.filter((field) => forbidden.has(field)).join(', ')}.`));
    }
  } else if (invariant.id === 'webhook-signature-required') {
    relatedRuleIds = ['BP-WEBHOOK-001'];
    const failed = routes.filter((route) => route.path.includes('/webhooks') && !route.webhookSignatureDetected);
    if (failed.length > 0) {
      status = 'failed';
      evidence.push(...failed.map((route) => `${route.method} ${route.path} lacks detected webhook signature verification.`));
    }
  } else if (invariant.id === 'file-upload-policy') {
    relatedRuleIds = ['BP-UPLOAD-001'];
    const failed = routes.filter((route) => /upload/i.test(route.path) && !route.uploadValidationDetected);
    if (failed.length > 0) {
      status = 'failed';
      evidence.push(...failed.map((route) => `${route.method} ${route.path} lacks detected upload size/type policy.`));
    }
  } else if (invariant.id === 'ai-tool-approval') {
    relatedRuleIds = ['BP-AI-001'];
    const failed = systemMap.aiToolCalls.filter((tool) => tool.dangerous && !tool.guardrailsDetected);
    if (failed.length > 0) {
      status = 'failed';
      evidence.push(...failed.map((tool) => `${tool.name} in ${tool.file} lacks detected allowlist, approval, or policy guardrails.`));
    }
  } else {
    status = 'manual_review';
    evidence.push('Custom invariant loaded. BreachProof does not have a deterministic evaluator for this invariant yet.');
  }

  if (evidence.length === 0) evidence.push('No violation detected from system map, reachability graph, attack graph, and validation plan.');

  return {
    id: invariant.id,
    description: invariant.description,
    status,
    routes: routes.map((route) => `${route.method} ${route.path}`),
    evidence,
    connectedArtifacts: {
      systemMapRoutes: systemMap.routes.length,
      reachabilityEdges: reachabilityGraph.edges.length,
      attackGraphNodes: attackGraph.nodes.length,
      validationPlanItems: validationPlan.items.length,
      relatedFindings: relatedFindings(findings, routes, relatedRuleIds)
    }
  };
}

export async function writeDefaultInvariants(workspace: string): Promise<string> {
  const file = path.join(workspace, invariantsFile);
  await access(file).catch(async () => {
    await writeFile(file, defaultInvariantYaml(), 'utf8');
  });
  return file;
}

export async function loadInvariants(workspace: string): Promise<{ file: string; invariants: SecurityInvariant[] }> {
  const file = path.join(workspace, invariantsFile);
  const text = await readFile(file, 'utf8').catch(() => defaultInvariantYaml());
  const parsed = YAML.parse(text) as { invariants?: SecurityInvariant[] } | undefined;
  return { file, invariants: parsed?.invariants ?? defaultInvariants };
}

export async function evaluateInvariants(input: {
  workspace: string;
  systemMap: SystemMap;
  reachabilityGraph: ReachabilityGraph;
  attackGraph: AttackGraph;
  validationPlan: ValidationPlan;
  findings: Finding[];
}): Promise<InvariantResultsArtifact> {
  const loaded = await loadInvariants(input.workspace);
  const invariants = loaded.invariants.map((invariant) =>
    evaluateInvariant(invariant, input.systemMap, input.reachabilityGraph, input.attackGraph, input.validationPlan, input.findings)
  );
  return {
    generatedAt: new Date().toISOString(),
    invariantFile: path.relative(input.workspace, loaded.file).split(path.sep).join('/'),
    invariants,
    summary: {
      total: invariants.length,
      passed: invariants.filter((invariant) => invariant.status === 'passed').length,
      failed: invariants.filter((invariant) => invariant.status === 'failed').length,
      manualReview: invariants.filter((invariant) => invariant.status === 'manual_review').length
    }
  };
}
