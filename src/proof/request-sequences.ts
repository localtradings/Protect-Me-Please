import path from 'node:path';
import { toRelative, walkFiles } from '../core/files.js';
import type { Finding, RouteNode, SystemMap } from '../core/types.js';

export interface RequestSequenceStep {
  actor: string;
  method: string;
  path: string;
  description: string;
  expectedStatus: number;
  body?: Record<string, string | number | boolean>;
  headers?: Record<string, string>;
}

export interface RequestSequence {
  id: string;
  findingId?: string;
  type: 'cross_tenant_access' | 'admin_bypass' | 'webhook_unsigned' | 'upload_policy' | 'ai_tool_policy';
  source: 'openapi' | 'route-map';
  safe: boolean;
  localOnly: boolean;
  steps: RequestSequenceStep[];
}

export interface RequestSequencesArtifact {
  generatedAt: string;
  source: 'openapi' | 'route-map';
  openApiFiles: string[];
  sequences: RequestSequence[];
  summary: {
    total: number;
    crossTenant: number;
    admin: number;
    webhook: number;
    upload: number;
    aiTool: number;
  };
}

function slug(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 80);
}

function routeKey(route: RouteNode): string {
  return `${route.method.toUpperCase()} ${route.path}`;
}

function routeForFinding(systemMap: SystemMap, finding: Finding): RouteNode | undefined {
  return systemMap.routes.find((route) => finding.affectedRoutes.includes(route.path) || finding.attackPath.includes(routeKey(route)));
}

function crossTenantSequence(route: RouteNode, finding?: Finding): RequestSequence {
  return {
    id: `cross-tenant-${slug(route.id)}`,
    findingId: finding?.id,
    type: 'cross_tenant_access',
    source: 'route-map',
    safe: true,
    localOnly: true,
    steps: [
      {
        actor: 'tenant-a-user',
        method: 'POST',
        path: '/__breachproof/range/seed/tenant-a-object',
        description: 'Create or select a fake Tenant A principal and a fake Tenant B object in the local range.',
        expectedStatus: 201,
        body: { tenantAUser: 'user_tenant_a', tenantBObject: 'invoice_tenant_b' }
      },
      {
        actor: 'tenant-a-user',
        method: route.method,
        path: route.path.replace(/\[id\]|:id/g, 'invoice_tenant_b'),
        description: 'Replay the mapped route as Tenant A while requesting the fake Tenant B object.',
        expectedStatus: 403,
        headers: { 'x-breachproof-user': 'user_tenant_a' }
      }
    ]
  };
}

function adminSequence(route: RouteNode): RequestSequence {
  return {
    id: `admin-${slug(route.id)}`,
    type: 'admin_bypass',
    source: 'route-map',
    safe: true,
    localOnly: true,
    steps: [
      {
        actor: 'normal-user',
        method: route.method,
        path: route.path,
        description: 'Attempt the admin route with a fake non-admin principal in the local range.',
        expectedStatus: 403,
        headers: { 'x-breachproof-role': 'user' }
      }
    ]
  };
}

function webhookSequence(route: RouteNode, finding?: Finding): RequestSequence {
  return {
    id: `webhook-${slug(route.id)}`,
    findingId: finding?.id,
    type: 'webhook_unsigned',
    source: 'route-map',
    safe: true,
    localOnly: true,
    steps: [
      {
        actor: 'mock-webhook-provider',
        method: route.method,
        path: route.path,
        description: 'Replay a fake provider event without a signature header.',
        expectedStatus: 401,
        body: { id: 'evt_breachproof_unsigned', type: 'invoice.updated' }
      }
    ]
  };
}

function uploadSequence(route: RouteNode, finding?: Finding): RequestSequence {
  return {
    id: `upload-${slug(route.id)}`,
    findingId: finding?.id,
    type: 'upload_policy',
    source: 'route-map',
    safe: true,
    localOnly: true,
    steps: [
      {
        actor: 'tenant-a-user',
        method: route.method,
        path: route.path,
        description: 'Attempt a fake upload that lacks an allowed content type and size policy.',
        expectedStatus: 400,
        headers: { 'content-type': 'application/octet-stream' }
      }
    ]
  };
}

function aiToolSequence(route: RouteNode | undefined, finding: Finding): RequestSequence {
  return {
    id: `ai-tool-${slug(finding.id)}`,
    findingId: finding.id,
    type: 'ai_tool_policy',
    source: 'route-map',
    safe: true,
    localOnly: true,
    steps: [
      {
        actor: 'tenant-a-user',
        method: route?.method ?? 'POST',
        path: route?.path ?? '/__breachproof/ai-tool',
        description: 'Submit a fake dangerous tool request and require allowlist or human approval before execution.',
        expectedStatus: 403,
        body: { tool: 'delete', reason: 'breachproof defensive policy test' }
      }
    ]
  };
}

export async function generateRequestSequences(workspace: string, systemMap: SystemMap, findings: Finding[]): Promise<RequestSequencesArtifact> {
  const files = await walkFiles(workspace);
  const openApiFiles = files
    .map((file) => toRelative(path.resolve(workspace), file))
    .filter((file) => /(^|\/)(openapi|swagger)\.(json|ya?ml)$/.test(file))
    .sort();
  const source: 'openapi' | 'route-map' = openApiFiles.length > 0 ? 'openapi' : 'route-map';
  const sequences: RequestSequence[] = [];

  for (const finding of findings) {
    const route = routeForFinding(systemMap, finding);
    if (finding.ruleId.startsWith('BP-BOLA') && route) sequences.push(crossTenantSequence(route, finding));
    if (finding.ruleId === 'BP-WEBHOOK-001' && route) sequences.push(webhookSequence(route, finding));
    if (finding.ruleId === 'BP-UPLOAD-001' && route) sequences.push(uploadSequence(route, finding));
    if (finding.ruleId === 'BP-AI-001') sequences.push(aiToolSequence(route, finding));
  }

  for (const route of systemMap.routes.filter((candidate) => /\/admin(\/|$)/i.test(candidate.path))) {
    if (!sequences.some((sequence) => sequence.type === 'admin_bypass' && sequence.steps.some((step) => step.path === route.path))) {
      sequences.push(adminSequence(route));
    }
  }

  return {
    generatedAt: new Date().toISOString(),
    source,
    openApiFiles,
    sequences,
    summary: {
      total: sequences.length,
      crossTenant: sequences.filter((sequence) => sequence.type === 'cross_tenant_access').length,
      admin: sequences.filter((sequence) => sequence.type === 'admin_bypass').length,
      webhook: sequences.filter((sequence) => sequence.type === 'webhook_unsigned').length,
      upload: sequences.filter((sequence) => sequence.type === 'upload_policy').length,
      aiTool: sequences.filter((sequence) => sequence.type === 'ai_tool_policy').length
    }
  };
}
