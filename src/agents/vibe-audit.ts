import path from 'node:path';
import { readTextIfSmall, toRelative, walkFiles } from '../core/files.js';
import type { Finding, SystemMap } from '../core/types.js';

export interface VibeAuditCheck {
  id: string;
  title: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  status: 'passed' | 'failed' | 'manual_review';
  evidence: string[];
  recommendation: string;
}

export interface VibeAuditResult {
  generatedAt: string;
  message: string;
  checks: VibeAuditCheck[];
  summary: {
    failed: number;
    manualReview: number;
    passed: number;
  };
}

function check(id: string, title: string, evidence: string[], recommendation: string, severity: VibeAuditCheck['severity'] = 'high'): VibeAuditCheck {
  return {
    id,
    title,
    severity,
    status: evidence.length > 0 ? 'failed' : 'passed',
    evidence: evidence.length > 0 ? evidence : ['No matching risk signal detected.'],
    recommendation
  };
}

async function scanSources(workspace: string): Promise<Array<{ file: string; source: string }>> {
  const files = await walkFiles(workspace);
  const codeFiles = files.filter((file) => /\.(tsx?|jsx?|mjs|cjs)$/.test(file));
  const sources: Array<{ file: string; source: string }> = [];
  for (const file of codeFiles) {
    sources.push({ file: toRelative(path.resolve(workspace), file), source: await readTextIfSmall(file).catch(() => '') });
  }
  return sources;
}

export async function runVibeAudit(workspace: string, systemMap: SystemMap, findings: Finding[]): Promise<VibeAuditResult> {
  const sources = await scanSources(workspace);
  const checks: VibeAuditCheck[] = [];
  checks.push(
    check(
      'vibe-frontend-auth',
      'Frontend-only auth or missing backend auth',
      systemMap.routes.filter((route) => !route.authDetected && !route.path.includes('/webhooks')).map((route) => `${route.method} ${route.path} in ${route.file}`),
      'Move authorization decisions into backend route handlers or server-side middleware.'
    )
  );
  checks.push(
    check(
      'vibe-ownership',
      'Backend route without ownership check',
      findings.filter((finding) => ['BP-AUTHZ-001', 'BP-BOLA-001'].includes(finding.ruleId)).map((finding) => `${finding.title}: ${finding.affectedRoutes.join(', ')}`),
      'Add object ownership or tenant predicates using authenticated principal context.'
    )
  );
  checks.push(
    check(
      'vibe-direct-prisma',
      'Direct Prisma calls in route handlers without guard',
      systemMap.routes
        .filter((route) => route.prismaModels.length > 0 && !route.ownershipCheckDetected)
        .map((route) => `${route.file} reaches ${route.prismaModels.join(', ')}`),
      'Route handlers should call guarded service functions or apply explicit scoped Prisma predicates.'
    )
  );
  checks.push(
    check(
      'vibe-client-privileged-fields',
      'User-controlled role, tenant, price, status, or plan fields',
      systemMap.routes.filter((route) => route.dangerousBodyFields.length > 0).map((route) => `${route.file}: ${route.dangerousBodyFields.join(', ')}`),
      'Reject privileged client fields and derive them server-side.'
    )
  );
  checks.push(
    check(
      'vibe-admin-routes',
      'Exposed admin routes',
      systemMap.routes.filter((route) => /\/admin(\/|$)/i.test(route.path) && !route.authDetected).map((route) => `${route.method} ${route.path}`),
      'Protect admin routes with server-side role checks.'
    )
  );
  checks.push(
    check(
      'vibe-placeholder-auth',
      'Mock or placeholder auth in production files',
      sources
        .filter((source) => /\b(TODO|FIXME|mockUser|fakeUser|placeholder auth|return null)\b/i.test(source.source) && !/test|fixture|mock/i.test(source.file))
        .map((source) => source.file),
      'Replace placeholder auth with real backend authorization before production use.',
      'medium'
    )
  );
  checks.push(
    check(
      'vibe-ai-client-config',
      'System prompt or AI tool config in frontend code',
      sources
        .filter((source) => /\.(tsx|jsx)$/.test(source.file) && /\b(systemPrompt|tools\s*:|toolChoice|mcpServers)\b/i.test(source.source))
        .map((source) => source.file),
      'Keep AI system prompts and tool permissions server-side.',
      'high'
    )
  );
  checks.push(
    check(
      'vibe-ai-dangerous-tools',
      'Dangerous AI tools without allowlist or approval',
      systemMap.aiToolCalls.filter((tool) => tool.dangerous && !tool.guardrailsDetected).map((tool) => `${tool.name} in ${tool.file}`),
      'Add allowlists, argument validation, audit logs, and human approval for dangerous tools.',
      'critical'
    )
  );
  checks.push(
    check(
      'vibe-fake-security-tests',
      'Tests that do not assert security behavior',
      sources
        .filter((source) => /(\.test|\.spec)\.[tj]sx?$/.test(source.file) && !/\b(403|401|unauthorized|forbidden|tenant|owner|signature|allowlist)\b/i.test(source.source))
        .map((source) => source.file),
      'Add regression tests for auth, ownership, signatures, uploads, and AI tool policy.',
      'medium'
    )
  );
  checks.push(
    check(
      'vibe-webhooks',
      'Missing webhook signature validation',
      findings.filter((finding) => finding.ruleId === 'BP-WEBHOOK-001').map((finding) => finding.affectedRoutes.join(', ')),
      'Verify webhook signatures before parsing or trusting payloads.'
    )
  );
  checks.push(
    check(
      'vibe-env-usage',
      'Broad service keys or unsafe env usage',
      sources.filter((source) => /\b(SERVICE_ROLE|service_role|PRIVATE_KEY|SECRET_KEY)\b/.test(source.source) && /app\/|src\//.test(source.file)).map((source) => source.file),
      'Keep service role keys and private keys out of frontend and route code unless the operation is explicitly trusted and audited.',
      'critical'
    )
  );

  return {
    generatedAt: new Date().toISOString(),
    message: 'Vibe-coded apps often look complete but miss backend security boundaries. These checks focus on security mistakes common in AI-generated code.',
    checks,
    summary: {
      failed: checks.filter((item) => item.status === 'failed').length,
      manualReview: checks.filter((item) => item.status === 'manual_review').length,
      passed: checks.filter((item) => item.status === 'passed').length
    }
  };
}

export function renderVibeAuditMarkdown(result: VibeAuditResult): string {
  return `# BreachProof Vibe-Code Audit

${result.message}

Failed checks: ${result.summary.failed}
Manual review: ${result.summary.manualReview}
Passed checks: ${result.summary.passed}

${result.checks
  .map(
    (checkItem) => `## ${checkItem.title}

Status: ${checkItem.status}
Severity: ${checkItem.severity}

Evidence:
${checkItem.evidence.map((item) => `- ${item}`).join('\n')}

Recommendation:
${checkItem.recommendation}
`
  )
  .join('\n')}
`;
}
