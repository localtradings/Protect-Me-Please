import type { Finding } from '../../src/core/types.js';

export function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'generated-id',
    ruleId: 'BP-BOLA-002',
    title: 'Tenant escape through invoice lookup',
    severity: 'high',
    status: 'validated',
    fixStatus: 'suggested',
    proofMode: 'static_trace',
    affectedFiles: ['app/api/invoices/[id]/route.ts'],
    affectedRoutes: ['GET /api/invoices/[id]'],
    attackPath: ['GET /api/invoices/[id]', 'Invoice'],
    evidence: 'Prisma Invoice lookup lacks tenantId',
    exploitabilityReasoning: 'A request-controlled invoice id reaches an Invoice lookup without tenant isolation.',
    recommendation: 'Scope the Invoice lookup to the authenticated principal tenantId.',
    patchStatus: 'suggested',
    verificationStatus: 'not_run',
    validation: {
      mode: 'local',
      destructive: false,
      productionTouched: false,
      summary: 'Static trace with local invoice and tenant fixtures.'
    },
    ...overrides
  };
}

export function makeProductionBolaFinding(overrides: Partial<Finding> = {}): Finding {
  return makeFinding({
    ruleId: 'BP-BOLA-001',
    title: 'Broken object-level authorization path is reachable',
    affectedRoutes: ['/api/invoices/[id]'],
    attackPath: [
      'user-controlled id',
      'GET /api/invoices/[id]',
      'Invoice.findUnique',
      'missing tenant or owner predicate'
    ],
    evidence: 'User-controlled id reaches Prisma Invoice.findUnique without a tenantId or ownerId predicate.',
    ...overrides
  });
}

export function makeAiToolFinding(overrides: Partial<Finding> = {}): Finding {
  return makeFinding({
    ruleId: 'BP-RULE-AI-TOOL-001',
    title: 'Dangerous AI tool call lacks guardrails',
    severity: 'critical',
    affectedFiles: ['src/agents/user-tools.ts'],
    affectedRoutes: ['POST /api/agents/execute'],
    attackPath: ['untrusted user input', 'deleteUser', 'destructive or privileged action'],
    evidence: 'deleteUser tool is reachable without an allowlist or policy guardrails.',
    ...overrides
  });
}
