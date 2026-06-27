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
