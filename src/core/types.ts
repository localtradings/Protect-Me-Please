import { z } from 'zod';

export const productName = 'BreachProof';
export const productTagline = 'Prove real breach paths locally. Fix them. Verify they stay fixed.';

export const modeSchema = z.enum(['local', 'staging', 'ci', 'audit', 'validate', 'fix', 'auto']);
export type ProtectMode = z.infer<typeof modeSchema>;

export const severitySchema = z.enum(['info', 'low', 'medium', 'high', 'critical']);
export type Severity = z.infer<typeof severitySchema>;

export const proofModeSchema = z.enum(['static_trace', 'local_fixture', 'temp_patch_verify', 'http_replay_local_only', 'manual_review']);
export type ProofMode = z.infer<typeof proofModeSchema>;

export const fixStatusSchema = z.enum(['suggested', 'patch_created', 'test_added', 'verified_fixed', 'needs_human_review']);
export type FixStatus = z.infer<typeof fixStatusSchema>;

export const proofVerificationStatusSchema = z.enum([
  'unverified',
  'simulated',
  'confirmed_local',
  'patch_created',
  'verified_fixed',
  'needs_human_review'
]);
export type ProofVerificationStatus = z.infer<typeof proofVerificationStatusSchema>;

export const scopeConfigSchema = z.object({
  version: z.literal(1),
  product: z.literal(productName),
  mode: modeSchema,
  workspace: z.string().min(1),
  allowedPaths: z.array(z.string().min(1)).default(['.']),
  stagingTargets: z.array(z.string().url()).default([]),
  reportsDir: z.string().min(1).default('reports'),
  stateDir: z.string().min(1).default('.breachproof'),
  autofix: z
    .object({
      enabled: z.boolean().default(false),
      apply: z.boolean().default(false),
      createPrReadyPatch: z.boolean().default(true)
    })
    .default({ enabled: false, apply: false, createPrReadyPatch: true }),
  ci: z
    .object({
      failOnSeverity: severitySchema.default('critical'),
      uploadSarif: z.boolean().default(true)
    })
    .default({ failOnSeverity: 'critical', uploadSarif: true }),
  plugins: z
    .object({
      enabled: z.boolean().default(true),
      directories: z.array(z.string()).default(['plugins'])
    })
    .default({ enabled: true, directories: ['plugins'] })
});

export type ScopeConfig = z.infer<typeof scopeConfigSchema>;

export const approvalRecordSchema = z.object({
  product: z.literal(productName),
  approvedAt: z.string().datetime(),
  approvedBy: z.string().min(1),
  mode: modeSchema,
  workspace: z.string().min(1),
  scopeHash: z.string().length(64),
  scopeSummary: z.object({
    allowedPaths: z.array(z.string()),
    stagingTargets: z.array(z.string()),
    autofixEnabled: z.boolean(),
    applyEnabled: z.boolean()
  })
});

export type ApprovalRecord = z.infer<typeof approvalRecordSchema>;

export const routeNodeSchema = z.object({
  id: z.string(),
  path: z.string(),
  method: z.string(),
  file: z.string(),
  framework: z.enum(['nextjs', 'express', 'unknown']),
  authDetected: z.boolean(),
  ownershipCheckDetected: z.boolean(),
  bodyFields: z.array(z.string()),
  dangerousBodyFields: z.array(z.string()),
  prismaModels: z.array(z.string()),
  webhookSignatureDetected: z.boolean(),
  uploadValidationDetected: z.boolean(),
  sourceSummary: z.string()
});

export type RouteNode = z.infer<typeof routeNodeSchema>;

export const dataModelSchema = z.object({
  name: z.string(),
  fields: z.array(z.string()),
  file: z.string()
});

export type DataModel = z.infer<typeof dataModelSchema>;

export const authBoundarySchema = z.object({
  routeId: z.string(),
  mechanism: z.string(),
  file: z.string()
});

export type AuthBoundary = z.infer<typeof authBoundarySchema>;

export const aiToolCallSchema = z.object({
  name: z.string(),
  file: z.string(),
  routePath: z.string().optional(),
  dangerous: z.boolean(),
  guardrailsDetected: z.boolean()
});

export type AiToolCall = z.infer<typeof aiToolCallSchema>;

export const systemMapSchema = z.object({
  product: z.literal(productName),
  projectName: z.string(),
  workspace: z.string(),
  generatedAt: z.string().datetime(),
  languages: z.array(z.string()),
  frameworks: z.array(z.string()),
  packageManifests: z.array(z.string()),
  dependencies: z.record(z.string(), z.string()),
  routes: z.array(routeNodeSchema),
  dataModels: z.array(dataModelSchema),
  authBoundaries: z.array(authBoundarySchema),
  aiToolCalls: z.array(aiToolCallSchema),
  docker: z.object({
    files: z.array(z.string()),
    services: z.array(z.string())
  }),
  ci: z.object({
    workflows: z.array(z.string()),
    unsafeTriggers: z.array(z.string())
  }),
  filesScanned: z.number().int().nonnegative()
});

export type SystemMap = z.infer<typeof systemMapSchema>;

export const affectedPackageSchema = z.object({
  ecosystem: z.string(),
  name: z.string(),
  range: z.string().optional(),
  fixedVersion: z.string().optional(),
  purl: z.string().optional()
});

export type AffectedPackage = z.infer<typeof affectedPackageSchema>;

export const normalizedVulnerabilitySchema = z.object({
  id: z.string(),
  aliases: z.array(z.string()).default([]),
  source: z.string(),
  sources: z.array(z.string()).default([]),
  summary: z.string(),
  details: z.string().default(''),
  severity: severitySchema,
  cvss: z.number().min(0).max(10).optional(),
  cwe: z.array(z.string()).default([]),
  affectedPackages: z.array(affectedPackageSchema).default([]),
  kev: z.boolean().default(false),
  kevDetails: z
    .object({
      dateAdded: z.string().optional(),
      dueDate: z.string().optional(),
      requiredAction: z.string().optional()
    })
    .optional(),
  epss: z
    .object({
      score: z.number().min(0).max(1),
      percentile: z.number().min(0).max(1),
      date: z.string().optional()
    })
    .optional(),
  exploitLikelihood: z.number().min(0).max(1),
  references: z.array(z.string()).default([]),
  remediation: z.string()
});

export type NormalizedVulnerability = z.infer<typeof normalizedVulnerabilitySchema>;
export type VulnerabilityRecord = NormalizedVulnerability;

export const vulnerabilityCorpusSchema = z.object({
  importedAt: z.string().datetime(),
  sources: z.array(z.string()),
  records: z.array(normalizedVulnerabilitySchema)
});

export type VulnerabilityCorpus = z.infer<typeof vulnerabilityCorpusSchema>;

export const vulnerabilityCorpusSummarySchema = z.object({
  generatedAt: z.string().datetime(),
  sources: z.array(z.string()),
  recordsLoaded: z.number().int().nonnegative(),
  matchedComponents: z.number().int().nonnegative(),
  possiblyReachableIssues: z.number().int().nonnegative(),
  highExploitLikelihoodIssues: z.number().int().nonnegative(),
  safelyValidatedIssues: z.number().int().nonnegative(),
  autoFixedIssues: z.number().int().nonnegative(),
  manualReviewIssues: z.number().int().nonnegative()
});

export type VulnerabilityCorpusSummary = z.infer<typeof vulnerabilityCorpusSummarySchema>;

export const reachabilityNodeSchema = z.object({
  id: z.string(),
  type: z.enum(['route', 'file', 'function', 'import', 'field', 'model', 'package', 'auth', 'ownership', 'webhook', 'upload', 'ai_tool', 'job', 'ci']),
  label: z.string(),
  file: z.string().optional(),
  metadata: z.record(z.string(), z.string()).default({})
});

export type ReachabilityNode = z.infer<typeof reachabilityNodeSchema>;

export const reachabilityEdgeSchema = z.object({
  from: z.string(),
  to: z.string(),
  kind: z.string(),
  evidence: z.string(),
  file: z.string().optional()
});

export type ReachabilityEdge = z.infer<typeof reachabilityEdgeSchema>;

export const reachabilityGraphSchema = z.object({
  generatedAt: z.string().datetime(),
  nodes: z.array(reachabilityNodeSchema),
  edges: z.array(reachabilityEdgeSchema),
  summary: z.object({
    reachableRoutes: z.number().int().nonnegative(),
    reachableDependencies: z.array(z.string()),
    reachableModels: z.array(z.string()),
    aiToolFlows: z.number().int().nonnegative()
  })
});

export type ReachabilityGraph = z.infer<typeof reachabilityGraphSchema>;

export const attackGraphSchema = z.object({
  nodes: z.array(
    z.object({
      id: z.string(),
      type: z.enum(['route', 'auth', 'data', 'weakness', 'dependency', 'ai_tool', 'ci', 'proof']),
      label: z.string(),
      metadata: z.record(z.string(), z.string()).default({})
    })
  ),
  edges: z.array(
    z.object({
      from: z.string(),
      to: z.string(),
      label: z.string()
    })
  )
});

export type AttackGraph = z.infer<typeof attackGraphSchema>;

export const findingSchema = z.object({
  id: z.string(),
  ruleId: z.string(),
  title: z.string(),
  severity: severitySchema,
  status: z.enum(['validated', 'needs_fix', 'manual_review', 'fixed']),
  fixStatus: fixStatusSchema.default('suggested'),
  proofMode: proofModeSchema,
  affectedFiles: z.array(z.string()),
  affectedRoutes: z.array(z.string()),
  attackPath: z.array(z.string()),
  evidence: z.string(),
  exploitabilityReasoning: z.string(),
  recommendation: z.string(),
  patchStatus: fixStatusSchema.default('suggested'),
  verificationStatus: z.enum(['not_run', 'passed', 'failed', 'manual_review']),
  validation: z.object({
    mode: modeSchema,
    destructive: z.boolean(),
    productionTouched: z.boolean(),
    summary: z.string()
  })
});

export type Finding = z.infer<typeof findingSchema>;

export const validationPlanSchema = z.object({
  generatedAt: z.string().datetime(),
  items: z.array(
    z.object({
      findingId: z.string(),
      ruleId: z.string(),
      proofMode: proofModeSchema,
      safe: z.boolean(),
      destructive: z.boolean(),
      steps: z.array(z.string()),
      expectedEvidence: z.string()
    })
  )
});

export type ValidationPlan = z.infer<typeof validationPlanSchema>;

export const evidenceBundleSchema = z.object({
  generatedAt: z.string().datetime(),
  items: z.array(
    z.object({
      findingId: z.string(),
      proofMode: proofModeSchema,
      before: z.string(),
      after: z.string().optional(),
      productionTouched: z.boolean(),
      destructive: z.boolean()
    })
  )
});

export type EvidenceBundle = z.infer<typeof evidenceBundleSchema>;

export const patchSummarySchema = z.object({
  generatedAt: z.string().datetime(),
  apply: z.boolean(),
  items: z.array(
    z.object({
      findingId: z.string(),
      status: fixStatusSchema,
      patchFile: z.string().optional(),
      testFile: z.string().optional(),
      summary: z.string()
    })
  )
});

export type PatchSummary = z.infer<typeof patchSummarySchema>;

export const verificationSchema = z.object({
  generatedAt: z.string().datetime(),
  items: z.array(
    z.object({
      findingId: z.string(),
      status: proofVerificationStatusSchema,
      proofMode: proofModeSchema,
      productionTouched: z.boolean(),
      destructive: z.boolean(),
      summary: z.string()
    })
  )
});

export type Verification = z.infer<typeof verificationSchema>;

export const reportSchema = z.object({
  product: z.literal(productName),
  tagline: z.literal(productTagline),
  project: z.string(),
  mode: modeSchema,
  scopeApproved: z.boolean(),
  productionTouched: z.boolean(),
  generatedAt: z.string().datetime(),
  summary: vulnerabilityCorpusSummarySchema,
  systemMap: systemMapSchema,
  reachabilityGraph: reachabilityGraphSchema,
  attackGraph: attackGraphSchema,
  validationPlan: validationPlanSchema,
  evidence: evidenceBundleSchema,
  patchSummary: patchSummarySchema,
  verification: verificationSchema,
  findings: z.array(findingSchema)
});

export type ProtectReport = z.infer<typeof reportSchema>;

export const pluginManifestSchema = z.object({
  name: z.string().min(1),
  version: z.string().min(1),
  type: z.enum([
    'analyzer',
    'validator',
    'vulnerability-feed',
    'reporter',
    'fixer',
    'rule-pack',
    'invariant-pack',
    'range-provider',
    'patch-generator',
    'report-renderer',
    'ai-agent-policy-check'
  ]),
  supportedFrameworks: z.array(z.string()),
  inputs: z.array(z.string()),
  outputs: z.array(z.string()),
  permissionsNeeded: z.array(z.string()),
  entrypoint: z.string().min(1)
});

export type PluginManifest = z.infer<typeof pluginManifestSchema>;

export const auditEventSchema = z.object({
  timestamp: z.string().datetime(),
  product: z.literal(productName),
  action: z.string(),
  actor: z.string(),
  mode: modeSchema,
  status: z.enum(['started', 'completed', 'failed', 'refused']),
  message: z.string()
});

export type AuditEvent = z.infer<typeof auditEventSchema>;
