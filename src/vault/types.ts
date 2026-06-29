import { z } from 'zod';
import {
  findingSchema,
  fixStatusSchema,
  modeSchema,
  severitySchema,
  type Finding,
  type FixStatus,
  type ProtectMode
} from '../core/types.js';

export const vaultNodeTypeSchema = z.enum([
  'run',
  'route',
  'finding',
  'invariant',
  'patch',
  'replay',
  'test',
  'asset'
]);
export type VaultNodeType = z.infer<typeof vaultNodeTypeSchema>;

export const vaultEdgeTypeSchema = z.enum([
  'observed_in',
  'affects',
  'violates',
  'reaches',
  'proved_by',
  'fixed_by',
  'verified_by',
  'similar_to',
  'reopened_from',
  'repeated_from',
  'protects'
]);
export type VaultEdgeType = z.infer<typeof vaultEdgeTypeSchema>;

export const vaultLifecycleSchema = z.enum([
  'new',
  'repeated',
  'fixed',
  'reopened',
  'not_observed'
]);
export type VaultLifecycle = z.infer<typeof vaultLifecycleSchema>;

export const vaultNodeSchema = z
  .object({
    id: z.string().min(1),
    type: vaultNodeTypeSchema,
    label: z.string().min(1),
    status: z.string().min(1),
    severity: severitySchema.optional(),
    runId: z.string().min(1).optional(),
    route: z.string().min(1).optional(),
    notePath: z.string().min(1).optional(),
    profilePath: z.string().min(1).optional(),
    metadata: z.record(z.string(), z.string()).default({})
  })
  .strict();
export type VaultNode = z.infer<typeof vaultNodeSchema>;

const vaultEdgeBaseSchema = z
  .object({
    id: z.string().min(1),
    from: z.string().min(1),
    to: z.string().min(1),
    label: z.string().min(1),
    evidence: z.string().min(1),
    artifactPaths: z.array(z.string().min(1)).nonempty()
  })
  .strict();

const vaultNonSimilarEdgeTypeSchema = z.enum([
  'observed_in',
  'affects',
  'violates',
  'reaches',
  'proved_by',
  'fixed_by',
  'verified_by',
  'reopened_from',
  'repeated_from',
  'protects'
]);

const vaultNonSimilarEdgeSchema = vaultEdgeBaseSchema
  .extend({
    type: vaultNonSimilarEdgeTypeSchema,
    score: z.number().min(0).max(1).optional(),
    signals: z.array(z.string().min(1)).default([])
  })
  .strict();

const vaultSimilarEdgeSchema = vaultEdgeBaseSchema
  .extend({
    type: z.literal('similar_to'),
    score: z.number().min(0).max(1),
    signals: z.array(z.string().min(1)).nonempty()
  })
  .strict();

export const vaultEdgeSchema = z.discriminatedUnion('type', [
  vaultSimilarEdgeSchema,
  vaultNonSimilarEdgeSchema
]);
export type VaultEdge = z.infer<typeof vaultEdgeSchema>;

export const vaultTimelineEventSchema = z
  .object({
    id: z.string().min(1),
    runId: z.string().min(1),
    findingFingerprint: z.string().min(1),
    lifecycle: vaultLifecycleSchema,
    timestamp: z.string().datetime(),
    ruleId: z.string().min(1),
    title: z.string().min(1),
    relatedFingerprint: z.string().min(1).optional(),
    evidence: z.string().min(1).optional(),
    artifactPaths: z.array(z.string().min(1)).default([])
  })
  .strict();
export type VaultTimelineEvent = z.infer<typeof vaultTimelineEventSchema>;

export const vaultGraphSummarySchema = z
  .object({
    nodes: z.number().int().nonnegative(),
    edges: z.number().int().nonnegative(),
    newIssues: z.number().int().nonnegative(),
    fixedIssues: z.number().int().nonnegative(),
    reopenedIssues: z.number().int().nonnegative(),
    repeatedIssues: z.number().int().nonnegative()
  })
  .strict();
export type VaultGraphSummary = z.infer<typeof vaultGraphSummarySchema>;

export const vaultGraphSchema = z
  .object({
    schemaVersion: z.literal(1),
    generatedAt: z.string().datetime(),
    project: z.string().min(1),
    currentRunId: z.string().min(1),
    nodes: z.array(vaultNodeSchema),
    edges: z.array(vaultEdgeSchema),
    timeline: z.array(vaultTimelineEventSchema),
    summary: vaultGraphSummarySchema
  })
  .strict();
export type VaultGraph = z.infer<typeof vaultGraphSchema>;

export const vaultLifecycleInputSchema = z.enum(['observed', 'verified_fixed']);
export type VaultLifecycleInput = z.infer<typeof vaultLifecycleInputSchema>;

export interface VaultRunEvent {
  id: string;
  mode: ProtectMode;
  scopeHash: string;
  startedAt: string;
  completedAt: string;
  reportPath: string;
}

export const vaultRunEventSchema = z
  .object({
    id: z.string().min(1),
    mode: modeSchema,
    scopeHash: z.string().length(64),
    startedAt: z.string().datetime(),
    completedAt: z.string().datetime(),
    reportPath: z.string().min(1)
  })
  .strict();

export interface VaultFindingEvent {
  id: string;
  runId: string;
  fingerprint: string;
  lifecycleInput: VaultLifecycleInput;
  ruleId: string;
  finding: Finding;
  verificationStatus: Finding['verificationStatus'] | 'verified_fixed';
  observedAt: string;
}

export const vaultFindingEventSchema = z
  .object({
    id: z.string().min(1),
    runId: z.string().min(1),
    fingerprint: z.string().min(1),
    lifecycleInput: vaultLifecycleInputSchema,
    ruleId: z.string().min(1),
    finding: findingSchema,
    verificationStatus: z.enum(['not_run', 'passed', 'failed', 'manual_review', 'verified_fixed']),
    observedAt: z.string().datetime()
  })
  .strict();

export interface VaultPatchEvent {
  id: string;
  runId: string;
  findingFingerprint: string;
  patternId: string;
  ruleId: string;
  framework: string;
  fileRole: string;
  strategy: string;
  changePattern: string;
  outcome: FixStatus;
  patchFile?: string;
  testFile?: string;
  verificationEvidence: string;
  observedAt: string;
}

export const vaultPatchEventSchema = z
  .object({
    id: z.string().min(1),
    runId: z.string().min(1),
    findingFingerprint: z.string().min(1),
    patternId: z.string().min(1),
    ruleId: z.string().min(1),
    framework: z.string().min(1),
    fileRole: z.string().min(1),
    strategy: z.string().min(1),
    changePattern: z.string().min(1),
    outcome: fixStatusSchema,
    patchFile: z.string().min(1).optional(),
    testFile: z.string().min(1).optional(),
    verificationEvidence: z.string().min(1),
    observedAt: z.string().datetime()
  })
  .strict();

export interface VaultReplayEvent {
  id: string;
  runId: string;
  findingFingerprint: string;
  replayId: string;
  status: 'passed' | 'failed' | 'not_run' | 'manual_review';
  evidence: string;
  artifactPath?: string;
  localOnly: boolean;
  observedAt: string;
}

export const vaultReplayEventSchema = z
  .object({
    id: z.string().min(1),
    runId: z.string().min(1),
    findingFingerprint: z.string().min(1),
    replayId: z.string().min(1),
    status: z.enum(['passed', 'failed', 'not_run', 'manual_review']),
    evidence: z.string().min(1),
    artifactPath: z.string().min(1).optional(),
    localOnly: z.boolean(),
    observedAt: z.string().datetime()
  })
  .strict();

export interface VaultRunSnapshot {
  run: VaultRunEvent;
  findings: Array<{
    finding: Finding;
    fingerprint: string;
    lifecycleInput: VaultLifecycleInput;
  }>;
  patches: VaultPatchEvent[];
  replays: VaultReplayEvent[];
}

export const vaultRunSnapshotSchema = z
  .object({
    run: vaultRunEventSchema,
    findings: z.array(
      z
        .object({
          finding: findingSchema,
          fingerprint: z.string().min(1),
          lifecycleInput: vaultLifecycleInputSchema
        })
        .strict()
    ),
    patches: z.array(vaultPatchEventSchema),
    replays: z.array(vaultReplayEventSchema)
  })
  .strict();

export interface VaultHistory {
  runs: VaultRunEvent[];
  findings: VaultFindingEvent[];
  patches: VaultPatchEvent[];
  replays: VaultReplayEvent[];
}

export const vaultHistorySchema = z
  .object({
    runs: z.array(vaultRunEventSchema),
    findings: z.array(vaultFindingEventSchema),
    patches: z.array(vaultPatchEventSchema),
    replays: z.array(vaultReplayEventSchema)
  })
  .strict();

export interface VaultPatchMemory {
  patternId: string;
  ruleId: string;
  framework: string;
  fileRole: string;
  strategy: string;
  changePattern: string;
  regressionTestArtifact: string;
  verificationRunId: string;
  verificationEvidence: string;
  findingFingerprints: string[];
  reopenedCount: number;
  outcome: 'verified_fixed';
}

export const vaultPatchMemorySchema = z
  .object({
    patternId: z.string().min(1),
    ruleId: z.string().min(1),
    framework: z.string().min(1),
    fileRole: z.string().min(1),
    strategy: z.string().min(1),
    changePattern: z.string().min(1),
    regressionTestArtifact: z.string().min(1),
    verificationRunId: z.string().min(1),
    verificationEvidence: z.string().min(1),
    findingFingerprints: z.array(z.string().min(1)),
    reopenedCount: z.number().int().nonnegative(),
    outcome: z.literal('verified_fixed')
  })
  .strict();

export interface FindingSimilarity {
  currentFingerprint: string;
  previousFingerprint: string;
  score: number;
  signals: string[];
  exactMatch: boolean;
  components: FindingSimilarityComponents;
}

export interface FindingSimilarityComponents {
  same_rule: number;
  same_control_family: number;
  same_sink: number;
  route_tokens: number;
  same_framework_file_role: number;
  evidence_tags: number;
}
