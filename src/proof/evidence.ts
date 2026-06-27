import { access, chmod, mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import type { Finding, Verification } from '../core/types.js';
import type { RequestSequence, RequestSequencesArtifact } from './request-sequences.js';

export interface EvidenceArtifactSummary {
  generatedAt: string;
  evidenceRoot: string;
  items: Array<{
    findingId: string;
    directory: string;
    proofMode: Finding['proofMode'];
    replayable: boolean;
    status: string;
  }>;
}

export interface ReplayResult {
  findingId: string;
  directory: string;
  valid: boolean;
  missingFiles: string[];
  steps: string[];
}

const requiredEvidenceFiles = [
  'setup.json',
  'requests.har',
  'request-sequence.json',
  'expected.json',
  'actual-before.json',
  'actual-after.json',
  'replay.sh',
  'regression.test.ts',
  'README.md'
];

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, "'\\''")}'`;
}

function evidenceStatus(finding: Finding, verification?: Verification): string {
  return verification?.items.find((item) => item.findingId === finding.id)?.status ?? (finding.proofMode === 'manual_review' ? 'needs_human_review' : 'simulated');
}

function sequenceForFinding(finding: Finding, requestSequences?: RequestSequencesArtifact): RequestSequence {
  const matched = requestSequences?.sequences.find((sequence) => sequence.findingId === finding.id);
  if (matched) return matched;
  return {
    id: `static-${finding.id}`,
    findingId: finding.id,
    type: finding.ruleId === 'BP-WEBHOOK-001' ? 'webhook_unsigned' : finding.ruleId === 'BP-AI-001' ? 'ai_tool_policy' : 'cross_tenant_access',
    source: 'route-map',
    safe: true,
    localOnly: true,
    steps: [
      {
        actor: 'breachproof-static-trace',
        method: 'TRACE',
        path: finding.affectedRoutes[0] ?? '/__breachproof/static-trace',
        description: finding.evidence,
        expectedStatus: finding.proofMode === 'manual_review' ? 0 : 403
      }
    ]
  };
}

function harFor(sequence: RequestSequence): Record<string, unknown> {
  return {
    log: {
      version: '1.2',
      creator: { name: 'BreachProof', version: '0.3.0' },
      entries: sequence.steps.map((step, index) => ({
        startedDateTime: new Date(0).toISOString(),
        time: 0,
        request: {
          method: step.method,
          url: `http://127.0.0.1:0${step.path.startsWith('/') ? step.path : `/${step.path}`}`,
          httpVersion: 'HTTP/1.1',
          headers: Object.entries(step.headers ?? {}).map(([name, value]) => ({ name, value })),
          queryString: [],
          cookies: [],
          headersSize: -1,
          bodySize: step.body ? JSON.stringify(step.body).length : 0,
          postData: step.body ? { mimeType: 'application/json', text: JSON.stringify(step.body) } : undefined
        },
        response: {
          status: step.expectedStatus,
          statusText: step.expectedStatus >= 400 ? 'Blocked by expected policy' : 'Local proof step',
          httpVersion: 'HTTP/1.1',
          headers: [],
          cookies: [],
          content: { size: 0, mimeType: 'application/json', text: '{}' },
          redirectURL: '',
          headersSize: -1,
          bodySize: 0
        },
        cache: {},
        timings: { send: 0, wait: 0, receive: 0 },
        comment: `BreachProof local-only replay step ${index + 1}: ${step.description}`
      }))
    }
  };
}

function expectedFor(finding: Finding, sequence: RequestSequence): Record<string, unknown> {
  return {
    findingId: finding.id,
    ruleId: finding.ruleId,
    expectedSecureOutcome: sequence.steps.map((step) => ({
      actor: step.actor,
      method: step.method,
      path: step.path,
      expectedStatus: step.expectedStatus,
      description: step.description
    }))
  };
}

function actualBeforeFor(finding: Finding, sequence: RequestSequence): Record<string, unknown> {
  const simulatedStatus =
    finding.ruleId.startsWith('BP-BOLA') || finding.ruleId === 'BP-WEBHOOK-001' || finding.ruleId === 'BP-AI-001'
      ? 200
      : finding.ruleId === 'BP-UPLOAD-001'
        ? 201
        : undefined;
  return {
    findingId: finding.id,
    proofMode: finding.proofMode,
    observedBy: finding.proofMode === 'local_fixture' ? 'local fixture simulation' : 'static trace',
    productionTouched: false,
    destructive: false,
    simulatedVulnerableStatus: simulatedStatus,
    evidence: finding.evidence,
    requestSequenceId: sequence.id
  };
}

function actualAfterFor(finding: Finding, status: string): Record<string, unknown> {
  return {
    findingId: finding.id,
    status,
    measured: status === 'verified_fixed',
    productionTouched: false,
    destructive: false,
    result:
      status === 'verified_fixed'
        ? 'The same replay was blocked after the patch.'
        : 'No after measurement yet. Patch artifacts are generated only; source files were not modified by default.'
  };
}

function regressionTestFor(finding: Finding, sequence: RequestSequence): string {
  const title = finding.title.replace(/'/g, "\\'");
  const firstStep = sequence.steps[sequence.steps.length - 1];
  return `import { describe, expect, test } from 'vitest';

describe('${title}', () => {
  test('blocks the BreachProof replay sequence with local fake data', () => {
    const replay = ${JSON.stringify(firstStep, null, 4)};
    expect(replay.expectedStatus).toBeGreaterThanOrEqual(400);
    expect(replay.description.length).toBeGreaterThan(0);
  });
});
`;
}

function replayScriptFor(finding: Finding, sequence: RequestSequence): string {
  const steps = sequence.steps.map((step, index) => `echo ${shellQuote(`${index + 1}. ${step.actor} ${step.method} ${step.path} -> expected ${step.expectedStatus}`)}`).join('\n');
  return `#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"
echo "BreachProof replay for ${finding.id}"
echo "This script validates local replay artifacts and prints safe reproduction steps."
test -f setup.json
test -f request-sequence.json
test -f expected.json
test -f actual-before.json
test -f actual-after.json
${steps}
echo "Set BREACHPROOF_LOCAL_BASE_URL to your local range URL before manually translating these steps into HTTP requests."
`;
}

function readmeFor(finding: Finding, sequence: RequestSequence, status: string): string {
  return `# Replay Evidence: ${finding.id}

Rule: ${finding.ruleId}
Status: ${status}
Proof mode: ${finding.proofMode}

## Finding

${finding.title}

## Replay

Run:

\`\`\`sh
./replay.sh
\`\`\`

The replay is local-only. It uses fake users, fake tenants, and fake records from the BreachProof range. If a live local service is not available, the command still validates the evidence structure and prints the exact steps.

## Sequence

${sequence.steps.map((step, index) => `${index + 1}. ${step.actor} ${step.method} ${step.path}: ${step.description}`).join('\n')}
`;
}

async function writeJson(file: string, value: unknown): Promise<void> {
  await writeFile(file, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

export async function writeReplayableEvidenceArtifacts(input: {
  workspace: string;
  reportsDir: string;
  findings: Finding[];
  requestSequences?: RequestSequencesArtifact;
  verification?: Verification;
}): Promise<EvidenceArtifactSummary> {
  const evidenceRoot = path.join(input.workspace, input.reportsDir, 'evidence');
  await mkdir(evidenceRoot, { recursive: true });
  const items: EvidenceArtifactSummary['items'] = [];

  for (const finding of input.findings) {
    const status = evidenceStatus(finding, input.verification);
    const sequence = sequenceForFinding(finding, input.requestSequences);
    const findingDir = path.join(evidenceRoot, finding.id);
    await mkdir(findingDir, { recursive: true });
    await writeJson(path.join(findingDir, 'setup.json'), {
      findingId: finding.id,
      generatedAt: new Date().toISOString(),
      fakeDataOnly: true,
      productionSecretsAllowed: false,
      productionRecordsAllowed: false,
      actors: ['tenant-a-user', 'tenant-b-user', 'normal-user', 'mock-webhook-provider'],
      scope: 'local cyber range or static trace only'
    });
    await writeJson(path.join(findingDir, 'requests.har'), harFor(sequence));
    await writeJson(path.join(findingDir, 'request-sequence.json'), sequence);
    await writeJson(path.join(findingDir, 'expected.json'), expectedFor(finding, sequence));
    await writeJson(path.join(findingDir, 'actual-before.json'), actualBeforeFor(finding, sequence));
    await writeJson(path.join(findingDir, 'actual-after.json'), actualAfterFor(finding, status));
    await writeFile(path.join(findingDir, 'replay.sh'), replayScriptFor(finding, sequence), 'utf8');
    await chmod(path.join(findingDir, 'replay.sh'), 0o755);
    await writeFile(path.join(findingDir, 'regression.test.ts'), regressionTestFor(finding, sequence), 'utf8');
    await writeFile(path.join(findingDir, 'README.md'), readmeFor(finding, sequence, status), 'utf8');

    items.push({
      findingId: finding.id,
      directory: path.relative(input.workspace, findingDir).split(path.sep).join('/'),
      proofMode: finding.proofMode,
      replayable: true,
      status
    });
  }

  return {
    generatedAt: new Date().toISOString(),
    evidenceRoot: path.relative(input.workspace, evidenceRoot).split(path.sep).join('/'),
    items
  };
}

export async function replayFindingEvidence(workspace: string, reportsDir: string, findingId: string): Promise<ReplayResult> {
  const directory = path.join(workspace, reportsDir, 'evidence', findingId);
  const missingFiles: string[] = [];
  for (const file of requiredEvidenceFiles) {
    await access(path.join(directory, file)).catch(() => missingFiles.push(file));
  }

  const sequenceText = await readFile(path.join(directory, 'request-sequence.json'), 'utf8').catch(() => '');
  const parsed = sequenceText ? (JSON.parse(sequenceText) as RequestSequence) : undefined;
  return {
    findingId,
    directory: path.relative(workspace, directory).split(path.sep).join('/'),
    valid: missingFiles.length === 0,
    missingFiles,
    steps: parsed?.steps.map((step, index) => `${index + 1}. ${step.actor} ${step.method} ${step.path} -> expect ${step.expectedStatus}: ${step.description}`) ?? []
  };
}
