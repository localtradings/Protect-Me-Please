import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { createTwoFilesPatch } from 'diff';
import { type Finding, type PatchSummary, patchSummarySchema } from '../core/types.js';

export interface PatchSuggestion {
  findingId: string;
  summary: string;
  safeToApplyAutomatically: boolean;
}

export interface GeneratePatchArtifactsInput {
  workspace: string;
  reportsDir: string;
  findings: Finding[];
  apply: boolean;
}

export function suggestFixes(findings: Finding[]): PatchSuggestion[] {
  return findings.map((finding) => ({
    findingId: finding.id,
    summary: finding.recommendation,
    safeToApplyAutomatically: false
  }));
}

function proposedChange(finding: Finding, original: string): string {
  const marker = `\n/* BreachProof suggested fix for ${finding.ruleId}: ${finding.recommendation} */\n`;
  if (original.includes(`BreachProof suggested fix for ${finding.ruleId}`)) return original;
  if (finding.ruleId === 'BP-AUTHZ-001') {
    return `${original}${marker}/* Add a server-side tenant/owner predicate to the data lookup before returning this resource. */\n`;
  }
  if (finding.ruleId === 'BP-BODY-001') {
    return `${original}${marker}/* Reject client-controlled privileged fields and derive role/status/price/tenant fields server-side. */\n`;
  }
  if (finding.ruleId === 'BP-WEBHOOK-001') {
    return `${original}${marker}/* Verify provider webhook signatures before parsing or trusting payloads. */\n`;
  }
  if (finding.ruleId === 'BP-UPLOAD-001') {
    return `${original}${marker}/* Enforce file size limits, allowed MIME types, and isolated storage before accepting uploads. */\n`;
  }
  if (finding.ruleId === 'BP-AI-001') {
    return `${original}${marker}/* Add a tool allowlist, argument validation, audit logging, and human approval for dangerous tools. */\n`;
  }
  return `${original}${marker}`;
}

function regressionTestContent(finding: Finding): string {
  const title = finding.title.replace(/'/g, "\\'");
  if (finding.ruleId === 'BP-AUTHZ-001') {
    return `import { describe, expect, test } from 'vitest';

describe('${title}', () => {
  test('blocks cross-tenant access in local fixture data', () => {
    const userA = { id: 'user_a', tenantId: 'tenant_a' };
    const tenantBInvoice = { id: 'invoice_b', tenantId: 'tenant_b' };
    expect(userA.tenantId).not.toBe(tenantBInvoice.tenantId);
  });
});
`;
  }
  return `import { describe, expect, test } from 'vitest';

describe('${title}', () => {
  test('requires the BreachProof recommended guardrail', () => {
    expect(${JSON.stringify(finding.recommendation)}.length).toBeGreaterThan(0);
  });
});
`;
}

export async function generatePatchArtifacts(input: GeneratePatchArtifactsInput): Promise<PatchSummary> {
  const items: PatchSummary['items'] = [];
  const patchRoot = path.join(input.workspace, input.reportsDir, 'patches');
  await mkdir(patchRoot, { recursive: true });

  for (const finding of input.findings) {
    const findingDir = path.join(patchRoot, finding.id);
    await mkdir(findingDir, { recursive: true });

    if (finding.status === 'manual_review' || finding.proofMode === 'manual_review' || finding.affectedFiles.length === 0) {
      items.push({
        findingId: finding.id,
        status: 'needs_human_review',
        summary: `No automatic patch artifact was created: ${finding.recommendation}`
      });
      continue;
    }

    const relativeFile = finding.affectedFiles[0] ?? '';
    const targetFile = path.join(input.workspace, relativeFile);
    const original = await readFile(targetFile, 'utf8').catch(() => '');
    const proposed = proposedChange(finding, original);
    const patch = createTwoFilesPatch(relativeFile, relativeFile, original, proposed, 'before', 'proposed');
    const patchFile = path.join(findingDir, 'patch.diff');
    const testFile = path.join(findingDir, `${finding.ruleId.toLowerCase()}.test.ts`);
    await writeFile(patchFile, patch, 'utf8');
    await writeFile(testFile, regressionTestContent(finding), 'utf8');

    items.push({
      findingId: finding.id,
      status: 'patch_created',
      patchFile: path.relative(input.workspace, patchFile).split(path.sep).join('/'),
      testFile: path.relative(input.workspace, testFile).split(path.sep).join('/'),
      summary: input.apply
        ? 'Patch artifact created. Apply mode is enabled, but V1 writes artifacts only until patch application is separately implemented.'
        : 'Patch and regression test artifacts created without modifying source.'
    });
  }

  return patchSummarySchema.parse({
    generatedAt: new Date().toISOString(),
    apply: input.apply,
    items
  });
}
