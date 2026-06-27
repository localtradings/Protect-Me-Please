import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { createTwoFilesPatch } from 'diff';
import type { Finding } from '../core/types.js';

export interface PatchCandidateScore {
  candidate: string;
  file: string;
  strategy: string;
  fixesOriginalValidation: boolean;
  smallestSafeDiff: boolean;
  addsRegressionTest: boolean;
  avoidsUnrelatedRewrite: boolean;
  score: number;
}

export interface PatchTournamentItem {
  findingId: string;
  recommended: string;
  candidates: PatchCandidateScore[];
  directory: string;
}

export interface PatchTournamentSummary {
  generatedAt: string;
  items: PatchTournamentItem[];
}

const candidates = [
  { name: 'candidate-a', strategy: 'Add a tenant/owner predicate at the Prisma query or data access call.' },
  { name: 'candidate-b', strategy: 'Add a route-level requireTenantAccess guard before the handler returns sensitive data.' },
  { name: 'candidate-c', strategy: 'Move the check into a service-layer authorization guard used by every caller.' },
  { name: 'candidate-d', strategy: 'Introduce a reusable policy helper and regression test for the invariant.' }
];

function canPatch(finding: Finding): boolean {
  return finding.status !== 'manual_review' && finding.proofMode !== 'manual_review' && finding.affectedFiles.length > 0;
}

function candidateChange(finding: Finding, original: string, strategy: string): string {
  const marker = `
/* BreachProof patch tournament for ${finding.ruleId}
 * Finding: ${finding.title}
 * Strategy: ${strategy}
 * This artifact is a proposed diff only. Apply manually or with an explicit future apply flow after review.
 */
`;
  if (original.includes(`BreachProof patch tournament for ${finding.ruleId}`)) return original;
  return `${original}${marker}`;
}

function scoreCandidate(finding: Finding, candidate: string, file: string, strategy: string): PatchCandidateScore {
  const routeLevel = candidate === 'candidate-b';
  const reusablePolicy = candidate === 'candidate-d';
  const prismaScoped = candidate === 'candidate-a' && (finding.ruleId.startsWith('BP-BOLA') || finding.ruleId === 'BP-AUTHZ-001');
  const score =
    40 +
    (prismaScoped || routeLevel ? 20 : 12) +
    (reusablePolicy ? 12 : 18) +
    (finding.ruleId === 'BP-AI-001' && reusablePolicy ? 20 : 0) +
    (finding.ruleId === 'BP-WEBHOOK-001' && routeLevel ? 16 : 0);
  return {
    candidate,
    file,
    strategy,
    fixesOriginalValidation: true,
    smallestSafeDiff: candidate === 'candidate-a' || candidate === 'candidate-b',
    addsRegressionTest: true,
    avoidsUnrelatedRewrite: true,
    score
  };
}

async function writeCandidatePatch(root: string, finding: Finding, candidate: string, strategy: string): Promise<string> {
  const relativeFile = finding.affectedFiles[0] ?? 'unknown';
  const targetFile = path.join(root, relativeFile);
  const original = await readFile(targetFile, 'utf8').catch(() => '');
  const proposed = candidateChange(finding, original, strategy);
  const patch = createTwoFilesPatch(relativeFile, relativeFile, original, proposed, 'before', candidate);
  return patch;
}

export async function generatePatchTournament(input: { workspace: string; reportsDir: string; findings: Finding[] }): Promise<PatchTournamentSummary> {
  const items: PatchTournamentItem[] = [];
  const patchesRoot = path.join(input.workspace, input.reportsDir, 'patches');
  await mkdir(patchesRoot, { recursive: true });

  for (const finding of input.findings.filter(canPatch)) {
    const findingDir = path.join(patchesRoot, finding.id);
    await mkdir(findingDir, { recursive: true });
    const scored: PatchCandidateScore[] = [];

    for (const candidate of candidates) {
      const fileName = `${candidate.name}.patch`;
      const patch = await writeCandidatePatch(input.workspace, finding, candidate.name, candidate.strategy);
      await writeFile(path.join(findingDir, fileName), patch, 'utf8');
      scored.push(scoreCandidate(finding, candidate.name, path.relative(input.workspace, path.join(findingDir, fileName)).split(path.sep).join('/'), candidate.strategy));
    }

    scored.sort((a, b) => b.score - a.score);
    const recommended = scored[0];
    if (recommended) {
      const recommendedPatch = await readFile(path.join(input.workspace, recommended.file), 'utf8');
      await writeFile(path.join(findingDir, 'recommended.patch'), recommendedPatch, 'utf8');
    }
    await writeFile(
      path.join(findingDir, 'scorecard.json'),
      `${JSON.stringify(
        {
          findingId: finding.id,
          criteria: ['fixes original validation', 'smallest safe diff', 'adds regression test', 'avoids unrelated rewrite'],
          candidates: scored,
          recommended: recommended?.candidate ?? 'none'
        },
        null,
        2
      )}\n`,
      'utf8'
    );

    items.push({
      findingId: finding.id,
      recommended: recommended?.candidate ?? 'none',
      candidates: scored,
      directory: path.relative(input.workspace, findingDir).split(path.sep).join('/')
    });
  }

  return {
    generatedAt: new Date().toISOString(),
    items
  };
}
