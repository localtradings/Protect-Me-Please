import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';

export async function exportCodexSkill(workspace: string): Promise<string> {
  const target = path.join(workspace, 'skills', 'breachproof-codex');
  await mkdir(target, { recursive: true });
  await writeFile(
    path.join(target, 'SKILL.md'),
    `# BreachProof Codex Skill

Use this skill when running authorized local breach-path proof and fix verification with BreachProof.

## Boundaries

- Owned or explicitly authorized systems only.
- No destructive database actions.
- No billing, payment, subscription, or paid API activation.
- No public-target exploitation.
- Prefer local fixtures, fake data, and safe validation.

## Workflow

Map the repo, import corpus data, build reachability and attack graphs, run safe validation, generate patch and regression-test artifacts, verify the original weakness no longer reproduces after explicit application, then report evidence.
`,
    'utf8'
  );
  await writeFile(path.join(target, 'tool-usage.md'), '# Tool Usage\n\nUse shell for repo search, tests, builds, and reports. Use browser only for current official docs when useful.\n', 'utf8');
  await writeFile(path.join(target, 'workflows.md'), '# Workflows\n\n1. `breachproof map`\n2. `breachproof corpus import`\n3. `breachproof reachability`\n4. `breachproof validate`\n5. `breachproof fix`\n6. `breachproof verify`\n7. `breachproof report`\n', 'utf8');
  await writeFile(
    path.join(target, 'report-schema.json'),
    JSON.stringify(
      {
        product: 'BreachProof',
        finding: ['ruleId', 'severity', 'evidence', 'recommendation', 'verificationStatus']
      },
      null,
      2
    ),
    'utf8'
  );
  return target;
}
