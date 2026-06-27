import path from 'node:path';
import { readTextIfSmall, toRelative, walkFiles } from '../core/files.js';
import type { SystemMap } from '../core/types.js';

export interface AiLabIssue {
  id: string;
  title: string;
  severity: 'medium' | 'high' | 'critical';
  evidence: string;
  recommendation: string;
}

export interface AiLabResult {
  generatedAt: string;
  policy: string;
  issues: AiLabIssue[];
  summary: {
    dangerousTools: number;
    missingGuardrails: number;
    clientPromptExposure: number;
    broadManifests: number;
  };
}

async function sourceFiles(workspace: string): Promise<Array<{ file: string; source: string }>> {
  const files = await walkFiles(workspace);
  const selected = files.filter((file) => /\.(tsx?|jsx?|json|ya?ml)$/.test(file));
  const sources: Array<{ file: string; source: string }> = [];
  for (const file of selected) {
    sources.push({ file: toRelative(path.resolve(workspace), file), source: await readTextIfSmall(file).catch(() => '') });
  }
  return sources;
}

export async function runAiLab(workspace: string, systemMap: SystemMap): Promise<AiLabResult> {
  const sources = await sourceFiles(workspace);
  const issues: AiLabIssue[] = [];

  for (const tool of systemMap.aiToolCalls.filter((candidate) => candidate.dangerous)) {
    const route = systemMap.routes.find((candidate) => candidate.file === tool.file);
    if (route && route.bodyFields.length > 0) {
      issues.push({
        id: `ai-untrusted-tool-input-${tool.name}-${tool.file}`.replace(/[^A-Za-z0-9_-]/g, '-'),
        title: 'Untrusted request input reaches AI tool calls',
        severity: 'high',
        evidence: `${route.method} ${route.path} reads request fields (${route.bodyFields.join(', ')}) and exposes ${tool.name} in ${tool.file}.`,
        recommendation: 'Validate and constrain user-controlled tool names and arguments before model or tool dispatch.'
      });
    }
    if (!tool.guardrailsDetected) {
      issues.push({
        id: `ai-tool-${tool.name}-${tool.file}`.replace(/[^A-Za-z0-9_-]/g, '-'),
        title: 'Dangerous AI tool lacks policy guardrails',
        severity: 'critical',
        evidence: `${tool.name} is reachable in ${tool.file} without detected allowlist, approval, audit log, or tool policy.`,
        recommendation: 'Add a server-side tool policy with allowlists, argument validation, audit logging, and human approval for destructive tools.'
      });
    }
  }

  for (const source of sources.filter((candidate) => /\b(modelOutput|completion|assistantMessage)\b[\s\S]{0,120}\b(prisma\.|db\.|sql`|execute)\b/i.test(candidate.source))) {
    issues.push({
      id: `ai-db-write-${source.file}`.replace(/[^A-Za-z0-9_-]/g, '-'),
      title: 'Model output appears to reach database writes',
      severity: 'critical',
      evidence: `${source.file} contains model output near database write primitives.`,
      recommendation: 'Validate and constrain model output before writes; require policy approval for privileged changes.'
    });
  }

  for (const source of sources.filter((candidate) => /\.(tsx|jsx)$/.test(candidate.file) && /\b(systemPrompt|developerPrompt|mcpServers|tools\s*:)\b/i.test(candidate.source))) {
    issues.push({
      id: `ai-client-prompt-${source.file}`.replace(/[^A-Za-z0-9_-]/g, '-'),
      title: 'AI prompt or tool configuration appears in client code',
      severity: 'high',
      evidence: `${source.file} contains prompt/tool configuration names in a frontend file.`,
      recommendation: 'Move system prompts, MCP/tool manifests, and privileged tool choices to server-side code.'
    });
  }

  for (const source of sources.filter((candidate) => /mcp|plugin|tool/i.test(candidate.file) && /\b(all|admin|write|delete|\*)\b/i.test(candidate.source))) {
    issues.push({
      id: `ai-broad-manifest-${source.file}`.replace(/[^A-Za-z0-9_-]/g, '-'),
      title: 'MCP/plugin/tool manifest may grant broad permissions',
      severity: 'medium',
      evidence: `${source.file} contains broad permission words such as all/admin/write/delete/* in a tool manifest-like file.`,
      recommendation: 'Narrow tool permissions to the minimum scope and require explicit approval for destructive capabilities.'
    });
  }

  return {
    generatedAt: new Date().toISOString(),
    policy: 'Defensive AI-agent security lab. No jailbreak payload libraries, credential access, destructive tool execution, or public-target automation.',
    issues,
    summary: {
      dangerousTools: systemMap.aiToolCalls.filter((tool) => tool.dangerous).length,
      missingGuardrails: systemMap.aiToolCalls.filter((tool) => tool.dangerous && !tool.guardrailsDetected).length,
      clientPromptExposure: issues.filter((issue) => issue.title.includes('client code')).length,
      broadManifests: issues.filter((issue) => issue.title.includes('manifest')).length
    }
  };
}

export function renderAiLabMarkdown(result: AiLabResult): string {
  return `# BreachProof AI-Agent Security Lab

${result.policy}

- Dangerous tools: ${result.summary.dangerousTools}
- Missing guardrails: ${result.summary.missingGuardrails}
- Client prompt exposure: ${result.summary.clientPromptExposure}
- Broad manifests: ${result.summary.broadManifests}

${result.issues
  .map(
    (issue) => `## ${issue.title}

Severity: ${issue.severity}

Evidence:
${issue.evidence}

Recommendation:
${issue.recommendation}
`
  )
  .join('\n') || 'No AI-agent policy issues detected.'}
`;
}
