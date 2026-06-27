import { mkdtemp, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { describe, expect, test } from 'vitest';
import { parsePluginManifest } from '../../src/plugins/plugin-manifest.js';
import { exportCodexSkill } from '../../src/skills/exporter.js';

describe('plugin manifests and skill export', () => {
  test('validates plugin manifest shape', () => {
    const manifest = parsePluginManifest({
      name: 'nextjs-authz-pack',
      version: '0.1.0',
      type: 'validator',
      supportedFrameworks: ['nextjs'],
      inputs: ['system-map'],
      outputs: ['findings'],
      permissionsNeeded: ['read-workspace'],
      entrypoint: './dist/index.js'
    });

    expect(manifest.type).toBe('validator');
    expect(manifest.permissionsNeeded).toContain('read-workspace');
  });

  test('accepts Proof Mode plugin contribution types', () => {
    const manifest = parsePluginManifest({
      name: 'ai-agent-pack',
      version: '0.1.0',
      type: 'ai-agent-policy-check',
      supportedFrameworks: ['nextjs'],
      inputs: ['system-map'],
      outputs: ['ai-lab'],
      permissionsNeeded: ['read-workspace'],
      entrypoint: './dist/index.js'
    });

    expect(manifest.type).toBe('ai-agent-policy-check');
  });

  test('exports a Codex skill pack with safety boundaries and workflow guidance', async () => {
    const workspace = await mkdtemp(path.join(tmpdir(), 'pmp-skill-'));
    try {
      const target = await exportCodexSkill(workspace);
      const files = await readdir(target);

      expect(files).toEqual(expect.arrayContaining(['SKILL.md', 'report-schema.json', 'tool-usage.md', 'workflows.md']));
      expect(target.endsWith('skills/breachproof-codex')).toBe(true);
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  });
});
