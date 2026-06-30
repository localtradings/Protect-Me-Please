import { execFile } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { promisify } from 'node:util';
import { expect, test } from '@playwright/test';
import { buildVaultGraph } from '../../src/vault/graph.js';
import { writeVaultReport } from '../../src/vault/report.js';
import { makeGraphInput } from '../helpers/vault-fixtures.js';

const execFileAsync = promisify(execFile);
let workspace = '';
let reportUrl = '';

test.beforeAll(async () => {
  workspace = await mkdtemp(path.join(tmpdir(), 'bp-vault-browser-'));
  await execFileAsync('npm', ['run', 'build:vault-ui'], { cwd: process.cwd() });
  const graph = buildVaultGraph(makeGraphInput());
  const report = await writeVaultReport({
    workspace,
    reportsDir: 'reports',
    graph,
    routeProfiles: [
      {
        routeId: 'next-invoice-route',
        html: '<!doctype html><html lang="en"><title>Invoice route profile</title><body>tenant-isolation</body></html>'
      }
    ]
  });
  reportUrl = pathToFileURL(report.indexFile).href;
});

test.afterAll(async () => {
  if (workspace) await rm(workspace, { recursive: true, force: true });
});

test('renders the approved graph shell and focuses evidence', async ({ page }) => {
  const consoleErrors: string[] = [];
  page.on('console', (message) => {
    if (message.type() === 'error') consoleErrors.push(message.text());
  });
  await page.goto(reportUrl);

  await expect(page.getByText('BREACHPROOF VAULT')).toBeVisible();
  await expect(page.locator('canvas')).toBeVisible();
  await page.getByRole('button', { name: 'Breach paths' }).click();
  await expect(page.getByRole('button', { name: 'Breach paths' })).toHaveAttribute(
    'aria-pressed',
    'true'
  );
  await page
    .getByPlaceholder('Search routes, findings, invariants, patches')
    .fill('BP-BOLA-002');
  await page.getByRole('button', { name: /BP-BOLA-002/ }).first().click();

  await expect(page.getByRole('complementary')).toContainText('tenant-isolation');
  await expect(page.getByRole('complementary')).toContainText('Tenant escape through invoice lookup');
  await expect(page.locator('[data-testid="vault-timeline"]')).toContainText('REOPENED');
  expect(consoleErrors).toEqual([]);
});

test('shows an accessible fallback when WebGL is disabled', async ({ browser }) => {
  const context = await browser.newContext({ javaScriptEnabled: true });
  const page = await context.newPage();
  await page.addInitScript(() => {
    HTMLCanvasElement.prototype.getContext = () => null;
  });
  await page.goto(reportUrl);

  await expect(page.getByRole('table', { name: 'Vault graph fallback' })).toBeVisible();
  await expect(page.getByText('BREACHPROOF VAULT')).toBeVisible();
  await context.close();
});
