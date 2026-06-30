/// <reference lib="dom" />

import { vaultGraphSchema, type VaultGraph, type VaultNode } from '../types.js';

function element<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  className?: string,
  text?: string
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function routeProfileHref(profilePath: string | undefined): string | undefined {
  if (!profilePath) return undefined;
  const normalized = profilePath.replace(/\\/g, '/');
  const prefix = 'reports/vault/';
  if (!normalized.startsWith(`${prefix}route-profiles/`)) return undefined;
  const relative = normalized.slice(prefix.length);
  if (relative.split('/').some((segment) => !segment || segment === '.' || segment === '..')) {
    return undefined;
  }
  return `./${relative}`;
}

function nodeLabelCell(node: VaultNode): HTMLTableCellElement {
  const cell = element('td');
  const href = routeProfileHref(node.profilePath);
  if (!href) {
    cell.textContent = node.label;
    return cell;
  }
  const link = element('a', 'vault-fallback-link', node.label);
  link.href = href;
  cell.append(link);
  return cell;
}

export function renderVaultFallback(
  root: HTMLElement,
  graphInput: VaultGraph,
  reason = 'Interactive 3D rendering is unavailable in this browser.'
): void {
  const graph = vaultGraphSchema.parse(graphInput);
  const shell = element('div', 'vault-fallback-shell');
  const header = element('header', 'vault-fallback-header');
  const brand = element('strong', 'vault-fallback-brand', 'BREACHPROOF VAULT');
  const status = element('span', 'vault-local-status', 'LOCAL ONLY');
  header.append(brand, status);

  const main = element('main', 'vault-fallback-main');
  const heading = element('h1', undefined, 'Security memory graph');
  const explanation = element('p', 'vault-fallback-reason', reason);
  main.append(heading, explanation);

  const tableRegion = element('div', 'vault-fallback-table-region');
  const table = element('table', 'vault-fallback-table');
  table.setAttribute('aria-label', 'Vault graph fallback');
  const caption = element('caption', undefined, `${graph.summary.nodes} nodes · ${graph.summary.edges} evidence links`);
  const head = element('thead');
  const headerRow = element('tr');
  for (const label of ['Type', 'Node', 'State', 'Evidence']) {
    headerRow.append(element('th', undefined, label));
  }
  head.append(headerRow);
  const body = element('tbody');
  const edgesByNode = new Map<string, string[]>();
  for (const edge of graph.edges) {
    for (const id of [edge.from, edge.to]) {
      const evidence = edgesByNode.get(id) ?? [];
      evidence.push(edge.evidence);
      edgesByNode.set(id, evidence);
    }
  }
  for (const node of graph.nodes) {
    const row = element('tr');
    const evidence = [...new Set(edgesByNode.get(node.id) ?? [])].slice(0, 2).join(' · ');
    row.append(
      element('td', 'vault-fallback-type', node.type),
      nodeLabelCell(node),
      element('td', undefined, node.status),
      element('td', undefined, evidence || 'No linked evidence')
    );
    body.append(row);
  }
  table.append(caption, head, body);
  tableRegion.append(table);
  main.append(tableRegion);

  const timeline = element('section', 'vault-fallback-timeline');
  timeline.setAttribute('aria-label', 'Vault timeline');
  timeline.append(element('h2', undefined, 'Timeline'));
  const events = element('ol');
  for (const event of graph.timeline) {
    const item = element('li');
    item.append(
      element('time', undefined, event.timestamp.slice(0, 10)),
      element('strong', undefined, event.lifecycle.toUpperCase()),
      document.createTextNode(` ${event.ruleId} · ${event.title}`)
    );
    events.append(item);
  }
  if (graph.timeline.length === 0) events.append(element('li', undefined, 'No recorded events.'));
  timeline.append(events);
  main.append(timeline);

  shell.append(header, main);
  root.replaceChildren(shell);
}
