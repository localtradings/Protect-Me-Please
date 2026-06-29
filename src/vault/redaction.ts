import { redactSensitiveText } from '../core/audit.js';

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export function redactVaultText(value: string, workspace: string): string {
  const normalizedValue = value.replace(/\\/g, '/');
  const normalizedWorkspace = workspace.replace(/\\/g, '/').replace(/\/+$/g, '');
  const withoutWorkspace = normalizedWorkspace
    ? normalizedValue.replace(new RegExp(escapeRegExp(normalizedWorkspace), 'g'), '<workspace>')
    : normalizedValue;
  return redactSensitiveText(withoutWorkspace);
}

export function safeSlug(value: string): string {
  return (
    value
      .normalize('NFKD')
      .replace(/[\u0300-\u036f]/g, '')
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '') || 'item'
  );
}
