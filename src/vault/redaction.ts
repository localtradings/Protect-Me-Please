import { redactSensitiveText } from '../core/audit.js';

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function workspaceMatcher(workspace: string): RegExp | undefined {
  const withoutTrailingSeparators = workspace.replace(/[\\/]+$/g, '');
  if (!withoutTrailingSeparators) return undefined;
  const pattern = [...withoutTrailingSeparators]
    .map((character) =>
      character === '/' || character === '\\'
        ? String.raw`[\\/]`
        : escapeRegExp(character)
    )
    .join('');
  return new RegExp(`${pattern}(?=$|[\\\\/])`, 'g');
}

export function redactVaultText(value: string, workspace: string): string {
  const matcher = workspaceMatcher(workspace);
  const withoutWorkspace = matcher ? value.replace(matcher, '<workspace>') : value;
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
