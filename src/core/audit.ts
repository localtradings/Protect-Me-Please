import { appendFile, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { auditEventSchema, productName, type AuditEvent, type ProtectMode } from './types.js';

const redactionPatterns = [
  /sk-(?:live|proj|test)-[A-Za-z0-9_-]+/g,
  /\b[A-Za-z0-9_-]*(?:token|api[_-]?key|secret|password|authorization)[A-Za-z0-9_-]*\s*[:=]\s*["']?[^"'\s]+/gi,
  /\b[A-Za-z0-9._%+-]+:[A-Za-z0-9._%+-]+@/g
];

export function redactSensitiveText(text: string): string {
  return redactionPatterns.reduce((current, pattern) => current.replace(pattern, '[REDACTED]'), text);
}

export async function appendAuditEvent(
  workspace: string,
  event: Omit<AuditEvent, 'timestamp' | 'product'> & { mode: ProtectMode }
): Promise<AuditEvent> {
  const stateDir = path.join(workspace, '.breachproof');
  await mkdir(stateDir, { recursive: true });
  const parsed = auditEventSchema.parse({
    timestamp: new Date().toISOString(),
    product: productName,
    ...event,
    message: redactSensitiveText(event.message)
  });
  await appendFile(path.join(stateDir, 'audit.log'), `${JSON.stringify(parsed)}\n`, 'utf8');
  return parsed;
}
