import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import YAML from 'yaml';
import type { SystemMap } from '../core/types.js';

export interface RangeArtifactSummary {
  generatedAt: string;
  directory: string;
  files: string[];
  fakeDataOnly: boolean;
  supportedStack: string[];
}

const tenants = [
  { id: 'tenant_a', name: 'BreachProof Tenant A' },
  { id: 'tenant_b', name: 'BreachProof Tenant B' }
];

const users = [
  { id: 'user_tenant_a', tenantId: 'tenant_a', role: 'user', email: 'user-a@example.local' },
  { id: 'user_tenant_b', tenantId: 'tenant_b', role: 'user', email: 'user-b@example.local' },
  { id: 'owner_tenant_a', tenantId: 'tenant_a', role: 'owner', email: 'owner-a@example.local' }
];

const fakeRecords = {
  invoices: [
    { id: 'invoice_tenant_a', tenantId: 'tenant_a', ownerId: 'user_tenant_a', amountCents: 1200, status: 'draft' },
    { id: 'invoice_tenant_b', tenantId: 'tenant_b', ownerId: 'user_tenant_b', amountCents: 9900, status: 'paid' }
  ],
  projects: [
    { id: 'project_tenant_a', tenantId: 'tenant_a', ownerId: 'user_tenant_a', name: 'Tenant A Range Project' },
    { id: 'project_tenant_b', tenantId: 'tenant_b', ownerId: 'user_tenant_b', name: 'Tenant B Range Project' }
  ],
  files: [
    { id: 'file_tenant_a', tenantId: 'tenant_a', ownerId: 'user_tenant_a', name: 'tenant-a-report.txt', mimeType: 'text/plain' },
    { id: 'file_tenant_b', tenantId: 'tenant_b', ownerId: 'user_tenant_b', name: 'tenant-b-report.txt', mimeType: 'text/plain' }
  ]
};

function dockerCompose(systemMap: SystemMap): string {
  const compose = {
    name: 'breachproof-range',
    services: {
      postgres: {
        image: 'postgres:16-alpine',
        environment: {
          POSTGRES_USER: 'breachproof',
          POSTGRES_PASSWORD: 'breachproof_local_only',
          POSTGRES_DB: 'breachproof_range'
        },
        ports: ['127.0.0.1:55432:5432'],
        volumes: ['./seed.sql:/docker-entrypoint-initdb.d/001-seed.sql:ro']
      },
      'mock-webhook-provider': {
        image: 'node:24-alpine',
        command: ['node', '-e', "require('http').createServer((_,res)=>{res.end('breachproof mock webhook provider')}).listen(7781)"],
        ports: ['127.0.0.1:7781:7781']
      },
      'mock-payment-provider': {
        image: 'node:24-alpine',
        command: ['node', '-e', "require('http').createServer((_,res)=>{res.end('breachproof mock payment provider placeholder')}).listen(7782)"],
        ports: ['127.0.0.1:7782:7782']
      },
      'mock-email-provider': {
        image: 'node:24-alpine',
        command: ['node', '-e', "require('http').createServer((_,res)=>{res.end('breachproof mock email provider placeholder')}).listen(7783)"],
        ports: ['127.0.0.1:7783:7783']
      }
    },
    'x-breachproof': {
      fakeDataOnly: true,
      supportedFrameworks: systemMap.frameworks,
      productionSecretsAllowed: false,
      productionRecordsAllowed: false
    }
  };
  return YAML.stringify(compose);
}

function seedSql(): string {
  return `-- BreachProof local cyber range seed.
-- Fake data only. Never load production records or secrets into this range.
CREATE TABLE IF NOT EXISTS tenants (
  id text PRIMARY KEY,
  name text NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
  id text PRIMARY KEY,
  tenant_id text NOT NULL REFERENCES tenants(id),
  role text NOT NULL,
  email text NOT NULL
);

CREATE TABLE IF NOT EXISTS invoices (
  id text PRIMARY KEY,
  tenant_id text NOT NULL REFERENCES tenants(id),
  owner_id text NOT NULL REFERENCES users(id),
  amount_cents integer NOT NULL,
  status text NOT NULL
);

CREATE TABLE IF NOT EXISTS projects (
  id text PRIMARY KEY,
  tenant_id text NOT NULL REFERENCES tenants(id),
  owner_id text NOT NULL REFERENCES users(id),
  name text NOT NULL
);

CREATE TABLE IF NOT EXISTS files (
  id text PRIMARY KEY,
  tenant_id text NOT NULL REFERENCES tenants(id),
  owner_id text NOT NULL REFERENCES users(id),
  name text NOT NULL,
  mime_type text NOT NULL
);

INSERT INTO tenants (id, name) VALUES
  ('tenant_a', 'BreachProof Tenant A'),
  ('tenant_b', 'BreachProof Tenant B')
ON CONFLICT (id) DO NOTHING;

INSERT INTO users (id, tenant_id, role, email) VALUES
  ('user_tenant_a', 'tenant_a', 'user', 'user-a@example.local'),
  ('user_tenant_b', 'tenant_b', 'user', 'user-b@example.local'),
  ('owner_tenant_a', 'tenant_a', 'owner', 'owner-a@example.local')
ON CONFLICT (id) DO NOTHING;

INSERT INTO invoices (id, tenant_id, owner_id, amount_cents, status) VALUES
  ('invoice_tenant_a', 'tenant_a', 'user_tenant_a', 1200, 'draft'),
  ('invoice_tenant_b', 'tenant_b', 'user_tenant_b', 9900, 'paid')
ON CONFLICT (id) DO NOTHING;

INSERT INTO projects (id, tenant_id, owner_id, name) VALUES
  ('project_tenant_a', 'tenant_a', 'user_tenant_a', 'Tenant A Range Project'),
  ('project_tenant_b', 'tenant_b', 'user_tenant_b', 'Tenant B Range Project')
ON CONFLICT (id) DO NOTHING;

INSERT INTO files (id, tenant_id, owner_id, name, mime_type) VALUES
  ('file_tenant_a', 'tenant_a', 'user_tenant_a', 'tenant-a-report.txt', 'text/plain'),
  ('file_tenant_b', 'tenant_b', 'user_tenant_b', 'tenant-b-report.txt', 'text/plain')
ON CONFLICT (id) DO NOTHING;
`;
}

function readme(systemMap: SystemMap): string {
  return `# BreachProof Local Cyber Range

This range is generated for local defensive proof work only.

- Fake tenants: ${tenants.length}
- Fake users: ${users.length}
- Fake invoices/projects/files: ${fakeRecords.invoices.length + fakeRecords.projects.length + fakeRecords.files.length}
- Supported stack detected: ${systemMap.frameworks.join(', ') || 'unknown'}
- Production secrets: forbidden
- Production records: forbidden

Start the optional local services:

\`\`\`sh
cd .breachproof/range
docker compose -f docker-compose.range.yml up
\`\`\`

BreachProof evidence can be replayed against an app you run locally with fake data. Do not point replay steps at public targets or production/staging systems outside the approved scope.
`;
}

async function writeJson(file: string, value: unknown): Promise<void> {
  await writeFile(file, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

export async function composeLocalCyberRange(workspace: string, systemMap: SystemMap, stateDir = '.breachproof'): Promise<RangeArtifactSummary> {
  const rangeDir = path.join(workspace, stateDir, 'range');
  await mkdir(rangeDir, { recursive: true });
  const files = [
    'docker-compose.range.yml',
    'seed.json',
    'seed.sql',
    'users.json',
    'tenants.json',
    'README.md'
  ];

  await writeFile(path.join(rangeDir, 'docker-compose.range.yml'), dockerCompose(systemMap), 'utf8');
  await writeJson(path.join(rangeDir, 'seed.json'), {
    generatedAt: new Date().toISOString(),
    fakeDataOnly: true,
    tenants,
    users,
    records: fakeRecords,
    mocks: {
      webhookProvider: 'http://127.0.0.1:7781',
      paymentProviderPlaceholder: 'http://127.0.0.1:7782',
      emailProviderPlaceholder: 'http://127.0.0.1:7783'
    }
  });
  await writeFile(path.join(rangeDir, 'seed.sql'), seedSql(), 'utf8');
  await writeJson(path.join(rangeDir, 'users.json'), users);
  await writeJson(path.join(rangeDir, 'tenants.json'), tenants);
  await writeFile(path.join(rangeDir, 'README.md'), readme(systemMap), 'utf8');

  return {
    generatedAt: new Date().toISOString(),
    directory: path.relative(workspace, rangeDir).split(path.sep).join('/'),
    files: files.map((file) => `${path.relative(workspace, rangeDir).split(path.sep).join('/')}/${file}`),
    fakeDataOnly: true,
    supportedStack: systemMap.frameworks
  };
}
