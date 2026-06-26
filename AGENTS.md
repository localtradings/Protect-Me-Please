# Tool Use and Research Warning

Codex must use available tools intelligently. Research official docs before changing code that depends on current SDKs/APIs such as Apple MapKit, SwiftUI, SwiftData, Supabase, PostHog, Sentry, XcodeGen, TestFlight, or App Store Connect. Plan before coding. Use repo search before editing. Use shell to build/test. Use browser only when useful. Use computer use only for UI/Xcode/simulator verification when needed. Do not use tools for billing/payment pages or sensitive account areas.

If a tool is unavailable, say so. Do not pretend to have used it. Do not guess APIs or rules without verification when verification is available.

# Financial Safety Warning

Codex must never access, use, edit, add, remove, or view my payment methods or billing pages. Codex must never buy, subscribe, upgrade, start a paid trial, activate billing, enable paid APIs, create paid products, charge cards, refund payments, connect bank/payout accounts, or spend money.

For any action that could cost money, Codex must stop and wait until I write exactly:

`I approve this paid action.`

Travel Search MVP has no payments, no ads, no subscriptions, no premium gating, no paid API activation, no Stripe, no Apple In-App Purchases, no Google Play Billing, no billing tables, and no checkout. Codex may only provide manual instructions or safe free-tier setup guidance.

# Payment Safety Warning

Travel Search MVP has no payments, no ads, and no premium gating. Codex must not add payment SDKs, Stripe, Apple In-App Purchase, subscriptions, paid plans, upgrade buttons, billing tables, live checkout, refunds, payouts, or pricing changes unless I explicitly say:

`I approve this real payment/billing action.`

Any payment work must default to sandbox/test mode and planning only. Never commit live payment secrets, webhook secrets, App Store private keys, bank details, tax IDs, or card data.

# Database Safety Warning

Codex must never delete, reset, truncate, drop, wipe, overwrite, or destructively modify any database, table, schema, storage bucket, auth users, seed data, or production/staging data unless I explicitly say:

`I approve this destructive database action.`

Before any database operation, Codex must identify the target environment, database/project, affected tables, operation type, whether it is destructive, whether a backup exists, and whether RLS or service role keys are involved.

If anything is unknown, stop and ask. Treat unknown remote databases as production. Never run `supabase db reset`, `DROP`, `TRUNCATE`, or unsafe `DELETE/UPDATE` commands without explicit approval.

# Critical Database Safety Rules

Never delete, reset, truncate, drop, wipe, overwrite, or destructively modify any database, table, schema, bucket, auth user list, storage object, production data, staging data, or seed data unless the user explicitly requests that exact destructive action in the current chat.

Forbidden without exact approval:

- `DROP DATABASE`
- `DROP SCHEMA`
- `DROP TABLE`
- `TRUNCATE`
- `DELETE FROM` without a safe `WHERE`
- `DELETE FROM` affecting all rows
- `UPDATE` without a safe `WHERE`
- `supabase db reset`
- `supabase db push --include-all`
- `supabase migration repair`
- destructive migrations
- deleting Supabase Storage buckets
- deleting Auth users
- deleting production rows
- replacing production seed data
- overwriting `.env`, `.env.production`, `.env.local`, `.xcconfig`, or config files containing real values
- running scripts that modify remote Supabase data unless approved

Treat every remote database as production unless clearly proven otherwise.

Before touching any database, Codex must identify:

1. environment: local, development, staging, or production
2. database/project targeted
3. operation type: read-only, additive, update, or destructive
4. backup status
5. whether safe limits or safe `WHERE` clauses exist

Migrations must be additive by default. `CREATE TABLE`, `CREATE INDEX`, `ALTER TABLE ADD COLUMN`, `ALTER TABLE ADD CONSTRAINT`, `CREATE POLICY`, `CREATE VIEW`, safe inserts, and safe upserts with natural keys are allowed. Dropping, renaming, deleting, disabling RLS, exposing data through RLS changes, deleting storage files, or modifying Auth users requires explicit approval.

Every `UPDATE` or `DELETE` must have a specific `WHERE` clause, expected affected row count, and preview query first:

```sql
SELECT * FROM table_name WHERE condition;
```

# Financial Account and Payment Access Safety Rules

Codex must never access, use, edit, create, test, connect, authorize, subscribe, upgrade, purchase, pay, charge, refund, transfer, withdraw, or spend money using any account.

For any action that could cost money, Codex must stop and wait until the user writes exactly:

`I approve this paid action.`

Codex must not log in to, open, modify, or configure billing/payment pages for any service, including Apple Developer billing, App Store Connect agreements/banking/tax, Supabase billing, Vercel billing, Cloudflare billing, Google Cloud billing, AWS billing, Azure billing, OpenAI billing, PostHog billing, Sentry billing, Stripe dashboard, PayPal dashboard, RevenueCat dashboard, bank portals, credit card portals, or subscription management pages.

Codex must never request, read, store, print, log, copy, screenshot, or use credit card numbers, debit card numbers, CVV, expiration dates, billing addresses, bank account numbers, routing numbers, PayPal credentials, payment details, Stripe live secret keys, webhook signing secrets, App Store Connect API private keys, tax IDs, payout information, or sensitive invoices.

Free-tier services are allowed only when they do not require a payment method, billing activation, paid trial, or automatic charges. If unsure, stop and ask first.

# Codex Tool, Research, Planning, and Debugging Rules

Codex must use the best available tools, skills, plugins, and workflows only when useful. Do not use tools randomly. Use tools to improve accuracy, verify assumptions, test behavior, debug issues, inspect UI, and reduce mistakes.

Before implementing work involving current APIs, frameworks, SDKs, Apple rules, Supabase behavior, PostHog, Sentry, MapKit, TestFlight, Xcode, SwiftUI, or third-party packages, Codex must research or verify current documentation first when browser/web access is available. Prefer official or primary sources.

For non-trivial work, Codex must plan first and wait for approval before coding. The plan should cover goal, files, approach, data/schema impact, privacy/security impact, tool usage, tests, risks, blockers, and explicit out-of-scope items.

Before writing code, Codex must check likely bugs and edge cases: crashes, missing config, offline behavior, empty data, long text, private data leaks, bad records, Release builds, tests, App Store/TestFlight problems, accidental costs, and accidental data deletion.

Use browser/web research for current API behavior, package version behavior, official Apple/Supabase/PostHog/Sentry/TestFlight/App Store rules, dependency errors, and current best practices. Do not browse for purely local code changes that repo inspection can answer.

Use computer use only for GUI-only verification such as iOS Simulator behavior, Xcode signing, Xcode Organizer/archive state, visual UI layout bugs, local app/browser previews, or GUI-only reproduction. Do not use computer use for sensitive billing, payment, banking, private keys, passwords, or payment pages.

Use shell for reading files, running tests, building apps, checking git status, running xcodegen/xcodebuild, searching the repo, verifying generated files, and checking package resolution. Before risky shell commands, run:

```sh
git status --short
```
