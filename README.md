# BreachProof

**Prove real breach paths locally. Fix them. Verify they stay fixed.**

BreachProof is a local autonomous security validation platform for repositories and environments you own or are explicitly authorized to test. It is not a generic vulnerability scanner, not a public exploit bot, and not a toy checklist. It maps the app, reasons about exploitability, validates safely with local proof, generates patch and regression-test artifacts, and verifies fixes after explicit application.

## What Makes BreachProof Different

Traditional scanners report possible issues. BreachProof is built around a stronger loop:

```text
map -> corpus -> reachability -> attack plan -> safe proof -> patch artifact -> regression test -> verification -> final report
```

The goal is not to dump every CVE or every lint finding. The goal is to answer:

- Is the vulnerable component actually installed?
- Is it reachable from a route, job, webhook, upload, or AI tool flow?
- Is there a realistic breach path?
- Can BreachProof prove it safely with local fixtures or static trace evidence?
- Can it produce a focused fix and regression test artifact?
- Does the same validation pass after the fix is explicitly applied?

## Safety Model

BreachProof is defensive and local-first:

- owned or explicitly authorized systems only
- one-time scope approval
- no repeated permission prompts inside approved scope
- no public-target scanning
- no credential theft or data exfiltration
- no destructive exploitation
- no malware, stealth, or persistence
- no paid API activation or billing flows
- no source-code upload by default
- deterministic behavior without an LLM
- optional online corpus imports only when explicitly requested

By default, `breachproof run --auto` writes artifacts only. It does not edit the analyzed repository unless explicit apply mode is enabled.

## Install

From this repository:

```sh
npm install
npm run build
node dist/cli/index.js doctor
```

Future published usage:

```sh
npx breachproof run --auto
```

Docker:

```sh
docker build -t breachproof .
docker run --rm -v "$PWD:/workspace" breachproof run --auto --yes
```

## One-Time Approval Gate

Approve the local project scope once:

```sh
breachproof init --yes
```

This writes:

- `breachproof.scope.yml`
- `.breachproof/approval.json`
- `.breachproof/state.sqlite`
- `.breachproof/audit.log`

The approval stores timestamp, workspace, mode, allowed paths, staging targets, autofix settings, and a scope hash. After approval, BreachProof runs inside that scope without repeated prompts. Anything outside scope is refused or marked for manual review.

## CLI

```sh
breachproof run --auto
breachproof map
breachproof corpus import advisories/osv.json advisories/epss.csv
breachproof reachability
breachproof validate --focus authz
breachproof fix
breachproof verify
breachproof report --format markdown
breachproof report --format sarif
breachproof skill export --codex
breachproof ci
breachproof doctor
```

Modes:

- `local`: local repo, local containers, local services, local test data
- `staging`: exact allowlisted staging URLs/domains only
- `ci`: audit and safe validation with SARIF output
- `audit`: passive analysis
- `validate`: safe non-destructive validation
- `fix`: patch and regression-test artifacts
- `auto`: full artifact loop

## Required Artifacts

`breachproof run --auto` writes:

- `reports/system-map.json`
- `reports/vulnerability-corpus-summary.json`
- `reports/reachability-graph.json`
- `reports/attack-graph.json`
- `reports/validation-plan.json`
- `reports/evidence.json`
- `reports/patch-summary.json`
- `reports/verification.json`
- `reports/final-report.md`
- `reports/final-report.sarif`

Per-finding patch proposals live under:

```text
reports/patches/<findingId>/
```

Each patch folder contains a `patch.diff`, proposed regression test content, and status metadata through `patch-summary.json`.

## Vulnerability Intelligence

BreachProof normalizes local files shaped like:

- OSV records
- NVD/CVE API records
- GitHub advisory records
- CISA KEV JSON/CSV data
- FIRST EPSS CSV/API-style data
- BreachProof local rule packs

It merges aliases, CWE, severity/CVSS, KEV flags, EPSS scores, references, affected package ranges, and remediation guidance into a single local corpus model. It then prioritizes based on installed packages and reachability instead of blindly reporting every record.

## Reports

The final report is breach-path oriented:

- executive summary
- vulnerability corpus loaded
- relevant matches
- reachability analysis
- confirmed breach paths
- local proof evidence
- generated fixes
- regression tests
- verification results
- remaining risk
- manual review items
- attack graph

Example:

```md
Finding: Cross-tenant invoice access
Status: patch_created
Path: normal user -> invoice route -> missing tenant ownership check -> invoice data exposure
Proof: local validation created fake tenants and showed the unsafe path without production data
Fix: add tenant ownership check
Regression test: user A cannot access tenant B invoice
Verification: not run until the patch is explicitly applied
```

## Plugins and Skills

Plugins use manifest fields:

- `name`
- `version`
- `type`
- `supportedFrameworks`
- `inputs`
- `outputs`
- `permissionsNeeded`
- `entrypoint`

Export a Codex-compatible skill pack:

```sh
breachproof skill export --codex
```

## CI

CI mode is non-destructive:

```sh
breachproof ci
```

The included GitHub Actions workflow runs typecheck, lint, tests, build, doctor, and CI SARIF generation.

## Limitations

BreachProof does not guarantee that an application is secure. Static analysis and deterministic simulation can miss issues or produce false positives. It does not run unsafe exploits, steal data, dump credentials, mutate production, or scan public targets. Manual review remains required for issues that cannot be safely validated.
