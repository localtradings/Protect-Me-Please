# Architecture

BreachProof is organized as a set of deterministic local agents.

1. Scope Agent validates the approved workspace and mode.
2. Mapper Agent reads files and creates a structured system map.
3. Vulnerability Intelligence Agent normalizes OSV, CVE/NVD, GitHub advisory, KEV, EPSS, and rule-pack inputs.
4. Reachability Agent connects routes, code, imports, Prisma models, dependencies, auth, ownership checks, uploads, webhooks, jobs, and AI tools.
5. Business Logic Agent detects authorization, tenant, workflow, webhook, upload, and AI-tool misuse risks.
6. Attack Planner Agent creates safe validation plans.
7. Local Validation Agent produces proof evidence without destructive exploitation.
8. Fix Agent writes patch and regression-test artifacts.
9. Regression Test Agent proposes focused test files.
10. Verification Agent records rerun status after explicit patch application.
11. Report Agent renders Markdown, JSON, and SARIF.

The default workflow is:

```text
approve scope -> map -> corpus -> reachability -> attack graph -> validation plan -> evidence -> patch artifacts -> verification -> final report
```
