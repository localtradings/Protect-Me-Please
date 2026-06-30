# CI Integration

CI mode is non-destructive.

```sh
breachproof ci
```

The command writes:

- `reports/final-report.sarif` for code scanning
- `reports/final-report.md` for job summaries
- `reports/final-report.html` for artifact download
- `reports/evidence-summary.json` for replay evidence counts
- `reports/patch-tournament.json` for patch candidate counts
- `reports/vault/` for the offline security-memory graph, timeline, route profiles, and static assets

The included workflow uses Node 24 action families, installs the local Chromium test runtime, runs the Vault browser suite, uploads report artifacts, writes a Markdown step summary, and posts a best-effort PR comment when the GitHub token has permission. CI should run audit and safe validation only, and fail based on a configured severity threshold.

The Vault directory is included only in the workflow's private `breachproof-reports` artifact. The workflow does not publish the report through GitHub Pages or another public host. Local SQLite state under `.breachproof/` is not uploaded.

Do not place production secrets, service role keys, payment credentials, bank data, or live private keys in CI logs or reports.
