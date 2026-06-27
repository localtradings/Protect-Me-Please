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

The included workflow uses Node 24 action families, uploads report artifacts, writes a Markdown step summary, and posts a best-effort PR comment when the GitHub token has permission. CI should run audit and safe validation only, and fail based on a configured severity threshold.

Do not place production secrets, service role keys, payment credentials, bank data, or live private keys in CI logs or reports.
