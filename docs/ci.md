# CI Integration

CI mode is non-destructive.

```sh
breachproof ci
```

The command writes `reports/final-report.sarif` for upload to code scanning. CI should run audit and safe validation only, and fail based on a configured severity threshold.

Do not place production secrets, service role keys, payment credentials, bank data, or live private keys in CI logs or reports.
