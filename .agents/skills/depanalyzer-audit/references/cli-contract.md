# CLI Contract

## Analyze

Detect the installed contract first:

```text
depanalyzer --version
depanalyzer capabilities --output json
```

For CLI 2.3.0 and report schema 1.3 use:

```text
depanalyzer analyze <project-path> --dynamic --show-chains --tree-expand all \
  --output json --output-file <temporary-file> --quiet --progress-json
```

The JSON object has `schemaVersion`, `projectName`, `upToDate`, `outdated`,
`directVulnerable`, `transitiveVulnerable`, `vulnerabilityChains`, and optional
`dependencyTree`. Schema 1.3 also includes `analysis` with requested/actual mode,
project type, ecosystems, duration, warnings, and provider status. `STATIC_FALLBACK`
must never be presented as a complete dynamic analysis.
`analysis.inputFingerprint` identifies the dependency manifests and lockfiles used by the report.
`analysis.vulnerabilityCoverage` is `COMPLETE`, `FALLBACK`, or `UNAVAILABLE`; never present
`UNAVAILABLE` as zero vulnerabilities. npm projects fall back to `npm audit` when OSS Index fails.
Vulnerability identifiers may be CVE or GHSA and include their real source.

With `--progress-json`, NDJSON progress events are written to stderr. Keep stderr
separate from the final JSON. Prefer a temporary output file for large reports.

Direct dependencies can include `sourceLocation` with `file`, `line`, `startColumn`, and
`endColumn`. Positions are 1-based and the end column is exclusive. A missing location means the
declaration could not be mapped reliably; never invent a range.

Provider flags:

- `--oss`: require OSS Index without fallback.
- `--nvd`: require NVD without fallback; only Maven coordinates are supported.
- No provider flag: prefer OSS Index and enrich/fallback with NVD where applicable.

Environment credentials:

- `OSS_INDEX_TOKEN`
- `NVD_API_KEY`

## Update

Create a machine-readable plan:

```text
depanalyzer update <project-path> --plan --output-file -
```

Add `--only-security` to exclude ordinary outdated-version suggestions. Each suggestion has a
stable `id` derived from its complete proposed change. IDs become invalid when the plan changes.

Reuse a current report to avoid querying providers again:

```text
depanalyzer update <project-path> --plan --report-file <report.json> \
  --output-file <plan.json> --progress-json
```

Apply explicitly approved suggestions:

```text
depanalyzer update <project-path> --apply-id <id>
```

For transactional application without recalculation:

```text
depanalyzer update <project-path> --plan-file <plan.json> --apply-id <id> \
  --output-file - --progress-json
```

The CLI validates the input fingerprint, rejects stale IDs, emits a JSON result, creates unique
backups, and synchronizes an existing npm lockfile without running lifecycle scripts. The legacy
`--apply-id` flow still recalculates its plan.

## Exit Codes

- `0`: command completed.
- `1`: critical vulnerability policy failed.
- `2`: analysis failed.
