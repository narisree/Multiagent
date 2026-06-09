# Generated Outputs Index

All translated Sentinel rules. One folder per rule or batch.

## Index

| Folder | Source SIEM | Rule Name | Date | Confidence | Validated |
|---|---|---|---|---|---|
| *(none yet)* | | | | | |

## Folder structure per translation

```
08-generated/<rule-name>/
├── query.kql        # KQL query only
├── rule.json        # Full ARM template
├── tests.md         # Test cases (positive + negative)
└── notes.md         # Translation notes, field mapping decisions
```

## Naming convention

`<source-siem>-<detection-type>-<YYYYMMDD>`

Examples:
- `arcsight-brute-force-20260615`
- `qradar-lateral-movement-20260615`
- `logrhythm-data-exfil-20260615`
