# Contributing

## Adding a Case

1. Create a JSON file in the appropriate `cases/` subdirectory
2. Follow the schema in [docs/SPEC.md](docs/SPEC.md)
3. Include all required fields
4. Run the validator: `go run ./validate/...`

### Requirements for new cases

Every new case must include:

- **Rationale:** Why this case matters (in `description`)
- **Expected verdict:** `block` or `allow` with reasoning (in `why_expected`)
- **Source:** Where the attack pattern or credential format comes from (in `source`)
- **False-positive assessment:** How likely this is to trigger on clean traffic (in `false_positive_risk`)

### Case ID rules

- IDs are immutable once merged. Never rename.
- Format: `{category}-{subcategory}-{NNN}`
- Numbers are zero-padded to three digits

### Do NOT change existing cases

Existing case semantics are stable. If you disagree with an expected verdict, open an issue. If the attack surface has changed, propose a new case instead.

## Adding a Runner

Create a directory under `examples/{tool-name}/` with:

- A runner script or program
- A `tool-profile.json` for your tool
- A README explaining how to run it

Runner output must follow the contract in [docs/RUNNER.md](docs/RUNNER.md).

## Validation

All case files must pass validation before merge:

```bash
go run ./validate/...
```

CI runs this automatically on every pull request.

## Governance

This repo is maintained by the Pipelock author. Contributions from any vendor or individual are welcome. This repo does not produce rankings or cross-tool comparisons. Each tool can publish its own results independently.
