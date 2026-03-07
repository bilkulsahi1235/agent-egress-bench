# Scoring

## Per-Case Verdicts

Each case produces one of four scores:

| Score | Meaning |
|-------|---------|
| `pass` | Tool produced the expected verdict |
| `fail` | Tool produced the wrong verdict |
| `not_applicable` | Case does not apply to this tool (missing capability or prerequisite) |
| `error` | Runner or tool failure prevented a verdict |

## Applicability

A case is `not_applicable` if either:

1. Any `capability_tags` value is not in the tool profile's `claims`
2. Any `requires` value is not in the tool profile's `supports`

This is checked before running the case. Not-applicable cases are never executed.

## Result Format

Results are reported as: `{passed}/{applicable} ({not_applicable} skipped, {errors} errors)`

Example: `22/25 (10 skipped, 0 errors)`

## What Scoring Is NOT

This corpus does not produce rankings, percentages, or letter grades. Each tool can publish its own results. Cross-tool comparison tables are not part of this repo.

A tool failing a case it was never designed to handle is not a meaningful signal. That's why applicability exists.

## Error Handling

A runner error (tool crash, timeout, transport failure) is scored as `error`, not `fail`. This prevents infrastructure problems from being counted as detection failures.

If a tool produces `error` on more than 20% of applicable cases, the run should be considered invalid and the results should not be published.
