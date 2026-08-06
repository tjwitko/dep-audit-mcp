# dep-audit-mcp

An MCP server exposing one tool, `check_dependencies`, that scans a project directory for
known-vulnerable dependencies via [OSV-Scanner](https://github.com/google/osv-scanner) before
a new package gets trusted — npm, PyPI, Maven, NuGet, Go modules, Cargo, and whatever else
OSV-Scanner supports, across whatever new project gets created next (Java, Python, C#, ...).

## Architecture

```
Calling model → MCP tool "check_dependencies" → this server (index.mjs, Node/stdio)
                                                        │
                                                        └─ spawns `osv-scanner scan -r <dir> --format json`
                                                               │
                                                               ▼
                                                        OSV.dev (aggregates GHSA, PyPA, RustSec, etc.)
```

This project is **only the audit client** — it doesn't vendor or reimplement any vulnerability
database, it shells out to a real `osv-scanner` binary. Requires `brew install osv-scanner`
first; tool calls fail with a clear error if it isn't on `PATH`.

## The tool

**`check_dependencies`** — one tool, one job. Takes:

- `directory` (required): path to scan, relative to this server's working directory or absolute
  within it. OSV-Scanner recursively finds every supported manifest/lockfile under it — no need
  to say which ecosystem.
- `severity_threshold` (optional, default `"high"`): minimum severity included in the returned
  `findings` list (`"low"`/`"moderate"`/`"high"`/`"critical"`). Summary `counts` always cover
  every severity regardless of this filter.

Returns a JSON report: `packagesWithFindings`, `counts` per severity, `worstSeverityFound`, and
a `findings` array (package, version, ecosystem, advisory id, one-line summary, CVSS score, and
the fixed version if one exists).

**Advisory only, same as `local-delegate-mcp`'s tool**: this reports findings, it cannot and
does not prevent an install command from actually running afterward. The enforcement is "the
calling model checks before treating a new dependency as safe," not a technical barrier — no
MCP tool can block a separate `npm install`/`pip install` call.

**Does not cover Terraform** (or other infrastructure-as-code) despite being one of the original
motivating ecosystems. Terraform provider/module risk is a misconfiguration problem, addressed
by tools like `tfsec` or `checkov`, not a "this package version has a known CVE" problem —
conflating the two would make this look like it covers something it doesn't.

## Security & Guardrails

- **Environment sanitization**: only `PATH`, `HOME`, `SCAN_ROOT` survive startup; everything
  else in `process.env` is deleted, so this server never inherits secrets from whatever spawned
  it.
- **Scan containment**: `directory` must resolve within `SCAN_ROOT` (default: this process's
  working directory at startup, override with the `SCAN_ROOT` env var) — no `../` escapes, no
  absolute paths elsewhere on disk.
- **No `shell: true`**: the `osv-scanner` prerequisite check and the scan itself are both spawned
  as direct argv arrays, not through a shell — avoids Node's own DEP0190 warning class of risk,
  even though the specific command here (a hardcoded binary name) wasn't actually exploitable.

## Known gotchas (found during development)

- **`osv-scanner` exits 1 when it finds vulnerabilities.** That's a successful scan with real
  results, not a tool failure — don't treat a non-zero exit code as an error without checking
  whether stdout actually has parseable JSON first.
- **A clean scan returns `results: []` with no enumeration of what was checked.** OSV-Scanner's
  JSON only lists packages that matched something; the "N packages found" count only exists in
  the CLI's human-readable stderr. `packagesWithFindings: 0` means "nothing vulnerable," not
  "the scan didn't run" — don't rename that field back to something like "packagesScanned," it
  reads as the wrong claim.
- **`max_severity` is a raw CVSS score string** (e.g. `"8.1"`), sometimes empty — not a
  pre-bucketed label. `severityBand()` buckets it using the standard CVSS v3 qualitative ranges
  (FIRST.org): ≥9.0 critical, ≥7.0 high, ≥4.0 moderate, >0 low, else unknown.
- **A single vulnerability "group" can map to multiple entries in `vulnerabilities[]`** (matched
  by id) — don't assume a 1:1 relationship between groups and vulnerability detail objects.
- `sample-osv-output.json` is a trimmed but real, schema-accurate example of `osv-scanner`'s
  JSON output (from an actual scan of a deliberately vulnerable `lodash@4.17.4`), kept as a
  reference for future changes to the parsing logic.

## Setup

```bash
brew install osv-scanner
cd dep-audit-mcp
npm install
```

No build step. Run directly by an MCP client via:
```json
{"command": "node", "args": ["/absolute/path/to/dep-audit-mcp/index.mjs"]}
```

Optional environment variable:
- `SCAN_ROOT` — directory `directory` arguments are resolved against and confined to (default:
  this process's working directory at startup)

## Status

Built and verified against a real vulnerable project (deliberately installed
`lodash@4.17.4`/`minimist@0.0.8`, both with known critical/high CVEs) and a clean one, plus the
scan-containment and missing-binary error paths. Registered as a project-scoped MCP server via
`/Users/tomwitkowski/LLM/.mcp.json`.
