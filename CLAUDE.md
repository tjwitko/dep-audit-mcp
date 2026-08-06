# CLAUDE.md

An MCP server exposing `check_dependencies`: scans a project directory for known-vulnerable
dependencies via OSV-Scanner (npm, PyPI, Maven, NuGet, Go modules, Cargo, etc.) before a new
package gets trusted, regardless of what language a new project uses.

## Architecture

Calling model → MCP tool `check_dependencies` → this server (`index.mjs`, Node/stdio) →
spawns `osv-scanner scan -r <dir> --format json` → OSV.dev's aggregated advisory database.
Requires `osv-scanner` on `PATH` (`brew install osv-scanner`); the tool fails with a clear
error if it isn't installed.

## Key files

- `index.mjs` — the entire server: env sanitization, scan-path containment, `osv-scanner`
  invocation, JSON summarization (`summarizeFindings`), the one tool
- `sample-osv-output.json` — trimmed but real, schema-accurate example of `osv-scanner`'s JSON
  output; reference for anyone touching the parsing logic

## Common commands

```sh
npm install
node --check index.mjs          # syntax check, no server needed
osv-scanner --version           # confirm the prerequisite is actually installed
```

No build step. Run directly by an MCP client via:
```json
{"command": "node", "args": ["/absolute/path/to/dep-audit-mcp/index.mjs"]}
```

## Things to know

- **`osv-scanner` exits 1 when it finds vulnerabilities.** That's success-with-results, not a
  failure — check whether stdout has parseable JSON before treating a non-zero exit as an error.
- **A clean scan returns `results: []`, with no list of what was actually checked.** The
  `packagesWithFindings` field name is deliberate — `results` only enumerates packages that
  matched something, so a 0 there means "nothing vulnerable," not "nothing was scanned." Don't
  rename it to something implying a total-scanned count; that data isn't in the JSON.
- **`max_severity` is a raw CVSS score string, not a severity label**, and can be empty.
  `severityBand()` buckets it (CVSS v3 qualitative ranges: ≥9.0 critical, ≥7.0 high, ≥4.0
  moderate, >0 low, else unknown) — don't assume the JSON hands you "critical"/"high" directly.
- **`directory` must resolve within `SCAN_ROOT`** (default: server's cwd at startup, override
  via `SCAN_ROOT` env var) — same path-containment pattern as `local-delegate-mcp`'s
  `CONTEXT_ROOT`/`resolveContextPath`.
- **Advisory only.** This tool cannot block a subsequent `npm install`/`pip install`/etc. from
  running — it can only report findings for the calling model to act on.
- **Does not cover Terraform** or other IaC — that's a misconfiguration-scanning problem
  (`tfsec`, `checkov`), not a known-vulnerable-package-version problem. Don't imply it's covered.
- **Never use `spawnSync(..., { shell: true })` with an args array here** — Node flags that
  combination (DEP0190) as unsafe in general, even in cases like the `osv-scanner` prerequisite
  check where the command is hardcoded and there's no real injection risk. Use a direct argv
  array and check `.error` for a missing binary instead of shelling out to `command -v`.
- **`package` is a reserved word in strict-mode/ESM JavaScript.** A local-model draft of
  `summarizeFindings` used it as a loop variable (`for (const package of ...)`) and failed
  `node --check` with "Unexpected strict mode reserved word" — use `pkg` instead. Worth
  rechecking if any future delegated JS code iterates over anything called "package".
