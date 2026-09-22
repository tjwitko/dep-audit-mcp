# dep-audit-mcp

[![release](https://img.shields.io/github/v/release/tjwitko/dep-audit-mcp)](https://github.com/tjwitko/dep-audit-mcp/releases/latest)
[![license](https://img.shields.io/github/license/tjwitko/dep-audit-mcp)](LICENSE)

An MCP server that scans a project's dependencies for known vulnerabilities and tells you **which
ones are yours**.

It wraps [OSV-Scanner](https://github.com/google/osv-scanner), so it covers npm, PyPI, Maven, NuGet,
Go modules, Cargo and everything else OSV supports — no configuration, no per-ecosystem setup. What
it adds on top is the part that decides whether you act: each finding is marked as a package your
project **declares itself** or one that arrived through something else.

That distinction is the whole point. A scan that returns twenty-eight findings and no way to rank
them gets skimmed and dismissed in one sentence. One real project explained away SSH vulnerabilities
in a transitive crypto library and left a SQL injection in the Postgres driver its own `main.go`
imported directly, in the same write-up.

---

## Getting started

### Requirements

- **Node.js 20 or newer**
- **`osv-scanner`** on your `PATH`:

  ```bash
  brew install osv-scanner
  ```

  It is not vendored and no advisory database is bundled — this server shells out to the real
  binary. If it is missing, the tool says so plainly rather than returning an empty result.

### Install

```bash
npm install --save-dev github:tjwitko/dep-audit-mcp#v1.0.0
```

### Register it with an MCP client

```json
{
  "mcpServers": {
    "dep-audit": {
      "command": "node",
      "args": ["/absolute/path/to/dep-audit-mcp/index.mjs"],
      "env": { "SCAN_ROOT": "/absolute/path/to/your/project" }
    }
  }
}
```

---

## The tool

### `check_dependencies`

| parameter | required | default | description |
|---|---|---|---|
| `directory` | yes | — | Path to scan, resolved within `SCAN_ROOT`. Manifests and lockfiles are found recursively; you never name the ecosystem. |
| `severity_threshold` | no | `"high"` | Lowest severity included in `findings`: `low`, `moderate`, `high`, `critical`. Counts always cover every severity regardless. |

Returns JSON:

```json
{
  "directory": "/path/scanned",
  "packagesWithFindings": 3,
  "counts": { "critical": 1, "high": 2, "moderate": 4, "low": 0, "unknown": 0 },
  "worstSeverityFound": "critical",
  "directFindings": 1,
  "directPackages": ["github.com/lib/pq"],
  "unclassifiedFindings": 0,
  "guidance": "1 of 3 finding(s) are in packages this project DECLARES ITSELF …",
  "findings": [
    {
      "package": "github.com/lib/pq",
      "version": "1.10.0",
      "ecosystem": "Go",
      "id": "GHSA-xxxx-xxxx-xxxx",
      "summary": "SQL injection via …",
      "cvssScore": "9.1",
      "fixedVersion": "1.10.9",
      "direct": true
    }
  ]
}
```

Severity is banded from the raw CVSS score using the standard FIRST.org ranges — ≥9.0 critical,
≥7.0 high, ≥4.0 moderate, >0 low, otherwise unknown.

---

## Direct or transitive

Every finding carries `direct`:

| value | meaning |
|---|---|
| `true` | the package appears in a manifest this project owns |
| `false` | it arrived through another dependency |
| `null` | no manifest was readable, so nothing could be classified |

Manifests read for this: `package.json`, `go.mod` (respecting `// indirect`), `requirements.txt`
and `pyproject.toml`.

**`null` is never reported as transitive.** Calling a direct dependency transitive is the direction
that gets a real finding dismissed, so an unknown stays unknown and the guidance says to treat every
finding as potentially yours.

A transitive finding is not automatically inapplicable, either — a transitive package still runs in
your process. The classification tells you who owns the fix, not whether the vulnerability is
reachable.

---

## What it does not do

Stated plainly, because a scanner that appears to cover something it does not is worse than one
that says so:

- **It cannot block an install.** It reports; nothing stops a later `npm install`. Enforcement
  belongs at a boundary that owns the action — see [agent-gate](https://github.com/tjwitko/agent-gate),
  which fails a build on what this reports.
- **It does not cover Terraform or other infrastructure-as-code.** Provider and module risk is a
  misconfiguration problem, not a known-vulnerable-version problem. Use
  [terraform-guard-mcp](https://github.com/tjwitko/terraform-guard-mcp).
- **It does not find hardcoded credentials.** A vulnerable version and a leaked key are unrelated,
  and OSV sees neither file contents nor strings. Use
  [secret-guard-mcp](https://github.com/tjwitko/secret-guard-mcp).
- **Without a lockfile, results are indicative rather than authoritative.** OSV-Scanner resolves the
  transitive graph to minimum-satisfying versions, which is not what installs. `==` pins in
  `requirements.txt` constrain direct dependencies only. Commit a lockfile.

---

## Security

- **Environment sanitization.** Only `PATH`, `HOME` and `SCAN_ROOT` survive startup; everything else
  in `process.env` is deleted, so the server never inherits secrets from whatever spawned it.
- **Scan containment.** `directory` must resolve inside `SCAN_ROOT` — no `../` escapes, no absolute
  paths elsewhere on disk. A scan pointed somewhere else is not a result about your project in
  either direction: its findings are someone else's and its silence proves nothing about you.
- **No shell.** The prerequisite check and the scan are spawned as direct argv arrays, never through
  a shell.
- **No network of its own.** It runs `osv-scanner` and reads its output. It fetches nothing.

### Configuration

| variable | default | purpose |
|---|---|---|
| `SCAN_ROOT` | the process's working directory at startup | the directory `directory` arguments are resolved against and confined to |

---

## Behaviour worth knowing

- **`osv-scanner` exits 1 when it finds vulnerabilities.** That is a successful scan with results.
  This server treats a non-zero exit as an error only when stdout holds no parseable JSON.
- **`packagesWithFindings: 0` means nothing vulnerable was found, not that nothing was scanned.**
  OSV's JSON only enumerates packages that matched, so a total-scanned count does not exist in the
  output. The field is named for what it can honestly report.

---

## Development

```bash
npm install
npm test
node --check index.mjs
```

`sample-osv-output.json` is a trimmed but schema-accurate capture of real `osv-scanner` output,
kept as the reference for anyone changing the parsing.

---

## Part of agent-gate

This is one of four control servers behind
[agent-gate](https://github.com/tjwitko/agent-gate), which runs them together and fails a build on
what they find. It works standalone with any MCP client.

## License

[Apache License 2.0](LICENSE) © 2026 Tom Witkowski
