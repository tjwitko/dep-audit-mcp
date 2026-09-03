#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { spawnSync } from "child_process";
import { readFileSync } from "fs";
import path from "path";
import { pathToFileURL } from "url";

// A stdio MCP server inherits its entire parent environment by default even though it only
// needs its own config vars — drop the rest, same guardrail as local-delegate-mcp.
function sanitizeEnv(allowlist) {
  for (const key in process.env) {
    if (!allowlist.includes(key)) {
      delete process.env[key];
    }
  }
}
sanitizeEnv(["PATH", "HOME", "SCAN_ROOT"]);

// Sole allowed scan boundary — defaults to this process's cwd (wherever the MCP client
// launched it from), same containment pattern as local-delegate-mcp's CONTEXT_ROOT. Prevents
// a careless/compromised `directory` argument from pointing the scanner somewhere unintended.
const SCAN_ROOT = path.resolve(process.env.SCAN_ROOT || process.cwd());

export function resolveScanPath(relOrAbsPath, scanRoot) {
  const resolved = path.resolve(scanRoot, relOrAbsPath);
  if (resolved !== scanRoot && !resolved.startsWith(scanRoot + path.sep)) {
    throw new Error(`refuses to scan outside ${scanRoot}: ${relOrAbsPath}`);
  }
  return resolved;
}

// CVSS v3 qualitative severity bands (FIRST.org standard): 9.0-10.0 critical, 7.0-8.9 high,
// 4.0-6.9 moderate, 0.1-3.9 low, else unscored/unknown. OSV-Scanner reports a raw score
// string per finding group, not a pre-bucketed label, so this has to be done here.
export function severityBand(scoreStr) {
  const score = parseFloat(scoreStr);
  if (Number.isNaN(score)) return "unknown";
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "moderate";
  if (score > 0) return "low";
  return "unknown";
}

const SEVERITY_THRESHOLDS = ["low", "moderate", "high", "critical"];

// Maps raw osv-scanner JSON into severity-bucketed findings. `pkg` (not `package` — a reserved
// word in strict-mode/ESM JavaScript; the first draft used `package` as a loop variable and
// failed node --check with "Unexpected strict mode reserved word") for each ecosystem package.
//
// packagesWithFindings, not "packagesScanned": osv-scanner's JSON only lists packages that
// matched something — a clean scan returns `results: []` with no enumeration of what was
// actually checked (that count only exists in the CLI's human-readable stderr). Don't rename
// this back; "packagesScanned: 0" reads as "the scan didn't run," which is wrong.
export function summarizeFindings(osvResult) {
  const result = { critical: [], high: [], moderate: [], low: [], unknown: [], packagesWithFindings: 0 };
  if (!osvResult || !osvResult.results || osvResult.results.length === 0) {
    return result;
  }

  for (const resultItem of osvResult.results) {
    for (const pkg of resultItem.packages || []) {
      result.packagesWithFindings++;
      for (const group of pkg.groups || []) {
        const band = severityBand(group.max_severity);
        for (const groupId of group.ids || []) {
          const vulnerability = (pkg.vulnerabilities || []).find((v) => v.id === groupId);
          if (!vulnerability) continue;

          let fixedVersion = null;
          for (const affected of vulnerability.affected || []) {
            if (affected.package?.name !== pkg.package.name) continue;
            for (const range of affected.ranges || []) {
              const fixedEvent = (range.events || []).find((e) => e.fixed);
              if (fixedEvent) {
                fixedVersion = fixedEvent.fixed;
                break;
              }
            }
            if (fixedVersion) break;
          }

          result[band].push({
            package: pkg.package.name,
            version: pkg.package.version,
            ecosystem: pkg.package.ecosystem,
            id: vulnerability.id,
            summary: vulnerability.summary,
            cvssScore: group.max_severity,
            fixedVersion,
          });
        }
      }
    }
  }

  return result;
}

// Which packages this project declares itself, per ecosystem. A finding in one of these is in
// something the project chose; a transitive one arrived through something else.
//
// A deliverable met 28 high-and-critical findings by writing a section arguing they were SSH
// vulnerabilities in golang.org/x/crypto that could not affect code using only the standard
// library. That was true of the 22 x/crypto findings -- and it silently generalised over 6 more in
// github.com/jackc/pgx/v5, including a SQL injection, in the Postgres driver its own main.go
// imports on line 16. The report gave it counts and CVE summaries and no way to see that the set it
// examined was not the set it was dismissing.
//
// Unknown is never reported as transitive. Calling a direct dependency transitive is the direction
// that lets a reader put a finding down.
export function directDependencies(dir) {
  const direct = new Set();
  let known = false;

  // Go: `// indirect` is the marker the toolchain itself maintains.
  try {
    const gomod = readFileSync(path.join(dir, "go.mod"), "utf8");
    known = true;
    for (const m of gomod.matchAll(/^\s*(?:require\s+)?([\w.\-]+\/[^\s]+)\s+v[^\s]+(.*)$/gm)) {
      if (!/\/\/\s*indirect/.test(m[2])) direct.add(m[1]);
    }
  } catch {
    /* no go.mod */
  }

  // npm: everything the manifest declares, dev included -- a vulnerable test-only package is still
  // one this project chose.
  try {
    const pkg = JSON.parse(readFileSync(path.join(dir, "package.json"), "utf8"));
    known = true;
    for (const field of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) {
      for (const name of Object.keys(pkg[field] || {})) direct.add(name);
    }
  } catch {
    /* no package.json */
  }

  // Python: requirements.txt and PEP 621 pyproject dependencies.
  try {
    const reqs = readFileSync(path.join(dir, "requirements.txt"), "utf8");
    known = true;
    for (const line of reqs.split("\n")) {
      const m = /^\s*([A-Za-z0-9._-]+)\s*(?:[<>=!~[].*)?$/.exec(line.split("#")[0]);
      if (m) direct.add(m[1].toLowerCase());
    }
  } catch {
    /* no requirements.txt */
  }
  try {
    const toml = readFileSync(path.join(dir, "pyproject.toml"), "utf8");
    known = true;
    for (const m of toml.matchAll(/^\s*"([A-Za-z0-9._-]+)\s*(?:[<>=!~].*)?"/gm)) direct.add(m[1].toLowerCase());
  } catch {
    /* no pyproject.toml */
  }

  return { direct, known };
}

/** true / false / null, where null means no manifest was readable for that ecosystem. */
export function classifyDirect(name, { direct, known }) {
  if (!known) return null;
  if (direct.has(name) || direct.has(name.toLowerCase())) return true;
  // A Go module path is declared as the module root; a finding may name a subpackage of it.
  for (const d of direct) {
    if (name.startsWith(`${d}/`)) return true;
  }
  return false;
}

const server = new McpServer({
  name: "dep-audit",
  version: "1.0.0",
});

server.tool(
  "check_dependencies",
  "Scan a project directory's dependency manifests/lockfiles (npm, PyPI, Maven, NuGet, Go " +
    "modules, Cargo, and others OSV-Scanner supports) for known vulnerabilities, before " +
    "treating a new or existing dependency as safe. Use this after adding a new package to a " +
    "project, or before adopting one, not as a one-time audit — run it again each time " +
    "dependencies change. Advisory only: this reports findings, it does not and cannot prevent " +
    "an install command from running. Does NOT cover Terraform providers/modules or other " +
    "infrastructure-as-code — that's a misconfiguration-scanning problem (tools like tfsec), " +
    "not a known-vulnerable-package-version problem, and this tool doesn't address it.",
  {
    directory: z
      .string()
      .describe(
        "Path to the project directory to scan (relative to this server's working directory, " +
          "or absolute within it). OSV-Scanner recursively finds and scans every supported " +
          "manifest/lockfile under it automatically — no need to specify which ecosystem."
      ),
    severity_threshold: z
      .enum(SEVERITY_THRESHOLDS)
      .optional()
      .describe(
        "Minimum severity to include in the returned findings list (default \"high\"). " +
          "Summary counts are always reported for every severity regardless of this threshold."
      ),
  },
  async ({ directory, severity_threshold }) => {
    const threshold = severity_threshold || "high";
    const thresholdIndex = SEVERITY_THRESHOLDS.indexOf(threshold);

    let resolvedDir;
    try {
      resolvedDir = resolveScanPath(directory, SCAN_ROOT);
    } catch (error) {
      return {
        content: [{ type: "text", text: `Refusing to scan: ${error.message}` }],
        isError: true,
      };
    }

    // No shell:true — that combination with args is unsafe in general (Node flags it,
    // DEP0190) even though there's no injection risk here specifically. spawnSync surfaces a
    // missing binary as an ENOENT error rather than a shell exit code, which is what we check.
    const which = spawnSync("osv-scanner", ["--version"], { encoding: "utf8" });
    if (which.error) {
      return {
        content: [
          {
            type: "text",
            text:
              "osv-scanner is not installed or not on PATH. Install it with " +
              "`brew install osv-scanner` and retry.",
          },
        ],
        isError: true,
      };
    }

    const scan = spawnSync("osv-scanner", ["scan", "-r", resolvedDir, "--format", "json"], {
      encoding: "utf8",
      maxBuffer: 50 * 1024 * 1024,
    });

    // osv-scanner exits 1 when it finds vulnerabilities — that's a successful scan with
    // results, not a failure. Only treat it as an error if there's no parseable JSON at all.
    let parsed;
    try {
      parsed = JSON.parse(scan.stdout || "{}");
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: `osv-scanner produced no parseable output (exit ${scan.status}). stderr: ${scan.stderr?.slice(0, 2000) || "(empty)"}`,
          },
        ],
        isError: true,
      };
    }

    const summary = summarizeFindings(parsed);
    const includedSeverities = SEVERITY_THRESHOLDS.slice(thresholdIndex);
    const findings = includedSeverities.flatMap((sev) => summary[sev] || []);

    const counts = Object.fromEntries(
      [...SEVERITY_THRESHOLDS, "unknown"].map((sev) => [sev, (summary[sev] || []).length])
    );
    const worstFound = [...SEVERITY_THRESHOLDS].reverse().find((sev) => counts[sev] > 0) || "none";

    // Tag each finding with whether the project declares that package itself. Reported per finding
    // AND as a count, because the count is what a reader acts on and a per-finding flag buried in a
    // list of 28 is one nobody adds up.
    const manifest = directDependencies(resolvedDir);
    for (const f of findings) f.direct = classifyDirect(f.package, manifest);
    const directFindings = findings.filter((f) => f.direct === true);
    const unclassified = findings.filter((f) => f.direct === null);

    const directPackages = [...new Set(directFindings.map((f) => f.package))];
    const guidance = !manifest.known
      ? "No dependency manifest was readable here, so no finding could be classified as direct or " +
        "transitive. Treat every one as potentially yours."
      : directFindings.length === 0
        ? `None of these are in packages this project declares itself — every finding arrived ` +
          `through something else. That is not the same as being unreachable: a transitive package ` +
          `still runs in your process. Check whether your code path reaches the vulnerable function ` +
          `before deciding it does not apply.`
        : `${directFindings.length} of ${findings.length} finding(s) are in packages this project ` +
          `DECLARES ITSELF — ${directPackages.join(", ")}. These are not somebody else's ` +
          `dependencies. If you write up why a set of findings does not apply to you, say which ` +
          `packages the write-up covers: an argument about one package does not carry to another, ` +
          `and a project has explained away SSH vulnerabilities in a transitive crypto library while ` +
          `leaving a SQL injection in the database driver it imports directly.`;

    const report = {
      directory: resolvedDir,
      packagesWithFindings: summary.packagesWithFindings,
      counts,
      worstSeverityFound: worstFound,
      directFindings: directFindings.length,
      directPackages,
      unclassifiedFindings: unclassified.length,
      guidance,
      findings,
    };

    return {
      content: [{ type: "text", text: JSON.stringify(report, null, 2) }],
    };
  }
);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("dep-audit MCP server running on stdio");
}
// Only when run as a server, not when imported. Everything in this file lives in one module, so a
// test that imports severityBand would otherwise start an MCP server on stdio and hang.
const invokedDirectly =
  process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (invokedDirectly) main().catch(console.error);
