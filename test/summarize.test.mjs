import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "fs";
import path from "path";
import { fileURLToPath } from "url";

import { severityBand, summarizeFindings, resolveScanPath } from "../index.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));

// These bands decide whether a finding counts as "high", which is what the commit gate blocks on
// once a lockfile makes the scan authoritative. A boundary error here silently changes what is
// enforceable, in either direction -- the same class of bug as a lockfile probe that reported an
// unlocked project as locked.
test("CVSS bands match the FIRST.org boundaries exactly", () => {
  assert.equal(severityBand("10.0"), "critical");
  assert.equal(severityBand("9.0"), "critical");
  assert.equal(severityBand("8.9"), "high");
  assert.equal(severityBand("7.0"), "high");
  assert.equal(severityBand("6.9"), "moderate");
  assert.equal(severityBand("4.0"), "moderate");
  assert.equal(severityBand("3.9"), "low");
  assert.equal(severityBand("0.1"), "low");
});

// An unscored vulnerability is real and must not be dropped or promoted; it lands in `unknown`
// so a reader can see it exists without it silently becoming blocking.
test("unscored and malformed severities are unknown, not low and not critical", () => {
  for (const v of ["0", "0.0", "", null, undefined, "n/a", "HIGH"]) {
    assert.equal(severityBand(v), "unknown", `for ${JSON.stringify(v)}`);
  }
});

test("a clean scan is empty rather than absent", () => {
  for (const input of [null, undefined, {}, { results: [] }]) {
    const r = summarizeFindings(input);
    assert.equal(r.packagesWithFindings, 0);
    assert.deepEqual(r.critical, []);
    assert.deepEqual(r.high, []);
  }
});

// The real osv-scanner output that shipped with this repo and was never asserted against.
test("the sample osv-scanner output parses into banded findings", () => {
  const sample = JSON.parse(readFileSync(path.join(here, "..", "sample-osv-output.json"), "utf8"));
  const r = summarizeFindings(sample);
  assert.ok(r.packagesWithFindings > 0, "should count the package that matched");
  const all = [...r.critical, ...r.high, ...r.moderate, ...r.low, ...r.unknown];
  assert.ok(all.length > 0, "should produce at least one finding");
  for (const f of all) {
    assert.ok(f.id, "every finding carries its advisory id");
    assert.ok(f.pkg || f.package, "every finding names its package");
  }
});

// summarizeFindings skips a group id with no matching entry in `vulnerabilities`. That is a
// silent drop, and this pins the behaviour so a future change has to do it deliberately: the
// count of packages must still reflect that something matched.
test("a group id with no matching vulnerability record is dropped, not fabricated", () => {
  const r = summarizeFindings({
    results: [
      {
        packages: [
          {
            package: { name: "left-pad", ecosystem: "npm" },
            groups: [{ ids: ["GHSA-does-not-exist"], max_severity: "9.8" }],
            vulnerabilities: [],
          },
        ],
      },
    ],
  });
  assert.equal(r.packagesWithFindings, 1, "the package still counted as having matched");
  assert.deepEqual(r.critical, [], "but no finding is invented for the missing record");
});

test("the scan path cannot escape its root", () => {
  assert.throws(() => resolveScanPath("../../../.aws", "/srv/project"));
  assert.throws(() => resolveScanPath("/etc", "/srv/project"));
  assert.equal(resolveScanPath("app", "/srv/project"), "/srv/project/app");
});
