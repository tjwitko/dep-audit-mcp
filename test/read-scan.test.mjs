import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "child_process";
import { mkdtempSync, writeFileSync, rmSync } from "fs";
import { tmpdir } from "os";
import path from "path";

import { readScan } from "../index.mjs";

// This was `JSON.parse(scan.stdout || "{}")`. osv-scanner writes nothing to stdout when it has
// nothing to read or when it fails, and `{}` summarises to zero findings -- so a package.json with a
// vulnerable dependency and no lockfile, which osv-scanner does not read, was reported clean.

test("exit 128, nothing to scan, is neither clean nor an error", () => {
  assert.deepEqual(readScan(128, "", "No package sources found"), { noSources: true });
});

test("a scanner failure with empty stdout is an error, not zero findings", () => {
  for (const status of [127, 2, null]) {
    const r = readScan(status, "", "boom");
    assert.ok(r.error, `exit ${status} must be an error`);
    assert.match(r.error, /boom/);
  }
});

test("exit 0 or 1 without parseable JSON is an error", () => {
  assert.ok(readScan(0, "").error);
  assert.ok(readScan(1, "not json").error);
});

test("exit 0 and 1 with JSON are results", () => {
  assert.deepEqual(readScan(0, '{"results":[]}'), { parsed: { results: [] } });
  assert.deepEqual(readScan(1, '{"results":[{"packages":[]}]}'), { parsed: { results: [{ packages: [] }] } });
});

// Against the real scanner, because the defect was a wrong belief about what it prints.
const haveScanner = spawnSync("osv-scanner", ["--version"]).status === 0;

test("a package.json with no lockfile really is exit 128 with empty stdout", { skip: !haveScanner && "osv-scanner not installed" }, () => {
  const dir = mkdtempSync(path.join(tmpdir(), "readscan-"));
  try {
    writeFileSync(path.join(dir, "package.json"), '{"name":"p","version":"1.0.0","dependencies":{"lodash":"4.17.4"}}\n');
    const r = spawnSync("osv-scanner", ["scan", "-r", dir, "--format", "json"], { encoding: "utf8" });
    assert.equal(r.status, 128);
    assert.equal(r.stdout.trim(), "");
    assert.deepEqual(readScan(r.status, r.stdout, r.stderr), { noSources: true });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
