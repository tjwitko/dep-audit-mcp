import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "child_process";
import { mkdtempSync, writeFileSync, rmSync } from "fs";
import { tmpdir } from "os";
import path from "path";
import { fileURLToPath } from "url";

const SERVER = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "index.mjs");

// index.mjs used to clear the environment as it loaded. The other test files import it, so they lost
// NODE_TEST_CONTEXT and ran as standalone runs: `npm test` said "tests 3" when 19 ran, and a skip or
// todo inside them never reached the summary.

test("importing index.mjs leaves the importer's environment alone", async () => {
  const before = { ...process.env, DEP_AUDIT_IMPORT_SENTINEL: "kept" };
  process.env.DEP_AUDIT_IMPORT_SENTINEL = "kept";
  try {
    await import("../index.mjs");
    assert.deepEqual({ ...process.env }, before);
  } finally {
    delete process.env.DEP_AUDIT_IMPORT_SENTINEL;
  }
});

test("started as the server, it still keeps only PATH, HOME and SCAN_ROOT", () => {
  // A preload reports the environment the server ends with. stdin is empty, so the server sees EOF
  // and exits after main() has run.
  const dir = mkdtempSync(path.join(tmpdir(), "dep-audit-env-"));
  try {
    const preload = path.join(dir, "report-env.mjs");
    writeFileSync(
      preload,
      `process.on("exit", () => process.stderr.write("ENV=" + JSON.stringify(Object.keys(process.env).sort()) + "\\n"));\n`
    );
    const r = spawnSync(process.execPath, ["--import", preload, SERVER], {
      input: "",
      encoding: "utf8",
      timeout: 15000,
      env: { PATH: process.env.PATH, HOME: process.env.HOME, SCAN_ROOT: dir, LEAKED_TOKEN: "x" },
    });
    assert.equal(r.error, undefined, `server did not exit: ${r.error}`);
    assert.match(r.stderr, /dep-audit MCP server running on stdio/);
    const line = r.stderr.split("\n").find((l) => l.startsWith("ENV="));
    assert.ok(line, `no environment report in stderr: ${r.stderr}`);
    assert.deepEqual(JSON.parse(line.slice(4)), ["HOME", "PATH", "SCAN_ROOT"]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
