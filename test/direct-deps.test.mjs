import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "fs";
import { tmpdir } from "os";
import path from "path";

import { directDependencies, classifyDirect } from "../index.mjs";

function inProject(files, fn) {
  const dir = mkdtempSync(path.join(tmpdir(), "directdeps-"));
  for (const [name, contents] of Object.entries(files)) {
    writeFileSync(path.join(dir, name), contents);
  }
  try {
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// A deliverable met 28 high-and-critical findings by arguing they were SSH vulnerabilities in
// golang.org/x/crypto that could not affect code using only the standard library. True of the 22
// x/crypto findings, and it silently generalised over 6 more in github.com/jackc/pgx/v5 -- a SQL
// injection among them -- in the Postgres driver its own main.go imports directly.
const GO_MOD = `
module webhook-receiver

go 1.21

require (
	github.com/jackc/pgx/v5 v5.5.2
	github.com/aws/aws-sdk-go-v2 v1.30.0
)

require (
	golang.org/x/crypto v0.24.0 // indirect
	golang.org/x/sys v0.21.0 // indirect
)
`;

test("go.mod: an indirect requirement is transitive, a plain one is direct", () => {
  inProject({ "go.mod": GO_MOD }, (dir) => {
    const m = directDependencies(dir);
    assert.equal(classifyDirect("github.com/jackc/pgx/v5", m), true);
    assert.equal(classifyDirect("golang.org/x/crypto", m), false);
  });
});

// osv-scanner names the module a finding lives in, which can be a subpackage of the declared root.
test("a subpackage of a declared Go module is direct", () => {
  inProject({ "go.mod": GO_MOD }, (dir) => {
    assert.equal(classifyDirect("github.com/jackc/pgx/v5/pgxpool", directDependencies(dir)), true);
  });
});

test("npm: dependencies and devDependencies are both direct", () => {
  inProject(
    {
      "package.json": JSON.stringify({
        dependencies: { express: "^4.18.2" },
        devDependencies: { jest: "^29.7.0" },
      }),
    },
    (dir) => {
      const m = directDependencies(dir);
      assert.equal(classifyDirect("express", m), true);
      // A vulnerable test-only package is still one this project chose.
      assert.equal(classifyDirect("jest", m), true);
      assert.equal(classifyDirect("fast-uri", m), false);
    }
  );
});

test("python: requirements.txt entries are direct, with versions and comments stripped", () => {
  inProject({ "requirements.txt": "boto3>=1.34\n# a comment\nFlask==3.0.0\n\n" }, (dir) => {
    const m = directDependencies(dir);
    assert.equal(classifyDirect("boto3", m), true);
    assert.equal(classifyDirect("flask", m), true);
    assert.equal(classifyDirect("urllib3", m), false);
  });
});

// Unknown is never reported as transitive: calling a direct dependency transitive is the direction
// that lets a reader put a finding down.
test("with no readable manifest, nothing is classified either way", () => {
  inProject({ "README.md": "# no manifest\n" }, (dir) => {
    const m = directDependencies(dir);
    assert.equal(m.known, false);
    assert.equal(classifyDirect("anything", m), null);
  });
});

test("a project with two ecosystems classifies both", () => {
  inProject(
    { "go.mod": GO_MOD, "package.json": JSON.stringify({ dependencies: { express: "^4.18.2" } }) },
    (dir) => {
      const m = directDependencies(dir);
      assert.equal(classifyDirect("github.com/jackc/pgx/v5", m), true);
      assert.equal(classifyDirect("express", m), true);
      assert.equal(classifyDirect("golang.org/x/crypto", m), false);
    }
  );
});
