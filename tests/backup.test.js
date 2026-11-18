import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, readFile, rm, chmod } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
function run(args, env) {
  return new Promise((yes, no) => {
    const child = spawn(process.execPath, ["src/cli.js", ...args], {
      env,
      stdio: ["ignore", "ignore", "ignore"],
    });
    child.once("error", no);
    child.once("exit", yes);
  });
}
test("backup archives are authenticated and tampering is rejected before restore", async () => {
  const dir = await mkdtemp(join(tmpdir(), "secretmanager-backup-test-"));
  try {
    const key = join(dir, "master.key"),
      fixture = join(dir, "fixture"),
      restored = join(dir, "restored"),
      archive = join(dir, "archive.smbak");
    await writeFile(key, randomBytes(32).toString("base64"), { mode: 0o600 });
    const bytes = randomBytes(8192);
    await writeFile(fixture, bytes, { mode: 0o600 });
    const dump = join(dir, "pg_dump"),
      restore = join(dir, "pg_restore");
    await writeFile(
      dump,
      '#!/usr/bin/env node\nprocess.stdout.write(require("fs").readFileSync(process.env.TEST_FIXTURE));\n',
    );
    await writeFile(
      restore,
      '#!/usr/bin/env node\nrequire("fs").copyFileSync(process.argv.at(-1),process.env.TEST_RESTORED);\n',
    );
    await chmod(dump, 0o700);
    await chmod(restore, 0o700);
    const env = {
      ...process.env,
      PATH: dir + ":" + process.env.PATH,
      MASTER_KEY_FILE: key,
      TEST_FIXTURE: fixture,
      TEST_RESTORED: restored,
      TMPDIR: dir,
    };
    assert.equal(await run(["backup", "--file", archive], env), 0);
    const encrypted = await readFile(archive);
    assert.ok(!encrypted.includes(bytes));
    assert.equal(
      await run(["restore", "--file", archive, "--confirm-replace"], env),
      0,
    );
    assert.deepEqual(await readFile(restored), bytes);
    await rm(restored);
    encrypted[20] ^= 1;
    await writeFile(archive, encrypted);
    assert.equal(
      await run(["restore", "--file", archive, "--confirm-replace"], env),
      1,
    );
    await assert.rejects(readFile(restored));
    assert.equal(await run(["backup", "--file", archive], env), 1);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
