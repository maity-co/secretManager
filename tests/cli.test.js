import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { spawn } from "node:child_process";
import { mkdtemp, mkdir, readFile, stat, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { token } from "../src/security.js";
function login(origin, file) {
  return new Promise((yes, no) => {
    const child = spawn(
      process.execPath,
      ["src/cli.js", "machine-login", "--url", origin],
      {
        env: { ...process.env, SM_AUTH_FILE: file },
        stdio: ["pipe", "ignore", "ignore"],
      },
    );
    child.once("error", no);
    child.once("exit", yes);
    child.stdin.end(
      JSON.stringify({ clientId: "synthetic-client", clientSecret: token() }),
    );
  });
}
test("CLI session files are private without changing existing directory permissions", async () => {
  const dir = await mkdtemp(join(tmpdir(), "secretmanager-cli-test-"));
  const access = token();
  const server = http.createServer((req, res) => {
    req.resume();
    req.on("end", () =>
      res.writeHead(200, { "Content-Type": "application/json" }).end(
        JSON.stringify({
          accessToken: access,
          expiresAt: new Date(Date.now() + 60000),
        }),
      ),
    );
  });
  await new Promise((yes) => server.listen(0, "127.0.0.1", yes));
  const origin = "http://127.0.0.1:" + server.address().port;
  try {
    const privateFile = join(dir, "private", "auth.json");
    assert.equal(await login(origin, privateFile), 0);
    assert.equal((await stat(privateFile)).mode & 0o777, 0o600);
    assert.equal(
      JSON.parse(await readFile(privateFile, "utf8")).accessToken,
      access,
    );
    const publicDir = join(dir, "shared");
    await mkdir(publicDir, { mode: 0o755 });
    const before = (await stat(publicDir)).mode;
    assert.equal(await login(origin, join(publicDir, "auth.json")), 1);
    assert.equal((await stat(publicDir)).mode, before);
    await assert.rejects(readFile(join(publicDir, "auth.json")));
    const linked = join(dir, "linked");
    await symlink(join(dir, "private"), linked);
    assert.equal(await login(origin, join(linked, "auth.json")), 1);
  } finally {
    await new Promise((yes) => server.close(yes));
    await rm(dir, { recursive: true, force: true });
  }
});
