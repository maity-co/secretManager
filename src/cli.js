#!/usr/bin/env node
import {
  mkdir,
  readFile,
  writeFile,
  rename,
  lstat,
  chmod,
  unlink,
} from "node:fs/promises";
import { randomBytes, createCipheriv, createDecipheriv } from "node:crypto";
import { createReadStream, createWriteStream } from "node:fs";
import { pipeline } from "node:stream/promises";
import { spawn } from "node:child_process";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { parseEnv } from "./env-format.js";
import { token, digest } from "./security.js";
import { randomUUID } from "node:crypto";
const args = process.argv.slice(2),
  command = args.shift();
const flag = (name) => {
  const index = args.indexOf("--" + name);
  return index < 0 ? null : args[index + 1];
};
const configFile =
  process.env.SM_AUTH_FILE ||
  join(
    process.env.XDG_CONFIG_HOME || join(homedir(), ".config"),
    "secretmanager",
    "auth.json",
  );
async function input() {
  let value = "";
  for await (const chunk of process.stdin) {
    value += chunk;
    if (value.length > 384 * 1024) throw new Error("Input too large.");
  }
  return value ? JSON.parse(value) : {};
}
async function save(config) {
  const dir = dirname(configFile);
  await mkdir(dir, { recursive: true, mode: 0o700 });
  if ((await lstat(dir)).isSymbolicLink())
    throw new Error("Auth directory must not be a symlink.");
  await chmod(dir, 0o700);
  const temp = join(dir, ".auth-" + randomBytes(8).toString("hex"));
  await writeFile(temp, JSON.stringify(config), { mode: 0o600, flag: "wx" });
  await rename(temp, configFile);
}
function safeUrl(value) {
  const url = new URL(value);
  if (
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    url.pathname !== "/" ||
    (url.protocol !== "https:" &&
      !["localhost", "127.0.0.1", "[::1]"].includes(url.hostname))
  )
    throw new Error("Use an HTTPS origin or loopback development origin.");
  return url.origin;
}
async function request(origin, path, method = "GET", body, bearer) {
  if (!path.startsWith("/api/") || path.includes(".."))
    throw new Error("Use an /api/ path.");
  const response = await fetch(origin + path, {
    method,
    headers: {
      ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
      ...(bearer ? { Authorization: "Bearer " + bearer } : {}),
    },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    signal: AbortSignal.timeout(30000),
    redirect: "error",
  });
  if (!response.ok) throw new Error(`Request rejected (${response.status}).`);
  return response.headers.get("content-type")?.includes("application/json")
    ? response.json()
    : response.text();
}
async function runChild(program, childArgs, options = {}) {
  const child = spawn(program, childArgs, options);
  await new Promise((yes, no) => {
    child.once("error", no);
    child.once("exit", (code) =>
      code === 0 ? yes() : no(new Error("Child command failed.")),
    );
  });
}
async function main() {
  if (command === "init") {
    const dir = resolve(flag("directory") || ".local/keys");
    await mkdir(dir, { recursive: true, mode: 0o700 });
    if ((await lstat(dir)).isSymbolicLink())
      throw new Error("Key directory must not be a symlink.");
    await chmod(dir, 0o700);
    for (const [name, value] of [
      ["master.key", randomBytes(32).toString("base64")],
      ["setup-token", randomBytes(32).toString("base64url")],
    ]) {
      try {
        await writeFile(join(dir, name), value + "\n", {
          mode: 0o600,
          flag: "wx",
        });
      } catch (error) {
        if (error.code !== "EEXIST") throw error;
      }
    }
    console.log("Key files initialized; existing files were preserved.");
    return;
  }
  if (command === "owner-reset-link") {
    const filename = flag("file");
    if (!filename)
      throw new Error("--file is required for protected recovery output.");
    const origin = safeUrl(
      flag("url") || process.env.APP_ORIGIN || "http://localhost:8080",
    );
    const { postgres } = await import("./db.js");
    const db = postgres(
      process.env.DATABASE_URL
        ? { connectionString: process.env.DATABASE_URL }
        : {
            host: process.env.PGHOST || "/run/postgresql",
            user: process.env.PGUSER || "secretmanager",
            database: process.env.PGDATABASE || "secretmanager",
          },
    );
    const raw = token(),
      id = randomUUID();
    // Reserve the output file before making any account change.
    await writeFile(filename, "", { flag: "wx", mode: 0o600 });
    try {
      await db.transaction(async (tx) => {
        const owner = (
          await tx.query(
            "SELECT id,email FROM users WHERE owner=true FOR UPDATE",
          )
        ).rows[0];
        if (!owner) throw new Error("No owner exists.");
        await tx.query("UPDATE invitations SET used=true WHERE email=$1", [
          owner.email,
        ]);
        if (args.includes("--reset-mfa"))
          await tx.query(
            "UPDATE users SET totp_box=NULL,totp_pending=NULL,pending_until=NULL,totp_counter=-1,recovery_hashes=ARRAY[]::text[] WHERE id=$1",
            [owner.id],
          );
        await tx.query(
          "DELETE FROM sessions WHERE actor_type=$1 AND actor_id=$2",
          ["user", owner.id],
        );
        await tx.query(
          "INSERT INTO invitations (id,email,token_hash,kind,user_id,expires_at) VALUES ($1,$2,$3,$4,$5,$6)",
          [
            id,
            owner.email,
            digest(raw),
            "reset",
            owner.id,
            new Date(Date.now() + 3600000),
          ],
        );
        await tx.query(
          "INSERT INTO audit_events (id,actor_type,actor_id,action,resource_id) VALUES ($1,$2,$3,$4,$5)",
          [
            randomUUID(),
            "user",
            owner.id,
            args.includes("--reset-mfa")
              ? "owner.host_recovery.mfa_reset"
              : "owner.host_recovery.issued",
            id,
          ],
        );
      });
      await writeFile(filename, origin + "/#reset=" + raw + "\n", {
        mode: 0o600,
      });
    } catch (error) {
      await unlink(filename).catch(() => {});
      throw error;
    } finally {
      await db.close();
    }
    console.log("Owner recovery link saved to the protected output file.");
    return;
  }
  if (command === "backup" || command === "restore") {
    const filename = flag("file");
    if (!filename) throw new Error("--file is required.");
    const key = Buffer.from(
      (
        await readFile(
          process.env.MASTER_KEY_FILE || "/keys/master.key",
          "utf8",
        )
      ).trim(),
      "base64",
    );
    if (key.length !== 32) throw new Error("Invalid encryption key.");
    if (command === "backup") {
      const nonce = randomBytes(12),
        cipher = createCipheriv("aes-256-gcm", key, nonce);
      cipher.setAAD(Buffer.from("SMBAK1"));
      const output = createWriteStream(filename, { mode: 0o600, flags: "wx" });
      output.write(Buffer.concat([Buffer.from("SMBAK1"), nonce]));
      const child = spawn(
        "pg_dump",
        [
          "--format=custom",
          "--no-owner",
          process.env.PGDATABASE || "secretmanager",
        ],
        { stdio: ["ignore", "pipe", "ignore"] },
      );
      const exited = new Promise((yes, no) => {
        child.once("error", no);
        child.once("exit", (code) =>
          code === 0 ? yes() : no(new Error("Backup process failed.")),
        );
      });
      try {
        await Promise.all([
          pipeline(child.stdout, cipher, output, { end: false }),
          exited,
        ]);
        await new Promise((yes, no) => {
          output.once("error", no);
          output.end(cipher.getAuthTag(), yes);
        });
      } catch (error) {
        child.kill();
        output.destroy();
        await unlink(filename).catch(() => {});
        throw error;
      }
      console.log(
        "Encrypted backup created. Preserve the encryption key separately.",
      );
      return;
    }
    if (!args.includes("--confirm-replace"))
      throw new Error(
        "Restore replaces the database; --confirm-replace is required.",
      );
    const bytes = await readFile(filename);
    if (bytes.length < 34 || bytes.subarray(0, 6).toString() !== "SMBAK1")
      throw new Error("Invalid backup format.");
    const cipher = createDecipheriv("aes-256-gcm", key, bytes.subarray(6, 18));
    cipher.setAAD(Buffer.from("SMBAK1"));
    cipher.setAuthTag(bytes.subarray(-16));
    // Authenticate the full archive before allowing pg_restore to change the database.
    const plaintext = Buffer.concat([
      cipher.update(bytes.subarray(18, -16)),
      cipher.final(),
    ]);
    const dir = process.env.TMPDIR || "/tmp",
      temporary = join(
        dir,
        "secretmanager-restore-" + randomBytes(16).toString("hex"),
      );
    try {
      await writeFile(temporary, plaintext, { flag: "wx", mode: 0o600 });
      await runChild(
        "pg_restore",
        [
          "--clean",
          "--if-exists",
          "--no-owner",
          "--exit-on-error",
          "--single-transaction",
          "--dbname",
          process.env.PGDATABASE || "secretmanager",
          temporary,
        ],
        { stdio: ["ignore", "ignore", "ignore"] },
      );
    } finally {
      plaintext.fill(0);
      await unlink(temporary).catch(() => {});
    }
    console.log("Database restored.");
    return;
  }
  if (command === "login" || command === "machine-login") {
    const origin = safeUrl(
        flag("url") || process.env.SM_URL || "http://localhost:8080",
      ),
      body = await input();
    let session;
    if (command === "machine-login")
      session = await request(origin, "/api/auth/machine", "POST", body);
    else {
      session = await request(origin, "/api/auth/login", "POST", {
        email: body.email,
        password: body.password,
        delivery: "token",
      });
      if (session.enrollmentRequired)
        throw new Error(
          "Enroll an authenticator in the web UI before using CLI login.",
        );
      if (session.pending)
        session = await request(
          origin,
          "/api/auth/mfa/verify",
          "POST",
          { code: body.code, delivery: "token" },
          session.accessToken,
        );
    }
    await save({
      origin,
      accessToken: session.accessToken,
      expiresAt: session.expiresAt,
    });
    console.log("Signed in. Session saved with owner-only permissions.");
    return;
  }
  if (command === "logout") {
    try {
      const config = JSON.parse(await readFile(configFile, "utf8"));
      await request(
        config.origin,
        "/api/auth/logout",
        "POST",
        {},
        config.accessToken,
      );
    } finally {
      await unlink(configFile).catch(() => {});
    }
    console.log("Signed out.");
    return;
  }
  if (!["projects", "get", "export", "run", "request"].includes(command)) {
    console.log(
      "Commands: init, login, machine-login, logout, projects, get, export, run, request, backup, restore, owner-reset-link. See docs/operations.md for safe stdin-based usage.",
    );
    return;
  }
  const config = JSON.parse(await readFile(configFile, "utf8")),
    origin = safeUrl(config.origin);
  if (new Date(config.expiresAt) <= new Date())
    throw new Error("Session expired. Sign in again.");
  if (command === "projects") {
    console.log(
      JSON.stringify(
        await request(
          origin,
          "/api/projects",
          "GET",
          undefined,
          config.accessToken,
        ),
        null,
        2,
      ),
    );
    return;
  }
  if (command === "request") {
    const [method, path] = args;
    const result = await request(
      origin,
      path,
      method,
      ["GET", "HEAD"].includes(method) ? undefined : await input(),
      config.accessToken,
    );
    process.stdout.write(
      typeof result === "string"
        ? result
        : JSON.stringify(result, null, 2) + "\n",
    );
    return;
  }
  const projectId = flag("project"),
    environment = flag("environment") || "development",
    path = flag("path") || "/";
  if (!projectId) throw new Error("--project is required.");
  const base = "/api/projects/" + encodeURIComponent(projectId),
    query = "?" + new URLSearchParams({ environment, path });
  if (command === "get") {
    const list = await request(
        origin,
        base + "/secrets" + query,
        "GET",
        undefined,
        config.accessToken,
      ),
      row = list.secrets.find(
        (item) => item.key === flag("key") && !item.deleted_at,
      );
    if (!row) throw new Error("Secret not found.");
    const value = await request(
      origin,
      base + "/secrets/" + row.id + "/value",
      "GET",
      undefined,
      config.accessToken,
    );
    process.stdout.write(value.value);
    return;
  }
  const content = await request(
    origin,
    base + "/export" + query,
    "GET",
    undefined,
    config.accessToken,
  );
  if (command === "export") {
    process.stdout.write(content);
    return;
  }
  const separator = args.indexOf("--");
  if (separator < 0 || !args[separator + 1])
    throw new Error("run requires -- executable [arguments].");
  await runChild(args[separator + 1], args.slice(separator + 2), {
    stdio: "inherit",
    env: { ...process.env, ...parseEnv(content) },
    shell: false,
  });
}
main().catch(() => {
  console.error(
    "Command failed. Check arguments, authorization and service availability. Sensitive diagnostics suppressed.",
  );
  process.exitCode = 1;
});
