import { readFile, mkdir, readdir, stat, unlink } from "node:fs/promises";
import { spawn } from "node:child_process";
import { join } from "node:path";
import { digest } from "./security.js";
import { postgres, migrate } from "./db.js";
import { createApp } from "./app.js";
import { backupIntervalHours } from "./config.js";
import { googleSettings } from "./google-auth.js";
let db;
async function main() {
  const backupHours = backupIntervalHours(process.env.BACKUP_INTERVAL_HOURS);
  const keyFile = process.env.MASTER_KEY_FILE || "/keys/master.key";
  const keyText = (await readFile(keyFile, "utf8")).trim();
  const key = Buffer.from(keyText, "base64");
  if (key.length !== 32 || key.toString("base64") !== keyText)
    throw new Error("Invalid encryption key file.");
  const setup = (
    await readFile(process.env.SETUP_TOKEN_FILE || "/keys/setup-token", "utf8")
  ).trim();
  if (setup.length < 32) throw new Error("Invalid setup token file.");
  db = postgres(
    process.env.DATABASE_URL
      ? { connectionString: process.env.DATABASE_URL }
      : {
          host: process.env.PGHOST || "/run/postgresql",
          user: process.env.PGUSER || "secretmanager",
          database: process.env.PGDATABASE || "secretmanager",
        },
  );
  await migrate(db);
  const mailKey = process.env.RESEND_API_KEY_FILE
    ? (await readFile(process.env.RESEND_API_KEY_FILE, "utf8")).trim()
    : process.env.RESEND_API_KEY;
  const mailEnvironment =
    mailKey !== undefined
      ? { enabled: !!mailKey, from: process.env.EMAIL_FROM || "", key: mailKey }
      : null;
  const trustProxy = Number(process.env.TRUST_PROXY_HOPS || 0);
  if (![0, 1, 2].includes(trustProxy))
    throw new Error("TRUST_PROXY_HOPS must be 0, 1 or 2.");
  if (
    process.env.GOOGLE_ONLY &&
    !["true", "false"].includes(process.env.GOOGLE_ONLY)
  )
    throw new Error("GOOGLE_ONLY must be true or false.");
  const googleSecret = process.env.GOOGLE_CLIENT_SECRET_FILE
    ? (await readFile(process.env.GOOGLE_CLIENT_SECRET_FILE, "utf8")).trim()
    : process.env.GOOGLE_CLIENT_SECRET || "";
  const google = googleSettings({
    clientId: process.env.GOOGLE_CLIENT_ID || "",
    clientSecret: googleSecret,
    hostedDomain: process.env.GOOGLE_HOSTED_DOMAIN || "",
    only: process.env.GOOGLE_ONLY === "true",
    ownerEmail: process.env.BOOTSTRAP_OWNER_EMAIL || "",
  });
  const app = await createApp({
    google,
    db,
    masterKey: key,
    setupTokenHash: digest(setup),
    origin: process.env.APP_ORIGIN || "http://localhost:8080",
    mailEnvironment,
    trustProxy,
    allowedEmailDomains: process.env.ALLOWED_EMAIL_DOMAINS || "",
    publicOperatorName: process.env.PUBLIC_OPERATOR_NAME || "",
  });
  const port = Number(process.env.PORT || 8080);
  if (!Number.isInteger(port) || port < 1 || port > 65535)
    throw new Error("Invalid PORT.");
  const server = app.listen(port, process.env.BIND_ADDRESS || "0.0.0.0", () =>
    console.log("SecretManager is listening."),
  );
  const cleanup = setInterval(async () => {
    try {
      await db.transaction(async (tx) => {
        await tx.query("DELETE FROM sessions WHERE expires_at<now()");
        await tx.query("DELETE FROM google_flows WHERE expires_at<now()");
        await tx.query(
          "DELETE FROM invitations WHERE expires_at<now()-interval '30 days'",
        );
        await tx.query(
          "DELETE FROM secrets WHERE deleted_at<now()-interval '30 days'",
        );
      });
    } catch {
      console.error("Scheduled cleanup failed; retrying later.");
    }
  }, 3600000);
  cleanup.unref();

  let backupChild = null;
  async function scheduledBackup() {
    if (backupChild) return;
    const directory = process.env.BACKUP_DIRECTORY || "/backups";
    try {
      await mkdir(directory, { recursive: true, mode: 0o700 });
      const filename = join(
        directory,
        "backup-" + new Date().toISOString().replaceAll(":", "-") + ".smbak",
      );
      const child = spawn(
        process.execPath,
        ["src/cli.js", "backup", "--file", filename],
        { stdio: "ignore" },
      );
      backupChild = child;
      await new Promise((yes, no) => {
        child.once("error", no);
        child.once("exit", (code) =>
          code === 0 ? yes() : no(new Error("Backup failed.")),
        );
      });
      for (const name of await readdir(directory)) {
        if (!/^backup-[0-9TZ.:-]+\.smbak$/.test(name)) continue;
        const file = join(directory, name);
        if (Date.now() - (await stat(file)).mtimeMs > 7 * 86400000)
          await unlink(file);
      }
      console.log("Scheduled encrypted backup completed.");
    } catch {
      console.error(
        "Scheduled backup failed; check storage and configuration.",
      );
    } finally {
      backupChild = null;
    }
  }
  const backupStart = backupHours ? setTimeout(scheduledBackup, 60000) : null;
  const backupTimer = backupHours
    ? setInterval(scheduledBackup, backupHours * 3600000)
    : null;
  backupStart?.unref();
  backupTimer?.unref();
  let stopping = false;
  async function shutdown() {
    if (stopping) return;
    stopping = true;
    clearInterval(cleanup);
    clearTimeout(backupStart);
    clearInterval(backupTimer);
    backupChild?.kill("SIGTERM");
    server.close(async () => {
      await db.close();
      process.exit(0);
    });
    setTimeout(() => process.exit(1), 15000).unref();
  }
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}
main().catch(async () => {
  console.error(
    "Service startup failed. Check database, encryption key files, origin and runtime configuration.",
  );
  await db?.close().catch(() => {});
  process.exit(1);
});
