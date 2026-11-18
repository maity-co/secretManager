// Executed inside an isolated CI container. All identities and data are disposable.
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import * as OTPAuth from "otpauth";
const base = "http://127.0.0.1:8080",
  file = "/tmp/secretmanager-smoke.json";
let bearer = "",
  cookie = "",
  csrf = "";
async function call(path, method = "GET", body) {
  const response = await fetch(base + "/api" + path, {
    method,
    headers: {
      ...(body ? { "Content-Type": "application/json" } : {}),
      ...(bearer
        ? { Authorization: "Bearer " + bearer }
        : cookie
          ? { Cookie: cookie, "X-CSRF-Token": csrf }
          : {}),
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const data = await response.json();
  if (!response.ok) throw new Error("Container API smoke check failed.");
  const header = response.headers.getSetCookie()[0];
  if (header) cookie = header.split(";")[0];
  if (data.csrf) csrf = data.csrf;
  if (data.accessToken) bearer = data.accessToken;
  return data;
}
try {
  if (process.argv.includes("--owner-recovery")) {
    const saved = JSON.parse(await readFile(file, "utf8"));
    const revoked = await fetch(base + "/api/auth/me", {
      headers: { Authorization: "Bearer " + saved.bearer },
    });
    if (revoked.status !== 401)
      throw new Error("Owner sessions were not revoked.");
    const link = new URL(
      (await readFile("/tmp/owner-recovery-link", "utf8")).trim(),
    );
    const resetToken = new URLSearchParams(link.hash.slice(1)).get("reset");
    const password = randomBytes(24).toString("base64url");
    bearer = "";
    await call("/accept-invitation", "POST", { token: resetToken, password });
    const login = await call("/auth/login", "POST", {
      email: "owner@example.com",
      password,
      delivery: "token",
    });
    if (!login.pending || !login.enrollmentRequired)
      throw new Error("Owner recovery bypassed required MFA.");
    const enrolled = await call("/auth/mfa/start", "POST", {});
    const code = new OTPAuth.TOTP({
      secret: OTPAuth.Secret.fromBase32(enrolled.manualKey),
      algorithm: "SHA1",
      digits: 6,
      period: 30,
    }).generate();
    await call("/auth/mfa/confirm", "POST", { code, delivery: "token" });
    const value = await call(
      `/projects/${saved.projectId}/secrets/${saved.secretId}/value`,
    );
    if (value.value !== saved.value)
      throw new Error("Owner recovery lost secret data.");
    const events = await call("/audit");
    if (
      !events.events.some(
        (event) => event.action === "owner.host_recovery.mfa_reset",
      )
    )
      throw new Error("Host recovery audit event missing.");
  } else if (process.argv.includes("--verify")) {
    const saved = JSON.parse(await readFile(file, "utf8"));
    bearer = saved.bearer;
    const value = await call(
      `/projects/${saved.projectId}/secrets/${saved.secretId}/value`,
    );
    if (value.value !== saved.value)
      throw new Error("Persistent data did not survive restart/restore.");
  } else {
    const setupToken = (await readFile("/keys/setup-token", "utf8")).trim();
    const ownerPassword = randomBytes(24).toString("base64url");
    await call("/bootstrap", "POST", {
      setupToken,
      email: "owner@example.com",
      name: "Container Test",
      password: ownerPassword,
    });
    const enrolled = await call("/auth/mfa/start", "POST", {});
    const code = new OTPAuth.TOTP({
      secret: OTPAuth.Secret.fromBase32(enrolled.manualKey),
      algorithm: "SHA1",
      digits: 6,
      period: 30,
    }).generate();
    const confirmed = await call("/auth/mfa/confirm", "POST", {
      code,
      delivery: "token",
    });
    const projectId = (
        await call("/projects", "POST", { name: "Container Example" })
      ).id,
      value = randomBytes(24).toString("base64url");
    const secretId = (
      await call(`/projects/${projectId}/secrets`, "POST", {
        key: "EXAMPLE",
        value,
        environment: "development",
        path: "/",
      })
    ).id;
    const machine = (
      await call(`/projects/${projectId}/machines`, "POST", {
        name: "CLI Test Worker",
      })
    ).id;
    const role = (
      await call(`/projects/${projectId}/roles`, "POST", {
        name: "CLI Reader",
        permissions: [
          "project.read",
          "secrets.list",
          "secrets.read",
          "secrets.export",
        ],
      })
    ).id;
    await call(`/projects/${projectId}/bindings`, "POST", {
      roleId: role,
      principalType: "machine",
      principalId: machine,
      environment: "development",
      path: "/",
    });
    const credential = await call(
      `/projects/${projectId}/machines/${machine}/credentials`,
      "POST",
      { days: 1 },
    );
    await mkdir("/tmp/secretmanager-cli", { mode: 0o700 });
    const clientEnv = {
      ...process.env,
      SM_AUTH_FILE: "/tmp/secretmanager-cli/auth.json",
    };
    function cli(args, input) {
      const result = spawnSync(process.execPath, ["src/cli.js", ...args], {
        env: clientEnv,
        input,
        encoding: "utf8",
      });
      if (result.status !== 0) throw new Error("CLI smoke check failed.");
      return result.stdout;
    }
    cli(
      ["login", "--url", base],
      JSON.stringify({
        email: "owner@example.com",
        password: ownerPassword,
        code: confirmed.recoveryCodes[0],
      }),
    );
    const humanProjects = JSON.parse(cli(["projects"]));
    if (!humanProjects.projects.some((project) => project.id === projectId))
      throw new Error("Human CLI access failed.");
    cli(["logout"]);
    cli(
      ["machine-login", "--url", base],
      JSON.stringify({
        clientId: machine,
        clientSecret: credential.clientSecret,
      }),
    );
    if (cli(["get", "--project", projectId, "--key", "EXAMPLE"]) !== value)
      throw new Error("CLI read failed.");
    if (
      cli([
        "run",
        "--project",
        projectId,
        "--",
        process.execPath,
        "-e",
        'process.stdout.write(process.env.EXAMPLE||"")',
        "--",
        "--path",
        "/child-argument-not-a-secret-scope",
      ]) !== value
    )
      throw new Error("CLI environment injection failed.");
    cli(["logout"]);
    await writeFile(
      file,
      JSON.stringify({ bearer, projectId, secretId, value }),
      { mode: 0o600 },
    );
  }
  console.log(
    "Container identity, encryption and persistence smoke check passed.",
  );
} catch {
  console.error(
    "Container smoke check failed; sensitive diagnostics suppressed.",
  );
  process.exitCode = 1;
}
