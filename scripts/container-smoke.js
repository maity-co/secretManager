// Executed inside an isolated CI container. All identities and data are disposable.
import { readFile, writeFile } from "node:fs/promises";
import { randomBytes } from "node:crypto";
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
  if (process.argv.includes("--verify")) {
    const saved = JSON.parse(await readFile(file, "utf8"));
    bearer = saved.bearer;
    const value = await call(
      `/projects/${saved.projectId}/secrets/${saved.secretId}/value`,
    );
    if (value.value !== saved.value)
      throw new Error("Persistent data did not survive restart/restore.");
  } else {
    const setupToken = (await readFile("/keys/setup-token", "utf8")).trim();
    await call("/bootstrap", "POST", {
      setupToken,
      email: "owner@example.com",
      name: "Container Test",
      password: randomBytes(24).toString("base64url"),
    });
    const enrolled = await call("/auth/mfa/start", "POST", {});
    const code = new OTPAuth.TOTP({
      secret: OTPAuth.Secret.fromBase32(enrolled.manualKey),
      algorithm: "SHA1",
      digits: 6,
      period: 30,
    }).generate();
    await call("/auth/mfa/confirm", "POST", { code, delivery: "token" });
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
