// Runs only in an isolated, network-disabled CI container with synthetic Google
// configuration. It never contacts Google or prints generated runtime tokens.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
const origin = "http://localhost:8080";
async function call(path, body) {
  const response = await fetch(origin + "/api" + path, {
    method: body ? "POST" : "GET",
    headers: body ? { "Content-Type": "application/json", Origin: origin } : {},
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  return { response, body: await response.json() };
}
const instance = await call("/instance");
assert.equal(instance.body.googleEnabled, true);
assert.equal(instance.body.googleOnly, true);
assert.equal(
  JSON.stringify(instance.body).includes(process.env.GOOGLE_CLIENT_SECRET),
  false,
);
const password = await call("/auth/login", {
  email: "owner@example.com",
  password: "synthetic-only",
});
assert.equal(password.response.status, 403);
const setupToken = (await readFile("/keys/setup-token", "utf8")).trim();
const start = await call("/auth/google/start", {
  action: "bootstrap",
  setupToken,
  email: "owner@example.com",
  name: "Example Owner",
});
assert.equal(start.response.status, 200);
assert.ok(start.response.headers.get("set-cookie").includes("HttpOnly"));
assert.ok(start.response.headers.get("set-cookie").includes("SameSite=Lax"));
const url = new URL(start.body.url);
assert.equal(url.origin, "https://accounts.google.com");
assert.equal(
  url.searchParams.get("redirect_uri"),
  origin + "/api/auth/google/callback",
);
assert.equal(url.searchParams.get("code_challenge_method"), "S256");
assert.equal(url.searchParams.get("hd"), "example.com");
assert.equal(url.searchParams.get("scope"), "openid email");
assert.equal(url.searchParams.has("client_secret"), false);
assert.equal(url.searchParams.has("setupToken"), false);
console.log("Synthetic Google runtime configuration and bootstrap passed.");
