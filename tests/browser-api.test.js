import test from "node:test";
import assert from "node:assert/strict";
import { createApi, SESSION_CHANGED_MESSAGE } from "../web/api.js";

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });

test("a replaced cookie blocks the stale client without replaying the mutation", async () => {
  const calls = [];
  let changed = 0;
  const api = createApi({
    fetcher: async (path, options) => {
      calls.push({ path, options });
      return calls.length === 1
        ? json({ csrf: "synthetic-old-session", email: "owner@example.com" })
        : json(
            { code: "CSRF_MISMATCH", error: "CSRF verification failed." },
            403,
          );
    },
    onSessionChanged: () => changed++,
  });
  await api("/auth/me");
  await assert.rejects(api("/projects", "POST", { name: "Example" }), {
    message: SESSION_CHANGED_MESSAGE,
  });
  assert.equal(changed, 1);
  assert.equal(calls.length, 2);
  assert.equal(
    calls[1].options.headers["X-CSRF-Token"],
    "synthetic-old-session",
  );
  assert.equal(calls[1].options.credentials, "same-origin");
  await assert.rejects(api("/auth/me"), { message: SESSION_CHANGED_MESSAGE });
  await assert.rejects(api("/auth/logout", "POST", {}), {
    message: SESSION_CHANGED_MESSAGE,
  });
  assert.equal(calls.length, 2);
});

test("an in-flight response cannot restore stale state after a session mismatch", async () => {
  let finishRead;
  const api = createApi({
    fetcher: async (path) =>
      path === "/api/projects"
        ? new Promise((resolve) => {
            finishRead = resolve;
          })
        : json({ code: "CSRF_MISMATCH" }, 403),
  });
  const read = api("/projects");
  await assert.rejects(api("/settings", "PUT", {}), {
    message: SESSION_CHANGED_MESSAGE,
  });
  finishRead(json({ csrf: "synthetic-new-session", projects: [] }));
  await assert.rejects(read, { message: SESSION_CHANGED_MESSAGE });
});

test("ordinary permission denials do not block the browser client", async () => {
  let changed = 0;
  let calls = 0;
  const api = createApi({
    fetcher: async () =>
      ++calls === 1
        ? json({ error: "Permission denied." }, 403)
        : json({ projects: [] }),
    onSessionChanged: () => changed++,
  });
  await assert.rejects(api("/admin/users"), { message: "Permission denied." });
  assert.deepEqual(await api("/projects"), { projects: [] });
  assert.equal(changed, 0);
});

test("legacy CSRF errors also require reload without retry", async () => {
  let changed = 0;
  const api = createApi({
    fetcher: async () => json({ error: "CSRF verification failed." }, 403),
    onSessionChanged: () => changed++,
  });
  await assert.rejects(api("/auth/logout", "POST", {}), {
    message: SESSION_CHANGED_MESSAGE,
  });
  assert.equal(changed, 1);
});

test("hosted email restriction keeps its information-page behavior", async () => {
  let restricted = 0;
  const api = createApi({
    fetcher: async () =>
      json(
        {
          code: "EMAIL_DOMAIN_NOT_ALLOWED",
          error: "Email domain is not allowed.",
        },
        403,
      ),
    onRestricted: () => restricted++,
  });
  await assert.rejects(api("/auth/login", "POST", {}), {
    message: "Email domain is not allowed.",
  });
  assert.equal(restricted, 1);
});

test("trusted-session reauthentication redirects an identified browser without replay", async () => {
  let calls = 0;
  let redirects = 0;
  const api = createApi({
    fetcher: async () =>
      ++calls === 1
        ? json({ csrf: "synthetic-session" })
        : json(
            { code: "SESSION_REAUTH_REQUIRED", error: "Sign in required." },
            401,
          ),
    onReauthenticationRequired: () => redirects++,
  });
  await api("/auth/me");
  await assert.rejects(api("/projects", "POST", { name: "Example" }), {
    message: "Sign in required.",
  });
  assert.equal(redirects, 1);
  assert.equal(calls, 2);
});

test("an anonymous initial request does not cause a sign-in redirect loop", async () => {
  let redirects = 0;
  const api = createApi({
    fetcher: async () =>
      json(
        { code: "SESSION_REAUTH_REQUIRED", error: "Sign in required." },
        401,
      ),
    onReauthenticationRequired: () => redirects++,
  });
  await assert.rejects(api("/auth/me"), { message: "Sign in required." });
  assert.equal(redirects, 0);
});
