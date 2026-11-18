import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import request from "supertest";
import { PGlite } from "@electric-sql/pglite";
import { postgres, migrate } from "../src/db.js";
import { createApp, PROJECT_PERMISSIONS } from "../src/app.js";
import { token, digest, authenticator } from "../src/security.js";
const origin = "http://localhost:8080";
async function database() {
  if (process.env.TEST_DATABASE_URL) {
    const url = new URL(process.env.TEST_DATABASE_URL);
    if (
      !["localhost", "127.0.0.1"].includes(url.hostname) ||
      !url.pathname.startsWith("/secretmanager_test")
    )
      throw new Error(
        "Tests require a loopback database named secretmanager_test*.",
      );
    return postgres({ connectionString: url.href, max: 5 });
  }
  const pg = new PGlite();
  const wrap = (tx) => ({
    query: async (text, values) => {
      if (values === undefined && text.includes(";")) {
        const result = await tx.exec(text);
        return result.at(-1) || { rows: [] };
      }
      return tx.query(text, values);
    },
  });
  return {
    ...wrap(pg),
    transaction: (fn) => pg.transaction((tx) => fn(wrap(tx))),
    close: () => pg.close(),
  };
}
test("end-to-end authorization, identity and secret lifecycle", async (t) => {
  const db = await database();
  await migrate(db);
  const setup = token(),
    ownerPassword = token(),
    masterKey = randomBytes(32);
  let mailCalls = 0;
  const app = await createApp({
    db,
    masterKey,
    setupTokenHash: digest(setup),
    origin,
    authLimit: 10000,
    fetchMail: async () => {
      mailCalls++;
      return new Response("Provider diagnostics must remain private", {
        status: 503,
      });
    },
  });
  const owner = { bearer: null, csrf: null, cookie: null },
    member = { bearer: null },
    outsider = { bearer: null };
  async function call(actor, method, path, body, expected = 200) {
    let req = request(app)
      [method]("/api" + path)
      .set("Origin", origin);
    if (actor?.bearer) req = req.set("Authorization", "Bearer " + actor.bearer);
    else if (actor?.cookie) {
      req = req.set("Cookie", actor.cookie);
      if (actor.csrf) req = req.set("X-CSRF-Token", actor.csrf);
    }
    if (body !== undefined) req = req.send(body);
    const response = await req;
    assert.equal(
      response.status,
      expected,
      `${method} ${path}: ${response.body.error || response.status}`,
    );
    if (actor) {
      if (response.body.accessToken) actor.bearer = response.body.accessToken;
      if (response.body.csrf) actor.csrf = response.body.csrf;
      if (response.headers["set-cookie"])
        actor.cookie = response.headers["set-cookie"][0].split(";")[0];
    }
    return response;
  }
  async function enroll(actor, email) {
    const start = await call(actor, "post", "/auth/mfa/start", {});
    const seed = start.body.manualKey;
    const code = authenticator(email, seed).generate();
    const done = await call(actor, "post", "/auth/mfa/confirm", {
      code,
      delivery: "token",
    });
    return { seed, codes: done.body.recoveryCodes };
  }
  async function addUser(email) {
    const invite = await call(owner, "post", "/admin/invitations", { email });
    assert.equal(invite.body.emailStatus, "not_requested");
    const invitation = new URL(invite.body.url).hash.split("=")[1],
      password = token();
    await call(null, "post", "/accept-invitation", {
      token: invitation,
      name: "Test Person",
      password,
    });
    const actor = { bearer: null };
    await call(actor, "post", "/auth/login", {
      email,
      password,
      delivery: "token",
    });
    const factors = await enroll(actor, email);
    return { ...actor, email, password, ...factors };
  }
  let ownerFactors,
    projectId,
    otherProject,
    secretId,
    readerId,
    memberInfo,
    plain = token(),
    machineId,
    machineSecret,
    machineCredential,
    machine;
  try {
    await t.test("a database rejects an unrelated encryption key", async () => {
      await assert.rejects(
        createApp({
          db,
          masterKey: randomBytes(32),
          setupTokenHash: digest(setup),
          origin,
        }),
      );
    });
    await t.test(
      "bootstrap is single-use and pending sessions cannot access projects",
      async () => {
        assert.equal(
          (await call(null, "get", "/bootstrap")).body.required,
          true,
        );
        await call(
          null,
          "post",
          "/bootstrap",
          {
            setupToken: token(),
            email: "owner@example.com",
            name: "Test Owner",
            password: ownerPassword,
          },
          403,
        );
        await call(owner, "post", "/bootstrap", {
          setupToken: setup,
          email: "owner@example.com",
          name: "Test Owner",
          password: ownerPassword,
        });
        assert.equal((await call(owner, "get", "/auth/me")).body.pending, true);
        await call(owner, "get", "/projects", undefined, 403);
        ownerFactors = await enroll(owner, "owner@example.com");
        assert.equal(ownerFactors.codes.length, 10);
        await call(
          null,
          "post",
          "/bootstrap",
          {
            setupToken: setup,
            email: "other@example.com",
            name: "Other Owner",
            password: token(),
          },
          403,
        );
      },
    );
    await t.test(
      "cookie mutations require CSRF and cross-origin requests fail",
      async () => {
        const browser = {};
        await call(browser, "post", "/auth/login", {
          email: "owner@example.com",
          password: ownerPassword,
        });
        await call(browser, "post", "/auth/mfa/verify", {
          code: ownerFactors.codes[0],
        });
        const noCsrf = await request(app)
          .post("/api/projects")
          .set("Origin", origin)
          .set("Cookie", browser.cookie)
          .send({ name: "CSRF attempt" });
        assert.equal(noCsrf.status, 403);
        assert.equal(noCsrf.body.code, "CSRF_MISMATCH");
        const peer = await addUser("session-switch@example.com");
        const otherBrowser = {};
        await call(otherBrowser, "post", "/auth/login", {
          email: peer.email,
          password: peer.password,
        });
        await call(otherBrowser, "post", "/auth/mfa/verify", {
          code: peer.codes[0],
        });
        // Another tab replaced the browser cookie, but this tab retains the
        // previous account's in-memory CSRF token and workspace.
        const staleTab = { cookie: otherBrowser.cookie, csrf: browser.csrf };
        const mismatch = await call(
          staleTab,
          "post",
          "/projects",
          {
            name: "Rejected Account Switch",
          },
          403,
        );
        assert.equal(mismatch.body.code, "CSRF_MISMATCH");
        assert.equal(
          (
            await db.query("SELECT id FROM projects WHERE name=$1", [
              "Rejected Account Switch",
            ])
          ).rows.length,
          0,
        );
        const current = await call(staleTab, "get", "/auth/me");
        assert.equal(current.body.email, peer.email);
        const denied = await call(
          staleTab,
          "post",
          "/projects",
          {
            name: "Still Not Authorized",
          },
          403,
        );
        assert.equal(denied.body.code, undefined);
        await call(staleTab, "post", "/auth/logout", {});
        await call(
          browser,
          "post",
          "/projects",
          { name: "CSRF Authorized Project" },
          201,
        );
        const foreign = await request(app)
          .post("/api/projects")
          .set("Origin", "https://untrusted.example")
          .set("Authorization", "Bearer " + owner.bearer)
          .send({ name: "Foreign" });
        assert.equal(foreign.status, 403);
        const malformed = await request(app)
          .post("/api/auth/login")
          .set("Content-Type", "application/json")
          .send("{invalid");
        assert.equal(malformed.status, 400);
      },
    );
    await t.test(
      "new projects have environments and users begin without project access",
      async () => {
        projectId = (
          await call(
            owner,
            "post",
            "/projects",
            { name: "Example Application" },
            201,
          )
        ).body.id;
        otherProject = (
          await call(
            owner,
            "post",
            "/projects",
            { name: "Separate Application" },
            201,
          )
        ).body.id;
        memberInfo = await addUser("reader@example.com");
        member.bearer = memberInfo.bearer;
        const guest = await addUser("outsider@example.com");
        outsider.bearer = guest.bearer;
        assert.equal(
          (await call(member, "get", "/projects")).body.projects.length,
          0,
        );
        await call(member, "get", "/admin/users", undefined, 403);
        const roles = (await call(owner, "get", `/projects/${projectId}/roles`))
          .body.roles;
        readerId = roles.find((role) => role.name === "Reader").id;
        await call(
          owner,
          "post",
          `/projects/${projectId}/bindings`,
          {
            roleId: readerId,
            principalType: "user",
            email: memberInfo.email,
            environment: "production",
            path: "/app",
          },
          201,
        );
        assert.equal(
          (await call(member, "get", "/projects")).body.projects.length,
          1,
        );
      },
    );
    await t.test(
      "secret values are encrypted, versioned and absent from list/audit output",
      async () => {
        secretId = (
          await call(
            owner,
            "post",
            `/projects/${projectId}/secrets`,
            {
              environment: "production",
              path: "/app",
              key: "EXAMPLE_VALUE",
              value: plain,
            },
            201,
          )
        ).body.id;
        const encrypted = (
          await db.query("SELECT box FROM secret_versions WHERE secret_id=$1", [
            secretId,
          ])
        ).rows[0].box;
        assert.ok(!encrypted.includes(plain));
        const list = await call(
          member,
          "get",
          `/projects/${projectId}/secrets?environment=production&path=/app`,
        );
        assert.ok(!JSON.stringify(list.body).includes(plain));
        assert.equal(
          (
            await call(
              member,
              "get",
              `/projects/${projectId}/secrets/${secretId}/value`,
            )
          ).body.value,
          plain,
        );
        await call(
          member,
          "post",
          `/projects/${projectId}/secrets`,
          {
            environment: "production",
            path: "/app",
            key: "OTHER",
            value: token(),
          },
          403,
        );
        await call(
          member,
          "get",
          `/projects/${projectId}/export?environment=production&path=/app`,
          undefined,
          403,
        );
        assert.ok(
          !JSON.stringify((await call(owner, "get", "/audit")).body).includes(
            plain,
          ),
        );
      },
    );
    await t.test(
      "project, environment and folder boundaries reject sideways access",
      async () => {
        await call(
          member,
          "get",
          `/projects/${projectId}/secrets?environment=production&path=/application`,
          undefined,
          403,
        );
        await call(
          member,
          "get",
          `/projects/${projectId}/secrets?environment=staging&path=/app`,
          undefined,
          403,
        );
        await call(
          member,
          "get",
          `/projects/${otherProject}/secrets/${secretId}/value`,
          undefined,
          404,
        );
        await call(
          outsider,
          "get",
          `/projects/${projectId}/secrets/${secretId}/value`,
          undefined,
          403,
        );
        await call(
          member,
          "post",
          `/projects/${projectId}/bindings`,
          {
            roleId: readerId,
            principalType: "user",
            email: "outsider@example.com",
          },
          403,
        );
      },
    );
    await t.test(
      "custom roles cannot be used to self-escalate organization permissions",
      async () => {
        const role = (
          await call(
            owner,
            "post",
            "/roles",
            { name: "Role Maintainer", permissions: ["org.roles.manage"] },
            201,
          )
        ).body.id;
        await call(
          owner,
          "post",
          "/bindings",
          { roleId: role, principalType: "user", email: memberInfo.email },
          201,
        );
        await call(
          member,
          "post",
          "/roles",
          { name: "Escalation", permissions: ["org.users.manage"] },
          403,
        );
        await call(
          member,
          "post",
          "/bindings",
          {
            roleId: (await call(owner, "get", "/roles")).body.roles.find(
              (role) => role.name === "Administrator",
            ).id,
            principalType: "user",
            email: memberInfo.email,
          },
          403,
        );
      },
    );
    await t.test(
      "soft deletion and restoration preserve encrypted versions",
      async () => {
        await call(
          owner,
          "post",
          `/projects/${projectId}/secrets`,
          {
            environment: "production",
            path: "/app",
            key: "EXAMPLE_VALUE",
            value: token(),
          },
          201,
        );
        await call(
          owner,
          "delete",
          `/projects/${projectId}/secrets/${secretId}`,
          {},
        );
        await call(
          member,
          "get",
          `/projects/${projectId}/secrets/${secretId}/value`,
          undefined,
          404,
        );
        assert.equal(
          (
            await call(
              owner,
              "get",
              `/projects/${projectId}/secrets/${secretId}/versions`,
            )
          ).body.versions.length,
          2,
        );
        assert.equal(
          (
            await call(
              owner,
              "post",
              `/projects/${projectId}/secrets/${secretId}/restore`,
              { version: 1 },
            )
          ).body.version,
          3,
        );
        assert.equal(
          (
            await call(
              member,
              "get",
              `/projects/${projectId}/secrets/${secretId}/value`,
            )
          ).body.value,
          plain,
        );
      },
    );
    await t.test(
      "dotenv preview is non-mutating and import is atomic with explicit conflict behavior",
      async () => {
        const content =
          'IMPORT_ONE="first\\nsecond"\nIMPORT_TWO="${LITERAL}"\n';
        const preview = await call(
          owner,
          "post",
          `/projects/${projectId}/import/preview`,
          { environment: "production", path: "/app", content },
        );
        assert.equal(preview.body.keys.length, 2);
        assert.equal(
          (
            await call(
              owner,
              "get",
              `/projects/${projectId}/secrets?environment=production&path=/app`,
            )
          ).body.secrets.length,
          1,
        );
        await call(owner, "post", `/projects/${projectId}/import`, {
          environment: "production",
          path: "/app",
          content,
          conflicts: "skip",
        });
        assert.equal(
          (
            await call(owner, "post", `/projects/${projectId}/import`, {
              environment: "production",
              path: "/app",
              content,
              conflicts: "skip",
            })
          ).body.skipped,
          2,
        );
        const exported = await call(
          owner,
          "get",
          `/projects/${projectId}/export?environment=production&path=/app`,
        );
        assert.ok(exported.text.includes("IMPORT_ONE="));
        await call(
          owner,
          "post",
          `/projects/${projectId}/import`,
          {
            environment: "production",
            path: "/app",
            content: "VALID=one\ninvalid",
            conflicts: "skip",
          },
          400,
        );
      },
    );
    await t.test(
      "machine tokens respect scopes and credential revocation takes effect immediately",
      async () => {
        machineId = (
          await call(
            owner,
            "post",
            `/projects/${projectId}/machines`,
            { name: "Example Worker" },
            201,
          )
        ).body.id;
        const role = (
          await call(
            owner,
            "post",
            `/projects/${projectId}/roles`,
            {
              name: "Machine Reader",
              permissions: [
                "project.read",
                "secrets.list",
                "secrets.read",
                "secrets.export",
              ],
            },
            201,
          )
        ).body.id;
        await call(
          owner,
          "post",
          `/projects/${projectId}/bindings`,
          {
            roleId: role,
            principalType: "machine",
            principalId: machineId,
            environment: "production",
            path: "/app",
          },
          201,
        );
        const credential = await call(
          owner,
          "post",
          `/projects/${projectId}/machines/${machineId}/credentials`,
          { days: 1 },
          201,
        );
        machineSecret = credential.body.clientSecret;
        machineCredential = credential.body.id;
        machine = { bearer: null };
        await call(machine, "post", "/auth/machine", {
          clientId: machineId,
          clientSecret: machineSecret,
        });
        assert.equal(
          (
            await call(
              machine,
              "get",
              `/projects/${projectId}/secrets/${secretId}/value`,
            )
          ).body.value,
          plain,
        );
        await call(
          machine,
          "get",
          `/projects/${projectId}/export?environment=staging&path=/app`,
          undefined,
          403,
        );
        await call(machine, "get", "/admin/users", undefined, 403);
        await call(
          owner,
          "delete",
          `/projects/${projectId}/credentials/${machineCredential}`,
          {},
        );
        await call(
          machine,
          "get",
          `/projects/${projectId}/secrets/${secretId}/value`,
          undefined,
          401,
        );
        await call(
          null,
          "post",
          "/auth/machine",
          { clientId: machineId, clientSecret: machineSecret },
          401,
        );

        const replacement = (
          await call(
            owner,
            "post",
            `/projects/${projectId}/machines/${machineId}/credentials`,
            { days: 1 },
            201,
          )
        ).body;
        const resumed = { bearer: null };
        await call(resumed, "post", "/auth/machine", {
          clientId: machineId,
          clientSecret: replacement.clientSecret,
        });
        await call(
          owner,
          "patch",
          `/projects/${projectId}/machines/${machineId}`,
          { disabled: true },
        );
        await call(
          owner,
          "patch",
          `/projects/${projectId}/machines/${machineId}`,
          { disabled: false },
        );
        await call(
          resumed,
          "get",
          `/projects/${projectId}/secrets/${secretId}/value`,
          undefined,
          401,
        );
        await call(resumed, "post", "/auth/machine", {
          clientId: machineId,
          clientSecret: replacement.clientSecret,
        });
        await db.query(
          "UPDATE machine_credentials SET expires_at=now()-interval '1 minute' WHERE id=$1",
          [replacement.id],
        );
        await call(
          resumed,
          "get",
          `/projects/${projectId}/secrets/${secretId}/value`,
          undefined,
          401,
        );
      },
    );
    await t.test(
      "invitations are single-use, revocable and work without email",
      async () => {
        const invite = await call(owner, "post", "/admin/invitations", {
          email: "single@example.com",
          sendEmail: true,
        });
        assert.equal(invite.body.emailStatus, "not_configured");
        assert.equal(mailCalls, 0);
        const invitation = new URL(invite.body.url).hash.split("=")[1];
        await call(null, "post", "/accept-invitation", {
          token: invitation,
          name: "Single Use",
          password: token(),
        });
        await call(
          null,
          "post",
          "/accept-invitation",
          { token: invitation, name: "Second Attempt", password: token() },
          400,
        );
        const revoked = await call(owner, "post", "/admin/invitations", {
          email: "revoked@example.com",
        });
        await call(
          owner,
          "delete",
          "/admin/invitations/" + revoked.body.id,
          {},
        );
        await call(
          null,
          "post",
          "/accept-invitation",
          {
            token: new URL(revoked.body.url).hash.split("=")[1],
            name: "Revoked",
            password: token(),
          },
          400,
        );
      },
    );
    await t.test(
      "email settings are encrypted and provider errors never escape",
      async () => {
        const key = token();
        await call(owner, "put", "/settings", {
          requireMfa: true,
          mail: { enabled: true, from: "secrets@example.com", key },
        });
        const settings = await call(owner, "get", "/settings");
        assert.equal(settings.body.mail.keyConfigured, true);
        assert.ok(!JSON.stringify(settings.body).includes(key));
        assert.ok(
          !JSON.stringify(
            (await db.query("SELECT mail FROM service_state WHERE id=1")).rows,
          ).includes(key),
        );
        const invite = await call(owner, "post", "/admin/invitations", {
          email: "delivery@example.com",
          sendEmail: true,
        });
        assert.equal(invite.body.emailStatus, "failed");
        assert.ok(
          !JSON.stringify(invite.body).includes("Provider diagnostics"),
        );
        assert.equal(mailCalls, 1);
      },
    );
    await t.test(
      "password resets preserve enrolled MFA and revoke existing sessions",
      async () => {
        const invite = await call(owner, "post", "/admin/invitations", {
          email: memberInfo.email,
          kind: "reset",
        });
        const password = token();
        await call(null, "post", "/accept-invitation", {
          token: new URL(invite.body.url).hash.split("=")[1],
          password,
        });
        await call(member, "get", "/auth/me", undefined, 401);
        member.bearer = null;
        const login = await call(member, "post", "/auth/login", {
          email: memberInfo.email,
          password,
          delivery: "token",
        });
        assert.equal(login.body.pending, true);
        await call(member, "get", "/projects", undefined, 403);
        await call(member, "post", "/auth/mfa/verify", {
          code: memberInfo.codes[0],
          delivery: "token",
        });
        const pending = { bearer: null };
        await call(pending, "post", "/auth/login", {
          email: memberInfo.email,
          password,
          delivery: "token",
        });
        await call(
          pending,
          "post",
          "/auth/mfa/verify",
          { code: memberInfo.codes[0], delivery: "token" },
          401,
        );
        await call(pending, "post", "/auth/mfa/verify", {
          code: memberInfo.codes[1],
          delivery: "token",
        });
        memberInfo.password = password;
      },
    );
    await t.test(
      "factor attempts are limited per identity across pending sessions",
      async () => {
        const limited = await createApp({
          db,
          masterKey,
          setupTokenHash: digest(setup),
          origin,
          authLimit: 30,
        });
        const pending = [];
        for (let index = 0; index < 2; index++) {
          const response = await request(limited)
            .post("/api/auth/login")
            .set("Origin", origin)
            .send({
              email: memberInfo.email,
              password: memberInfo.password,
              delivery: "token",
            });
          assert.equal(response.status, 200);
          pending.push(response.body.accessToken);
        }
        for (let index = 0; index < 11; index++) {
          const response = await request(limited)
            .post("/api/auth/mfa/verify")
            .set("Origin", origin)
            .set("Authorization", "Bearer " + pending[index % 2])
            .send({ code: "invalid-format", delivery: "token" });
          assert.equal(response.status, index < 10 ? 401 : 429);
        }
      },
    );
    await t.test(
      "an authenticator code cannot authenticate two simultaneous challenges",
      async () => {
        const a = { bearer: null },
          b = { bearer: null };
        for (const actor of [a, b])
          await call(actor, "post", "/auth/login", {
            email: memberInfo.email,
            password: memberInfo.password,
            delivery: "token",
          });
        const code = authenticator(memberInfo.email, memberInfo.seed).generate({
          timestamp: Date.now() + 30000,
        });
        const results = await Promise.all(
          [a, b].map((actor) =>
            request(app)
              .post("/api/auth/mfa/verify")
              .set("Origin", origin)
              .set("Authorization", "Bearer " + actor.bearer)
              .send({ code, delivery: "token" }),
          ),
        );
        assert.deepEqual(results.map((row) => row.status).sort(), [200, 401]);
      },
    );
    await t.test(
      "disabled users and removed role bindings lose access on their next request",
      async () => {
        const current = (
          await call(owner, "get", `/projects/${projectId}/roles`)
        ).body.bindings.find((row) => row.role_id === readerId);
        await call(
          owner,
          "delete",
          `/projects/${projectId}/bindings/${current.id}`,
          {},
        );
        await call(
          member,
          "get",
          `/projects/${projectId}/secrets/${secretId}/value`,
          undefined,
          403,
        );
        const users = (await call(owner, "get", "/admin/users")).body.users;
        const target = users.find((user) => user.email === memberInfo.email);
        await call(owner, "patch", "/admin/users/" + target.id, {
          disabled: true,
        });
        await call(member, "get", "/auth/me", undefined, 401);
      },
    );
  } finally {
    await db.close();
  }
});
