import test from "node:test";
import assert from "node:assert/strict";
import {
  randomBytes,
  randomUUID,
  generateKeyPairSync,
  sign,
  createHash,
} from "node:crypto";
import { OAuth2Client } from "google-auth-library";
import request from "supertest";
import { PGlite } from "@electric-sql/pglite";
import { postgres, migrate } from "../src/db.js";
import { createApp } from "../src/app.js";
import { googleSettings, googleProvider } from "../src/google-auth.js";
import {
  digest,
  token,
  authenticator,
  hashPassword,
  vault,
} from "../src/security.js";

const origin = "http://localhost:8080";
const settings = googleSettings({
  clientId: "synthetic-client.apps.googleusercontent.com",
  clientSecret: "synthetic-client-secret-for-tests",
  hostedDomain: "company.example",
  only: true,
  ownerEmail: "owner@company.example",
});
function claims(nonce, extra = {}) {
  return {
    iss: "https://accounts.google.com",
    aud: settings.clientId,
    sub: "synthetic-owner",
    email: "owner@company.example",
    email_verified: true,
    hd: "company.example",
    nonce,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
    ...extra,
  };
}
function fakeGoogle() {
  return {
    starts: [],
    extra: {},
    exchanges: 0,
    generateAuthUrl(options) {
      this.starts.push(options);
      return (
        "https://accounts.google.com/o/oauth2/v2/auth?" +
        new URLSearchParams(options)
      );
    },
    async getToken(options) {
      this.exchanges++;
      assert.equal(options.redirect_uri, origin + "/api/auth/google/callback");
      assert.equal(
        createHash("sha256").update(options.codeVerifier).digest("base64url"),
        this.starts.at(-1).code_challenge,
      );
      if (this.failure)
        throw new Error("synthetic-sensitive-provider-response");
      return { tokens: { id_token: "synthetic-only" } };
    },
    async verifyIdToken(options) {
      assert.equal(options.audience, settings.clientId);
      return { getPayload: () => claims(this.starts.at(-1).nonce, this.extra) };
    },
  };
}
async function isolatedDatabase() {
  if (process.env.TEST_DATABASE_URL) {
    const url = new URL(process.env.TEST_DATABASE_URL);
    if (
      !["localhost", "127.0.0.1"].includes(url.hostname) ||
      !url.pathname.startsWith("/secretmanager_test")
    )
      throw new Error("Tests require a loopback test database.");
    const admin = postgres({ connectionString: url.href }),
      schema = "google_" + randomUUID().replaceAll("-", "");
    await admin.query(`CREATE SCHEMA "${schema}"`);
    const db = postgres({
      connectionString: url.href,
      options: `-c search_path=${schema}`,
      max: 5,
    });
    return {
      ...db,
      close: async () => {
        await db.close();
        try {
          await admin.query(`DROP SCHEMA "${schema}" CASCADE`);
        } finally {
          await admin.close();
        }
      },
    };
  }
  const pg = new PGlite(),
    wrap = (tx) => ({
      query: async (text, values) =>
        values === undefined && text.includes(";")
          ? (await tx.exec(text)).at(-1)
          : tx.query(text, values),
    });
  return {
    ...wrap(pg),
    transaction: (fn) => pg.transaction((tx) => fn(wrap(tx))),
    close: () => pg.close(),
  };
}
function actor(app) {
  return { agent: request.agent(app), csrf: "" };
}
async function call(who, method, path, body, status = 200) {
  let req = who.agent[method]("/api" + path)
    .set("Origin", origin)
    .set("X-CSRF-Token", who.csrf);
  const res = await (body === undefined ? req : req.send(body));
  assert.equal(res.status, status, res.body.error || path);
  if (res.body.csrf) who.csrf = res.body.csrf;
  return res;
}
async function begin(who, body = {}) {
  const res = await call(who, "post", "/auth/google/start", body);
  return {
    state: new URL(res.body.url).searchParams.get("state"),
    response: res,
  };
}
async function callback(who, flow, extra = {}) {
  const res = await who.agent
    .get("/api/auth/google/callback")
    .query({ state: flow.state, code: "synthetic-code", ...extra });
  assert.equal(res.status, 303);
  return res;
}
async function finishMfa(who, email) {
  const start = await call(who, "post", "/auth/mfa/start", {});
  return (
    await call(who, "post", "/auth/mfa/confirm", {
      code: authenticator(email, start.body.manualKey).generate(),
    })
  ).body.recoveryCodes;
}

test("Google runtime configuration is optional and invalid combinations fail closed", () => {
  assert.equal(googleSettings(), null);
  for (const patch of [
    { clientId: "" },
    { clientSecret: "" },
    { hostedDomain: "*.company.example" },
    { hostedDomain: "company.example,other.example" },
    { only: "false" },
    { ownerEmail: "invalid" },
    { clientSecret: "line\nbreak" },
  ])
    assert.throws(() => googleSettings({ ...settings, ...patch }));
});

test("Google library verifies actual signed ID tokens before application claim checks", async () => {
  const keys = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const wrongKeys = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const client = new OAuth2Client({
    clientId: settings.clientId,
    clientSecret: settings.clientSecret,
    issuers: ["https://accounts.google.com", "accounts.google.com"],
  });
  let payload,
    signingKey = keys.privateKey,
    requests = 0;
  client.transporter.request = async (opts) => {
    requests++;
    if (opts.url.includes("/certs"))
      return {
        data: {
          synthetic: keys.publicKey.export({ type: "spki", format: "pem" }),
        },
        headers: new Headers({ "cache-control": "max-age=3600" }),
      };
    assert.equal(opts.url, "https://oauth2.googleapis.com/token");
    assert.equal(opts.data.get("code_verifier").length, 86);
    const unsigned = [{ alg: "RS256", kid: "synthetic" }, payload]
      .map((x) => Buffer.from(JSON.stringify(x)).toString("base64url"))
      .join(".");
    return {
      data: {
        id_token:
          unsigned +
          "." +
          sign("RSA-SHA256", Buffer.from(unsigned), signingKey).toString(
            "base64url",
          ),
      },
    };
  };
  const provider = googleProvider(settings, origin, client),
    flow = provider.begin();
  const auth = new URL(flow.url);
  assert.equal(auth.searchParams.get("scope"), "openid email");
  assert.equal(auth.searchParams.get("code_challenge_method"), "S256");
  assert.equal(auth.searchParams.get("access_type"), "online");
  payload = claims(flow.nonce);
  assert.deepEqual(
    await provider.identity("synthetic", flow.verifier, flow.nonce),
    { subject: payload.sub, email: payload.email },
  );
  const certRequests = requests;
  for (const patch of [
    { iss: "https://attacker.example" },
    { aud: "another-client" },
    { azp: "another-client" },
    { exp: Math.floor(Date.now() / 1000) - 1 },
    { iat: Math.floor(Date.now() / 1000) + 120 },
    { nonce: "wrong" },
    { email_verified: false },
    { hd: "elsewhere.example" },
    { hd: undefined },
    { sub: "" },
    { email: "bad" },
  ]) {
    payload = claims(flow.nonce, patch);
    await assert.rejects(
      provider.identity("synthetic", flow.verifier, flow.nonce),
    );
  }
  payload = claims(flow.nonce);
  signingKey = wrongKeys.privateKey;
  await assert.rejects(
    provider.identity("synthetic", flow.verifier, flow.nonce),
  );
  assert.equal(
    requests - certRequests,
    12,
    "verification keys should be cached",
  );
});

test("Google sessions, owner admission and invitations enforce browser identity and MFA", async (t) => {
  const db = await isolatedDatabase(),
    setup = token(),
    googleClient = fakeGoogle(),
    masterKey = randomBytes(32);
  await migrate(db);
  const app = await createApp({
    db,
    masterKey,
    setupTokenHash: digest(setup),
    origin,
    google: settings,
    googleClient,
    allowedEmailDomains: "company.example",
    authLimit: 1000,
  });
  const owner = actor(app);
  let recovery = [],
    ownerId;
  try {
    await t.test(
      "owner setup requires the configured address and protected setup token",
      async () => {
        await call(
          owner,
          "post",
          "/auth/google/start",
          {
            action: "bootstrap",
            setupToken: "wrong",
            email: settings.ownerEmail,
            name: "Owner",
          },
          403,
        );
        await call(
          owner,
          "post",
          "/auth/google/start",
          {
            action: "bootstrap",
            setupToken: setup,
            email: "another@company.example",
            name: "Owner",
          },
          403,
        );
        await call(
          owner,
          "post",
          "/bootstrap",
          {
            setupToken: setup,
            email: settings.ownerEmail,
            name: "Owner",
            password: "synthetic-test-password",
          },
          403,
        );
        assert.equal(
          Number((await db.query("SELECT count(*) FROM users")).rows[0].count),
          0,
        );
      },
    );
    await t.test(
      "state is short lived, encrypted, browser bound, single use and does not expose provider failures",
      async () => {
        const f = await begin(owner, {
          action: "bootstrap",
          setupToken: setup,
          email: settings.ownerEmail,
          name: "Owner",
        });
        assert.ok(f.response.headers["set-cookie"][0].includes("HttpOnly"));
        assert.ok(f.response.headers["set-cookie"][0].includes("SameSite=Lax"));
        const stored = (
          await db.query("SELECT * FROM google_flows WHERE token_hash=$1", [
            digest(f.state),
          ])
        ).rows[0];
        assert.ok(!JSON.stringify(stored).includes(settings.ownerEmail));
        assert.ok(!stored.box.includes(googleClient.starts.at(-1).nonce));
        assert.equal(
          (await callback(actor(app), f)).headers.location,
          "/signin#google=failed",
        );
        assert.equal(googleClient.exchanges, 0);
        googleClient.failure = true;
        const denied = await callback(owner, f);
        assert.equal(denied.headers.location, "/signin#google=failed");
        assert.ok(
          !denied.text.includes("synthetic-sensitive-provider-response"),
        );
        googleClient.failure = false;
        assert.equal(
          (await callback(owner, f)).headers.location,
          "/signin#google=failed",
        );
        assert.equal(googleClient.exchanges, 1);
        const expired = await begin(owner);
        await db.query(
          "UPDATE google_flows SET expires_at=now()-interval '1 minute'",
        );
        assert.equal(
          (await callback(owner, expired)).headers.location,
          "/signin#google=failed",
        );
        const cancelled = await begin(owner);
        assert.equal(
          (await callback(owner, cancelled, { error: "access_denied" })).headers
            .location,
          "/signin#google=failed",
        );
        assert.equal(
          Number(
            (
              await db.query(
                "SELECT count(*) FROM google_flows WHERE token_hash=$1",
                [digest(cancelled.state)],
              )
            ).rows[0].count,
          ),
          0,
        );
      },
    );
    await t.test(
      "Google creates the pinned owner without a password and requires authenticator enrollment",
      async () => {
        const f = await begin(owner, {
          action: "bootstrap",
          setupToken: setup,
          email: settings.ownerEmail,
          name: "Owner",
        });
        assert.equal((await callback(owner, f)).headers.location, "/signin");
        const user = (await call(owner, "get", "/auth/me")).body;
        ownerId = user.id;
        assert.equal(user.owner, true);
        assert.equal(user.pending, true);
        assert.equal(user.googleLinked, true);
        assert.equal(user.hasPassword, false);
        await call(owner, "get", "/projects", undefined, 403);
        recovery = await finishMfa(owner, settings.ownerEmail);
        assert.equal(
          (await call(owner, "get", "/auth/me")).body.primaryMethod,
          "google",
        );
        await call(owner, "get", "/projects");
        await call(
          owner,
          "post",
          "/auth/login",
          { email: settings.ownerEmail, password: "anything" },
          403,
        );
        await call(
          owner,
          "post",
          "/auth/password",
          { password: "synthetic-test-password" },
          403,
        );
        await call(
          owner,
          "post",
          "/admin/invitations",
          { email: settings.ownerEmail, kind: "reset" },
          403,
        );
        assert.equal(
          (
            await db.query("SELECT password_hash FROM users WHERE id=$1", [
              ownerId,
            ])
          ).rows[0].password_hash,
          "!google",
        );
        await call(
          owner,
          "post",
          "/auth/google/start",
          {
            action: "bootstrap",
            setupToken: setup,
            email: settings.ownerEmail,
            name: "Owner",
          },
          403,
        );
      },
    );
    await t.test(
      "Google login requires another authenticator challenge and session revocation remains effective",
      async () => {
        const login = actor(app),
          f = await begin(login);
        assert.equal((await callback(login, f)).headers.location, "/signin");
        assert.equal((await call(login, "get", "/auth/me")).body.pending, true);
        await call(login, "get", "/projects", undefined, 403);
        await call(login, "post", "/auth/mfa/verify", {
          code: recovery.shift(),
        });
        assert.equal(
          (await call(login, "get", "/auth/me")).body.primaryMethod,
          "google",
        );
        await call(login, "delete", "/auth/sessions", {});
        await call(login, "get", "/auth/me", undefined, 401);
        const f2 = await begin(owner);
        await callback(owner, f2);
        await call(owner, "get", "/auth/me");
        await call(owner, "post", "/auth/mfa/verify", {
          code: recovery.shift(),
        });
      },
    );
    await t.test(
      "unknown users, wrong subjects and unverified/outsider Google accounts gain no access",
      async () => {
        for (const extra of [
          { sub: "unknown-person", email: "unknown@company.example" },
          { sub: "unknown-person" },
          { email_verified: false },
          { nonce: "wrong" },
          { email: "outsider@elsewhere.example" },
          { hd: "elsewhere.example" },
        ]) {
          googleClient.extra = extra;
          const who = actor(app),
            f = await begin(who),
            res = await callback(who, f);
          assert.equal(
            res.headers.location,
            extra.email?.endsWith("elsewhere.example") || extra.hd
              ? "/info"
              : "/signin#google=failed",
          );
          await call(who, "get", "/auth/me", undefined, 401);
        }
        googleClient.extra = {};
        assert.equal(
          Number((await db.query("SELECT count(*) FROM users")).rows[0].count),
          1,
        );
      },
    );
    await t.test(
      "an invitation creates only its matching Google identity and does not grant project access",
      async () => {
        const invite = (
          await call(owner, "post", "/admin/invitations", {
            email: "reader@company.example",
          })
        ).body;
        assert.equal(invite.emailStatus, "not_requested");
        const inviteToken = new URLSearchParams(
          new URL(invite.url).hash.slice(1),
        ).get("invite");
        const wrong = actor(app),
          f = await begin(wrong, {
            action: "invite",
            token: inviteToken,
            name: "Reader",
          });
        assert.equal(
          (await callback(wrong, f)).headers.location,
          "/signin#google=failed",
        );
        googleClient.extra = {
          sub: "synthetic-reader",
          email: "reader@company.example",
        };
        const reader = actor(app),
          valid = await begin(reader, {
            action: "invite",
            token: inviteToken,
            name: "Reader",
          });
        assert.equal(
          (await callback(reader, valid)).headers.location,
          "/signin",
        );
        await call(reader, "get", "/auth/me");
        await finishMfa(reader, "reader@company.example");
        assert.deepEqual(
          (await call(reader, "get", "/projects")).body.projects,
          [],
        );
        await call(reader, "get", "/admin/users", undefined, 403);
        await call(
          actor(app),
          "post",
          "/auth/google/start",
          { action: "invite", token: inviteToken, name: "Reader" },
          400,
        );
        googleClient.extra = {};
      },
    );
    await t.test(
      "recent Google login plus an existing factor is required to replace an authenticator",
      async () => {
        await call(owner, "post", "/auth/mfa/start", { code: "invalid" }, 401);
        const current = (
          await db.query(
            "SELECT token_hash FROM sessions WHERE actor_id=$1 AND kind='full'",
            [ownerId],
          )
        ).rows[0].token_hash;
        await db.query(
          "UPDATE sessions SET created_at=now()-interval '6 minutes' WHERE token_hash=$1",
          [current],
        );
        await call(
          owner,
          "post",
          "/auth/mfa/start",
          { code: recovery[0] },
          401,
        );
        const f = await begin(owner);
        await callback(owner, f);
        await call(owner, "get", "/auth/me");
        await call(owner, "post", "/auth/mfa/verify", {
          code: recovery.shift(),
        });
        await call(owner, "post", "/auth/mfa/start", {
          code: recovery.shift(),
        });
      },
    );
    await t.test(
      "metadata and audit records never contain client secrets, state or provider tokens",
      async () => {
        const info = (await call(owner, "get", "/instance")).body;
        assert.equal(info.googleEnabled, true);
        assert.equal(info.googleOnly, true);
        const audit = JSON.stringify(
          (await db.query("SELECT * FROM audit_events")).rows,
        );
        for (const value of [
          settings.clientSecret,
          "synthetic-only",
          "synthetic-sensitive-provider-response",
          googleClient.starts.at(-1).state,
        ])
          assert.ok(!audit.includes(value));
        assert.ok(!JSON.stringify(info).includes(settings.clientId));
      },
    );
  } finally {
    await db.close();
  }
});

test("existing password users link Google explicitly and hosted Google-only policy invalidates old password sessions", async () => {
  const db = await isolatedDatabase(),
    masterKey = randomBytes(32),
    setup = token(),
    googleClient = fakeGoogle();
  await migrate(db);
  const optional = { ...settings, only: false, ownerEmail: "" };
  const options = {
    db,
    masterKey,
    setupTokenHash: digest(setup),
    origin,
    google: optional,
    googleClient,
    allowedEmailDomains: "company.example",
    authLimit: 1000,
  };
  const app = await createApp(options),
    local = actor(app),
    password = "synthetic-password-for-linking";
  try {
    await call(local, "post", "/bootstrap", {
      setupToken: setup,
      email: settings.ownerEmail,
      name: "Local Owner",
      password,
    });
    let codes = await finishMfa(local, settings.ownerEmail);
    const original = await call(local, "get", "/auth/me");
    assert.equal(original.body.hasPassword, true);
    const stranger = actor(app),
      login = await begin(stranger);
    assert.equal(
      (await callback(stranger, login)).headers.location,
      "/signin#google=failed",
      "matching email alone must not link accounts",
    );
    await call(
      local,
      "post",
      "/auth/google/start",
      { action: "link", password: "wrong", code: codes[0] },
      401,
    );
    const csrfDenied = await local.agent
      .post("/api/auth/google/start")
      .send({ action: "link", password, code: codes[0] });
    assert.equal(csrfDenied.status, 403);
    const wrong = await begin(local, {
      action: "link",
      password,
      code: codes.shift(),
    });
    googleClient.extra = { email: "someone-else@company.example" };
    assert.equal(
      (await callback(local, wrong)).headers.location,
      "/signin#google=failed",
    );
    googleClient.extra = {};
    const valid = await begin(local, {
      action: "link",
      password,
      code: codes.shift(),
    });
    assert.equal((await callback(local, valid)).headers.location, "/signin");
    const linked = (await call(local, "get", "/auth/me")).body;
    assert.equal(linked.googleLinked, true);
    assert.equal(linked.pending, true);
    await call(local, "post", "/auth/mfa/verify", { code: codes.shift() });
    await call(local, "get", "/projects");
    const passwordSession = actor(app);
    await call(passwordSession, "post", "/auth/login", {
      email: settings.ownerEmail,
      password,
      delivery: "token",
    });
    const raw = (
      await call(passwordSession, "post", "/auth/login", {
        email: settings.ownerEmail,
        password,
        delivery: "token",
      })
    ).body.accessToken;
    const googleOnlyApp = await createApp({ ...options, google: settings });
    const old = await request(googleOnlyApp)
      .get("/api/auth/me")
      .set("Authorization", "Bearer " + raw);
    assert.equal(old.status, 401);
    await db.query("UPDATE users SET disabled=true WHERE id=$1", [linked.id]);
    const disabled = actor(app),
      f = await begin(disabled);
    assert.equal(
      (await callback(disabled, f)).headers.location,
      "/signin#google=failed",
    );
  } finally {
    await db.close();
  }
});

test("existing schema version 1 identities and sessions migrate without losing secrets or roles", async () => {
  const db = await isolatedDatabase();
  try {
    await migrate(db);
    const id = randomUUID();
    await db.query(
      "INSERT INTO users (id,email,name,password_hash) VALUES ($1,'local@company.example','Local',$2)",
      [id, await hashPassword("synthetic-migration-password")],
    );
    await db.query(
      "INSERT INTO sessions (token_hash,actor_type,actor_id,kind,csrf,expires_at) VALUES ($1,'user',$2,'full',$3,now()+interval '1 hour')",
      [digest(token()), id, token()],
    );
    const projectId = randomUUID(),
      roleId = randomUUID(),
      secretId = randomUUID();
    const sealed = vault(randomBytes(32)).seal(
      "synthetic preserved value",
      "migration",
    );
    await db.query(
      "INSERT INTO projects (id,name) VALUES ($1,'Migration Project')",
      [projectId],
    );
    await db.query(
      "INSERT INTO environments (project_id,name) VALUES ($1,'development')",
      [projectId],
    );
    await db.query(
      "INSERT INTO roles (id,project_id,name,permissions) VALUES ($1,$2,'Scoped Reader',$3)",
      [roleId, projectId, JSON.stringify(["secrets.read"])],
    );
    await db.query(
      "INSERT INTO bindings (id,role_id,principal_type,principal_id,path) VALUES ($1,$2,'user',$3,'/app')",
      [randomUUID(), roleId, id],
    );
    await db.query(
      "INSERT INTO secrets (id,project_id,environment,path,key,version) VALUES ($1,$2,'development','/app','SYNTHETIC',1)",
      [secretId, projectId],
    );
    await db.query(
      "INSERT INTO secret_versions (secret_id,version,box,actor_type,actor_id) VALUES ($1,1,$2,'user',$3)",
      [secretId, sealed, id],
    );
    await db.query("DROP TABLE google_flows");
    await db.query("DROP INDEX google_subject_identity");
    await db.query("ALTER TABLE users DROP COLUMN google_subject");
    await db.query("ALTER TABLE sessions DROP COLUMN auth_method");
    await db.query("UPDATE service_state SET schema_version=1");
    await migrate(db);
    await migrate(db);
    assert.equal(
      (
        await db.query("SELECT auth_method FROM sessions WHERE actor_id=$1", [
          id,
        ])
      ).rows[0].auth_method,
      "password",
    );
    assert.equal(
      (await db.query("SELECT google_subject FROM users WHERE id=$1", [id]))
        .rows[0].google_subject,
      null,
    );
    assert.equal(
      (await db.query("SELECT schema_version FROM service_state")).rows[0]
        .schema_version,
      2,
    );
    assert.equal(
      (
        await db.query("SELECT box FROM secret_versions WHERE secret_id=$1", [
          secretId,
        ])
      ).rows[0].box,
      sealed,
    );
    assert.deepEqual(
      (
        await db.query(
          "SELECT r.permissions,b.path FROM roles r JOIN bindings b ON b.role_id=r.id WHERE r.id=$1",
          [roleId],
        )
      ).rows[0],
      { permissions: ["secrets.read"], path: "/app" },
    );
    await db.query("UPDATE service_state SET schema_version=3");
    await assert.rejects(migrate(db), /newer/);
  } finally {
    await db.close();
  }
});
