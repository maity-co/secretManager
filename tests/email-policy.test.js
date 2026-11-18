import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import request from "supertest";
import { PGlite } from "@electric-sql/pglite";
import { postgres, migrate } from "../src/db.js";
import { createApp } from "../src/app.js";
import { token, digest, authenticator } from "../src/security.js";
import { emailDomainPolicy } from "../src/email-policy.js";
import { publicInfoPage, PROJECT_REPOSITORY } from "../src/info-page.js";
const origin = "http://localhost:8080";

async function isolatedDatabase() {
  if (process.env.TEST_DATABASE_URL) {
    const url = new URL(process.env.TEST_DATABASE_URL);
    if (
      !["localhost", "127.0.0.1"].includes(url.hostname) ||
      !url.pathname.startsWith("/secretmanager_test")
    )
      throw new Error("Tests require a loopback test database.");
    const admin = postgres({ connectionString: url.href }),
      schema = "policy_" + randomUUID().replaceAll("-", "");
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
  const pg = new PGlite();
  const wrap = (tx) => ({
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
function client(app, actor, method, path, body) {
  let req = request(app)
    [method]("/api" + path)
    .set("Origin", origin);
  if (actor?.bearer) req = req.set("Authorization", "Bearer " + actor.bearer);
  else if (actor?.cookie) {
    req = req.set("Cookie", actor.cookie).set("X-CSRF-Token", actor.csrf || "");
  }
  return body === undefined ? req : req.send(body);
}
async function call(app, actor, method, path, body, status = 200) {
  const response = await client(app, actor, method, path, body);
  assert.equal(
    response.status,
    status,
    `${method} ${path}: ${response.body.error || response.status}`,
  );
  if (actor) {
    if (response.headers["set-cookie"])
      actor.cookie = response.headers["set-cookie"][0].split(";")[0];
    if (response.body.csrf) actor.csrf = response.body.csrf;
    if (response.body.accessToken) actor.bearer = response.body.accessToken;
  }
  return response;
}
async function enroll(app, actor, email) {
  const start = await call(app, actor, "post", "/auth/mfa/start", {});
  return call(app, actor, "post", "/auth/mfa/confirm", {
    code: authenticator(email, start.body.manualKey).generate(),
    delivery: "token",
  });
}
function linkToken(link) {
  return new URLSearchParams(new URL(link).hash.slice(1)).values().next().value;
}

test("email domain policy matches exact normalized domains and fails closed on bad configuration", () => {
  const policy = emailDomainPolicy(" COMPANY.EXAMPLE, second.example ");
  assert.deepEqual(policy.domains, ["company.example", "second.example"]);
  for (const email of [
    "person@company.example",
    "  Person@COMPANY.EXAMPLE  ",
    "person+tag@second.example",
  ])
    assert.ok(policy.permits(email));
  for (const email of [
    "person@company.example.evil",
    "person@evilcompany.example",
    "person@sub.company.example",
    "person@company.example.",
    "person@company.example@elsewhere.example",
    "person@company.example\nBcc: victim@elsewhere.example",
    "Person <person@company.example>",
    "person@coмpany.example",
    "person@elsewhere.example",
    {},
    null,
  ])
    assert.equal(policy.permits(email), false);
  for (const value of [
    "*.company.example",
    "@company.example",
    "https://company.example",
    "company.example,",
    ",company.example",
    "company..example",
    "-company.example",
    [],
    "company.example\nelsewhere.example",
  ])
    assert.throws(() => emailDomainPolicy(value));
  assert.ok(emailDomainPolicy().permits("person@elsewhere.example"));
  assert.equal(emailDomainPolicy().restricted, false);
});

test("public information is available without scripts and escapes operator text", () => {
  const html = publicInfoPage({
    restricted: true,
    emailDomains: ["company.example"],
    operatorName: "<script>alert(1)</script>",
  });
  assert.ok(html.includes(PROJECT_REPOSITORY));
  assert.ok(html.includes("Maity develops SecretManager for internal use"));
  assert.ok(html.includes("@company.example"));
  assert.ok(html.includes('href="/signin"'));
  assert.ok(!html.includes("<script>"));
  assert.ok(html.includes("&lt;script&gt;"));
  assert.ok(html.includes("Anyone is welcome to host their own instance"));
});

test("restricted bootstrap never creates an outside account or sets its password", async () => {
  const db = await isolatedDatabase();
  await migrate(db);
  const setup = token();
  try {
    const app = await createApp({
      db,
      masterKey: randomBytes(32),
      setupTokenHash: digest(setup),
      origin,
      allowedEmailDomains: "company.example",
      authLimit: 1000,
    });
    const denied = await call(
      app,
      null,
      "post",
      "/bootstrap",
      {
        setupToken: setup,
        email: "owner@elsewhere.example",
        name: "Outside Owner",
        password: token(),
      },
      403,
    );
    assert.equal(denied.body.code, "EMAIL_DOMAIN_NOT_ALLOWED");
    assert.equal(denied.body.infoUrl, "/info");
    assert.equal(
      (await db.query("SELECT count(*)::integer AS count FROM users")).rows[0]
        .count,
      0,
    );
    assert.equal(
      (await call(app, null, "get", "/bootstrap")).body.required,
      true,
    );
    await call(app, {}, "post", "/bootstrap", {
      setupToken: setup,
      email: " Owner@COMPANY.EXAMPLE ",
      name: "Company Owner",
      password: token(),
    });
    assert.equal(
      (await db.query("SELECT email FROM users")).rows[0].email,
      "owner@company.example",
    );
  } finally {
    await db.close();
  }
});

test("hosted email policy covers accounts, sessions, password links and every mail recipient", async (t) => {
  const db = await isolatedDatabase();
  await migrate(db);
  const key = randomBytes(32),
    setup = token(),
    password = token(),
    owner = {},
    outside = {};
  let mail = [];
  const options = {
    db,
    masterKey: key,
    setupTokenHash: digest(setup),
    origin,
    authLimit: 10000,
  };
  try {
    const unrestricted = await createApp(options);
    await call(unrestricted, owner, "post", "/bootstrap", {
      setupToken: setup,
      email: "owner@company.example",
      name: "Company Owner",
      password,
    });
    await enroll(unrestricted, owner, "owner@company.example");
    const outsideInvite = (
      await call(unrestricted, owner, "post", "/admin/invitations", {
        email: "legacy@elsewhere.example",
      })
    ).body;
    const outsidePassword = token();
    await call(unrestricted, null, "post", "/accept-invitation", {
      token: linkToken(outsideInvite.url),
      name: "Legacy Person",
      password: outsidePassword,
    });
    await call(unrestricted, outside, "post", "/auth/login", {
      email: "legacy@elsewhere.example",
      password: outsidePassword,
      delivery: "token",
    });
    await enroll(unrestricted, outside, "legacy@elsewhere.example");
    const pendingOutside = {};
    await call(unrestricted, pendingOutside, "post", "/auth/login", {
      email: "legacy@elsewhere.example",
      password: outsidePassword,
      delivery: "token",
    });
    const waitingInvite = (
      await call(unrestricted, owner, "post", "/admin/invitations", {
        email: "waiting@elsewhere.example",
      })
    ).body;
    const waitingReset = (
      await call(unrestricted, owner, "post", "/admin/invitations", {
        email: "legacy@elsewhere.example",
        kind: "reset",
      })
    ).body;
    const oldHash = (
      await db.query("SELECT password_hash FROM users WHERE email=$1", [
        "legacy@elsewhere.example",
      ])
    ).rows[0].password_hash;
    const restricted = await createApp({
      ...options,
      allowedEmailDomains: "company.example",
      publicOperatorName: "Example Team",
      mailEnvironment: {
        enabled: true,
        key: token(),
        from: "sender@delivery.example",
      },
      fetchMail: async (url, options) => {
        assert.equal(url, "https://api.resend.com/emails");
        mail.push(JSON.parse(options.body));
        return new Response("", { status: 200 });
      },
    });
    await t.test(
      "public metadata and the information/sign-in pages expose no credentials",
      async () => {
        const info = (await call(restricted, null, "get", "/instance")).body;
        assert.deepEqual(info, {
          restricted: true,
          emailDomains: ["company.example"],
          operatorName: "Example Team",
          googleEnabled: false,
          googleOnly: false,
        });
        const page = await request(restricted).get("/info");
        assert.equal(page.status, 200);
        assert.ok(page.text.includes("Example Team"));
        assert.ok(page.text.includes("@company.example"));
        assert.ok(page.text.includes(PROJECT_REPOSITORY));
        const signin = await request(restricted).get("/signin");
        assert.equal(signin.status, 200);
        assert.ok(signin.text.includes("/app.js"));
        assert.equal(page.headers["cache-control"], "no-store");
      },
    );
    await t.test(
      "outside logins and existing full/pending sessions return JSON denials",
      async () => {
        for (const email of [
          "anyone@elsewhere.example",
          "anyone@company.example.evil",
          "anyone@sub.company.example",
        ]) {
          const result = await call(
            restricted,
            null,
            "post",
            "/auth/login",
            { email, password: token() },
            403,
          );
          assert.equal(result.body.code, "EMAIL_DOMAIN_NOT_ALLOWED");
          assert.equal(result.body.infoUrl, "/info");
          assert.ok(!result.headers.location);
        }
        for (const actor of [outside, pendingOutside]) {
          const result = await call(
            restricted,
            actor,
            "get",
            "/auth/me",
            undefined,
            403,
          );
          assert.equal(result.body.code, "EMAIL_DOMAIN_NOT_ALLOWED");
          await call(restricted, actor, "post", "/auth/mfa/start", {}, 403);
        }
        const excludesOwner = await createApp({
          ...options,
          allowedEmailDomains: "elsewhere.example",
        });
        await call(excludesOwner, owner, "get", "/projects", undefined, 403);
        await call(
          restricted,
          null,
          "post",
          "/auth/login",
          { email: "owner@company.example", password: token() },
          401,
        );
      },
    );
    await t.test(
      "older outside invitations and resets cannot set any password",
      async () => {
        for (const invite of [waitingInvite, waitingReset]) {
          const result = await call(
            restricted,
            null,
            "post",
            "/accept-invitation",
            {
              token: linkToken(invite.url),
              name: "Outside Person",
              password: token(),
            },
            403,
          );
          assert.equal(result.body.code, "EMAIL_DOMAIN_NOT_ALLOWED");
        }
        await call(
          restricted,
          outside,
          "post",
          "/auth/password",
          {
            currentPassword: outsidePassword,
            password: token(),
            code: token(),
          },
          403,
        );
        assert.equal(
          (
            await db.query("SELECT password_hash FROM users WHERE email=$1", [
              "legacy@elsewhere.example",
            ])
          ).rows[0].password_hash,
          oldHash,
        );
        assert.equal(
          (
            await db.query(
              "SELECT count(*)::integer AS count FROM users WHERE email=$1",
              ["waiting@elsewhere.example"],
            )
          ).rows[0].count,
          0,
        );
        assert.equal(
          (
            await db.query("SELECT used FROM invitations WHERE id=$1", [
              waitingInvite.id,
            ])
          ).rows[0].used,
          false,
        );
      },
    );
    await t.test(
      "outside invitation/reset/test-email recipients never reach the provider",
      async () => {
        const count = (
          await db.query("SELECT count(*)::integer AS count FROM invitations")
        ).rows[0].count;
        for (const email of [
          "new@elsewhere.example",
          "person@company.example.evil",
          "person@sub.company.example",
        ]) {
          const invite = await call(
            restricted,
            owner,
            "post",
            "/admin/invitations",
            { email, sendEmail: true },
            403,
          );
          assert.equal(invite.body.code, undefined);
          await call(
            restricted,
            owner,
            "post",
            "/settings/test-email",
            { email },
            403,
          );
        }
        await call(
          restricted,
          owner,
          "post",
          "/admin/invitations",
          { email: "legacy@elsewhere.example", kind: "reset", sendEmail: true },
          403,
        );
        assert.equal(mail.length, 0);
        assert.equal(
          (await db.query("SELECT count(*)::integer AS count FROM invitations"))
            .rows[0].count,
          count,
        );
      },
    );
    await t.test(
      "allowed addresses are normalized and keep manual invitation and password setup",
      async () => {
        const invite = (
          await call(restricted, owner, "post", "/admin/invitations", {
            email: " New@COMPANY.EXAMPLE ",
            sendEmail: true,
          })
        ).body;
        assert.equal(invite.emailStatus, "sent");
        assert.equal(new URL(invite.url).pathname, "/signin");
        assert.deepEqual(mail[0].to, ["new@company.example"]);
        const newPassword = token();
        await call(restricted, null, "post", "/accept-invitation", {
          token: linkToken(invite.url),
          name: "New Colleague",
          password: newPassword,
        });
        const person = {};
        const logged = await call(restricted, person, "post", "/auth/login", {
          email: " NEW@company.example ",
          password: newPassword,
          delivery: "token",
        });
        assert.equal(logged.body.pending, true);
        await enroll(restricted, person, "new@company.example");
        const reset = (
          await call(restricted, owner, "post", "/admin/invitations", {
            email: "new@company.example",
            kind: "reset",
          })
        ).body;
        await call(restricted, null, "post", "/accept-invitation", {
          token: linkToken(reset.url),
          password: token(),
        });
        await call(restricted, owner, "post", "/settings/test-email", {
          email: " Owner@COMPANY.EXAMPLE ",
        });
        assert.deepEqual(mail.at(-1).to, ["owner@company.example"]);
      },
    );
    await t.test(
      "an account email changed after link issuance cannot be reset through the old link",
      async () => {
        const invite = (
          await call(restricted, owner, "post", "/admin/invitations", {
            email: "new@company.example",
            kind: "reset",
          })
        ).body;
        await db.query("UPDATE users SET email=$2 WHERE email=$1", [
          "new@company.example",
          "changed@elsewhere.example",
        ]);
        const before = (
          await db.query("SELECT password_hash FROM users WHERE email=$1", [
            "changed@elsewhere.example",
          ])
        ).rows[0].password_hash;
        await call(
          restricted,
          null,
          "post",
          "/accept-invitation",
          { token: linkToken(invite.url), password: token() },
          400,
        );
        assert.equal(
          (
            await db.query("SELECT password_hash FROM users WHERE email=$1", [
              "changed@elsewhere.example",
            ])
          ).rows[0].password_hash,
          before,
        );
      },
    );
    await t.test(
      "the policy cannot be widened through admin settings or request fields",
      async () => {
        await call(restricted, owner, "put", "/settings", {
          requireMfa: true,
          allowedEmailDomains: "elsewhere.example",
        });
        assert.deepEqual(
          (await call(restricted, null, "get", "/instance")).body.emailDomains,
          ["company.example"],
        );
        await call(
          restricted,
          null,
          "post",
          "/auth/login",
          {
            email: "legacy@elsewhere.example",
            password: outsidePassword,
            allowedEmailDomains: "",
          },
          403,
        );
      },
    );
    await t.test(
      "machine identities keep their project permissions without an email address",
      async () => {
        const project = (
          await call(
            restricted,
            owner,
            "post",
            "/projects",
            { name: "Company Project" },
            201,
          )
        ).body.id;
        const secret = (
          await call(
            restricted,
            owner,
            "post",
            `/projects/${project}/secrets`,
            {
              key: "EXAMPLE",
              value: token(),
              environment: "development",
              path: "/",
            },
            201,
          )
        ).body.id;
        const machine = (
          await call(
            restricted,
            owner,
            "post",
            `/projects/${project}/machines`,
            { name: "Company Worker" },
            201,
          )
        ).body.id;
        const reader = (
          await call(restricted, owner, "get", `/projects/${project}/roles`)
        ).body.roles.find((role) => role.name === "Reader");
        await call(
          restricted,
          owner,
          "post",
          `/projects/${project}/bindings`,
          { roleId: reader.id, principalType: "machine", principalId: machine },
          201,
        );
        const credential = (
          await call(
            restricted,
            owner,
            "post",
            `/projects/${project}/machines/${machine}/credentials`,
            {},
            201,
          )
        ).body;
        const workload = {};
        await call(restricted, workload, "post", "/auth/machine", {
          clientId: machine,
          clientSecret: credential.clientSecret,
        });
        await call(
          restricted,
          workload,
          "get",
          `/projects/${project}/secrets/${secret}/value`,
        );
      },
    );
    await t.test(
      "unrestricted self-hosted instances retain their own account policy",
      async () => {
        assert.deepEqual(
          (await call(unrestricted, null, "get", "/instance")).body
            .emailDomains,
          [],
        );
        await call(unrestricted, outside, "get", "/auth/me");
      },
    );
  } finally {
    await db.close();
  }
});
