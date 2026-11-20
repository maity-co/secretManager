import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import request from "supertest";
import { PGlite } from "@electric-sql/pglite";
import { postgres, migrate } from "../src/db.js";
import { createApp } from "../src/app.js";
import { token, digest, authenticator } from "../src/security.js";
import {
  trustedBrowsers,
  TRUSTED_BROWSER_MS,
} from "../src/trusted-browsers.js";

const origin = "https://secrets.company.example";
const sessionName = "__Host-sm_session";
const browserName = "__Host-sm_trusted_browser";

async function database() {
  if (process.env.TEST_DATABASE_URL) {
    const url = new URL(process.env.TEST_DATABASE_URL);
    if (
      !["localhost", "127.0.0.1"].includes(url.hostname) ||
      !url.pathname.startsWith("/secretmanager_test")
    )
      throw new Error("Tests require a loopback test database.");
    const admin = postgres({ connectionString: url.href });
    const schema = "browsers_" + randomUUID().replaceAll("-", "");
    await admin.query('CREATE SCHEMA "' + schema + '"');
    const db = postgres({
      connectionString: url.href,
      options: "-c search_path=" + schema,
      max: 5,
    });
    return {
      ...db,
      close: async () => {
        await db.close();
        try {
          await admin.query('DROP SCHEMA "' + schema + '" CASCADE');
        } finally {
          await admin.close();
        }
      },
    };
  }
  const pg = new PGlite();
  const wrap = (tx) => ({
    query: async (sql, args) =>
      args === undefined && sql.includes(";")
        ? (await tx.exec(sql)).at(-1)
        : tx.query(sql, args),
  });
  return {
    ...wrap(pg),
    transaction: (fn) => pg.transaction((tx) => fn(wrap(tx))),
    close: () => pg.close(),
  };
}
const actor = (ip = "198.51.100.10") => ({ ip, cookies: {}, csrf: "" });
const clone = (who) => ({ ...who, cookies: { ...who.cookies } });

test("trusted browsers require verified MFA, the same IP and revocable server state", async (t) => {
  const db = await database();
  await migrate(db);
  const setup = token(),
    masterKey = randomBytes(32),
    ownerPassword = token();
  const app = await createApp({
    db,
    masterKey,
    setupTokenHash: digest(setup),
    origin,
    trustProxy: 1,
    allowedEmailDomains: "company.example",
    authLimit: 10000,
  });
  async function call(who, method, path, body, status = 200) {
    let req = request(app)
      [method]("/api" + path)
      .set("Origin", origin)
      .set("X-Forwarded-For", who.ip)
      .set("User-Agent", "Synthetic Browser")
      .set("X-CSRF-Token", who.csrf);
    if (who.bearer) req = req.set("Authorization", "Bearer " + who.bearer);
    else if (Object.keys(who.cookies).length)
      req = req.set(
        "Cookie",
        Object.entries(who.cookies)
          .map(([k, v]) => k + "=" + v)
          .join("; "),
      );
    const res = await (body === undefined ? req : req.send(body));
    assert.equal(
      res.status,
      status,
      method + " " + path + ": " + (res.body.error || res.status),
    );
    if (res.body.csrf) who.csrf = res.body.csrf;
    for (const cookie of res.headers["set-cookie"] || []) {
      const [name, ...rest] = cookie.split(";")[0].split("=");
      const value = rest.join("=");
      if (value) who.cookies[name] = value;
      else delete who.cookies[name];
    }
    return res;
  }
  async function enroll(who, email, rememberBrowser = false) {
    const start = await call(who, "post", "/auth/mfa/start", {});
    const seed = start.body.manualKey;
    const res = await call(who, "post", "/auth/mfa/confirm", {
      code: authenticator(email, seed).generate(),
      rememberBrowser,
    });
    return { seed, codes: res.body.recoveryCodes };
  }
  const owner = actor();
  let nextUser = 0;
  async function account() {
    const email = "person" + ++nextUser + "@company.example",
      password = token();
    const invite = await call(owner, "post", "/admin/invitations", { email });
    const inviteToken = new URLSearchParams(
      new URL(invite.body.url).hash.slice(1),
    ).get("invite");
    const who = actor();
    await call(who, "post", "/accept-invitation", {
      token: inviteToken,
      name: "Synthetic User",
      password,
    });
    await call(who, "post", "/auth/login", { email, password });
    const factors = await enroll(who, email);
    const id = (await call(who, "get", "/auth/me")).body.id;
    return { email, password, id, who, ...factors };
  }
  async function remembered(user, ip = "198.51.100.10") {
    const who = actor(ip);
    const login = await call(who, "post", "/auth/login", {
      email: user.email,
      password: user.password,
    });
    assert.equal(login.body.pending, true);
    const res = await call(who, "post", "/auth/mfa/verify", {
      code: user.codes.shift(),
      rememberBrowser: true,
    });
    return { who, res };
  }
  async function count(user) {
    return Number(
      (
        await db.query(
          "SELECT count(*) FROM trusted_browsers WHERE user_id=$1",
          [user.id],
        )
      ).rows[0].count,
    );
  }
  try {
    await call(owner, "post", "/bootstrap", {
      setupToken: setup,
      email: "owner@company.example",
      name: "Owner",
      password: ownerPassword,
    });
    await enroll(owner, "owner@company.example");

    await t.test(
      "MFA remains the default and cookies are issued only after a valid factor",
      async () => {
        const user = await account(),
          who = actor();
        const login = await call(who, "post", "/auth/login", {
          email: user.email,
          password: user.password,
          rememberBrowser: true,
        });
        assert.equal(login.body.pending, true);
        assert.equal(who.cookies[browserName], undefined);
        await call(
          who,
          "post",
          "/auth/mfa/verify",
          { code: "invalid", rememberBrowser: true },
          401,
        );
        assert.equal(await count(user), 0);
        await call(who, "post", "/auth/mfa/verify", {
          code: user.codes.shift(),
        });
        assert.equal(await count(user), 0);
        await call(who, "post", "/auth/logout", {});
        assert.equal(
          (
            await call(who, "post", "/auth/login", {
              email: user.email,
              password: user.password,
            })
          ).body.pending,
          true,
        );
      },
    );

    await t.test(
      "trust is an opaque Secure/HttpOnly host cookie with a fixed 30-day expiry",
      async () => {
        const user = await account(),
          before = Date.now();
        const { who, res } = await remembered(user);
        const cookie = res.headers["set-cookie"].find((c) =>
          c.startsWith(browserName + "="),
        );
        assert.match(cookie, /; HttpOnly/);
        assert.match(cookie, /; Secure/);
        assert.match(cookie, /; SameSite=Strict/);
        assert.match(cookie, /; Path=\//);
        assert.doesNotMatch(cookie, /; Domain=/);
        const row = (
          await db.query("SELECT * FROM trusted_browsers WHERE user_id=$1", [
            user.id,
          ])
        ).rows[0];
        assert.equal(row.token_hash, digest(who.cookies[browserName]));
        assert.ok(!JSON.stringify(row).includes(who.cookies[browserName]));
        assert.ok(!JSON.stringify(row).includes(who.ip));
        assert.ok(
          new Date(row.expires_at).getTime() >= before + TRUSTED_BROWSER_MS,
        );
        assert.ok(
          new Date(row.expires_at).getTime() <= Date.now() + TRUSTED_BROWSER_MS,
        );
        assert.equal(res.body.trustedBrowserToken, undefined);
        const fixedExpiry = new Date(Date.now() + 10 * 86400000);
        await db.query(
          "UPDATE trusted_browsers SET expires_at=$2 WHERE id=$1",
          [row.id, fixedExpiry],
        );
        await call(who, "post", "/auth/logout", {});
        const result = await call(who, "post", "/auth/login", {
          email: user.email,
          password: user.password,
        });
        assert.equal(result.body.pending, false);
        assert.equal(
          new Date(
            (
              await db.query(
                "SELECT expires_at FROM trusted_browsers WHERE id=$1",
                [row.id],
              )
            ).rows[0].expires_at,
          ).getTime(),
          fixedExpiry.getTime(),
        );
        const cookieOnly = actor();
        cookieOnly.cookies[browserName] = who.cookies[browserName];
        await call(cookieOnly, "get", "/auth/me", undefined, 401);
        await call(
          clone(who),
          "post",
          "/auth/login",
          { email: user.email, password: "wrong" },
          401,
        );
        const other = await account(),
          swapped = clone(who);
        assert.equal(
          (
            await call(swapped, "post", "/auth/login", {
              email: other.email,
              password: other.password,
            })
          ).body.pending,
          true,
        );
      },
    );

    await t.test(
      "IP changes and missing/forged cookies require MFA and block linked sessions",
      async () => {
        const user = await account(),
          { who } = await remembered(user);
        const changed = clone(who);
        changed.ip = "203.0.113.20";
        const denied = await call(changed, "get", "/auth/me", undefined, 401);
        assert.equal(denied.body.code, "SESSION_REAUTH_REQUIRED");
        assert.equal(
          (
            await call(changed, "post", "/auth/login", {
              email: user.email,
              password: user.password,
            })
          ).body.pending,
          true,
        );
        const missing = clone(who);
        delete missing.cookies[browserName];
        await call(missing, "get", "/auth/me", undefined, 401);
        const forged = clone(who);
        forged.cookies[browserName] = token();
        assert.equal(
          (
            await call(forged, "post", "/auth/login", {
              email: user.email,
              password: user.password,
            })
          ).body.pending,
          true,
        );
        await db.query(
          "UPDATE trusted_browsers SET expires_at=now()-interval '1 second' WHERE user_id=$1",
          [user.id],
        );
        await call(who, "get", "/auth/me", undefined, 401);
        assert.equal(
          (
            await call(who, "post", "/auth/login", {
              email: user.email,
              password: user.password,
            })
          ).body.pending,
          true,
        );
      },
    );

    await t.test(
      "forgetting another browser preserves this one and cross-account revocation is denied",
      async () => {
        const user = await account(),
          a = (await remembered(user)).who,
          b = (await remembered(user)).who;
        const records = (await call(a, "get", "/auth/trusted-browsers")).body
          .browsers;
        assert.equal(records.length, 2);
        assert.ok(
          records.every((r) => !("token_hash" in r) && !("ip_hash" in r)),
        );
        const current = records.find((r) => r.current),
          other = records.find((r) => !r.current);
        const outsider = await account();
        await call(
          outsider.who,
          "delete",
          "/auth/trusted-browsers/" + current.id,
          {},
          404,
        );
        const tokenBefore = a.cookies[browserName];
        assert.equal(
          (await call(a, "delete", "/auth/trusted-browsers/" + other.id, {}))
            .body.sessionRevoked,
          false,
        );
        assert.equal(a.cookies[browserName], tokenBefore);
        await call(a, "get", "/auth/me");
        await call(b, "get", "/auth/me", undefined, 401);
        assert.equal(
          (await call(a, "delete", "/auth/trusted-browsers/" + current.id, {}))
            .body.sessionRevoked,
          true,
        );
        assert.equal(a.cookies[browserName], undefined);
        await call(a, "get", "/auth/me", undefined, 401);
        assert.equal(await count(user), 0);
      },
    );

    await t.test(
      "trusted browsers never satisfy fresh-factor checks or CLI MFA",
      async () => {
        const user = await account(),
          { who } = await remembered(user);
        await call(
          who,
          "post",
          "/auth/mfa/start",
          { password: user.password, code: "invalid" },
          401,
        );
        await call(
          who,
          "post",
          "/auth/password",
          {
            currentPassword: user.password,
            password: token(),
            code: "invalid",
          },
          401,
        );
        const cli = clone(who);
        const login = await call(cli, "post", "/auth/login", {
          email: user.email,
          password: user.password,
          delivery: "token",
        });
        assert.equal(login.body.pending, true);
        cli.bearer = login.body.accessToken;
        const done = await call(cli, "post", "/auth/mfa/verify", {
          code: user.codes.shift(),
          rememberBrowser: true,
          delivery: "token",
        });
        assert.ok(done.body.accessToken);
        assert.ok(
          !(done.headers["set-cookie"] || []).some((c) =>
            c.startsWith(browserName + "="),
          ),
        );
        assert.equal(await count(user), 1);
      },
    );

    await t.test(
      "password changes, password resets and session revocation invalidate browser trust",
      async () => {
        const user = await account(),
          { who } = await remembered(user);
        const copied = clone(who),
          password = token();
        await call(who, "post", "/auth/password", {
          currentPassword: user.password,
          password,
          code: user.codes.shift(),
        });
        assert.equal(await count(user), 0);
        assert.equal(
          (
            await call(copied, "post", "/auth/login", {
              email: user.email,
              password,
            })
          ).body.pending,
          true,
        );
        user.password = password;
        const next = (await remembered(user)).who;
        const invitation = await call(owner, "post", "/admin/invitations", {
          email: user.email,
          kind: "reset",
        });
        const resetToken = new URLSearchParams(
          new URL(invitation.body.url).hash.slice(1),
        ).get("reset");
        const resetPassword = token();
        await call(actor(), "post", "/accept-invitation", {
          token: resetToken,
          password: resetPassword,
        });
        assert.equal(await count(user), 0);
        user.password = resetPassword;
        const current = (await remembered(user)).who;
        await call(current, "delete", "/auth/sessions", {});
        assert.equal(await count(user), 0);
        await call(next, "get", "/auth/me", undefined, 401);
      },
    );

    await t.test(
      "admin revocation, disable/enable and authenticator replacement erase remembered access",
      async () => {
        const user = await account();
        let who = (await remembered(user)).who;
        await call(
          owner,
          "delete",
          "/admin/users/" + user.id + "/sessions",
          {},
        );
        assert.equal(await count(user), 0);
        who = (await remembered(user)).who;
        await call(owner, "patch", "/admin/users/" + user.id, {
          disabled: true,
        });
        assert.equal(await count(user), 0);
        await call(who, "get", "/auth/me", undefined, 401);
        await call(owner, "patch", "/admin/users/" + user.id, {
          disabled: false,
        });
        who = (await remembered(user)).who;
        const start = await call(who, "post", "/auth/mfa/start", {
          password: user.password,
          code: user.codes.shift(),
        });
        await call(who, "post", "/auth/mfa/confirm", {
          code: authenticator(user.email, start.body.manualKey).generate(),
        });
        assert.equal(await count(user), 0);
      },
    );

    await t.test(
      "all-browser revocation and CSRF protections apply to trust management",
      async () => {
        const user = await account(),
          who = (await remembered(user)).who;
        const bad = clone(who);
        bad.csrf = "";
        await call(bad, "delete", "/auth/trusted-browsers", {}, 403);
        assert.equal(await count(user), 1);
        const result = await call(who, "delete", "/auth/trusted-browsers", {});
        assert.equal(result.body.sessionRevoked, true);
        assert.equal(await count(user), 0);
        await call(who, "get", "/auth/me", undefined, 401);
      },
    );

    await t.test(
      "browser records are bounded and untrusted forwarding headers cannot choose an IP",
      async () => {
        const user = await account(),
          helper = trustedBrowsers(masterKey, browserName);
        const req = {
          ip: "127.0.0.1",
          headers: {},
          get: () => "Synthetic Browser",
        };
        for (let i = 0; i < 12; i++)
          await db.transaction((tx) => helper.remember(tx, user.id, req));
        assert.equal(await count(user), 10);
        assert.equal(
          await db.transaction((tx) =>
            helper.remember(tx, user.id, { ...req, ip: "not-an-address" }),
          ),
          null,
        );
        const remembered = await db.transaction((tx) =>
          helper.remember(tx, user.id, req),
        );
        const alternate = {
          ...req,
          ip: "::ffff:127.0.0.1",
          headers: { cookie: browserName + "=" + remembered.raw },
        };
        assert.ok(await helper.find(db, user.id, alternate));
        const direct = await createApp({
          db,
          masterKey,
          setupTokenHash: digest(setup),
          origin,
          trustProxy: 0,
        });
        const directCookies = { [browserName]: remembered.raw };
        const login = await request(direct)
          .post("/api/auth/login")
          .set("Origin", origin)
          .set("X-Forwarded-For", "203.0.113.99")
          .set("Cookie", browserName + "=" + directCookies[browserName])
          .send({ email: user.email, password: user.password });
        assert.equal(login.status, 200);
        assert.equal(login.body.pending, false);
      },
    );

    await t.test(
      "version-2 migration preserves old sessions and encrypted project data",
      async () => {
        const project = (
          await call(
            owner,
            "post",
            "/projects",
            { name: "Synthetic migration project" },
            201,
          )
        ).body.id;
        const secret = (
          await call(
            owner,
            "post",
            "/projects/" + project + "/secrets",
            {
              environment: "development",
              path: "/",
              key: "SYNTHETIC",
              value: "Synthetic migration value",
            },
            201,
          )
        ).body.id;
        await db.query("ALTER TABLE sessions DROP COLUMN trusted_browser_id");
        await db.query("DROP TABLE trusted_browsers");
        await db.query("UPDATE service_state SET schema_version=2");
        await migrate(db);
        await migrate(db);
        assert.equal(
          (await db.query("SELECT schema_version FROM service_state")).rows[0]
            .schema_version,
          4,
        );
        await call(owner, "get", "/auth/me");
        assert.equal(
          (
            await call(
              owner,
              "get",
              "/projects/" + project + "/secrets/" + secret + "/value",
            )
          ).body.value,
          "Synthetic migration value",
        );
      },
    );
  } finally {
    await db.close();
  }
});
