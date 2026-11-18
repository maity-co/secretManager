import express from "express";
import helmet from "helmet";
import { parse as parseCookie } from "cookie";
import QRCode from "qrcode";
import { randomUUID } from "node:crypto";
import { resolve } from "node:path";
import {
  token,
  digest,
  equal,
  hashPassword,
  verifyPassword,
  vault,
  authenticator,
  canonicalPath,
  containsPath,
  validKey,
  validName,
  validEnvironment,
  validEmail,
  validId,
} from "./security.js";
import { parseEnv, formatEnv } from "./env-format.js";
import { emailDomainPolicy } from "./email-policy.js";
import { publicInfoPage } from "./info-page.js";
import { googleProvider } from "./google-auth.js";

export const ORG_PERMISSIONS = [
  "org.projects.create",
  "org.users.manage",
  "org.roles.manage",
  "org.settings.manage",
  "org.audit.read",
];
export const PROJECT_PERMISSIONS = [
  "project.read",
  "project.manage",
  "project.roles.manage",
  "project.machines.manage",
  "project.audit.read",
  "secrets.list",
  "secrets.read",
  "secrets.write",
  "secrets.delete",
  "secrets.export",
];
class HttpError extends Error {
  constructor(status, message, code) {
    super(message);
    this.status = status;
    this.code = code;
  }
}
const fail = (status, message) => {
  throw new HttpError(status, message);
};
const requireValue = (ok, message = "Invalid request.") => {
  if (!ok) fail(400, message);
};
const first = async (tx, sql, values = []) =>
  (await tx.query(sql, values)).rows[0];
const expiry = (minutes) => new Date(Date.now() + minutes * 60000);
const normalizeEmail = (email) =>
  String(email || "")
    .trim()
    .toLowerCase();
const dummyHash = await hashPassword(token());

export async function createApp({
  db,
  masterKey,
  setupTokenHash,
  origin = "http://localhost:8080",
  mailEnvironment = null,
  fetchMail = fetch,
  authLimit = 30,
  trustProxy = 0,
  allowedEmailDomains = "",
  publicOperatorName = "",
  google = null,
  googleClient,
}) {
  const emailPolicy = emailDomainPolicy(allowedEmailDomains);
  if (
    typeof publicOperatorName !== "string" ||
    publicOperatorName.trim().length > 80 ||
    /[\u0000-\u001f\u007f]/.test(publicOperatorName)
  )
    throw new Error("Invalid public operator name.");
  const publicInstance = Object.freeze({
    restricted: emailPolicy.restricted,
    emailDomains: emailPolicy.domains,
    operatorName: publicOperatorName.trim(),
    googleEnabled: !!google,
    googleOnly: !!google?.only,
  });
  function enforceEmail(email, redirect = false) {
    if (!emailPolicy.permits(email))
      throw new HttpError(
        403,
        "This account is not permitted on this instance.",
        redirect ? "EMAIL_DOMAIN_NOT_ALLOWED" : undefined,
      );
  }
  const app = express(),
    crypto = vault(masterKey),
    originUrl = new URL(origin);
  await db.transaction(async (tx) => {
    const state = await first(
      tx,
      "SELECT key_fingerprint FROM service_state WHERE id=1 FOR UPDATE",
    );
    const fingerprint = digest(masterKey.toString("base64"));
    if (state.key_fingerprint && !equal(state.key_fingerprint, fingerprint))
      throw new Error(
        "Encryption key does not match this database. Restore the correct key.",
      );
    if (!state.key_fingerprint)
      await tx.query("UPDATE service_state SET key_fingerprint=$1 WHERE id=1", [
        fingerprint,
      ]);
  });
  if (
    originUrl.origin !== origin ||
    (originUrl.protocol !== "https:" &&
      !["localhost", "127.0.0.1", "[::1]"].includes(originUrl.hostname))
  )
    throw new Error(
      "APP_ORIGIN must be an HTTPS origin or a loopback development origin.",
    );
  if (google?.ownerEmail && !emailPolicy.permits(google.ownerEmail))
    throw new Error("Bootstrap owner must satisfy the email policy.");
  const googleAuth = google
    ? googleProvider(google, origin, googleClient)
    : null;
  const secure = originUrl.protocol === "https:",
    cookieName = secure ? "__Host-sm_session" : "sm_session",
    googleCookie = secure ? "__Host-sm_google" : "sm_google";
  const sessionCookie = (res, session) =>
    res.cookie(cookieName, session.raw, {
      httpOnly: true,
      secure,
      sameSite: "strict",
      path: "/",
      expires: session.until,
    });
  app.disable("x-powered-by");
  app.set("trust proxy", trustProxy);
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'"],
          styleSrc: ["'self'"],
          imgSrc: ["'self'", "data:"],
          connectSrc: ["'self'"],
          frameAncestors: ["'none'"],
          formAction: ["'self'"],
          upgradeInsecureRequests: secure ? [] : null,
        },
      },
      strictTransportSecurity: secure ? undefined : false,
    }),
  );
  app.use((req, res, next) => {
    res.set("Cache-Control", "no-store");
    res.set("Referrer-Policy", "no-referrer");
    next();
  });
  app.use("/api", (req, res, next) => {
    if (req.get("origin") && req.get("origin") !== origin)
      return res.status(403).json({ error: "Origin rejected." });
    if (
      !["GET", "HEAD", "OPTIONS"].includes(req.method) &&
      !req.is("application/json")
    )
      return res.status(415).json({ error: "Use application/json." });
    next();
  });
  app.use(express.json({ limit: "384kb", strict: true }));
  const rates = new Map();
  app.use("/api", (req, res, next) => {
    if (
      !req.path.startsWith("/auth") &&
      req.path !== "/bootstrap" &&
      req.path !== "/accept-invitation"
    )
      return next();
    if (req.method === "GET") return next();
    const now = Date.now();
    for (const [key, value] of rates) if (value.until <= now) rates.delete(key);
    const identifiers = ["ip:" + req.ip];
    if (typeof req.body?.email === "string")
      identifiers.push("email:" + digest(normalizeEmail(req.body.email)));
    for (const key of identifiers) {
      const row = rates.get(key) || { count: 0, until: now + 60000 };
      if (rates.size > 10000 || ++row.count > authLimit)
        return res
          .status(429)
          .set("Retry-After", "60")
          .json({ error: "Too many attempts. Try again later." });
      rates.set(key, row);
    }
    next();
  });
  const audit = (tx, actor, action, scope = {}, resource = null) =>
    tx.query(
      "INSERT INTO audit_events (id, actor_type, actor_id, action, project_id, environment, path, resource_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
      [
        randomUUID(),
        actor?.type || null,
        actor?.id || null,
        action,
        scope.projectId || null,
        scope.environment || null,
        scope.path || null,
        resource,
      ],
    );
  async function principal(tx, req, allowPending = false) {
    const header = req.get("authorization");
    const cookies = parseCookie(req.headers.cookie || "");
    const usingBearer = header?.startsWith("Bearer ");
    if (header && !usingBearer) fail(401, "Unsupported authentication scheme.");
    const raw = usingBearer ? header.slice(7) : cookies[cookieName];
    if (!raw || raw.length > 256) fail(401, "Sign in required.");
    const session = await first(
      tx,
      "SELECT * FROM sessions WHERE token_hash=$1 AND expires_at > now()",
      [digest(raw)],
    );
    if (!session) fail(401, "Session expired or revoked.");
    if (
      !["GET", "HEAD"].includes(req.method) &&
      !usingBearer &&
      !equal(req.get("x-csrf-token") || "", session.csrf)
    )
      throw new HttpError(403, "CSRF verification failed.", "CSRF_MISMATCH");
    let entity;
    if (session.actor_type === "user")
      entity = await first(
        tx,
        "SELECT * FROM users WHERE id=$1 AND disabled=false",
        [session.actor_id],
      );
    else {
      entity = await first(
        tx,
        "SELECT m.* FROM machines m JOIN machine_credentials c ON c.machine_id=m.id WHERE m.id=$1 AND m.disabled=false AND c.id=$2 AND c.revoked=false AND c.expires_at>now()",
        [session.actor_id, session.credential_id],
      );
    }
    if (!entity) fail(401, "Identity disabled or credential revoked.");
    if (session.actor_type === "user") {
      enforceEmail(entity.email, true);
      if (
        (google?.only && session.auth_method !== "google") ||
        (!googleAuth && session.auth_method === "google")
      )
        fail(401, "Sign in using the configured authentication method.");
    }
    const actor = {
      ...entity,
      type: session.actor_type,
      session,
      id: session.actor_id,
    };
    if (
      req.method !== "GET" &&
      (req.path.startsWith("/api/auth/mfa/") ||
        req.path === "/api/auth/password")
    ) {
      const key = "factor:" + actor.id,
        now = Date.now();
      const rate = rates.get(key);
      const value =
        rate && rate.until > now ? rate : { count: 0, until: now + 60000 };
      if (++value.count > Math.max(6, Math.floor(authLimit / 3)))
        fail(429, "Too many factor attempts. Try again later.");
      rates.set(key, value);
    }
    const state = await first(
      tx,
      "SELECT require_mfa FROM service_state WHERE id=1",
    );
    if (
      !allowPending &&
      (session.kind !== "full" ||
        (actor.type === "user" && state.require_mfa && !actor.totp_box))
    )
      fail(403, "Complete two-factor authentication first.");
    return actor;
  }
  async function allowed(tx, actor, permission, scope = {}) {
    if (actor.type === "user" && actor.owner) return true;
    const { rows } = await tx.query(
      "SELECT r.project_id, r.permissions, b.environment, b.path FROM bindings b JOIN roles r ON r.id=b.role_id WHERE b.principal_type=$1 AND b.principal_id=$2",
      [actor.type, actor.id],
    );
    return rows.some(
      (row) =>
        row.permissions.includes(permission) &&
        (permission.startsWith("org.")
          ? row.project_id === null
          : row.project_id === scope.projectId &&
            (!row.environment || row.environment === scope.environment) &&
            containsPath(row.path, scope.path || "/")),
    );
  }
  async function authorize(tx, actor, permission, scope = {}) {
    if (!(await allowed(tx, actor, permission, scope)))
      fail(403, "Permission denied.");
  }
  function human(actor) {
    if (actor.type !== "user") fail(403, "A human account is required.");
  }
  function scopeFrom(req) {
    const projectId = req.params.projectId;
    requireValue(validId(projectId));
    const environment =
      req.query.environment || req.body?.environment || "development";
    requireValue(validEnvironment(environment), "Invalid environment.");
    let path;
    try {
      path = canonicalPath(req.query.path || req.body?.path || "/");
    } catch {
      fail(400, "Invalid folder path.");
    }
    return { projectId, environment, path };
  }
  async function checkEnvironment(tx, scope) {
    if (
      !(await first(
        tx,
        "SELECT 1 FROM environments WHERE project_id=$1 AND name=$2",
        [scope.projectId, scope.environment],
      ))
    )
      fail(404, "Environment not found.");
  }
  async function issue(
    tx,
    actorId,
    type = "user",
    kind = "full",
    credentialId = null,
    authMethod = "password",
  ) {
    const raw = token(),
      csrf = token(),
      until = expiry(type === "machine" ? 15 : kind === "pending" ? 10 : 480);
    await tx.query(
      "INSERT INTO sessions (token_hash, actor_type, actor_id, kind, csrf, expires_at, credential_id, auth_method) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
      [digest(raw), type, actorId, kind, csrf, until, credentialId, authMethod],
    );
    return { raw, csrf, until, kind };
  }
  function sessionResult(session, extra = {}, delivery = "cookie") {
    return {
      body: {
        ...extra,
        csrf: session.csrf,
        pending: session.kind === "pending",
        expiresAt: session.until,
        ...(delivery === "token" ? { accessToken: session.raw } : {}),
      },
      cookie: delivery === "token" ? null : session,
    };
  }
  function route(
    method,
    path,
    fn,
    { anonymous = false, pending = false } = {},
  ) {
    app[method]("/api" + path, async (req, res, next) => {
      let actor;
      try {
        const result = (await db.transaction(async (tx) => {
          actor = anonymous ? null : await principal(tx, req, pending);
          return await fn(tx, actor, req.body || {}, req);
        })) || { body: { ok: true } };
        if (result.after) await result.after(result);
        if (result.cookie) sessionCookie(res, result.cookie);
        if (result.googleCookie)
          res.cookie(googleCookie, result.googleCookie, {
            httpOnly: true,
            secure,
            sameSite: "lax",
            path: "/",
            maxAge: 5 * 60000,
          });
        if (result.clearCookie)
          res.clearCookie(cookieName, {
            httpOnly: true,
            secure,
            sameSite: "strict",
            path: "/",
          });
        if (result.text !== undefined)
          return res
            .type("text/plain")
            .set("Content-Disposition", 'attachment; filename="secrets.env"')
            .send(result.text);
        res.status(result.status || 200).json(result.body || { ok: true });
      } catch (error) {
        if (error.status === 403 || (anonymous && error.status === 401)) {
          try {
            await audit(
              db,
              actor,
              error.status === 403 ? "access.denied" : "auth.failed",
            );
          } catch {
            /* Never expose provider/database diagnostics. */
          }
        }
        next(error);
      }
    });
  }
  async function factor(tx, user, code) {
    if (!user.totp_box || typeof code !== "string" || code.length > 128)
      return false;
    const locked = await first(
      tx,
      "SELECT * FROM users WHERE id=$1 FOR UPDATE",
      [user.id],
    );
    const recovery = digest(code.trim());
    if (locked.recovery_hashes.includes(recovery)) {
      await tx.query(
        "UPDATE users SET recovery_hashes=array_remove(recovery_hashes,$2) WHERE id=$1",
        [user.id, recovery],
      );
      return true;
    }
    const otp = authenticator(
      user.email,
      crypto.open(locked.totp_box, "totp:" + user.id),
    );
    const delta = otp.validate({ token: code, window: 1 });
    if (delta === null) return false;
    const counter = Math.floor(Date.now() / 30000) + delta;
    if (counter <= Number(locked.totp_counter)) return false;
    await tx.query("UPDATE users SET totp_counter=$2 WHERE id=$1", [
      user.id,
      counter,
    ]);
    return true;
  }
  async function mailConfig(tx) {
    if (mailEnvironment) return { ...mailEnvironment, source: "environment" };
    const row = await first(tx, "SELECT mail FROM service_state WHERE id=1");
    return {
      enabled: !!row.mail.enabled,
      from: row.mail.from || "",
      key: row.mail.keyBox ? crypto.open(row.mail.keyBox, "mail") : "",
      source: "database",
    };
  }
  async function sendMail(config, email, subject, text) {
    if (!emailPolicy.permits(email)) return "recipient_not_allowed";
    if (!config.enabled || !config.key || !config.from) return "not_configured";
    try {
      const response = await fetchMail("https://api.resend.com/emails", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${config.key}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ from: config.from, to: [email], subject, text }),
        signal: AbortSignal.timeout(10000),
        redirect: "error",
      });
      await response.body?.cancel();
      return response.ok ? "sent" : "failed";
    } catch {
      return "failed";
    }
  }

  route(
    "post",
    "/auth/google/start",
    async (tx, _actor, body, req) => {
      if (!googleAuth) fail(404, "Google sign-in is not configured.");
      const action = body.action || "login";
      requireValue(["login", "bootstrap", "invite", "link"].includes(action));
      const context = { action };
      if (action === "bootstrap") {
        const state = await first(
          tx,
          "SELECT bootstrapped FROM service_state WHERE id=1",
        );
        if (
          state.bootstrapped ||
          typeof body.setupToken !== "string" ||
          !equal(digest(body.setupToken), setupTokenHash)
        )
          fail(403, "Setup is unavailable or setup token is invalid.");
        context.email = normalizeEmail(body.email);
        context.name = body.name;
        requireValue(
          validEmail(context.email) && validName(context.name),
          "Valid name and email required.",
        );
        enforceEmail(context.email, true);
        if (google.ownerEmail && context.email !== google.ownerEmail)
          fail(403, "Use the configured owner account.");
      }
      if (action === "invite") {
        requireValue(
          typeof body.token === "string" &&
            body.token.length <= 256 &&
            validName(body.name),
        );
        context.inviteHash = digest(body.token);
        context.name = body.name;
        const invitation = await first(
          tx,
          "SELECT email FROM invitations WHERE token_hash=$1 AND kind='invite' AND used=false AND expires_at>now()",
          [context.inviteHash],
        );
        if (!invitation) fail(400, "Invalid or expired invitation.");
        enforceEmail(invitation.email, true);
      }
      if (action === "link") {
        const actor = await principal(tx, req);
        human(actor);
        if (actor.google_subject)
          fail(409, "A Google account is already linked.");
        if (
          !(await verifyPassword(body.password, actor.password_hash)) ||
          (actor.totp_box && !(await factor(tx, actor, body.code)))
        )
          fail(401, "Password and current factor required.");
        context.actorId = actor.id;
        context.sessionHash = actor.session.token_hash;
      }
      const flow = googleAuth.begin(),
        browser = token();
      await tx.query("DELETE FROM google_flows WHERE expires_at<=now()");
      await tx.query(
        "INSERT INTO google_flows (token_hash,browser_hash,box,expires_at) VALUES ($1,$2,$3,$4)",
        [
          digest(flow.state),
          digest(browser),
          crypto.seal(
            JSON.stringify({
              ...context,
              nonce: flow.nonce,
              verifier: flow.verifier,
            }),
            "google:" + digest(flow.state),
          ),
          expiry(5),
        ],
      );
      return { body: { url: flow.url }, googleCookie: browser };
    },
    { anonymous: true },
  );

  app.get("/api/auth/google/callback", async (req, res) => {
    res.clearCookie(googleCookie, {
      httpOnly: true,
      secure,
      sameSite: "lax",
      path: "/",
    });
    if (!googleAuth) return res.redirect(303, "/signin#google=failed");
    let actor;
    try {
      const rawState = req.query.state,
        browser = parseCookie(req.headers.cookie || "")[googleCookie];
      if (
        typeof rawState !== "string" ||
        !/^[A-Za-z0-9_-]{43}$/.test(rawState) ||
        typeof browser !== "string" ||
        !/^[A-Za-z0-9_-]{43}$/.test(browser)
      )
        fail(400, "Invalid login state.");
      // Consume before contacting Google, in a separate committed transaction.
      // Provider errors, denied users and replay attempts cannot reuse the flow.
      const flow = await db.transaction(async (tx) =>
        first(
          tx,
          "DELETE FROM google_flows WHERE token_hash=$1 AND browser_hash=$2 AND expires_at>now() RETURNING box",
          [digest(rawState), digest(browser)],
        ),
      );
      if (!flow || req.query.error || typeof req.query.code !== "string")
        fail(400, "Google sign-in failed.");
      const context = JSON.parse(
        crypto.open(flow.box, "google:" + digest(rawState)),
      );
      const identity = await googleAuth.identity(
        req.query.code,
        context.verifier,
        context.nonce,
      );
      enforceEmail(identity.email, true);
      const session = await db.transaction(async (tx) => {
        let user;
        if (context.action === "bootstrap") {
          const state = await first(
            tx,
            "SELECT bootstrapped FROM service_state WHERE id=1 FOR UPDATE",
          );
          if (
            state.bootstrapped ||
            context.email !== identity.email ||
            (google.ownerEmail && identity.email !== google.ownerEmail)
          )
            fail(403, "Owner setup rejected.");
          user = { id: randomUUID(), type: "user", email: identity.email };
          await tx.query(
            "INSERT INTO users (id,email,name,password_hash,owner,google_subject) VALUES ($1,$2,$3,'!google',true,$4)",
            [user.id, identity.email, context.name, identity.subject],
          );
          await tx.query(
            "UPDATE service_state SET bootstrapped=true WHERE id=1",
          );
          await tx.query(
            "INSERT INTO roles (id,name,permissions,builtin) VALUES ($1,'Administrator',$2,true)",
            [randomUUID(), JSON.stringify(ORG_PERMISSIONS)],
          );
          await audit(tx, user, "service.initialized");
        } else if (context.action === "invite") {
          const invitation = await first(
            tx,
            "SELECT * FROM invitations WHERE token_hash=$1 AND kind='invite' AND used=false AND expires_at>now() FOR UPDATE",
            [context.inviteHash],
          );
          if (!invitation || invitation.email !== identity.email)
            fail(403, "Invitation does not match this Google account.");
          user = { id: randomUUID(), type: "user", email: identity.email };
          await tx.query(
            "INSERT INTO users (id,email,name,password_hash,google_subject) VALUES ($1,$2,$3,'!google',$4)",
            [user.id, identity.email, context.name, identity.subject],
          );
          await tx.query("UPDATE invitations SET used=true WHERE id=$1", [
            invitation.id,
          ]);
          await audit(tx, user, "user.invite.accepted");
        } else if (context.action === "link") {
          user = await first(
            tx,
            "SELECT u.* FROM users u JOIN sessions s ON s.actor_id=u.id AND s.actor_type='user' WHERE u.id=$1 AND u.disabled=false AND s.token_hash=$2 AND s.kind='full' AND s.expires_at>now() FOR UPDATE OF u",
            [context.actorId, context.sessionHash],
          );
          if (!user || user.email !== identity.email || user.google_subject)
            fail(403, "Account linking rejected.");
          await tx.query("UPDATE users SET google_subject=$2 WHERE id=$1", [
            user.id,
            identity.subject,
          ]);
          await tx.query(
            "DELETE FROM sessions WHERE actor_type='user' AND actor_id=$1",
            [user.id],
          );
          await audit(tx, { id: user.id, type: "user" }, "user.google.linked");
        } else {
          user = await first(
            tx,
            "SELECT * FROM users WHERE google_subject=$1 AND disabled=false",
            [identity.subject],
          );
          if (!user || user.email !== identity.email)
            fail(403, "Use an invited, linked Google account.");
        }
        actor = { id: user.id, type: "user" };
        await audit(tx, actor, "auth.google.accepted");
        const state = await first(
          tx,
          "SELECT require_mfa FROM service_state WHERE id=1",
        );
        return issue(
          tx,
          user.id,
          "user",
          user.totp_box || state.require_mfa ? "pending" : "full",
          null,
          "google",
        );
      });
      sessionCookie(res, session);
      return res.redirect(303, "/signin");
    } catch (error) {
      try {
        await audit(db, actor, "auth.google.failed");
      } catch {
        /* No provider payloads or credentials in logs. */
      }
      return res.redirect(
        303,
        error.code === "EMAIL_DOMAIN_NOT_ALLOWED"
          ? "/info"
          : "/signin#google=failed",
      );
    }
  });

  app.get("/api/instance", (_req, res) => res.json(publicInstance));

  route(
    "get",
    "/health",
    async (tx) => {
      await tx.query("SELECT 1");
      return { body: { status: "ok" } };
    },
    { anonymous: true },
  );
  route(
    "get",
    "/bootstrap",
    async (tx) => ({
      body: {
        required: !(
          await first(tx, "SELECT bootstrapped FROM service_state WHERE id=1")
        ).bootstrapped,
      },
    }),
    { anonymous: true },
  );
  route(
    "post",
    "/bootstrap",
    async (tx, actor, body) => {
      if (google?.only) fail(403, "Use Google to initialize this instance.");
      const state = await first(
        tx,
        "SELECT * FROM service_state WHERE id=1 FOR UPDATE",
      );
      if (
        state.bootstrapped ||
        !equal(digest(body.setupToken || ""), setupTokenHash)
      )
        fail(403, "Setup is unavailable or setup token is invalid.");
      const email = normalizeEmail(body.email);
      if (google?.ownerEmail && email !== google.ownerEmail)
        fail(403, "Use the configured owner account.");
      requireValue(
        validEmail(email) && validName(body.name),
        "Valid name and email required.",
      );
      enforceEmail(email, true);
      let password;
      try {
        password = await hashPassword(body.password);
      } catch {
        fail(400, "Password must contain 14–256 characters.");
      }
      const id = randomUUID();
      await tx.query(
        "INSERT INTO users (id,email,name,password_hash,owner) VALUES ($1,$2,$3,$4,true)",
        [id, email, body.name, password],
      );
      await tx.query("UPDATE service_state SET bootstrapped=true WHERE id=1");
      const orgRole = randomUUID();
      await tx.query(
        "INSERT INTO roles (id,name,permissions,builtin) VALUES ($1,$2,$3,true)",
        [orgRole, "Administrator", JSON.stringify(ORG_PERMISSIONS)],
      );
      await audit(tx, { id, type: "user" }, "service.initialized");
      return sessionResult(await issue(tx, id, "user", "pending"), {
        enrollmentRequired: true,
      });
    },
    { anonymous: true },
  );
  route(
    "post",
    "/auth/login",
    async (tx, actor, body) => {
      if (google?.only) fail(403, "Use Google to sign in to this instance.");
      const email = normalizeEmail(body.email);
      if (!validEmail(email)) fail(401, "Invalid credentials.");
      enforceEmail(email, true);
      const user = await first(tx, "SELECT * FROM users WHERE email=$1", [
        email,
      ]);
      const valid = await verifyPassword(
        body.password,
        user?.password_hash || dummyHash,
      );
      if (!valid || !user || user.disabled) fail(401, "Invalid credentials.");
      const state = await first(
        tx,
        "SELECT require_mfa FROM service_state WHERE id=1",
      );
      const kind = user.totp_box || state.require_mfa ? "pending" : "full";
      await audit(tx, { id: user.id, type: "user" }, "auth.password.accepted");
      return sessionResult(
        await issue(tx, user.id, "user", kind),
        { enrollmentRequired: !user.totp_box && kind === "pending" },
        body.delivery,
      );
    },
    { anonymous: true },
  );
  route(
    "get",
    "/auth/me",
    async (tx, actor) => {
      human(actor);
      return {
        body: {
          id: actor.id,
          name: actor.name,
          email: actor.email,
          owner: actor.owner,
          mfaEnabled: !!actor.totp_box,
          googleLinked: !!actor.google_subject,
          primaryMethod: actor.session.auth_method,
          hasPassword: actor.password_hash !== "!google",
          googleOnly: !!google?.only,
          googleEnabled: !!googleAuth,
          pending: actor.session.kind === "pending",
          csrf: actor.session.csrf,
          permissions: (
            await Promise.all(
              ORG_PERMISSIONS.map(async (permission) =>
                (await allowed(tx, actor, permission)) ? permission : null,
              ),
            )
          ).filter(Boolean),
          projectPermissions: PROJECT_PERMISSIONS,
        },
      };
    },
    { pending: true },
  );
  route(
    "post",
    "/auth/mfa/start",
    async (tx, actor, body) => {
      human(actor);
      if (
        actor.totp_box &&
        (!(actor.session.auth_method === "google"
          ? !!googleAuth &&
            actor.session.kind === "full" &&
            Date.now() - new Date(actor.session.created_at).getTime() <
              5 * 60000
          : await verifyPassword(body.password, actor.password_hash)) ||
          !(await factor(tx, actor, body.code)))
      )
        fail(
          401,
          "Current factor and password or recent Google sign-in required.",
        );
      const otp = authenticator(actor.email),
        seed = otp.secret.base32;
      await tx.query(
        "UPDATE users SET totp_pending=$2,pending_until=$3 WHERE id=$1",
        [actor.id, crypto.seal(seed, "pending:" + actor.id), expiry(10)],
      );
      await audit(tx, actor, "mfa.enrollment.started");
      return {
        body: { qr: await QRCode.toDataURL(otp.toString()), manualKey: seed },
      };
    },
    { pending: true },
  );
  route(
    "post",
    "/auth/mfa/confirm",
    async (tx, actor, body) => {
      human(actor);
      const user = await first(
        tx,
        "SELECT * FROM users WHERE id=$1 FOR UPDATE",
        [actor.id],
      );
      if (!user.totp_pending || new Date(user.pending_until) <= new Date())
        fail(400, "Enrollment expired.");
      const seed = crypto.open(user.totp_pending, "pending:" + actor.id),
        otp = authenticator(actor.email, seed);
      const delta =
        typeof body.code === "string"
          ? otp.validate({ token: body.code, window: 1 })
          : null;
      if (delta === null) fail(401, "Invalid authenticator code.");
      const codes = Array.from({ length: 10 }, token);
      await tx.query(
        "UPDATE users SET totp_box=$2,totp_pending=NULL,pending_until=NULL,totp_counter=$3,recovery_hashes=$4 WHERE id=$1",
        [
          actor.id,
          crypto.seal(seed, "totp:" + actor.id),
          Math.floor(Date.now() / 30000) + delta,
          codes.map(digest),
        ],
      );
      await tx.query(
        "DELETE FROM sessions WHERE actor_type=$1 AND actor_id=$2",
        ["user", actor.id],
      );
      await audit(tx, actor, "mfa.enrollment.confirmed");
      return sessionResult(
        await issue(
          tx,
          actor.id,
          "user",
          "full",
          null,
          actor.session.auth_method,
        ),
        { recoveryCodes: codes },
        body.delivery,
      );
    },
    { pending: true },
  );
  route(
    "post",
    "/auth/mfa/verify",
    async (tx, actor, body) => {
      human(actor);
      if (
        actor.session.kind !== "pending" ||
        !(await factor(tx, actor, body.code))
      )
        fail(401, "Invalid or already used factor.");
      await tx.query("DELETE FROM sessions WHERE token_hash=$1", [
        actor.session.token_hash,
      ]);
      await audit(tx, actor, "auth.mfa.accepted");
      return sessionResult(
        await issue(
          tx,
          actor.id,
          "user",
          "full",
          null,
          actor.session.auth_method,
        ),
        {},
        body.delivery,
      );
    },
    { pending: true },
  );
  route("post", "/auth/password", async (tx, actor, body) => {
    human(actor);
    if (google?.only || actor.password_hash === "!google")
      fail(403, "This account uses Google sign-in.");
    if (
      !(await verifyPassword(body.currentPassword, actor.password_hash)) ||
      (actor.totp_box && !(await factor(tx, actor, body.code)))
    )
      fail(401, "Password and current factor required.");
    let password;
    try {
      password = await hashPassword(body.password);
    } catch {
      fail(400, "Password must contain 14–256 characters.");
    }
    await tx.query("UPDATE users SET password_hash=$2 WHERE id=$1", [
      actor.id,
      password,
    ]);
    await tx.query("DELETE FROM sessions WHERE actor_type=$1 AND actor_id=$2", [
      "user",
      actor.id,
    ]);
    await audit(tx, actor, "user.password.changed");
    return { clearCookie: true };
  });
  route(
    "post",
    "/auth/logout",
    async (tx, actor) => {
      await tx.query("DELETE FROM sessions WHERE token_hash=$1", [
        actor.session.token_hash,
      ]);
      return { clearCookie: true };
    },
    { pending: true },
  );
  route("get", "/auth/sessions", async (tx, actor) => {
    human(actor);
    return {
      body: {
        sessions: (
          await tx.query(
            "SELECT created_at,expires_at,token_hash=$3 AS current FROM sessions WHERE actor_type=$1 AND actor_id=$2 ORDER BY created_at DESC",
            ["user", actor.id, actor.session.token_hash],
          )
        ).rows,
      },
    };
  });
  route("delete", "/auth/sessions", async (tx, actor) => {
    human(actor);
    await tx.query("DELETE FROM sessions WHERE actor_type=$1 AND actor_id=$2", [
      "user",
      actor.id,
    ]);
    await audit(tx, actor, "user.sessions.revoked");
    return { clearCookie: true };
  });

  route("get", "/admin/users", async (tx, actor) => {
    await authorize(tx, actor, "org.users.manage");
    return {
      body: {
        users: (
          await tx.query(
            "SELECT id,email,name,owner,disabled,totp_box IS NOT NULL AS mfa_enabled FROM users ORDER BY email",
          )
        ).rows,
        invitations: (
          await tx.query(
            "SELECT id,email,kind,expires_at,used FROM invitations WHERE expires_at>now() ORDER BY created_at DESC",
          )
        ).rows,
      },
    };
  });
  route("patch", "/admin/users/:id", async (tx, actor, body, req) => {
    await authorize(tx, actor, "org.users.manage");
    requireValue(validId(req.params.id) && typeof body.disabled === "boolean");
    const user = await first(
      tx,
      "SELECT id,owner FROM users WHERE id=$1 FOR UPDATE",
      [req.params.id],
    );
    if (!user) fail(404, "User not found.");
    if (user.owner || user.id === actor.id)
      fail(403, "Cannot disable the owner or your own account.");
    await tx.query("UPDATE users SET disabled=$2 WHERE id=$1", [
      user.id,
      body.disabled,
    ]);
    await tx.query("DELETE FROM sessions WHERE actor_type=$1 AND actor_id=$2", [
      "user",
      user.id,
    ]);
    await audit(
      tx,
      actor,
      body.disabled ? "user.disabled" : "user.enabled",
      {},
      user.id,
    );
  });
  route("delete", "/admin/users/:id/sessions", async (tx, actor, body, req) => {
    await authorize(tx, actor, "org.users.manage");
    requireValue(validId(req.params.id));
    await tx.query("DELETE FROM sessions WHERE actor_type=$1 AND actor_id=$2", [
      "user",
      req.params.id,
    ]);
    await audit(tx, actor, "user.sessions.revoked", {}, req.params.id);
  });
  route("post", "/admin/invitations", async (tx, actor, body) => {
    human(actor);
    await authorize(tx, actor, "org.users.manage");
    const email = normalizeEmail(body.email);
    requireValue(validEmail(email));
    enforceEmail(email);
    const user = await first(tx, "SELECT id,owner FROM users WHERE email=$1", [
      email,
    ]);
    const kind = body.kind === "reset" ? "reset" : "invite";
    if (google?.only && kind === "reset")
      fail(403, "Google accounts use Google account recovery.");
    if ((kind === "invite" && user) || (kind === "reset" && !user))
      fail(
        400,
        "Use an invitation for new users and a reset for existing users.",
      );
    if (user?.owner && !actor.owner)
      fail(403, "Only the owner can reset the owner account.");
    await tx.query(
      "UPDATE invitations SET used=true WHERE email=$1 AND used=false",
      [email],
    );
    const raw = token(),
      id = randomUUID(),
      until = expiry(kind === "reset" ? 60 : 1440);
    await tx.query(
      "INSERT INTO invitations (id,email,token_hash,kind,user_id,expires_at) VALUES ($1,$2,$3,$4,$5,$6)",
      [id, email, digest(raw), kind, user?.id || null, until],
    );
    await audit(
      tx,
      actor,
      kind === "reset" ? "user.reset.issued" : "user.invitation.issued",
      {},
      id,
    );
    const url = origin + "/signin#" + kind + "=" + raw,
      config = await mailConfig(tx);
    return {
      body: { id, url, expiresAt: until, emailStatus: "not_requested" },
      after: async (result) => {
        if (body.sendEmail === true)
          result.body.emailStatus = await sendMail(
            config,
            email,
            kind === "reset"
              ? "Reset your password"
              : "Your SecretManager invitation",
            `Open this single-use link before it expires:\n${url}\n`,
          );
      },
    };
  });
  route("delete", "/admin/invitations/:id", async (tx, actor, body, req) => {
    await authorize(tx, actor, "org.users.manage");
    requireValue(validId(req.params.id));
    await tx.query("UPDATE invitations SET used=true WHERE id=$1", [
      req.params.id,
    ]);
    await audit(tx, actor, "invitation.revoked", {}, req.params.id);
  });
  route(
    "post",
    "/accept-invitation",
    async (tx, actor, body) => {
      if (google?.only) fail(403, "Accept your invitation with Google.");
      const invite = await first(
        tx,
        "SELECT * FROM invitations WHERE token_hash=$1 AND used=false AND expires_at>now() FOR UPDATE",
        [digest(body.token || "")],
      );
      if (!invite) fail(400, "Invalid or expired link.");
      enforceEmail(invite.email, true);
      if (invite.kind === "reset") {
        const target = await first(
          tx,
          "SELECT email FROM users WHERE id=$1 FOR UPDATE",
          [invite.user_id],
        );
        if (
          !target ||
          normalizeEmail(target.email) !== normalizeEmail(invite.email)
        )
          fail(400, "Invalid or expired link.");
        enforceEmail(target.email, true);
      }
      let password;
      try {
        password = await hashPassword(body.password);
      } catch {
        fail(400, "Password must contain 14–256 characters.");
      }
      let id = invite.user_id;
      if (invite.kind === "invite") {
        requireValue(validName(body.name));
        id = randomUUID();
        await tx.query(
          "INSERT INTO users (id,email,name,password_hash) VALUES ($1,$2,$3,$4)",
          [id, invite.email, body.name, password],
        );
      } else {
        await tx.query("UPDATE users SET password_hash=$2 WHERE id=$1", [
          id,
          password,
        ]);
        await tx.query(
          "DELETE FROM sessions WHERE actor_type=$1 AND actor_id=$2",
          ["user", id],
        );
      }
      await tx.query("UPDATE invitations SET used=true WHERE id=$1", [
        invite.id,
      ]);
      await audit(
        tx,
        { type: "user", id },
        "user." + invite.kind + ".accepted",
      );
      return {
        body: {
          ok: true,
          message:
            "Sign in to continue. Existing two-factor authentication remains required.",
        },
        clearCookie: true,
      };
    },
    { anonymous: true },
  );

  route("get", "/settings", async (tx, actor) => {
    await authorize(tx, actor, "org.settings.manage");
    const config = await mailConfig(tx),
      state = await first(
        tx,
        "SELECT require_mfa FROM service_state WHERE id=1",
      );
    return {
      body: {
        requireMfa: state.require_mfa,
        mail: {
          enabled: config.enabled,
          from: config.from,
          keyConfigured: !!config.key,
          source: config.source,
        },
      },
    };
  });
  route("put", "/settings", async (tx, actor, body) => {
    human(actor);
    await authorize(tx, actor, "org.settings.manage");
    requireValue(typeof body.requireMfa === "boolean");
    if (body.mail) {
      if (mailEnvironment)
        fail(409, "Email settings are managed by deployment configuration.");
      requireValue(
        typeof body.mail.enabled === "boolean" &&
          typeof body.mail.from === "string" &&
          body.mail.from.length <= 254,
      );
      if (body.mail.enabled)
        requireValue(
          validEmail(body.mail.from),
          "Use a plain sender email address.",
        );
      const old = await first(
        tx,
        "SELECT mail FROM service_state WHERE id=1 FOR UPDATE",
      );
      let keyBox = old.mail.keyBox;
      if (body.mail.clearKey === true) keyBox = null;
      if (body.mail.key !== undefined && body.mail.key !== "") {
        requireValue(
          typeof body.mail.key === "string" && body.mail.key.length <= 512,
        );
        keyBox = crypto.seal(body.mail.key, "mail");
      }
      if (body.mail.enabled && !keyBox)
        fail(400, "An email API key is required.");
      await tx.query("UPDATE service_state SET mail=$1 WHERE id=1", [
        JSON.stringify({
          enabled: body.mail.enabled,
          from: body.mail.from,
          keyBox,
        }),
      ]);
    }
    await tx.query("UPDATE service_state SET require_mfa=$1 WHERE id=1", [
      body.requireMfa,
    ]);
    await audit(tx, actor, "settings.updated");
  });
  route("post", "/settings/test-email", async (tx, actor, body) => {
    await authorize(tx, actor, "org.settings.manage");
    const email = normalizeEmail(body.email);
    requireValue(validEmail(email));
    enforceEmail(email);
    const config = await mailConfig(tx);
    await audit(tx, actor, "mail.test.requested");
    return {
      body: {},
      after: async (result) => {
        result.body.emailStatus = await sendMail(
          config,
          email,
          "SecretManager email test",
          "Your email configuration is working.",
        );
      },
    };
  });

  route("get", "/projects", async (tx, actor) => {
    const { rows } = await tx.query("SELECT * FROM projects ORDER BY name");
    const projects = [];
    for (const project of rows) {
      const bindings = (
        await tx.query(
          "SELECT b.environment,b.path,r.permissions FROM bindings b JOIN roles r ON r.id=b.role_id WHERE b.principal_type=$1 AND b.principal_id=$2 AND r.project_id=$3",
          [actor.type, actor.id, project.id],
        )
      ).rows;
      if (
        (actor.type === "user" && actor.owner) ||
        bindings.some((row) => row.permissions.includes("project.read"))
      )
        projects.push({
          ...project,
          scopes: actor.owner ? [{ environment: null, path: "/" }] : bindings,
        });
    }
    return {
      body: {
        projects,
        canCreate: await allowed(tx, actor, "org.projects.create"),
      },
    };
  });
  route("post", "/projects", async (tx, actor, body) => {
    human(actor);
    await authorize(tx, actor, "org.projects.create");
    requireValue(validName(body.name));
    const id = randomUUID();
    await tx.query("INSERT INTO projects (id,name) VALUES ($1,$2)", [
      id,
      body.name,
    ]);
    for (const environment of ["development", "staging", "production"])
      await tx.query(
        "INSERT INTO environments (project_id,name) VALUES ($1,$2)",
        [id, environment],
      );
    for (const [name, permissions] of [
      ["Administrator", PROJECT_PERMISSIONS],
      [
        "Writer",
        [
          "project.read",
          "secrets.list",
          "secrets.read",
          "secrets.write",
          "secrets.delete",
          "secrets.export",
        ],
      ],
      ["Reader", ["project.read", "secrets.list", "secrets.read"]],
    ]) {
      const roleId = randomUUID();
      await tx.query(
        "INSERT INTO roles (id,project_id,name,permissions,builtin) VALUES ($1,$2,$3,$4,true)",
        [roleId, id, name, JSON.stringify(permissions)],
      );
      if (name === "Administrator")
        await tx.query(
          "INSERT INTO bindings (id,role_id,principal_type,principal_id) VALUES ($1,$2,$3,$4)",
          [randomUUID(), roleId, "user", actor.id],
        );
    }
    await audit(tx, actor, "project.created", { projectId: id }, id);
    return { body: { id }, status: 201 };
  });
  async function projectVisible(tx, actor, id) {
    if (
      !validId(id) ||
      !(await first(tx, "SELECT 1 FROM projects WHERE id=$1", [id]))
    )
      fail(404, "Project not found.");
    if (actor.type === "user" && actor.owner) return;
    const { rows } = await tx.query(
      "SELECT r.permissions FROM bindings b JOIN roles r ON r.id=b.role_id WHERE b.principal_type=$1 AND b.principal_id=$2 AND r.project_id=$3",
      [actor.type, actor.id, id],
    );
    if (!rows.some((row) => row.permissions.includes("project.read")))
      fail(403, "Permission denied.");
  }
  route("get", "/projects/:projectId", async (tx, actor, body, req) => {
    const id = req.params.projectId;
    await projectVisible(tx, actor, id);
    return {
      body: {
        project: await first(tx, "SELECT * FROM projects WHERE id=$1", [id]),
        environments: (
          await tx.query(
            "SELECT name FROM environments WHERE project_id=$1 ORDER BY name",
            [id],
          )
        ).rows,
      },
    };
  });
  route(
    "post",
    "/projects/:projectId/environments",
    async (tx, actor, body, req) => {
      const scope = { projectId: req.params.projectId };
      requireValue(validId(scope.projectId) && validEnvironment(body.name));
      await authorize(tx, actor, "project.manage", scope);
      await tx.query(
        "INSERT INTO environments (project_id,name) VALUES ($1,$2)",
        [scope.projectId, body.name],
      );
      await audit(tx, actor, "environment.created", scope);
    },
  );

  function roleScope(req) {
    const id = req.params.projectId;
    if (id) requireValue(validId(id));
    return id ? { projectId: id } : {};
  }
  const rolePermission = (scope) =>
    scope.projectId ? "project.roles.manage" : "org.roles.manage";
  for (const prefix of ["", "/projects/:projectId"]) {
    route("get", prefix + "/roles", async (tx, actor, body, req) => {
      const scope = roleScope(req);
      await authorize(tx, actor, rolePermission(scope), scope);
      const roles = (
        await tx.query(
          "SELECT * FROM roles WHERE project_id IS NOT DISTINCT FROM $1 ORDER BY name",
          [scope.projectId || null],
        )
      ).rows;
      const bindings = (
        await tx.query(
          "SELECT b.id,b.role_id,b.principal_type,b.principal_id,b.environment,b.path,COALESCE(u.email,m.name) AS principal FROM bindings b JOIN roles r ON r.id=b.role_id LEFT JOIN users u ON b.principal_type='user' AND u.id=b.principal_id LEFT JOIN machines m ON b.principal_type='machine' AND m.id=b.principal_id WHERE r.project_id IS NOT DISTINCT FROM $1",
          [scope.projectId || null],
        )
      ).rows;
      return {
        body: {
          roles,
          bindings,
          availablePermissions: scope.projectId
            ? PROJECT_PERMISSIONS
            : ORG_PERMISSIONS,
        },
      };
    });
    async function validateRole(tx, actor, body, scope) {
      requireValue(
        validName(body.name) &&
          Array.isArray(body.permissions) &&
          body.permissions.length <= 30,
      );
      const choices = scope.projectId ? PROJECT_PERMISSIONS : ORG_PERMISSIONS;
      for (const permission of body.permissions) {
        requireValue(choices.includes(permission));
        await authorize(tx, actor, permission, scope);
      }
    }
    route("post", prefix + "/roles", async (tx, actor, body, req) => {
      human(actor);
      const scope = roleScope(req);
      await authorize(tx, actor, rolePermission(scope), scope);
      await validateRole(tx, actor, body, scope);
      const id = randomUUID();
      await tx.query(
        "INSERT INTO roles (id,project_id,name,permissions) VALUES ($1,$2,$3,$4)",
        [
          id,
          scope.projectId || null,
          body.name,
          JSON.stringify([...new Set(body.permissions)]),
        ],
      );
      await audit(tx, actor, "role.created", scope, id);
      return { body: { id }, status: 201 };
    });
    route("patch", prefix + "/roles/:id", async (tx, actor, body, req) => {
      human(actor);
      const scope = roleScope(req);
      await authorize(tx, actor, rolePermission(scope), scope);
      requireValue(validId(req.params.id));
      const role = await first(
        tx,
        "SELECT * FROM roles WHERE id=$1 AND project_id IS NOT DISTINCT FROM $2 FOR UPDATE",
        [req.params.id, scope.projectId || null],
      );
      if (!role) fail(404, "Role not found.");
      if (role.builtin)
        fail(403, "Create a custom role instead of changing a built-in role.");
      await validateRole(tx, actor, body, scope);
      await tx.query("UPDATE roles SET name=$2,permissions=$3 WHERE id=$1", [
        role.id,
        body.name,
        JSON.stringify([...new Set(body.permissions)]),
      ]);
      await audit(tx, actor, "role.updated", scope, role.id);
    });
    route("delete", prefix + "/roles/:id", async (tx, actor, body, req) => {
      human(actor);
      const scope = roleScope(req);
      await authorize(tx, actor, rolePermission(scope), scope);
      requireValue(validId(req.params.id));
      const role = await first(
        tx,
        "SELECT * FROM roles WHERE id=$1 AND project_id IS NOT DISTINCT FROM $2",
        [req.params.id, scope.projectId || null],
      );
      if (!role) fail(404, "Role not found.");
      if (role.builtin) fail(403, "Built-in roles cannot be deleted.");
      await tx.query("DELETE FROM roles WHERE id=$1", [role.id]);
      await audit(tx, actor, "role.deleted", scope, role.id);
    });
    route("post", prefix + "/bindings", async (tx, actor, body, req) => {
      human(actor);
      const scope = roleScope(req);
      await authorize(tx, actor, rolePermission(scope), scope);
      requireValue(
        validId(body.roleId) &&
          ["user", "machine"].includes(body.principalType),
      );
      const role = await first(
        tx,
        "SELECT * FROM roles WHERE id=$1 AND project_id IS NOT DISTINCT FROM $2",
        [body.roleId, scope.projectId || null],
      );
      if (!role) fail(404, "Role not found.");
      const environment = body.environment || null;
      let path;
      try {
        path = canonicalPath(body.path || "/");
      } catch {
        fail(400, "Invalid folder path.");
      }
      if (
        !scope.projectId &&
        (environment || path !== "/" || body.principalType === "machine")
      )
        fail(
          400,
          "Organization roles apply to human accounts without environment/folder restrictions.",
        );
      if (environment) {
        requireValue(validEnvironment(environment));
        await checkEnvironment(tx, { ...scope, environment });
      }
      const grant = { ...scope, environment, path };
      for (const permission of role.permissions)
        await authorize(tx, actor, permission, grant);
      let target;
      if (body.principalType === "user")
        target = body.email
          ? await first(
              tx,
              "SELECT id FROM users WHERE email=$1 AND disabled=false",
              [normalizeEmail(body.email)],
            )
          : validId(body.principalId)
            ? await first(
                tx,
                "SELECT id FROM users WHERE id=$1 AND disabled=false",
                [body.principalId],
              )
            : null;
      else if (validId(body.principalId))
        target = await first(
          tx,
          "SELECT id FROM machines WHERE id=$1 AND project_id=$2",
          [body.principalId, scope.projectId],
        );
      if (!target) fail(404, "Identity not found.");
      const id = randomUUID();
      await tx.query(
        "INSERT INTO bindings (id,role_id,principal_type,principal_id,environment,path) VALUES ($1,$2,$3,$4,$5,$6)",
        [id, role.id, body.principalType, target.id, environment, path],
      );
      await audit(tx, actor, "role.assigned", grant, id);
      return { body: { id }, status: 201 };
    });
    route("delete", prefix + "/bindings/:id", async (tx, actor, body, req) => {
      human(actor);
      const scope = roleScope(req);
      await authorize(tx, actor, rolePermission(scope), scope);
      requireValue(validId(req.params.id));
      await tx.query(
        "DELETE FROM bindings WHERE id=$1 AND role_id IN (SELECT id FROM roles WHERE project_id IS NOT DISTINCT FROM $2)",
        [req.params.id, scope.projectId || null],
      );
      await audit(tx, actor, "role.unassigned", scope, req.params.id);
    });
  }

  route(
    "get",
    "/projects/:projectId/machines",
    async (tx, actor, body, req) => {
      const scope = { projectId: req.params.projectId };
      requireValue(validId(scope.projectId));
      await authorize(tx, actor, "project.machines.manage", scope);
      return {
        body: {
          machines: (
            await tx.query(
              "SELECT * FROM machines WHERE project_id=$1 ORDER BY name",
              [scope.projectId],
            )
          ).rows,
          credentials: (
            await tx.query(
              "SELECT c.id,c.machine_id,c.expires_at,c.revoked,c.created_at FROM machine_credentials c JOIN machines m ON m.id=c.machine_id WHERE m.project_id=$1 ORDER BY c.created_at DESC",
              [scope.projectId],
            )
          ).rows,
        },
      };
    },
  );
  route(
    "post",
    "/projects/:projectId/machines",
    async (tx, actor, body, req) => {
      human(actor);
      const scope = { projectId: req.params.projectId };
      requireValue(validId(scope.projectId) && validName(body.name));
      await authorize(tx, actor, "project.machines.manage", scope);
      const id = randomUUID();
      await tx.query(
        "INSERT INTO machines (id,project_id,name) VALUES ($1,$2,$3)",
        [id, scope.projectId, body.name],
      );
      await audit(tx, actor, "machine.created", scope, id);
      return { body: { id }, status: 201 };
    },
  );
  route(
    "patch",
    "/projects/:projectId/machines/:id",
    async (tx, actor, body, req) => {
      human(actor);
      const scope = { projectId: req.params.projectId };
      requireValue(
        validId(scope.projectId) &&
          validId(req.params.id) &&
          typeof body.disabled === "boolean",
      );
      await authorize(tx, actor, "project.machines.manage", scope);
      const row = await first(
        tx,
        "UPDATE machines SET disabled=$3 WHERE id=$1 AND project_id=$2 RETURNING id",
        [req.params.id, scope.projectId, body.disabled],
      );
      if (!row) fail(404, "Machine not found.");
      await tx.query(
        "DELETE FROM sessions WHERE actor_type=$1 AND actor_id=$2",
        ["machine", row.id],
      );
      await audit(
        tx,
        actor,
        body.disabled ? "machine.disabled" : "machine.enabled",
        scope,
        row.id,
      );
    },
  );
  route(
    "post",
    "/projects/:projectId/machines/:id/credentials",
    async (tx, actor, body, req) => {
      human(actor);
      const scope = { projectId: req.params.projectId };
      requireValue(validId(scope.projectId) && validId(req.params.id));
      await authorize(tx, actor, "project.machines.manage", scope);
      const machine = await first(
        tx,
        "SELECT * FROM machines WHERE id=$1 AND project_id=$2 AND disabled=false FOR UPDATE",
        [req.params.id, scope.projectId],
      );
      if (!machine) fail(404, "Machine not found.");
      const days = body.days ?? 30;
      requireValue(
        Number.isInteger(days) && days >= 1 && days <= 365,
        "Credential lifetime must be 1–365 days.",
      );
      const count = await first(
        tx,
        "SELECT count(*)::integer AS count FROM machine_credentials WHERE machine_id=$1 AND revoked=false AND expires_at>now()",
        [machine.id],
      );
      if (count.count >= 5)
        fail(409, "Revoke an old credential before creating another.");
      const id = randomUUID(),
        raw = token(),
        until = expiry(days * 1440);
      await tx.query(
        "INSERT INTO machine_credentials (id,machine_id,secret_hash,expires_at) VALUES ($1,$2,$3,$4)",
        [id, machine.id, digest(raw), until],
      );
      await audit(tx, actor, "machine.credential.created", scope, id);
      return {
        body: { id, clientId: machine.id, clientSecret: raw, expiresAt: until },
        status: 201,
      };
    },
  );
  route(
    "delete",
    "/projects/:projectId/credentials/:id",
    async (tx, actor, body, req) => {
      human(actor);
      const scope = { projectId: req.params.projectId };
      requireValue(validId(scope.projectId) && validId(req.params.id));
      await authorize(tx, actor, "project.machines.manage", scope);
      await tx.query(
        "UPDATE machine_credentials SET revoked=true WHERE id=$1 AND machine_id IN (SELECT id FROM machines WHERE project_id=$2)",
        [req.params.id, scope.projectId],
      );
      await audit(
        tx,
        actor,
        "machine.credential.revoked",
        scope,
        req.params.id,
      );
    },
  );
  route(
    "post",
    "/auth/machine",
    async (tx, actor, body) => {
      if (
        !validId(body.clientId) ||
        typeof body.clientSecret !== "string" ||
        body.clientSecret.length > 256
      )
        fail(401, "Invalid machine credentials.");
      const credential = await first(
        tx,
        "SELECT c.* FROM machine_credentials c JOIN machines m ON m.id=c.machine_id WHERE c.machine_id=$1 AND c.secret_hash=$2 AND c.revoked=false AND c.expires_at>now() AND m.disabled=false",
        [body.clientId, digest(body.clientSecret)],
      );
      if (!credential) fail(401, "Invalid machine credentials.");
      const session = await issue(
        tx,
        body.clientId,
        "machine",
        "full",
        credential.id,
      );
      await audit(
        tx,
        { id: body.clientId, type: "machine" },
        "machine.authenticated",
      );
      return { body: { accessToken: session.raw, expiresAt: session.until } };
    },
    { anonymous: true },
  );

  async function secretRow(tx, req) {
    requireValue(validId(req.params.projectId) && validId(req.params.id));
    const row = await first(
      tx,
      "SELECT * FROM secrets WHERE id=$1 AND project_id=$2 FOR UPDATE",
      [req.params.id, req.params.projectId],
    );
    if (!row) fail(404, "Secret not found.");
    if (
      row.deleted_at &&
      Date.now() - new Date(row.deleted_at).getTime() > 30 * 86400000
    )
      fail(404, "Secret recovery window expired.");
    return row;
  }
  const secretScope = (row) => ({
    projectId: row.project_id,
    environment: row.environment,
    path: row.path,
  });
  async function putSecret(tx, actor, scope, key, value) {
    requireValue(
      validKey(key) &&
        typeof value === "string" &&
        Buffer.byteLength(value) <= 65536 &&
        !value.includes("\0"),
      "Invalid key or value (maximum 64 KiB).",
    );
    let row = await first(
      tx,
      "SELECT * FROM secrets WHERE project_id=$1 AND environment=$2 AND path=$3 AND key=$4 FOR UPDATE",
      [scope.projectId, scope.environment, scope.path, key],
    );
    if (row?.deleted_at)
      fail(
        409,
        "Restore or wait for removal of the deleted secret before reusing its key.",
      );
    const id = row?.id || randomUUID(),
      version = (row?.version || 0) + 1;
    if (row)
      await tx.query(
        "UPDATE secrets SET version=$2,updated_at=now() WHERE id=$1",
        [id, version],
      );
    else
      await tx.query(
        "INSERT INTO secrets (id,project_id,environment,path,key,version) VALUES ($1,$2,$3,$4,$5,$6)",
        [id, scope.projectId, scope.environment, scope.path, key, version],
      );
    await tx.query(
      "INSERT INTO secret_versions (secret_id,version,box,actor_type,actor_id) VALUES ($1,$2,$3,$4,$5)",
      [
        id,
        version,
        crypto.seal(value, `secret:${id}:${version}`),
        actor.type,
        actor.id,
      ],
    );
    await audit(tx, actor, "secret.written", scope, id);
    return { id, version };
  }
  route("get", "/projects/:projectId/secrets", async (tx, actor, body, req) => {
    const scope = scopeFrom(req);
    await authorize(tx, actor, "secrets.list", scope);
    await checkEnvironment(tx, scope);
    const rows = (
      await tx.query(
        "SELECT id,key,version,deleted_at,updated_at FROM secrets WHERE project_id=$1 AND environment=$2 AND path=$3 AND (deleted_at IS NULL OR deleted_at>now()-interval '30 days') ORDER BY key",
        [scope.projectId, scope.environment, scope.path],
      )
    ).rows;
    await audit(tx, actor, "secrets.listed", scope);
    return { body: { secrets: rows } };
  });
  route(
    "post",
    "/projects/:projectId/secrets",
    async (tx, actor, body, req) => {
      const scope = scopeFrom(req);
      await authorize(tx, actor, "secrets.write", scope);
      await checkEnvironment(tx, scope);
      return {
        body: await putSecret(tx, actor, scope, body.key, body.value),
        status: 201,
      };
    },
  );
  route(
    "get",
    "/projects/:projectId/secrets/:id/value",
    async (tx, actor, body, req) => {
      const row = await secretRow(tx, req),
        scope = secretScope(row);
      await authorize(tx, actor, "secrets.read", scope);
      if (row.deleted_at) fail(404, "Secret is deleted.");
      const version = await first(
        tx,
        "SELECT box FROM secret_versions WHERE secret_id=$1 AND version=$2",
        [row.id, row.version],
      );
      await audit(tx, actor, "secret.read", scope, row.id);
      return {
        body: {
          value: crypto.open(version.box, `secret:${row.id}:${row.version}`),
          version: row.version,
        },
      };
    },
  );
  route(
    "get",
    "/projects/:projectId/secrets/:id/versions",
    async (tx, actor, body, req) => {
      const row = await secretRow(tx, req),
        scope = secretScope(row);
      await authorize(tx, actor, "secrets.read", scope);
      const rows = (
        await tx.query(
          "SELECT version,created_at FROM secret_versions WHERE secret_id=$1 ORDER BY version DESC",
          [row.id],
        )
      ).rows;
      await audit(tx, actor, "secret.history.read", scope, row.id);
      return { body: { versions: rows } };
    },
  );
  route(
    "post",
    "/projects/:projectId/secrets/:id/restore",
    async (tx, actor, body, req) => {
      const row = await secretRow(tx, req),
        scope = secretScope(row);
      await authorize(tx, actor, "secrets.write", scope);
      await authorize(tx, actor, "secrets.read", scope);
      requireValue(Number.isInteger(body.version) && body.version > 0);
      const old = await first(
        tx,
        "SELECT box FROM secret_versions WHERE secret_id=$1 AND version=$2",
        [row.id, body.version],
      );
      if (!old) fail(404, "Version not found.");
      const value = crypto.open(old.box, `secret:${row.id}:${body.version}`),
        version = row.version + 1;
      await tx.query(
        "UPDATE secrets SET version=$2,deleted_at=NULL,updated_at=now() WHERE id=$1",
        [row.id, version],
      );
      await tx.query(
        "INSERT INTO secret_versions (secret_id,version,box,actor_type,actor_id) VALUES ($1,$2,$3,$4,$5)",
        [
          row.id,
          version,
          crypto.seal(value, `secret:${row.id}:${version}`),
          actor.type,
          actor.id,
        ],
      );
      await audit(tx, actor, "secret.restored", scope, row.id);
      return { body: { id: row.id, version } };
    },
  );
  route(
    "delete",
    "/projects/:projectId/secrets/:id",
    async (tx, actor, body, req) => {
      const row = await secretRow(tx, req);
      await authorize(tx, actor, "secrets.delete", secretScope(row));
      await tx.query(
        "UPDATE secrets SET deleted_at=COALESCE(deleted_at,now()),updated_at=now() WHERE id=$1",
        [row.id],
      );
      await audit(tx, actor, "secret.deleted", secretScope(row), row.id);
    },
  );
  route(
    "post",
    "/projects/:projectId/import/preview",
    async (tx, actor, body, req) => {
      const scope = scopeFrom(req);
      await authorize(tx, actor, "secrets.write", scope);
      await checkEnvironment(tx, scope);
      let values;
      try {
        values = parseEnv(body.content);
      } catch (error) {
        fail(400, error.message);
      }
      const existing = (
        await tx.query(
          "SELECT key,deleted_at FROM secrets WHERE project_id=$1 AND environment=$2 AND path=$3",
          [scope.projectId, scope.environment, scope.path],
        )
      ).rows;
      return {
        body: {
          keys: Object.keys(values),
          conflicts: existing
            .filter((row) => Object.hasOwn(values, row.key))
            .map((row) => ({ key: row.key, deleted: !!row.deleted_at })),
        },
      };
    },
  );
  route("post", "/projects/:projectId/import", async (tx, actor, body, req) => {
    const scope = scopeFrom(req);
    await authorize(tx, actor, "secrets.write", scope);
    await checkEnvironment(tx, scope);
    requireValue(
      ["skip", "overwrite"].includes(body.conflicts),
      "Select skip or overwrite for conflicts.",
    );
    let values;
    try {
      values = parseEnv(body.content);
    } catch (error) {
      fail(400, error.message);
    }
    let written = 0,
      skipped = 0;
    for (const [key, value] of Object.entries(values)) {
      const old = await first(
        tx,
        "SELECT id,deleted_at FROM secrets WHERE project_id=$1 AND environment=$2 AND path=$3 AND key=$4",
        [scope.projectId, scope.environment, scope.path, key],
      );
      if (old && (body.conflicts === "skip" || old.deleted_at)) {
        skipped++;
        continue;
      }
      await putSecret(tx, actor, scope, key, value);
      written++;
    }
    await audit(tx, actor, "secrets.imported", scope);
    return { body: { written, skipped } };
  });
  route("get", "/projects/:projectId/export", async (tx, actor, body, req) => {
    const scope = scopeFrom(req);
    await authorize(tx, actor, "secrets.export", scope);
    await authorize(tx, actor, "secrets.read", scope);
    const rows = (
      await tx.query(
        "SELECT s.id,s.key,s.version,v.box FROM secrets s JOIN secret_versions v ON v.secret_id=s.id AND v.version=s.version WHERE s.project_id=$1 AND s.environment=$2 AND s.path=$3 AND s.deleted_at IS NULL ORDER BY s.key",
        [scope.projectId, scope.environment, scope.path],
      )
    ).rows;
    const values = Object.create(null);
    for (const row of rows)
      values[row.key] = crypto.open(row.box, `secret:${row.id}:${row.version}`);
    await audit(tx, actor, "secrets.exported", scope);
    return { text: formatEnv(values) };
  });
  route("get", "/audit", async (tx, actor, body, req) => {
    if (!req.query.projectId) {
      await authorize(tx, actor, "org.audit.read");
      return {
        body: {
          events: (
            await tx.query(
              "SELECT * FROM audit_events ORDER BY created_at DESC LIMIT 200",
            )
          ).rows,
        },
      };
    }
    const scope = {
      projectId: req.query.projectId,
      environment: req.query.environment || null,
      path: (() => {
        try {
          return canonicalPath(req.query.path || "/");
        } catch {
          fail(400, "Invalid folder path.");
        }
      })(),
    };
    requireValue(validId(scope.projectId));
    if (scope.environment) requireValue(validEnvironment(scope.environment));
    await authorize(tx, actor, "project.audit.read", scope);
    const rows = (
      await tx.query(
        "SELECT * FROM audit_events WHERE project_id=$1 ORDER BY created_at DESC LIMIT 1000",
        [scope.projectId],
      )
    ).rows;
    return {
      body: {
        events: rows
          .filter(
            (row) =>
              (!scope.environment || row.environment === scope.environment) &&
              (!row.path
                ? scope.path === "/"
                : containsPath(scope.path, row.path)),
          )
          .slice(0, 200),
      },
    };
  });
  app.use("/api", (_req, res) =>
    res.status(404).json({ error: "API endpoint not found." }),
  );
  app.use(express.static(resolve("dist"), { index: false, etag: false }));
  app.get("/info", (_req, res) =>
    res.type("html").send(publicInfoPage(publicInstance)),
  );
  app.get(["/", "/signin"], (_req, res) =>
    res.sendFile(resolve("dist/index.html")),
  );
  app.use((error, _req, res, _next) => {
    if (error.status && error.status >= 400 && error.status < 500)
      return res.status(error.status).json({
        ...(error instanceof HttpError && error.code
          ? {
              code: error.code,
              ...(error.code === "EMAIL_DOMAIN_NOT_ALLOWED"
                ? { infoUrl: "/info" }
                : {}),
            }
          : {}),
        error:
          error.type === "entity.too.large"
            ? "Request too large."
            : error instanceof HttpError
              ? error.message
              : "Invalid request.",
      });
    if (error.code === "23505")
      return res
        .status(409)
        .json({ error: "An item with that identity already exists." });
    if (error.code === "23503")
      return res.status(400).json({ error: "Referenced item does not exist." });
    if (error.code === "40001")
      return res
        .status(409)
        .json({ error: "Concurrent change. Please retry." });
    // Do not log raw database/provider errors, SQL parameters or request bodies.
    console.error("Request failed; internal diagnostics suppressed.");
    res.status(500).json({ error: "Request failed." });
  });
  return app;
}
