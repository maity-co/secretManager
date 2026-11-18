import { OAuth2Client } from "google-auth-library";
import { createHash } from "node:crypto";
import { equal, token, validEmail } from "./security.js";
import { emailDomainPolicy } from "./email-policy.js";

export function googleSettings({
  clientId = "",
  clientSecret = "",
  hostedDomain = "",
  only = false,
  ownerEmail = "",
} = {}) {
  if (typeof only !== "boolean")
    throw new Error("Invalid Google-only setting.");
  for (const value of [clientId, clientSecret, hostedDomain, ownerEmail])
    if (typeof value !== "string" || /[\u0000-\u001f\u007f]/.test(value))
      throw new Error("Invalid Google configuration.");
  clientId = clientId.trim();
  clientSecret = clientSecret.trim();
  hostedDomain = hostedDomain.trim().toLowerCase();
  ownerEmail = ownerEmail.trim().toLowerCase();
  if (!clientId && !clientSecret && !hostedDomain && !only && !ownerEmail)
    return null;
  if (
    !/^[A-Za-z0-9_-]{8,200}\.apps\.googleusercontent\.com$/.test(clientId) ||
    clientSecret.length < 16 ||
    clientSecret.length > 1024
  )
    throw new Error("Google client ID and secret are required.");
  if (hostedDomain && emailDomainPolicy(hostedDomain).domains.length !== 1)
    throw new Error("One Google hosted domain is required.");
  if (ownerEmail && !validEmail(ownerEmail))
    throw new Error("Invalid bootstrap owner email.");
  return Object.freeze({
    clientId,
    clientSecret,
    hostedDomain,
    only,
    ownerEmail,
  });
}

// Token verification, Google endpoints and key caching are owned by Google's
// library. The injectable client is used only by credential-free tests.
export function googleProvider(settings, origin, client) {
  const callback = origin + "/api/auth/google/callback";
  client ||= new OAuth2Client({
    clientId: settings.clientId,
    clientSecret: settings.clientSecret,
    redirectUri: callback,
    issuers: ["https://accounts.google.com", "accounts.google.com"],
    transporterOptions: { timeout: 10000, retry: false, maxRedirects: 0 },
  });
  // Override the library's per-request retry defaults to bound token/key calls.
  client.transporter?.interceptors.request.add({
    resolved: (options) => {
      options.timeout = 10000;
      options.retry = false;
      options.maxRedirects = 0;
      return options;
    },
  });
  return {
    begin() {
      const verifier = token() + token(),
        nonce = token(),
        state = token();
      const url = client.generateAuthUrl({
        response_type: "code",
        scope: ["openid", "email"],
        redirect_uri: callback,
        state,
        nonce,
        access_type: "online",
        prompt: "select_account",
        code_challenge_method: "S256",
        code_challenge: createHash("sha256")
          .update(verifier)
          .digest("base64url"),
        ...(settings.hostedDomain ? { hd: settings.hostedDomain } : {}),
      });
      return { url, verifier, nonce, state };
    },
    async identity(code, verifier, nonce) {
      if (typeof code !== "string" || !code || code.length > 4096)
        throw new Error("Invalid Google response.");
      const { tokens } = await client.getToken({
        code,
        codeVerifier: verifier,
        redirect_uri: callback,
      });
      if (typeof tokens.id_token !== "string")
        throw new Error("Missing identity token.");
      const ticket = await client.verifyIdToken({
        idToken: tokens.id_token,
        audience: settings.clientId,
        maxExpiry: 3600,
      });
      const claims = ticket.getPayload();
      if (
        !claims ||
        typeof claims.sub !== "string" ||
        !/^[A-Za-z0-9_-]{1,255}$/.test(claims.sub) ||
        !["accounts.google.com", "https://accounts.google.com"].includes(
          claims.iss,
        ) ||
        claims.aud !== settings.clientId ||
        (claims.azp && claims.azp !== settings.clientId) ||
        claims.email_verified !== true ||
        typeof claims.email !== "string" ||
        !validEmail(claims.email) ||
        typeof claims.nonce !== "string" ||
        !equal(claims.nonce, nonce) ||
        !Number.isFinite(claims.exp) ||
        claims.exp * 1000 <= Date.now() ||
        !Number.isFinite(claims.iat) ||
        claims.iat * 1000 > Date.now() + 60000
      )
        throw new Error("Google identity rejected.");
      if (settings.hostedDomain && claims.hd !== settings.hostedDomain) {
        const error = new Error("Google hosted domain rejected.");
        error.code = "EMAIL_DOMAIN_NOT_ALLOWED";
        throw error;
      }
      if (
        !claims.email.toLowerCase().endsWith("@gmail.com") &&
        (typeof claims.hd !== "string" || !claims.hd)
      )
        throw new Error("Google is not authoritative for this email.");
      // No access/refresh/ID token is persisted or exposed to the browser.
      return { subject: claims.sub, email: claims.email.trim().toLowerCase() };
    },
  };
}
