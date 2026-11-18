import {
  randomBytes,
  createHash,
  createCipheriv,
  createDecipheriv,
  timingSafeEqual,
  scrypt as scryptCallback,
} from "node:crypto";
import { promisify } from "node:util";
import * as OTPAuth from "otpauth";
const scrypt = promisify(scryptCallback);
export const token = () => randomBytes(32).toString("base64url");
export const digest = (value) =>
  createHash("sha256").update(String(value)).digest("hex");
export function equal(a, b) {
  const x = Buffer.from(String(a)),
    y = Buffer.from(String(b));
  return x.length === y.length && timingSafeEqual(x, y);
}
export async function hashPassword(value) {
  if (typeof value !== "string" || value.length < 14 || value.length > 256)
    throw new Error("Password must contain 14–256 characters.");
  const salt = randomBytes(16);
  const hash = await scrypt(value, salt, 32, {
    N: 32768,
    r: 8,
    p: 3,
    maxmem: 64 * 1024 * 1024,
  });
  return `scrypt$32768$8$3$${salt.toString("hex")}$${hash.toString("hex")}`;
}
export async function verifyPassword(value, stored) {
  if (typeof value !== "string" || value.length > 256) return false;
  const [scheme, n, r, p, salt, expected] = String(stored).split("$");
  if (scheme !== "scrypt" || n !== "32768" || r !== "8" || p !== "3")
    return false;
  if (
    !/^[a-f0-9]{32}$/.test(salt || "") ||
    !/^[a-f0-9]{64}$/.test(expected || "")
  )
    return false;
  const actual = await scrypt(value, Buffer.from(salt, "hex"), 32, {
    N: 32768,
    r: 8,
    p: 3,
    maxmem: 64 * 1024 * 1024,
  });
  return equal(actual.toString("hex"), expected);
}
export function vault(key) {
  if (!Buffer.isBuffer(key) || key.length !== 32)
    throw new Error("A 32-byte encryption key is required.");
  return {
    seal(value, context) {
      const nonce = randomBytes(12),
        cipher = createCipheriv("aes-256-gcm", key, nonce);
      cipher.setAAD(Buffer.from(context));
      const bytes = Buffer.concat([
        cipher.update(String(value), "utf8"),
        cipher.final(),
      ]);
      return [
        "v1",
        nonce.toString("base64"),
        cipher.getAuthTag().toString("base64"),
        bytes.toString("base64"),
      ].join(".");
    },
    open(value, context) {
      const [version, nonce, tag, data, extra] = String(value).split(".");
      if (version !== "v1" || extra !== undefined)
        throw new Error("Invalid encrypted value.");
      const cipher = createDecipheriv(
        "aes-256-gcm",
        key,
        Buffer.from(nonce, "base64"),
      );
      cipher.setAAD(Buffer.from(context));
      cipher.setAuthTag(Buffer.from(tag, "base64"));
      return Buffer.concat([
        cipher.update(Buffer.from(data, "base64")),
        cipher.final(),
      ]).toString("utf8");
    },
  };
}
export function authenticator(email, secret) {
  return new OTPAuth.TOTP({
    issuer: "SecretManager",
    label: email,
    algorithm: "SHA1",
    digits: 6,
    period: 30,
    ...(secret ? { secret: OTPAuth.Secret.fromBase32(secret) } : {}),
  });
}
export function canonicalPath(value = "/") {
  if (typeof value !== "string" || value.length > 256 || !value.startsWith("/"))
    throw new Error("Invalid folder path.");
  const result = value.replace(/\/$/, "") || "/";
  if (
    result !== "/" &&
    !result
      .slice(1)
      .split("/")
      .every(
        (part) =>
          /^[A-Za-z0-9_.-]+$/.test(part) && part !== "." && part !== "..",
      )
  )
    throw new Error("Invalid folder path.");
  return result;
}
export const containsPath = (scope, path) =>
  scope === "/" || path === scope || path.startsWith(scope + "/");
export const validKey = (value) =>
  typeof value === "string" && /^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(value);
export const validName = (value) =>
  typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9 _.-]{0,79}$/.test(value);
export const validEnvironment = (value) =>
  typeof value === "string" && /^[a-z][a-z0-9_-]{0,39}$/.test(value);
export const validEmail = (value) =>
  typeof value === "string" &&
  value.length <= 254 &&
  /^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(value);
export const validId = (value) =>
  typeof value === "string" &&
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);
