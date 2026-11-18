import { createHmac, randomUUID } from "node:crypto";
import { isIP } from "node:net";
import { parse as parseCookie } from "cookie";
import { digest, token } from "./security.js";

export const TRUSTED_BROWSER_MS = 30 * 86400000;
const MAX_BROWSERS = 10;

export function trustedBrowsers(masterKey, cookieName) {
  function raw(req) {
    const value = parseCookie(req.headers.cookie || "")[cookieName];
    return typeof value === "string" && /^[A-Za-z0-9_-]{43}$/.test(value)
      ? value
      : null;
  }
  function ipHash(req) {
    let ip = req.ip;
    if (typeof ip !== "string") return null;
    if (ip.startsWith("::ffff:") && isIP(ip.slice(7)) === 4) ip = ip.slice(7);
    if (!isIP(ip)) return null;
    if (isIP(ip) === 6) {
      try {
        ip = new URL("http://[" + ip + "]").hostname;
      } catch {
        return null;
      }
    }
    return createHmac("sha256", masterKey)
      .update("trusted-browser-ip\0" + ip)
      .digest("hex");
  }
  function binding(req) {
    const value = raw(req),
      ip = ipHash(req);
    return value && ip ? { tokenHash: digest(value), ipHash: ip } : null;
  }
  async function findBound(tx, userId, req, bound, touch = false) {
    const ip = ipHash(req);
    if (
      !bound ||
      !ip ||
      bound.ipHash !== ip ||
      typeof bound.tokenHash !== "string" ||
      !/^[a-f0-9]{64}$/.test(bound.tokenHash)
    )
      return null;
    const row = (
      await tx.query(
        "SELECT id,user_id,expires_at,ip_hash FROM trusted_browsers WHERE token_hash=$1 AND user_id=$2 AND expires_at>now()",
        [bound.tokenHash, userId],
      )
    ).rows[0];
    if (!row || row.ip_hash !== ip) return null;
    if (touch)
      await tx.query(
        "UPDATE trusted_browsers SET last_used_at=now() WHERE id=$1",
        [row.id],
      );
    return row;
  }
  async function find(tx, userId, req, touch = false) {
    return findBound(tx, userId, req, binding(req), touch);
  }
  async function remember(tx, userId, req) {
    const ip = ipHash(req);
    if (!ip) return null;
    const previous = raw(req);
    if (previous)
      await tx.query(
        "DELETE FROM trusted_browsers WHERE user_id=$1 AND token_hash=$2",
        [userId, digest(previous)],
      );
    await tx.query(
      "DELETE FROM trusted_browsers WHERE user_id=$1 AND expires_at<=now()",
      [userId],
    );
    await tx.query(
      "DELETE FROM trusted_browsers WHERE id IN (SELECT id FROM trusted_browsers WHERE user_id=$1 ORDER BY last_used_at DESC,created_at DESC,id OFFSET $2)",
      [userId, MAX_BROWSERS - 1],
    );
    const value = token(),
      id = randomUUID(),
      until = new Date(Date.now() + TRUSTED_BROWSER_MS);
    const label = (req.get("user-agent") || "Browser")
      .replace(/[\u0000-\u001f\u007f]/g, " ")
      .slice(0, 160);
    await tx.query(
      "INSERT INTO trusted_browsers (id,user_id,token_hash,ip_hash,label,expires_at) VALUES ($1,$2,$3,$4,$5,$6)",
      [id, userId, digest(value), ip, label, until],
    );
    return { id, raw: value, until };
  }
  async function list(tx, userId, req) {
    const value = raw(req);
    return (
      await tx.query(
        "SELECT id,label,created_at,last_used_at,expires_at,token_hash=$2 AS current FROM trusted_browsers WHERE user_id=$1 AND expires_at>now() ORDER BY created_at DESC",
        [userId, value ? digest(value) : ""],
      )
    ).rows;
  }
  return { find, remember, list, binding, findBound };
}
