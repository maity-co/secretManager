import { backupIntervalHours } from "../src/config.js";
import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import {
  token,
  vault,
  hashPassword,
  verifyPassword,
  canonicalPath,
  containsPath,
} from "../src/security.js";
import { parseEnv, formatEnv } from "../src/env-format.js";
test("authenticated encryption binds ciphertext to the exact record context", () => {
  const crypto = vault(randomBytes(32)),
    value = token(),
    box = crypto.seal(value, "record:1");
  assert.equal(crypto.open(box, "record:1"), value);
  assert.notEqual(box, crypto.seal(value, "record:1"));
  assert.throws(() => crypto.open(box, "record:2"));
  const parts = box.split(".");
  parts[2] = randomBytes(16).toString("base64");
  assert.throws(() => crypto.open(parts.join("."), "record:1"));
});
test("password hashing verifies without storing the original", async () => {
  const password = token(),
    hash = await hashPassword(password);
  assert.ok(!hash.includes(password));
  assert.equal(await verifyPassword(password, hash), true);
  assert.equal(await verifyPassword(token(), hash), false);
  await assert.rejects(hashPassword("short"));
});
test("folder boundaries cannot escape or match adjacent names", () => {
  assert.equal(canonicalPath("/app/"), "/app");
  assert.ok(containsPath("/app", "/app/sub"));
  assert.ok(!containsPath("/app", "/application"));
  for (const path of [
    "/app/../other",
    "//app",
    "/app/./sub",
    "relative",
    "/app//sub",
  ])
    assert.throws(() => canonicalPath(path));
});
test("dotenv round-trip preserves multiline, quotes, unicode and literal shell syntax", () => {
  const values = {
    EMPTY: "",
    MULTILINE: "first\nsecond\r\nthird",
    QUOTES: "both ' and \" and `",
    LITERAL: "${NOT_EXPANDED} $(not-executed) \\n \\path",
    UNICODE: "naïve ☀",
    HASH: "#literal",
    TABS: "\t",
  };
  assert.deepEqual({ ...parseEnv(formatEnv(values)) }, values);
  assert.equal(
    parseEnv(
      "# comment\nexport NAME='line\none' # trailing\nOTHER=plain # note\n",
    ).NAME,
    "line\none",
  );
});
test("dotenv parser rejects ambiguous, malformed and oversized imports", () => {
  for (const text of [
    "A=1\nA=2",
    "not-an-assignment",
    "BAD-KEY=value",
    'A="unclosed',
    'A="ok" trailing',
  ])
    assert.throws(() => parseEnv(text));
  assert.throws(() => parseEnv("A=" + "x".repeat(65537)));
  assert.throws(() => parseEnv("A=\0"));
});

test("backup intervals reject millisecond-scale schedules and timer overflow", () => {
  assert.equal(backupIntervalHours(undefined), 24);
  assert.equal(backupIntervalHours("0"), 0);
  assert.ok(backupIntervalHours("168") * 3600000 < 2147483647);
  for (const value of ["0.0001", "-1", "169", "8760", "NaN", "Infinity"])
    assert.throws(() => backupIntervalHours(value));
});
