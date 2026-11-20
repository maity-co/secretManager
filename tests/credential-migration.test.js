import test from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { PGlite } from "@electric-sql/pglite";
import { migrate, postgres } from "../src/db.js";
import { digest, token } from "../src/security.js";

async function database() {
  if (process.env.TEST_DATABASE_URL) {
    const url = new URL(process.env.TEST_DATABASE_URL);
    if (
      !["localhost", "127.0.0.1"].includes(url.hostname) ||
      !url.pathname.startsWith("/secretmanager_test")
    )
      throw new Error("Tests require a loopback test database.");
    const admin = postgres({ connectionString: url.href });
    const schema = "credentials_" + randomUUID().replaceAll("-", "");
    await admin.query(`CREATE SCHEMA "${schema}"`);
    const db = postgres({
      connectionString: url.href,
      options: `-c search_path=${schema}`,
    });
    return {
      ...db,
      async close() {
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
    query: async (sql, values) =>
      values === undefined && sql.includes(";")
        ? (await tx.exec(sql)).at(-1) || { rows: [] }
        : tx.query(sql, values),
  });
  return {
    ...wrap(pg),
    transaction: (fn) => pg.transaction((tx) => fn(wrap(tx))),
    close: () => pg.close(),
  };
}

test("schema 3 credentials retain exact expiry, hashes and revocation during migration", async () => {
  const db = await database();
  try {
    await migrate(db);
    // Recreate the schema-3 constraint before inserting the legacy fixtures.
    await db.query(
      "ALTER TABLE machine_credentials ALTER COLUMN expires_at SET NOT NULL",
    );
    await db.query("UPDATE service_state SET schema_version=3");
    const project = randomUUID();
    const machine = randomUUID();
    await db.query("INSERT INTO projects (id,name) VALUES ($1,$2)", [
      project,
      "Credential migration fixture",
    ]);
    await db.query(
      "INSERT INTO machines (id,project_id,name) VALUES ($1,$2,$3)",
      [machine, project, "Migration machine"],
    );
    for (const revoked of [false, true])
      await db.query(
        "INSERT INTO machine_credentials (id,machine_id,secret_hash,expires_at,revoked) VALUES ($1,$2,$3,$4,$5)",
        [
          randomUUID(),
          machine,
          digest(token()),
          "2032-02-03T04:05:06.000Z",
          revoked,
        ],
      );
    const before = (
      await db.query("SELECT * FROM machine_credentials ORDER BY id")
    ).rows;
    await migrate(db);
    await migrate(db);
    assert.equal(
      (await db.query("SELECT schema_version FROM service_state")).rows[0]
        .schema_version,
      4,
    );
    assert.deepEqual(
      (await db.query("SELECT * FROM machine_credentials ORDER BY id")).rows,
      before,
    );
    const id = randomUUID();
    await db.query(
      "INSERT INTO machine_credentials (id,machine_id,secret_hash,expires_at) VALUES ($1,$2,$3,NULL)",
      [id, machine, digest(token())],
    );
    assert.equal(
      (
        await db.query(
          "SELECT expires_at FROM machine_credentials WHERE id=$1",
          [id],
        )
      ).rows[0].expires_at,
      null,
    );
  } finally {
    await db.close();
  }
});
