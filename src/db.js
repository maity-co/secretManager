import pg from "pg";
import { readFile } from "node:fs/promises";
export function postgres(options) {
  const pool = new pg.Pool(options);
  pool.on("error", () =>
    console.error(
      "An idle database connection failed; sensitive diagnostics suppressed.",
    ),
  );
  return {
    query: (text, values) => pool.query(text, values),
    async transaction(fn) {
      for (let attempt = 0; ; attempt++) {
        const client = await pool.connect();
        try {
          await client.query("BEGIN ISOLATION LEVEL SERIALIZABLE");
          const result = await fn(client);
          await client.query("COMMIT");
          return result;
        } catch (error) {
          await client.query("ROLLBACK");
          if (error.code === "40001" && attempt < 3) continue;
          throw error;
        } finally {
          client.release();
        }
      }
    },
    close: () => pool.end(),
  };
}
export async function migrate(db) {
  const schema = await readFile(
    new URL("./schema.sql", import.meta.url),
    "utf8",
  );
  await db.transaction(async (tx) => {
    await tx.query(schema);
    const version = (
      await tx.query(
        "SELECT schema_version FROM service_state WHERE id=1 FOR UPDATE",
      )
    ).rows[0].schema_version;
    if (version > 1)
      throw new Error("Database schema is newer than this application.");
    await tx.query("UPDATE service_state SET schema_version = 1 WHERE id = 1");
  });
}
