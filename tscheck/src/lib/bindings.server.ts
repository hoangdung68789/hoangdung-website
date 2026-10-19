// @ts-nocheck
import { DatabaseSync } from "node:sqlite";
import { readFileSync } from "node:fs";
const raw = new DatabaseSync(":memory:");
raw.exec(readFileSync(process.env.MIG, "utf8"));
function stmt(sql, args = []) {
  return {
    bind: (...a) => stmt(sql, a),
    first: async () => { const r = raw.prepare(sql).get(...args); return r ?? null; },
    all: async () => ({ results: raw.prepare(sql).all(...args) }),
    run: async () => { const r = raw.prepare(sql).run(...args); return { meta: { last_row_id: Number(r.lastInsertRowid), changes: r.changes } }; },
  };
}
const DB = { prepare: (sql) => stmt(sql), batch: async (list) => { for (const s of list) await s.run(); } };
globalThis.__ENV ??= { DB };
export const ENV = globalThis.__ENV;
export function bindings() { return globalThis.__ENV; }
