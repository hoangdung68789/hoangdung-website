import http from "node:http";
import { readFileSync, existsSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { handleApi } from "../cf/src/api.ts";
const raw = new DatabaseSync(":memory:");
function stmt(sql: string, args: unknown[] = []): any {
  return {
    bind: (...a: unknown[]) => stmt(sql, a),
    first: async () => (raw.prepare(sql).get(...(args as any[])) ?? null),
    all: async () => ({ results: raw.prepare(sql).all(...(args as any[])) }),
    run: async () => { const r = raw.prepare(sql).run(...(args as any[])); return { meta: { last_row_id: Number(r.lastInsertRowid), changes: r.changes } }; },
  };
}
const DB = { prepare: (sql: string) => stmt(sql), batch: async (l: any[]) => { for (const s of l) await s.run(); } };
const MODE = process.env.PROV || "both";
const ENV: any = { DB, PW_ITER: "100000" };
if (MODE === "both" || MODE === "sms") Object.assign(ENV, { TWILIO_ACCOUNT_SID: "AC_test", TWILIO_AUTH_TOKEN: "tok", TWILIO_VERIFY_SID: "VA_test" });
if (MODE === "both" || MODE === "mail") Object.assign(ENV, { BREVO_API_KEY: "xkeysib-test", MAIL_FROM: "Hoàng Dũng Real Estate <no-reply@test.vn>" });
if (MODE === "both") Object.assign(ENV, { GOOGLE_CLIENT_ID: "gid.apps", GOOGLE_CLIENT_SECRET: "gsec", FACEBOOK_APP_ID: "fbid", FACEBOOK_APP_SECRET: "fbsec" });
// giả lập Twilio Verify & Brevo
const codes: Record<string, string> = {}; const smsCodes: Record<string, string> = {};
const realFetch = globalThis.fetch;
(globalThis as any).fetch = async (u: string, o: any) => {
  if (String(u).includes("verify.twilio.com")) {
    const f = new URLSearchParams(o.body); const to = f.get("To")!;
    if (String(u).endsWith("/Verifications")) { smsCodes[to] = "246810"; codes[to] = "246810"; return new Response(JSON.stringify({ status: "pending" }), { status: 201 }); }
    return new Response(JSON.stringify({ status: f.get("Code") === smsCodes[to] ? "approved" : "pending" }), { status: 200 });
  }
  if (String(u).startsWith("https://oauth2.googleapis.com/token")) {
    const code = new URLSearchParams(o.body).get("code")!; const info = JSON.parse(Buffer.from(code, "base64url").toString());
    const payload = Buffer.from(JSON.stringify({ aud: "gid.apps", iss: "https://accounts.google.com", ...info })).toString("base64url");
    return new Response(JSON.stringify({ id_token: "h." + payload + ".s" }), { status: 200 });
  }
  if (String(u).startsWith("https://graph.facebook.com/oauth/access_token")) { const code = new URL(String(u)).searchParams.get("code"); return new Response(JSON.stringify({ access_token: code }), { status: 200 }); }
  if (String(u).startsWith("https://graph.facebook.com/me")) { const t = new URL(String(u)).searchParams.get("access_token")!; return new Response(Buffer.from(t, "base64url").toString(), { status: 200 }); }
  if (String(u).includes("api.brevo.com")) { const b = JSON.parse(o.body); const m = b.subject.match(/^(\d{6})/); if (m) codes[b.to[0].email] = m[1]; return new Response("{}", { status: 201 }); }
  return realFetch(u, o);
};
const P = "../cf/public";
const types: Record<string, string> = { webp: "image/webp", jpg: "image/jpeg", svg: "image/svg+xml", html: "text/html; charset=utf-8" };
http.createServer(async (req, res) => {
  const url = new URL(req.url!, "http://localhost:8788");
  const chunks: Buffer[] = []; for await (const c of req) chunks.push(c as Buffer);
  let r: Response;
  if (url.pathname === "/__test/codes") r = Response.json(codes);
  else if (url.pathname.startsWith("/api/")) {
    const h = new Headers(); for (const [k, v] of Object.entries(req.headers)) if (typeof v === "string") h.set(k, v);
    h.set("CF-Connecting-IP", "127.0.0.1");
    r = await handleApi(new Request(url, { method: req.method, headers: h, body: chunks.length ? Buffer.concat(chunks) : undefined }), url.pathname.slice(5), ENV);
  } else {
    let f = url.pathname === "/" ? "/index.html" : url.pathname === "/admin" ? "/admin.html" : url.pathname;
    if (!f.includes(".", f.lastIndexOf("/")) && existsSync(P + f + ".html")) f += ".html";
    if (existsSync(P + f)) { let body: any = readFileSync(P + f); if (f.endsWith(".html")) body = body.toString().replaceAll("__SITE__", url.origin); r = new Response(body, { headers: { "Content-Type": types[f.split(".").pop()!] || "application/octet-stream" } }); }
    else r = new Response("not found", { status: 404 });
  }
  const hdr: Record<string, string | string[]> = {}; r.headers.forEach((v, k) => { if (k !== "set-cookie") hdr[k] = v; });
  const sc = r.headers.getSetCookie(); if (sc.length) hdr["set-cookie"] = sc;
  res.writeHead(r.status, hdr); res.end(Buffer.from(await r.arrayBuffer()));
}).listen(8788, () => console.log("listening 8788 mode", MODE));
