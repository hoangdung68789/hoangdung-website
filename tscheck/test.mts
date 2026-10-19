import { handleApi } from "./src/server/api.server.ts";
import { ENV } from "./src/lib/bindings.server.ts";
const O = "https://x.test";
let jar: Record<string, string> = {};
async function call(path: string, body?: unknown, opt: { ip?: string; origin?: string; ct?: string } = {}) {
  const h: Record<string, string> = { "CF-Connecting-IP": opt.ip ?? "1.1.1.1" };
  if (body !== undefined) { h["Content-Type"] = opt.ct ?? "application/json"; h["Origin"] = opt.origin ?? O; }
  const ck = Object.entries(jar).map(([k, v]) => `${k}=${v}`).join("; "); if (ck) h["Cookie"] = ck;
  const req = new Request(O + "/api/" + path, { method: body !== undefined ? "POST" : "GET", headers: h, body: body !== undefined ? JSON.stringify(body) : undefined });
  const r = await handleApi(req, path.split("?")[0]);
  for (const c of r.headers.getSetCookie()) { const [kv] = c.split(";"); const [k, v] = kv.split("="); if (v) jar[k] = v; else delete jar[k]; }
  let j: any = null; try { j = await r.clone().json(); } catch {}
  return { s: r.status, j, r };
}
const ok = (c: boolean, m: string) => { console.log((c ? "PASS " : "FAIL ") + m); if (!c) process.exitCode = 1; };
let r;
r = await call("health"); ok(r.s === 200 && r.j.db, "health");
r = await call("auth/me"); ok(r.j.user === null, "me anon");
r = await call("auth/register", { name: "Nguyễn Văn A", phone: "0901 234 567", email: "A@Gmail.com", pass: "short", role: "Khách mua / thuê nhà" }); ok(r.s === 400, "weak pass rejected: " + r.j.error);
r = await call("auth/register", { name: "Nguyễn Văn A", phone: "0901 234 567", email: "A@Gmail.com", pass: "matkhau123", role: "Khách mua / thuê nhà", agree: true }); ok(r.s === 201 && r.j.user.email === "a@gmail.com" && jar.hd_sid, "register + session");
r = await call("auth/me"); ok(r.j.user?.name === "Nguyễn Văn A", "me after register");
r = await call("auth/register", { name: "B", phone: "0901234567", email: "a@gmail.com", pass: "matkhau123" }); ok(r.s === 400 || r.s === 409, "dup email/name check " + r.s);
r = await call("auth/register", { name: "Bình", phone: "0901234567", email: "b@gmail.com", pass: "matkhau123" }); ok(r.s === 409, "dup phone: " + r.j.error);
r = await call("favs", { ids: [3, 5, 5, -1, "x"] }); ok(r.j.ids.join() === "3,5", "favs save");
r = await call("favs"); ok(r.j.ids.join() === "3,5", "favs read");
r = await call("auth/logout", {}); ok(!jar.hd_sid, "logout clears cookie");
r = await call("favs"); ok(r.s === 401, "favs needs login");
r = await call("auth/login", { id: "0901.234.567", pass: "sai-mat-khau" }); ok(r.s === 401, "wrong pass");
r = await call("auth/login", { id: "+84901234567", pass: "matkhau123", remember: false }); ok(r.s === 200 && jar.hd_sid, "login by +84 phone");
const sc = r.r.headers.getSetCookie()[0]; ok(!/Max-Age/.test(sc) && /HttpOnly/.test(sc) && /Secure/.test(sc), "session cookie flags (no remember)");
r = await call("auth/password", { old: "matkhau123", pass: "matkhaumoi456" }); ok(r.s === 200, "change password");
r = await call("auth/login", { id: "a@gmail.com", pass: "matkhaumoi456" }); ok(r.s === 200, "login new pass");
// CSRF / content-type
r = await call("auth/login", { id: "a@gmail.com", pass: "x" }, { origin: "https://evil.test" }); ok(r.s === 403, "cross-origin blocked");
r = await call("auth/login", { id: "a@gmail.com", pass: "x" }, { ct: "text/plain" }); ok(r.s === 415, "non-json blocked");
// forgot (no mail) -> admin
r = await call("auth/forgot", { email: "a@gmail.com", phone: "0901234567" }); ok(r.j.mode === "admin", "forgot -> admin mode");
r = await call("auth/forgot", { email: "khongco@gmail.com" }); ok(r.j.mode === "admin", "forgot unknown same answer");
// leads
r = await call("leads", { form: "contact", kind: "Yêu cầu tư vấn", fields: { name: "Trần C", phone: "0912345678", msg: "Mua nhà 7 tỷ" }, text: "[Yêu cầu tư vấn]\nHọ tên: Trần C" }); ok(r.s === 201, "lead saved");
r = await call("leads", { form: "contact", fields: { name: "X", phone: "12" } }); ok(r.s === 400, "lead invalid");
// rate limit login
jar = {}; let last = 0; for (let i = 0; i < 10; i++) { last = (await call("auth/login", { id: "z@z.vn", pass: "nope" }, { ip: "9.9.9.9" })).s; } ok(last === 429, "login rate limit -> " + last);
// admin
jar = {};
r = await call("admin/state"); ok(r.j.setup === true && r.j.admin === null, "admin needs setup");
r = await call("admin/stats"); ok(r.s === 401, "admin stats protected");
r = await call("admin/setup", { code: "sai", email: "ad@x.vn", name: "Admin", pass: "matkhauadmin1" }); ok(r.s === 403, "bad setup code");
const CODE = process.env.CODE!;
r = await call("admin/setup", { code: CODE, email: "ad@x.vn", name: "Quản trị", pass: "matkhauadmin1" }); ok(r.s === 201, "setup ok");
r = await call("admin/setup", { code: CODE, email: "ad2@x.vn", name: "Quản trị 2", pass: "matkhauadmin1" }); ok(r.s === 403, "setup closed after first admin");
r = await call("admin/login", { email: "a@gmail.com", pass: "matkhaumoi456" }); ok(r.s === 401, "customer cannot login admin");
r = await call("admin/login", { email: "ad@x.vn", pass: "matkhauadmin1" }); ok(r.s === 200 && jar.hd_adm, "admin login");
r = await call("admin/stats"); ok(r.j.users === 1 && r.j.leadsNew === 1 && r.j.resets === 1, "stats " + JSON.stringify(r.j));
r = await call("admin/users?q=Văn"); ok(r.j.total === 1, "user search");
r = await call("admin/users?q=%25"); ok(r.j.total === 0, "LIKE wildcard escaped");
r = await call("admin/leads?status=new"); ok(r.j.rows.length === 1, "leads list"); const lid = r.j.rows[0].id;
r = await call("admin/lead", { id: lid, status: "contacted", note: "Đã gọi" }); r = await call("admin/leads?status=contacted"); ok(r.j.rows[0]?.note === "Đã gọi", "lead update");
r = await call("admin/resets"); ok(r.j.rows.length === 1 && r.j.rows[0].user_name, "resets list");
r = await call("admin/user", { id: 1, action: "temp-password" }); ok(r.j.temp?.length === 10, "temp password");
const temp = r.j.temp;
r = await call("admin/resets"); ok(r.j.rows.length === 0, "reset closed by temp password");
r = await call("admin/user", { id: 1, action: "disable" });
const adm = jar.hd_adm; delete jar.hd_adm;
r = await call("auth/login", { id: "a@gmail.com", pass: temp }, { ip: "2.2.2.2" }); ok(r.s === 403, "disabled user blocked");
jar.hd_adm = adm; await call("admin/user", { id: 1, action: "enable" }); delete jar.hd_adm;
r = await call("auth/login", { id: "a@gmail.com", pass: temp }, { ip: "2.2.2.2" }); ok(r.s === 200, "temp password login");
jar.hd_adm = adm;
r = await call("admin/export?what=leads"); const csv = await r.r.text(); console.log(r.s, JSON.stringify(csv.slice(0,300))); ok(csv.startsWith("﻿") && csv.includes("Trần C"), "csv export");
r = await call("admin/admins", { email: "ad2@x.vn", name: "Người 2", pass: "matkhauadmin2" }); ok(r.s === 201, "add admin");
r = await call("admin/password", { old: "matkhauadmin1", pass: "matkhauadminmoi" }); ok(r.s === 200, "admin change pw");
r = await call("admin/logout", {}); r = await call("admin/stats"); ok(r.s === 401, "admin logout");
// reset token flow (simulate mail configured)
(ENV as any).RESEND_API_KEY = "test"; (ENV as any).MAIL_FROM = "x@y.vn";
const realFetch = globalThis.fetch; let mailed = ""; (globalThis as any).fetch = async (u: string, o: any) => { mailed = JSON.parse(o.body).html; return new Response("{}", { status: 200 }); };
r = await call("auth/forgot", { email: "a@gmail.com" }, { ip: "3.3.3.3" }); console.log(r.s, r.j, mailed.slice(0,100)); ok(r.j.mode === "sent" && mailed.includes("#reset="), "reset email sent");
const tok = decodeURIComponent(mailed.match(/#reset=([^"&<]+)/)![1]);
r = await call("auth/reset", { token: tok, pass: "matkhausaureset" }, { ip: "3.3.3.3" }); ok(r.s === 200, "reset with token");
r = await call("auth/reset", { token: tok, pass: "matkhausaureset" }, { ip: "3.3.3.3" }); ok(r.s === 400, "token single-use");
r = await call("auth/login", { id: "a@gmail.com", pass: "matkhausaureset" }, { ip: "3.3.3.3" }); ok(r.s === 200, "login after reset");
r = await call("auth/register", { name: "Lê D", phone: "0933333333", email: "d@gmail.com", pass: "matkhau123" }, { ip: "4.4.4.4" }); ok(r.j.verifySent === true, "verify mail sent");
const vt = mailed.match(/verify\?t=([^"&<]+)/)![1];
r = await call("auth/verify?t=" + vt); ok(r.s === 302 && r.r.headers.get("Location")!.endsWith("#verified"), "verify link");
globalThis.fetch = realFetch;
r = await call("nope"); ok(r.s === 404, "404");
