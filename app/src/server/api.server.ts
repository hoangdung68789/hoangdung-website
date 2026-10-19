/**
 * Hoàng Dũng Real Estate — máy chủ API (Cloudflare Worker + D1)
 *
 * Khách hàng:  /api/auth/*  (đăng ký, đăng nhập, quên mật khẩu, xác minh email), /api/favs, /api/leads
 * Quản trị:    /api/admin/* (đăng nhập riêng, bảng tài khoản quản trị riêng — tách biệt hoàn toàn với khách)
 *
 * Bảo mật:
 * - Mật khẩu băm PBKDF2-SHA256 (100.000 vòng, muối ngẫu nhiên) — không lưu, không đọc lại được.
 * - Phiên đăng nhập: mã ngẫu nhiên 256-bit trong cookie HttpOnly + Secure; CSDL chỉ lưu bản băm SHA-256.
 * - Chống CSRF: chỉ nhận POST dạng JSON từ đúng nguồn (Origin); cookie SameSite.
 * - Giới hạn số lần thử (đăng nhập, quên mật khẩu, gửi form) theo IP và theo tài khoản.
 * - Email (xác minh, đặt lại mật khẩu) gửi qua Resend khi chủ web cấu hình RESEND_API_KEY + MAIL_FROM
 *   trong phần cài đặt website. Chưa cấu hình → yêu cầu quên mật khẩu chuyển cho quản trị viên xử lý.
 */
import { bindings } from "../lib/bindings.server";

type Row = Record<string, unknown>;
type DB = {
  prepare(sql: string): {
    bind(...v: unknown[]): {
      first<T = Row>(): Promise<T | null>;
      all<T = Row>(): Promise<{ results: T[] }>;
      run(): Promise<{ meta?: { last_row_id?: number; changes?: number } }>;
    };
  };
  batch(stmts: unknown[]): Promise<unknown>;
};
type Env = {
  DB?: DB;
  RESEND_API_KEY?: string;
  MAIL_FROM?: string;
  NOTIFY_EMAIL?: string;
};

/* Mã khởi tạo quản trị viên đầu tiên — chỉ lưu bản băm; vô hiệu ngay khi đã có quản trị viên. */
const SETUP_HASH = "554fbafa51f7fcbcc3707d4b9881bf1c0470b5283c39127472f27a75f7bb6b62";

const USER_COOKIE = "hd_sid";
const ADMIN_COOKIE = "hd_adm";
const DAY = 86_400_000;
const ROLES = ["Khách mua / thuê nhà", "Chủ nhà cần bán / cho thuê", "Môi giới / đối tác"];
const HOTLINE = "087.778.1796";

const enc = new TextEncoder();
const hex = (b: ArrayBuffer | Uint8Array) =>
  [...new Uint8Array(b as ArrayBuffer)].map((x) => x.toString(16).padStart(2, "0")).join("");
const fromHex = (h: string) => new Uint8Array((h.match(/../g) ?? []).map((x) => parseInt(x, 16)));
const now = () => Date.now();

function env(): Env {
  return bindings() as unknown as Env;
}
function db(): DB {
  const d = env().DB;
  if (!d) throw new HttpError(503, "Hệ thống dữ liệu chưa sẵn sàng. Vui lòng thử lại sau.");
  return d;
}
class HttpError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

/* ---------------- tiện ích bảo mật ---------------- */
function randomToken(bytes = 32): string {
  const a = crypto.getRandomValues(new Uint8Array(bytes));
  let s = "";
  for (const x of a) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function tempPassword(): string {
  const al = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";
  const a = crypto.getRandomValues(new Uint8Array(10));
  return [...a].map((x) => al[x % al.length]).join("");
}
async function sha256(t: string): Promise<string> {
  return hex(await crypto.subtle.digest("SHA-256", enc.encode(t)));
}
async function hashPass(pass: string, saltHex?: string) {
  const salt = saltHex ?? hex(crypto.getRandomValues(new Uint8Array(16)));
  const key = await crypto.subtle.importKey("raw", enc.encode(pass), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: fromHex(salt), iterations: 100_000 },
    key,
    256,
  );
  return { salt, hash: hex(bits) };
}
function safeEq(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
async function checkPass(pass: string, salt: string, hash: string) {
  return safeEq((await hashPass(pass, salt)).hash, hash);
}

/* ---------------- kiểm tra dữ liệu vào ---------------- */
const str = (v: unknown, max = 200) => (typeof v === "string" ? v.trim().slice(0, max) : "");
const isEmail = (e: string) => /^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,}$/.test(e) && e.length <= 160;
function normPhone(p: string): string {
  let d = p.replace(/[^\d+]/g, "");
  if (d.startsWith("+84")) d = "0" + d.slice(3);
  else if (d.startsWith("84") && d.length === 11) d = "0" + d.slice(2);
  return d.replace(/\D/g, "");
}
const isPhone = (p: string) => /^0\d{9,10}$/.test(p);

/* ---------------- HTTP ---------------- */
function json(data: unknown, status = 200, cookies: string[] = []): Response {
  const h = new Headers({ "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" });
  for (const c of cookies) h.append("Set-Cookie", c);
  return new Response(JSON.stringify(data), { status, headers: h });
}
function getCookie(req: Request, name: string): string {
  const c = req.headers.get("Cookie") ?? "";
  for (const part of c.split(";")) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i).trim() === name) return decodeURIComponent(part.slice(i + 1).trim());
  }
  return "";
}
function cookie(name: string, value: string, maxAgeSec: number | null, sameSite: "Lax" | "Strict" = "Lax") {
  return `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; Secure; SameSite=${sameSite}${
    maxAgeSec === null ? "" : `; Max-Age=${maxAgeSec}`
  }`;
}
const clientIp = (req: Request) => req.headers.get("CF-Connecting-IP") ?? "0.0.0.0";

async function readBody(req: Request): Promise<Row> {
  const ct = req.headers.get("Content-Type") ?? "";
  if (!ct.includes("application/json")) throw new HttpError(415, "Yêu cầu không hợp lệ.");
  const origin = req.headers.get("Origin");
  if (origin && origin !== new URL(req.url).origin) throw new HttpError(403, "Nguồn yêu cầu không hợp lệ.");
  const len = Number(req.headers.get("Content-Length") ?? 0);
  if (len > 64_000) throw new HttpError(413, "Dữ liệu gửi lên quá lớn.");
  const t = await req.text();
  if (t.length > 64_000) throw new HttpError(413, "Dữ liệu gửi lên quá lớn.");
  try {
    const v = JSON.parse(t || "{}");
    if (!v || typeof v !== "object" || Array.isArray(v)) throw 0;
    return v as Row;
  } catch {
    throw new HttpError(400, "Dữ liệu gửi lên không đúng định dạng.");
  }
}

/* Giới hạn tần suất: tối đa `max` lần trong `win` mili-giây cho mỗi khoá. */
async function limit(key: string, max: number, win: number) {
  const d = db();
  const t = now();
  const r = await d.prepare("SELECT COUNT(*) AS n FROM attempts WHERE key = ? AND at > ?").bind(key, t - win).first<{ n: number }>();
  if ((r?.n ?? 0) >= max) throw new HttpError(429, "Bạn thao tác quá nhiều lần. Vui lòng đợi ít phút rồi thử lại.");
  await d.prepare("INSERT INTO attempts (key, at) VALUES (?, ?)").bind(key, t).run();
  if (crypto.getRandomValues(new Uint8Array(1))[0] < 4) {
    await d.prepare("DELETE FROM attempts WHERE at < ?").bind(t - 2 * DAY).run();
  }
}

/* ---------------- email ---------------- */
function mailReady() {
  const e = env();
  return !!(e.RESEND_API_KEY && e.MAIL_FROM);
}
async function sendMail(to: string, subject: string, html: string): Promise<boolean> {
  const e = env();
  if (!e.RESEND_API_KEY || !e.MAIL_FROM) return false;
  try {
    const r = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: `Bearer ${e.RESEND_API_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({ from: e.MAIL_FROM, to: [to], subject, html }),
    });
    return r.ok;
  } catch {
    return false;
  }
}
const escHtml = (s: string) =>
  s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] as string);
function mailLayout(title: string, body: string, cta?: { href: string; label: string }) {
  return `<!doctype html><html lang="vi"><body style="margin:0;background:#f2f0ec;font-family:Arial,Helvetica,sans-serif;color:#121417">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="padding:28px 12px"><tr><td align="center">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:520px;background:#ffffff;border-radius:14px;overflow:hidden">
<tr><td style="background:#0c0d0f;padding:22px 28px;color:#f2f3f4;font-size:18px;font-weight:bold">Hoàng Dũng <span style="color:#e9a27a;font-size:11px;letter-spacing:2px">REAL ESTATE</span></td></tr>
<tr><td style="padding:28px">
<h2 style="margin:0 0 12px;font-size:20px">${title}</h2>
<div style="font-size:15px;line-height:1.6;color:#3b4048">${body}</div>
${cta ? `<p style="margin:26px 0"><a href="${cta.href}" style="background:#121417;color:#ffffff;text-decoration:none;padding:13px 22px;border-radius:999px;font-size:15px;display:inline-block">${cta.label}</a></p>
<p style="font-size:12px;color:#8a9099;word-break:break-all">Nếu nút không bấm được, hãy mở đường dẫn: ${cta.href}</p>` : ""}
</td></tr>
<tr><td style="padding:18px 28px;border-top:1px solid #eee;font-size:12px;color:#8a9099">Hoàng Dũng Real Estate · Kiến tạo mái ấm gia đình Việt<br>Hotline ${HOTLINE} · 37 Lê Thúc Hoạch, Phú Thọ Hoà, Tân Phú</td></tr>
</table></td></tr></table></body></html>`;
}

/* ---------------- phiên đăng nhập ---------------- */
type User = {
  id: number; email: string; phone: string; name: string; role: string;
  email_verified: number; status: string; created_at: number;
};
type Admin = { id: number; email: string; name: string };
const publicUser = (u: User) => ({
  id: u.id, name: u.name, email: u.email, phone: u.phone, role: u.role, verified: !!u.email_verified,
});

async function newSession(kind: "user" | "admin", id: number, ttl: number) {
  const tok = randomToken();
  const t = now();
  await db()
    .prepare("INSERT INTO sessions (token_hash, kind, subject_id, expires_at, created_at) VALUES (?, ?, ?, ?, ?)")
    .bind(await sha256(tok), kind, id, t + ttl, t)
    .run();
  return tok;
}
async function sessionSubject(req: Request, kind: "user" | "admin"): Promise<number | null> {
  const tok = getCookie(req, kind === "user" ? USER_COOKIE : ADMIN_COOKIE);
  if (!tok || tok.length > 100) return null;
  const r = await db()
    .prepare("SELECT subject_id FROM sessions WHERE token_hash = ? AND kind = ? AND expires_at > ?")
    .bind(await sha256(tok), kind, now())
    .first<{ subject_id: number }>();
  return r?.subject_id ?? null;
}
async function currentUser(req: Request): Promise<User | null> {
  const id = await sessionSubject(req, "user");
  if (!id) return null;
  const u = await db().prepare("SELECT * FROM users WHERE id = ?").bind(id).first<User>();
  return u && u.status === "active" ? u : null;
}
async function requireUser(req: Request): Promise<User> {
  const u = await currentUser(req);
  if (!u) throw new HttpError(401, "Phiên đăng nhập đã hết hạn. Vui lòng đăng nhập lại.");
  return u;
}
async function requireAdmin(req: Request): Promise<Admin> {
  const id = await sessionSubject(req, "admin");
  if (!id) throw new HttpError(401, "Vui lòng đăng nhập quản trị.");
  const a = await db().prepare("SELECT id, email, name FROM admins WHERE id = ?").bind(id).first<Admin>();
  if (!a) throw new HttpError(401, "Vui lòng đăng nhập quản trị.");
  return a;
}
async function dropSession(req: Request, kind: "user" | "admin") {
  const tok = getCookie(req, kind === "user" ? USER_COOKIE : ADMIN_COOKIE);
  if (tok) await db().prepare("DELETE FROM sessions WHERE token_hash = ?").bind(await sha256(tok)).run();
}
async function userToken(userId: number, purpose: "reset" | "verify", ttl: number) {
  const tok = randomToken();
  await db()
    .prepare("INSERT INTO tokens (token_hash, user_id, purpose, expires_at) VALUES (?, ?, ?, ?)")
    .bind(await sha256(tok), userId, purpose, now() + ttl)
    .run();
  return tok;
}
async function sendVerify(req: Request, u: { id: number; email: string; name: string }) {
  if (!mailReady()) return false;
  const tok = await userToken(u.id, "verify", 3 * DAY);
  const link = `${new URL(req.url).origin}/api/auth/verify?t=${encodeURIComponent(tok)}`;
  return sendMail(
    u.email,
    "Xác minh email – Hoàng Dũng Real Estate",
    mailLayout(
      `Chào ${escHtml(u.name)},`,
      "Cảm ơn bạn đã tạo tài khoản tại Hoàng Dũng Real Estate. Bấm nút bên dưới để xác minh địa chỉ email (hiệu lực 3 ngày).",
      { href: link, label: "Xác minh email" },
    ),
  );
}

/* ================= KHÁCH HÀNG ================= */
async function register(req: Request) {
  const b = await readBody(req);
  const name = str(b.name, 80), email = str(b.email, 160).toLowerCase(), phone = normPhone(str(b.phone, 20));
  const pass = typeof b.pass === "string" ? b.pass : "";
  const role = ROLES.includes(str(b.role, 60)) ? str(b.role, 60) : "";
  if (name.length < 2) throw new HttpError(400, "Vui lòng nhập họ và tên.");
  if (!isEmail(email)) throw new HttpError(400, "Vui lòng nhập địa chỉ email hợp lệ, ví dụ ten@gmail.com.");
  if (!isPhone(phone)) throw new HttpError(400, "Số điện thoại chưa đúng, ví dụ 0901 234 567.");
  if (pass.length < 8 || pass.length > 128) throw new HttpError(400, "Mật khẩu cần từ 8 đến 128 ký tự.");
  await limit(`reg:${clientIp(req)}`, 8, 3_600_000);
  const d = db();
  if (await d.prepare("SELECT id FROM users WHERE email = ?").bind(email).first())
    throw new HttpError(409, "Email này đã có tài khoản. Hãy đăng nhập hoặc dùng “Quên mật khẩu”.");
  if (await d.prepare("SELECT id FROM users WHERE phone = ?").bind(phone).first())
    throw new HttpError(409, "Số điện thoại này đã được dùng cho một tài khoản khác.");
  const { salt, hash } = await hashPass(pass);
  const t = now();
  const r = await d
    .prepare(
      "INSERT INTO users (email, phone, name, role, pass_hash, pass_salt, marketing, created_at, last_login) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(email, phone, name, role, hash, salt, b.agree ? 1 : 0, t, t)
    .run();
  const id = Number(r.meta?.last_row_id);
  const tok = await newSession("user", id, 30 * DAY);
  const verifySent = await sendVerify(req, { id, email, name });
  const u = (await d.prepare("SELECT * FROM users WHERE id = ?").bind(id).first<User>()) as User;
  return json({ user: publicUser(u), verifySent }, 201, [cookie(USER_COOKIE, tok, 30 * 86400)]);
}

async function login(req: Request) {
  const b = await readBody(req);
  const id = str(b.id, 160), pass = typeof b.pass === "string" ? b.pass.slice(0, 128) : "";
  if (!id || !pass) throw new HttpError(400, "Vui lòng nhập email (hoặc số điện thoại) và mật khẩu.");
  const ip = clientIp(req);
  await limit(`login:${ip}`, 12, 900_000);
  const key = id.includes("@") ? id.toLowerCase() : normPhone(id);
  await limit(`login:${key}`, 8, 900_000);
  const u = await db()
    .prepare(id.includes("@") ? "SELECT * FROM users WHERE email = ?" : "SELECT * FROM users WHERE phone = ?")
    .bind(key)
    .first<User & { pass_hash: string; pass_salt: string }>();
  if (!u || !(await checkPass(pass, u.pass_salt, u.pass_hash)))
    throw new HttpError(401, "Email/số điện thoại hoặc mật khẩu chưa đúng.");
  if (u.status !== "active") throw new HttpError(403, `Tài khoản đang tạm khoá. Vui lòng liên hệ ${HOTLINE}.`);
  await db().prepare("UPDATE users SET last_login = ? WHERE id = ?").bind(now(), u.id).run();
  const remember = b.remember !== false;
  const tok = await newSession("user", u.id, remember ? 30 * DAY : DAY);
  return json({ user: publicUser(u) }, 200, [cookie(USER_COOKIE, tok, remember ? 30 * 86400 : null)]);
}

async function forgot(req: Request) {
  const b = await readBody(req);
  const email = str(b.email, 160).toLowerCase(), phone = normPhone(str(b.phone, 20));
  if (!isEmail(email)) throw new HttpError(400, "Vui lòng nhập địa chỉ email hợp lệ.");
  await limit(`forgot:${clientIp(req)}`, 6, 3_600_000);
  await limit(`forgot:${email}`, 3, 3_600_000);
  const u = await db().prepare("SELECT * FROM users WHERE email = ?").bind(email).first<User>();
  if (mailReady()) {
    if (u && u.status === "active") {
      const tok = await userToken(u.id, "reset", 3_600_000);
      const link = `${new URL(req.url).origin}/#reset=${encodeURIComponent(tok)}`;
      await sendMail(
        u.email,
        "Đặt lại mật khẩu – Hoàng Dũng Real Estate",
        mailLayout(
          `Chào ${escHtml(u.name)},`,
          "Chúng tôi nhận được yêu cầu đặt lại mật khẩu cho tài khoản của bạn. Bấm nút bên dưới để tạo mật khẩu mới (hiệu lực 60 phút). Nếu bạn không yêu cầu, hãy bỏ qua email này.",
          { href: link, label: "Đặt lại mật khẩu" },
        ),
      );
    }
    return json({ mode: "sent" });
  }
  // Chưa bật gửi email → chuyển yêu cầu cho quản trị viên (không tiết lộ email có tồn tại hay không)
  if (u) {
    const dup = await db()
      .prepare("SELECT id FROM reset_requests WHERE user_id = ? AND status = 'pending' AND created_at > ?")
      .bind(u.id, now() - DAY)
      .first();
    if (!dup)
      await db()
        .prepare("INSERT INTO reset_requests (user_id, email, phone, created_at) VALUES (?, ?, ?, ?)")
        .bind(u.id, email, phone || u.phone, now())
        .run();
  }
  return json({ mode: "admin" });
}

async function reset(req: Request) {
  const b = await readBody(req);
  const tok = str(b.token, 100), pass = typeof b.pass === "string" ? b.pass : "";
  if (pass.length < 8 || pass.length > 128) throw new HttpError(400, "Mật khẩu mới cần từ 8 đến 128 ký tự.");
  await limit(`resetpw:${clientIp(req)}`, 10, 3_600_000);
  const th = await sha256(tok);
  const t = await db()
    .prepare("SELECT user_id FROM tokens WHERE token_hash = ? AND purpose = 'reset' AND used_at IS NULL AND expires_at > ?")
    .bind(th, now())
    .first<{ user_id: number }>();
  if (!tok || !t) throw new HttpError(400, "Đường dẫn đặt lại mật khẩu đã hết hạn hoặc đã được dùng. Vui lòng yêu cầu lại.");
  const { salt, hash } = await hashPass(pass);
  await db().batch([
    db().prepare("UPDATE users SET pass_hash = ?, pass_salt = ?, email_verified = 1 WHERE id = ?").bind(hash, salt, t.user_id),
    db().prepare("UPDATE tokens SET used_at = ? WHERE token_hash = ?").bind(now(), th),
    db().prepare("DELETE FROM sessions WHERE kind = 'user' AND subject_id = ?").bind(t.user_id),
  ]);
  return json({ ok: true });
}

async function verify(req: Request) {
  const tok = new URL(req.url).searchParams.get("t") ?? "";
  const origin = new URL(req.url).origin;
  const th = await sha256(tok);
  const t = tok
    ? await db()
        .prepare("SELECT user_id FROM tokens WHERE token_hash = ? AND purpose = 'verify' AND used_at IS NULL AND expires_at > ?")
        .bind(th, now())
        .first<{ user_id: number }>()
    : null;
  if (!t) return Response.redirect(`${origin}/#verify-failed`, 302);
  await db().batch([
    db().prepare("UPDATE users SET email_verified = 1 WHERE id = ?").bind(t.user_id),
    db().prepare("UPDATE tokens SET used_at = ? WHERE token_hash = ?").bind(now(), th),
  ]);
  return Response.redirect(`${origin}/#verified`, 302);
}

async function changePassword(req: Request) {
  const u = await requireUser(req);
  const b = await readBody(req);
  const old = typeof b.old === "string" ? b.old : "", pass = typeof b.pass === "string" ? b.pass : "";
  if (pass.length < 8 || pass.length > 128) throw new HttpError(400, "Mật khẩu mới cần từ 8 đến 128 ký tự.");
  await limit(`chpw:${u.id}`, 8, 900_000);
  const row = await db().prepare("SELECT pass_hash, pass_salt FROM users WHERE id = ?").bind(u.id).first<{ pass_hash: string; pass_salt: string }>();
  if (!row || !(await checkPass(old, row.pass_salt, row.pass_hash))) throw new HttpError(400, "Mật khẩu hiện tại chưa đúng.");
  const { salt, hash } = await hashPass(pass);
  await db().prepare("UPDATE users SET pass_hash = ?, pass_salt = ? WHERE id = ?").bind(hash, salt, u.id).run();
  return json({ ok: true });
}

async function favs(req: Request) {
  const u = await requireUser(req);
  if (req.method === "GET") {
    const r = await db().prepare("SELECT ids FROM favorites WHERE user_id = ?").bind(u.id).first<{ ids: string }>();
    return json({ ids: r ? JSON.parse(r.ids) : [] });
  }
  const b = await readBody(req);
  const ids = Array.isArray(b.ids) ? [...new Set(b.ids.filter((x) => Number.isInteger(x) && (x as number) > 0 && (x as number) < 1e6))].slice(0, 300) : [];
  await db()
    .prepare("INSERT INTO favorites (user_id, ids, updated_at) VALUES (?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET ids = excluded.ids, updated_at = excluded.updated_at")
    .bind(u.id, JSON.stringify(ids), now())
    .run();
  return json({ ok: true, ids });
}

async function lead(req: Request) {
  const b = await readBody(req);
  const form = str(b.form, 30) || "contact", kind = str(b.kind, 60) || "Yêu cầu";
  const raw = b.fields && typeof b.fields === "object" && !Array.isArray(b.fields) ? (b.fields as Row) : {};
  const fields: Record<string, string> = {};
  for (const [k, v] of Object.entries(raw).slice(0, 20)) fields[str(k, 30)] = str(v, 2000);
  const name = fields.name ?? "", phone = normPhone(fields.phone ?? "");
  if (name.length < 2) throw new HttpError(400, "Vui lòng nhập họ tên.");
  if (!isPhone(phone)) throw new HttpError(400, "Số điện thoại chưa đúng.");
  await limit(`lead:${clientIp(req)}`, 15, 3_600_000);
  const u = await currentUser(req);
  const text = str(b.text, 4000);
  await db()
    .prepare("INSERT INTO leads (form, kind, name, phone, fields, text, user_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
    .bind(form, kind, name, phone, JSON.stringify(fields), text, u?.id ?? null, now(), now())
    .run();
  const to = env().NOTIFY_EMAIL;
  if (to && mailReady())
    await sendMail(to, `[Website] ${kind} – ${name}`, mailLayout(`${escHtml(kind)} mới`, `<pre style="white-space:pre-wrap;font-family:inherit">${escHtml(text)}</pre>`, { href: `${new URL(req.url).origin}/admin`, label: "Mở trang quản trị" }));
  return json({ ok: true }, 201);
}

/* ================= QUẢN TRỊ ================= */
async function adminState(req: Request) {
  const n = await db().prepare("SELECT COUNT(*) AS n FROM admins").bind().first<{ n: number }>();
  let admin: Admin | null = null;
  try { admin = await requireAdmin(req); } catch { admin = null; }
  return json({ setup: (n?.n ?? 0) === 0, admin, mail: mailReady() });
}
async function adminSetup(req: Request) {
  const b = await readBody(req);
  await limit(`asetup:${clientIp(req)}`, 5, 3_600_000);
  const n = await db().prepare("SELECT COUNT(*) AS n FROM admins").bind().first<{ n: number }>();
  if ((n?.n ?? 0) > 0) throw new HttpError(403, "Hệ thống đã có quản trị viên.");
  if (!safeEq(await sha256(str(b.code, 100)), SETUP_HASH)) throw new HttpError(403, "Mã khởi tạo không đúng.");
  const email = str(b.email, 160).toLowerCase(), name = str(b.name, 80), pass = typeof b.pass === "string" ? b.pass : "";
  if (!isEmail(email) || name.length < 2 || pass.length < 10) throw new HttpError(400, "Thông tin quản trị viên chưa hợp lệ (mật khẩu tối thiểu 10 ký tự).");
  const { salt, hash } = await hashPass(pass);
  await db().prepare("INSERT INTO admins (email, name, pass_hash, pass_salt, created_at) VALUES (?, ?, ?, ?, ?)").bind(email, name, hash, salt, now()).run();
  return json({ ok: true }, 201);
}
async function adminLogin(req: Request) {
  const b = await readBody(req);
  const email = str(b.email, 160).toLowerCase(), pass = typeof b.pass === "string" ? b.pass.slice(0, 128) : "";
  await limit(`alogin:${clientIp(req)}`, 8, 900_000);
  const a = await db().prepare("SELECT * FROM admins WHERE email = ?").bind(email).first<Admin & { pass_hash: string; pass_salt: string }>();
  if (!a || !(await checkPass(pass, a.pass_salt, a.pass_hash))) throw new HttpError(401, "Email hoặc mật khẩu quản trị chưa đúng.");
  await db().prepare("UPDATE admins SET last_login = ? WHERE id = ?").bind(now(), a.id).run();
  const tok = await newSession("admin", a.id, DAY / 2);
  return json({ admin: { id: a.id, email: a.email, name: a.name } }, 200, [cookie(ADMIN_COOKIE, tok, 12 * 3600, "Strict")]);
}
async function adminStats(req: Request) {
  await requireAdmin(req);
  const d = db(), t = now();
  const q = async (sql: string, ...v: unknown[]) => ((await d.prepare(sql).bind(...v).first<{ n: number }>())?.n ?? 0);
  return json({
    users: await q("SELECT COUNT(*) AS n FROM users"),
    users7: await q("SELECT COUNT(*) AS n FROM users WHERE created_at > ?", t - 7 * DAY),
    leads: await q("SELECT COUNT(*) AS n FROM leads"),
    leadsNew: await q("SELECT COUNT(*) AS n FROM leads WHERE status = 'new'"),
    leads7: await q("SELECT COUNT(*) AS n FROM leads WHERE created_at > ?", t - 7 * DAY),
    resets: await q("SELECT COUNT(*) AS n FROM reset_requests WHERE status = 'pending'"),
    active30: await q("SELECT COUNT(*) AS n FROM users WHERE last_login > ?", t - 30 * DAY),
    mail: mailReady(),
    daily: (await d.prepare(
      "SELECT strftime('%Y-%m-%d', created_at / 1000, 'unixepoch', '+7 hours') AS day, COUNT(*) AS n FROM leads WHERE created_at > ? GROUP BY day ORDER BY day",
    ).bind(t - 14 * DAY).all<{ day: string; n: number }>()).results,
  });
}
const likeQ = (q: string) => `%${q.replace(/[%_\\]/g, (c) => "\\" + c)}%`;
async function adminUsers(req: Request) {
  await requireAdmin(req);
  const u = new URL(req.url), q = str(u.searchParams.get("q"), 80), off = Math.max(0, Number(u.searchParams.get("offset")) || 0);
  const where = q ? "WHERE email LIKE ?1 ESCAPE '\\' OR name LIKE ?1 ESCAPE '\\' OR phone LIKE ?1 ESCAPE '\\'" : "";
  const st = db().prepare(`SELECT id, email, phone, name, role, email_verified, status, marketing, created_at, last_login FROM users ${where} ORDER BY id DESC LIMIT 50 OFFSET ${off}`);
  const total = db().prepare(`SELECT COUNT(*) AS n FROM users ${where}`);
  const rows = (q ? await st.bind(likeQ(q)).all() : await st.bind().all()).results;
  const n = (q ? await total.bind(likeQ(q)).first<{ n: number }>() : await total.bind().first<{ n: number }>())?.n ?? 0;
  return json({ rows, total: n });
}
async function adminUserAction(req: Request) {
  const a = await requireAdmin(req);
  const b = await readBody(req);
  const id = Number(b.id), action = str(b.action, 20);
  const u = await db().prepare("SELECT * FROM users WHERE id = ?").bind(id).first<User>();
  if (!u) throw new HttpError(404, "Không tìm thấy tài khoản.");
  if (action === "disable" || action === "enable") {
    await db().prepare("UPDATE users SET status = ? WHERE id = ?").bind(action === "disable" ? "disabled" : "active", id).run();
    if (action === "disable") await db().prepare("DELETE FROM sessions WHERE kind = 'user' AND subject_id = ?").bind(id).run();
    return json({ ok: true });
  }
  if (action === "verify") {
    await db().prepare("UPDATE users SET email_verified = 1 WHERE id = ?").bind(id).run();
    return json({ ok: true });
  }
  if (action === "temp-password") {
    const temp = tempPassword();
    const { salt, hash } = await hashPass(temp);
    await db().batch([
      db().prepare("UPDATE users SET pass_hash = ?, pass_salt = ? WHERE id = ?").bind(hash, salt, id),
      db().prepare("DELETE FROM sessions WHERE kind = 'user' AND subject_id = ?").bind(id),
      db().prepare("UPDATE reset_requests SET status = 'done', handled_at = ?, note = ? WHERE user_id = ? AND status = 'pending'").bind(now(), `Cấp mật khẩu tạm bởi ${a.email}`, id),
    ]);
    return json({ ok: true, temp });
  }
  throw new HttpError(400, "Thao tác không hợp lệ.");
}
const LEAD_STATUS = ["new", "contacted", "deal", "closed", "spam"];
async function adminLeads(req: Request) {
  await requireAdmin(req);
  const u = new URL(req.url), q = str(u.searchParams.get("q"), 80), s = str(u.searchParams.get("status"), 20), off = Math.max(0, Number(u.searchParams.get("offset")) || 0);
  const cond: string[] = [], v: unknown[] = [];
  if (LEAD_STATUS.includes(s)) { cond.push("status = ?"); v.push(s); }
  if (q) { cond.push("(name LIKE ? ESCAPE '\\' OR phone LIKE ? ESCAPE '\\' OR text LIKE ? ESCAPE '\\')"); v.push(likeQ(q), likeQ(q), likeQ(q)); }
  const where = cond.length ? "WHERE " + cond.join(" AND ") : "";
  const rows = (await db().prepare(`SELECT * FROM leads ${where} ORDER BY id DESC LIMIT 50 OFFSET ${off}`).bind(...v).all()).results;
  const n = (await db().prepare(`SELECT COUNT(*) AS n FROM leads ${where}`).bind(...v).first<{ n: number }>())?.n ?? 0;
  return json({ rows, total: n });
}
async function adminLeadUpdate(req: Request) {
  await requireAdmin(req);
  const b = await readBody(req);
  const id = Number(b.id), status = str(b.status, 20), note = typeof b.note === "string" ? b.note.slice(0, 2000) : null;
  if (status && !LEAD_STATUS.includes(status)) throw new HttpError(400, "Trạng thái không hợp lệ.");
  await db()
    .prepare("UPDATE leads SET status = COALESCE(NULLIF(?, ''), status), note = COALESCE(?, note), updated_at = ? WHERE id = ?")
    .bind(status, note, now(), id)
    .run();
  return json({ ok: true });
}
async function adminResets(req: Request) {
  await requireAdmin(req);
  const s = str(new URL(req.url).searchParams.get("status"), 20) || "pending";
  const rows = (await db()
    .prepare("SELECT r.*, u.name AS user_name, u.phone AS user_phone FROM reset_requests r LEFT JOIN users u ON u.id = r.user_id WHERE r.status = ? ORDER BY r.id DESC LIMIT 100")
    .bind(s === "done" ? "done" : "pending")
    .all()).results;
  return json({ rows });
}
async function adminResetUpdate(req: Request) {
  const a = await requireAdmin(req);
  const b = await readBody(req);
  await db().prepare("UPDATE reset_requests SET status = 'done', handled_at = ?, note = ? WHERE id = ?").bind(now(), `Đóng bởi ${a.email}`, Number(b.id)).run();
  return json({ ok: true });
}
async function adminPassword(req: Request) {
  const a = await requireAdmin(req);
  const b = await readBody(req);
  const old = typeof b.old === "string" ? b.old : "", pass = typeof b.pass === "string" ? b.pass : "";
  if (pass.length < 10 || pass.length > 128) throw new HttpError(400, "Mật khẩu quản trị cần từ 10 ký tự.");
  await limit(`apw:${a.id}`, 6, 900_000);
  const row = await db().prepare("SELECT pass_hash, pass_salt FROM admins WHERE id = ?").bind(a.id).first<{ pass_hash: string; pass_salt: string }>();
  if (!row || !(await checkPass(old, row.pass_salt, row.pass_hash))) throw new HttpError(400, "Mật khẩu hiện tại chưa đúng.");
  const { salt, hash } = await hashPass(pass);
  const keep = getCookie(req, ADMIN_COOKIE);
  await db().batch([
    db().prepare("UPDATE admins SET pass_hash = ?, pass_salt = ? WHERE id = ?").bind(hash, salt, a.id),
    db().prepare("DELETE FROM sessions WHERE kind = 'admin' AND subject_id = ? AND token_hash != ?").bind(a.id, await sha256(keep)),
  ]);
  return json({ ok: true });
}
async function adminAdmins(req: Request) {
  await requireAdmin(req);
  if (req.method === "GET") {
    const rows = (await db().prepare("SELECT id, email, name, created_at, last_login FROM admins ORDER BY id").bind().all()).results;
    return json({ rows });
  }
  const b = await readBody(req);
  const email = str(b.email, 160).toLowerCase(), name = str(b.name, 80), pass = typeof b.pass === "string" ? b.pass : "";
  if (!isEmail(email) || name.length < 2 || pass.length < 10) throw new HttpError(400, "Nhập đủ họ tên, email và mật khẩu (tối thiểu 10 ký tự).");
  if (await db().prepare("SELECT id FROM admins WHERE email = ?").bind(email).first()) throw new HttpError(409, "Email này đã là quản trị viên.");
  const { salt, hash } = await hashPass(pass);
  await db().prepare("INSERT INTO admins (email, name, pass_hash, pass_salt, created_at) VALUES (?, ?, ?, ?, ?)").bind(email, name, hash, salt, now()).run();
  return json({ ok: true }, 201);
}
function csvCell(v: unknown) {
  let s = v === null || v === undefined ? "" : String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; // chặn công thức độc hại khi mở bằng Excel
  return `"${s.replace(/"/g, '""')}"`;
}
const fmtTime = (ms: unknown) =>
  typeof ms === "number" && ms > 0 ? new Date(ms + 7 * 3_600_000).toISOString().replace("T", " ").slice(0, 16) : "";
async function adminExport(req: Request) {
  await requireAdmin(req);
  const what = new URL(req.url).searchParams.get("what");
  let head: string[], rows: unknown[][];
  if (what === "users") {
    const r = (await db().prepare("SELECT * FROM users ORDER BY id").bind().all<Row>()).results;
    head = ["ID", "Họ tên", "Email", "Điện thoại", "Vai trò", "Đã xác minh email", "Trạng thái", "Nhận tư vấn", "Ngày tạo", "Đăng nhập gần nhất"];
    rows = r.map((u) => [u.id, u.name, u.email, u.phone, u.role, u.email_verified ? "Có" : "Chưa", u.status === "active" ? "Hoạt động" : "Tạm khoá", u.marketing ? "Có" : "Không", fmtTime(u.created_at), fmtTime(u.last_login)]);
  } else {
    const r = (await db().prepare("SELECT * FROM leads ORDER BY id").bind().all<Row>()).results;
    head = ["ID", "Loại", "Họ tên", "Điện thoại", "Nội dung", "Trạng thái", "Ghi chú", "Thời gian"];
    const SL: Record<string, string> = { new: "Mới", contacted: "Đã liên hệ", deal: "Đang thương lượng", closed: "Đã chốt", spam: "Rác" };
    rows = r.map((l) => [l.id, l.kind, l.name, l.phone, l.text, SL[l.status as string] ?? l.status, l.note, fmtTime(l.created_at)]);
  }
  const csv = "﻿" + [head, ...rows].map((r) => r.map(csvCell).join(",")).join("\r\n");
  return new Response(csv, {
    headers: {
      "Content-Type": "text/csv; charset=utf-8",
      "Content-Disposition": `attachment; filename="${what === "users" ? "khach-hang" : "yeu-cau-tu-van"}.csv"`,
      "Cache-Control": "no-store",
    },
  });
}

/* ================= ĐIỀU HƯỚNG ================= */
type Handler = (req: Request) => Promise<Response>;
const ROUTES: Record<string, Partial<Record<"GET" | "POST", Handler>>> = {
  "health": { GET: async () => json({ ok: true, db: !!env().DB, mail: mailReady() }) },
  "auth/me": { GET: async (r) => { const u = await currentUser(r); return json({ user: u ? publicUser(u) : null }); } },
  "auth/register": { POST: register },
  "auth/login": { POST: login },
  "auth/logout": { POST: async (r) => { await readBody(r); await dropSession(r, "user"); return json({ ok: true }, 200, [cookie(USER_COOKIE, "", 0)]); } },
  "auth/forgot": { POST: forgot },
  "auth/reset": { POST: reset },
  "auth/verify": { GET: verify },
  "auth/password": { POST: changePassword },
  "auth/resend-verify": { POST: async (r) => { await readBody(r); const u = await requireUser(r); await limit(`rv:${u.id}`, 3, 3_600_000); return json({ sent: await sendVerify(r, u) }); } },
  "favs": { GET: favs, POST: favs },
  "leads": { POST: lead },
  "admin/state": { GET: adminState },
  "admin/setup": { POST: adminSetup },
  "admin/login": { POST: adminLogin },
  "admin/logout": { POST: async (r) => { await readBody(r); await dropSession(r, "admin"); return json({ ok: true }, 200, [cookie(ADMIN_COOKIE, "", 0, "Strict")]); } },
  "admin/stats": { GET: adminStats },
  "admin/users": { GET: adminUsers },
  "admin/user": { POST: adminUserAction },
  "admin/leads": { GET: adminLeads },
  "admin/lead": { POST: adminLeadUpdate },
  "admin/resets": { GET: adminResets },
  "admin/reset": { POST: adminResetUpdate },
  "admin/password": { POST: adminPassword },
  "admin/admins": { GET: adminAdmins, POST: adminAdmins },
  "admin/export": { GET: adminExport },
};

export async function handleApi(request: Request, path: string): Promise<Response> {
  const route = ROUTES[path.replace(/^\/+|\/+$/g, "")];
  const method = request.method as "GET" | "POST";
  if (!route) return json({ error: "Không tìm thấy." }, 404);
  const fn = route[method];
  if (!fn) return json({ error: "Phương thức không được hỗ trợ." }, 405);
  try {
    return await fn(request);
  } catch (e) {
    if (e instanceof HttpError) return json({ error: e.message }, e.status);
    console.error(e);
    return json({ error: "Hệ thống đang bận, vui lòng thử lại sau ít phút." }, 500);
  }
}
