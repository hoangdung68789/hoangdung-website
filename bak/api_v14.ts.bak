/**
 * Hoàng Dũng Real Estate — máy chủ API (Cloudflare Workers + D1). Chạy được trên mọi môi trường Workers.
 *
 * Khách hàng
 *   /api/auth/*   đăng ký, đăng nhập (mật khẩu + mã xác minh), đăng nhập bằng mã, khôi phục tài khoản,
 *                 thiết bị đáng tin cậy, đổi mật khẩu
 *   /api/favs     tin đã lưu (đồng bộ mọi thiết bị)
 *   /api/leads    yêu cầu tư vấn từ các form
 * Quản trị (tài khoản riêng, tách biệt hoàn toàn với khách)
 *   /api/admin/*
 *
 * Mã xác minh 6 số gửi qua 2 kênh:
 *   - SMS: Twilio Verify (hỗ trợ số điện thoại quốc tế, định dạng E.164) — cần TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_VERIFY_SID
 *   - Email: Brevo (BREVO_API_KEY) hoặc Resend (RESEND_API_KEY) + MAIL_FROM
 * Các khoá bí mật được đặt trong phần cài đặt Worker trên Cloudflare, không bao giờ nằm trong mã nguồn.
 *
 * Bảo mật: mật khẩu băm PBKDF2-SHA256 + muối ngẫu nhiên (số vòng lưu theo từng tài khoản, tự nâng cấp);
 * phiên & thiết bị tin cậy là mã ngẫu nhiên 256-bit trong cookie HttpOnly/Secure, CSDL chỉ lưu bản băm;
 * mã xác minh chỉ lưu bản băm, hết hạn sau 10 phút, tối đa 5 lần nhập sai; giới hạn tần suất theo IP/đích nhận;
 * chỉ nhận POST JSON đúng nguồn (chống CSRF).
 */

type Row = Record<string, unknown>;
type Stmt = {
  bind(...v: unknown[]): Stmt;
  first<T = Row>(): Promise<T | null>;
  all<T = Row>(): Promise<{ results: T[] }>;
  run(): Promise<{ meta?: { last_row_id?: number; changes?: number } }>;
};
type DB = { prepare(sql: string): Stmt; batch(stmts: Stmt[]): Promise<unknown> };
export type Env = {
  DB?: DB;
  TWILIO_ACCOUNT_SID?: string;
  TWILIO_AUTH_TOKEN?: string;
  TWILIO_VERIFY_SID?: string;
  BREVO_API_KEY?: string;
  RESEND_API_KEY?: string;
  MAIL_FROM?: string;
  NOTIFY_EMAIL?: string;
  PW_ITER?: string;
};

/* Mã khởi tạo quản trị viên đầu tiên — chỉ lưu bản băm; vô hiệu ngay khi đã có quản trị viên. */
const SETUP_HASH = "554fbafa51f7fcbcc3707d4b9881bf1c0470b5283c39127472f27a75f7bb6b62";

const USER_COOKIE = "hd_sid";
const ADMIN_COOKIE = "hd_adm";
const DEVICE_COOKIE = "hd_td";
const MIN = 60_000, HOUR = 3_600_000, DAY = 86_400_000;
const TRUST_DAYS = 180;
const OTP_TTL = 10 * MIN;
const ROLES = ["Khách mua / thuê nhà", "Chủ nhà cần bán / cho thuê", "Môi giới / đối tác"];
const HOTLINE = "087.778.1796";

let ENV: Env = {};
const env = () => ENV;
const enc = new TextEncoder();
const hex = (b: ArrayBuffer | Uint8Array) =>
  [...new Uint8Array(b as ArrayBuffer)].map((x) => x.toString(16).padStart(2, "0")).join("");
const fromHex = (h: string) => new Uint8Array((h.match(/../g) ?? []).map((x) => parseInt(x, 16)));
const now = () => Date.now();

class HttpError extends Error {
  constructor(public status: number, message: string, public extra: Row = {}) {
    super(message);
  }
}
function db(): DB {
  const d = env().DB;
  if (!d) throw new HttpError(503, "Hệ thống dữ liệu chưa sẵn sàng. Vui lòng thử lại sau.");
  return d;
}

/* ---------------- lược đồ CSDL (tự tạo / tự bổ sung cột khi khởi động) ---------------- */
export const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL UNIQUE, phone TEXT NOT NULL DEFAULT '', name TEXT NOT NULL DEFAULT '', role TEXT NOT NULL DEFAULT '', pass_hash TEXT NOT NULL, pass_salt TEXT NOT NULL, email_verified INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'active', marketing INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL, last_login INTEGER)`,
  `CREATE INDEX IF NOT EXISTS users_phone ON users(phone)`,
  `CREATE TABLE IF NOT EXISTS admins (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL UNIQUE, name TEXT NOT NULL DEFAULT '', pass_hash TEXT NOT NULL, pass_salt TEXT NOT NULL, created_at INTEGER NOT NULL, last_login INTEGER)`,
  `CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, kind TEXT NOT NULL, subject_id INTEGER NOT NULL, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS sessions_subject ON sessions(kind, subject_id)`,
  `CREATE TABLE IF NOT EXISTS tokens (token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL, purpose TEXT NOT NULL, expires_at INTEGER NOT NULL, used_at INTEGER)`,
  `CREATE TABLE IF NOT EXISTS reset_requests (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, email TEXT NOT NULL, phone TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'pending', note TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL, handled_at INTEGER)`,
  `CREATE TABLE IF NOT EXISTS leads (id INTEGER PRIMARY KEY AUTOINCREMENT, form TEXT NOT NULL, kind TEXT NOT NULL, name TEXT NOT NULL DEFAULT '', phone TEXT NOT NULL DEFAULT '', fields TEXT NOT NULL DEFAULT '{}', text TEXT NOT NULL DEFAULT '', user_id INTEGER, status TEXT NOT NULL DEFAULT 'new', note TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL, updated_at INTEGER)`,
  `CREATE INDEX IF NOT EXISTS leads_status ON leads(status, created_at)`,
  `CREATE TABLE IF NOT EXISTS favorites (user_id INTEGER PRIMARY KEY, ids TEXT NOT NULL DEFAULT '[]', updated_at INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS attempts (id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT NOT NULL, at INTEGER NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS attempts_key ON attempts(key, at)`,
  `CREATE TABLE IF NOT EXISTS otp_challenges (token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL, purpose TEXT NOT NULL, channel TEXT NOT NULL DEFAULT '', dest TEXT NOT NULL DEFAULT '', code_hash TEXT, sends INTEGER NOT NULL DEFAULT 0, attempts INTEGER NOT NULL DEFAULT 0, last_sent INTEGER NOT NULL DEFAULT 0, remember INTEGER NOT NULL DEFAULT 1, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL, verified_at INTEGER)`,
  `CREATE TABLE IF NOT EXISTS trusted_devices (id INTEGER PRIMARY KEY AUTOINCREMENT, token_hash TEXT NOT NULL UNIQUE, user_id INTEGER NOT NULL, label TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL, last_used INTEGER NOT NULL, expires_at INTEGER NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS trusted_user ON trusted_devices(user_id)`,
];
const ADD_COLUMNS = [
  `ALTER TABLE users ADD COLUMN phone_cc TEXT NOT NULL DEFAULT ''`,
  `ALTER TABLE users ADD COLUMN phone_verified INTEGER NOT NULL DEFAULT 0`,
  `ALTER TABLE users ADD COLUMN pass_iter INTEGER NOT NULL DEFAULT 100000`,
  `ALTER TABLE admins ADD COLUMN pass_iter INTEGER NOT NULL DEFAULT 100000`,
];
let schemaReady: Promise<void> | null = null;
async function ensureSchema() {
  if (!env().DB) return;
  if (!schemaReady)
    schemaReady = (async () => {
      const d = db();
      await d.batch(SCHEMA.map((s) => d.prepare(s)));
      for (const s of ADD_COLUMNS) {
        try { await d.prepare(s).run(); } catch { /* cột đã có */ }
      }
    })().catch((e) => { schemaReady = null; throw e; });
  return schemaReady;
}

/* ---------------- tiện ích bảo mật ---------------- */
function randomToken(bytes = 32): string {
  const a = crypto.getRandomValues(new Uint8Array(bytes));
  let s = "";
  for (const x of a) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function randomCode(): string {
  const a = new Uint32Array(1);
  let v = 0;
  do { crypto.getRandomValues(a); v = a[0]; } while (v >= 4_294_000_000); // tránh lệch phân bố
  return String(v % 1_000_000).padStart(6, "0");
}
function tempPassword(): string {
  const al = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";
  return [...crypto.getRandomValues(new Uint8Array(10))].map((x) => al[x % al.length]).join("");
}
async function sha256(t: string): Promise<string> {
  return hex(await crypto.subtle.digest("SHA-256", enc.encode(t)));
}
const targetIter = () => {
  const n = Number(env().PW_ITER);
  return Number.isFinite(n) && n >= 10_000 && n <= 1_000_000 ? Math.round(n) : 100_000;
};
async function hashPass(pass: string, saltHex?: string, iter = targetIter()) {
  const salt = saltHex ?? hex(crypto.getRandomValues(new Uint8Array(16)));
  const key = await crypto.subtle.importKey("raw", enc.encode(pass), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: fromHex(salt), iterations: iter }, key, 256);
  return { salt, hash: hex(bits), iter };
}
function safeEq(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
async function checkPass(pass: string, salt: string, hash: string, iter = 100_000) {
  return safeEq((await hashPass(pass, salt, iter)).hash, hash);
}

/* ---------------- dữ liệu vào ---------------- */
const str = (v: unknown, max = 200) => (typeof v === "string" ? v.trim().slice(0, max) : "");
const isEmail = (e: string) => /^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,}$/.test(e) && e.length <= 160;
/** Ghép mã quốc gia + số điện thoại thành chuẩn quốc tế E.164 (+84901234567). */
function toE164(ccRaw: unknown, phoneRaw: unknown): string {
  const p = str(phoneRaw, 30);
  let cc = str(ccRaw, 6).replace(/\D/g, "");
  let digits = p.replace(/\D/g, "");
  if (p.startsWith("+") || p.startsWith("00")) {
    digits = p.startsWith("00") ? digits.slice(2) : digits;
    return /^[1-9]\d{7,14}$/.test(digits) ? "+" + digits : "";
  }
  if (!cc) cc = "84";
  if (digits.startsWith(cc) && digits.length > cc.length + 7 && cc !== "1") digits = digits.slice(cc.length);
  if (digits.startsWith("0") && cc !== "39") digits = digits.replace(/^0+/, ""); // bỏ số 0 đầu (trừ Ý)
  const full = cc + digits;
  if (!/^[1-9]\d{7,14}$/.test(full)) return "";
  if (cc === "84" && !/^84(3|5|7|8|9)\d{8}$/.test(full) && !/^842\d{9}$/.test(full)) return "";
  return "+" + full;
}
const maskEmail = (e: string) => { const [a, d] = e.split("@"); return (a.length <= 2 ? a[0] + "*" : a.slice(0, 2) + "***") + "@" + d; };
const DIALS = ["1721", "1809", "1868", "1441", "1268", "1876", "1767", "1264", "1784", "1671", "1246", "1345", "1473", "1758", "1649", "1869", "1284", "1242", "1670", "1664", "1340", "1684", "1787", "383", "680", "227", "256", "269", "258", "230", "506", "251", "377", "976", "964", "378", "220", "264", "675", "353", "992", "688", "423", "248", "998", "242", "687", "886", "852", "232", "236", "674", "685", "856", "238", "268", "375", "250", "507", "299", "972", "382", "213", "596", "222", "597", "241", "298", "505", "961", "683", "967", "356", "249", "594", "261", "351", "386", "599", "387", "975", "237", "224", "421", "598", "265", "218", "420", "692", "690", "226", "253", "243", "670", "374", "591", "359", "974", "290", "267", "354", "234", "963", "691", "880", "850", "504", "673", "971", "212", "233", "231", "502", "855", "352", "223", "593", "509", "355", "960", "221", "228", "389", "995", "686", "977", "500", "678", "381", "235", "968", "501", "246", "970", "240", "225", "255", "254", "962", "966", "262", "358", "380", "681", "376", "245", "994", "216", "592", "211", "677", "244", "252", "385", "590", "503", "679", "373", "676", "996", "263", "229", "371", "853", "993", "682", "508", "595", "973", "370", "297", "689", "357", "350", "372", "965", "239", "291", "257", "266", "260", "48", "58", "57", "91", "81", "95", "51", "34", "98", "43", "33", "60", "64", "56", "63", "61", "36", "53", "92", "55", "32", "82", "46", "66", "45", "93", "49", "62", "47", "54", "94", "41", "39", "86", "30", "31", "20", "65", "90", "52", "27", "40", "44", "84", "1", "7"];
const maskPhone = (p: string) => {
  const d = p.slice(1), cc = DIALS.find((x) => d.startsWith(x) && d.length - x.length >= 6) ?? d.slice(0, 2);
  return `+${cc} ••• ••• ${d.slice(-3)}`;
};

/* ---------------- HTTP ---------------- */
function json(data: unknown, status = 200, cookies: string[] = []): Response {
  const h = new Headers({ "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" });
  for (const c of cookies) h.append("Set-Cookie", c);
  return new Response(JSON.stringify(data), { status, headers: h });
}
function getCookie(req: Request, name: string): string {
  for (const part of (req.headers.get("Cookie") ?? "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i).trim() === name) return decodeURIComponent(part.slice(i + 1).trim());
  }
  return "";
}
function cookie(name: string, value: string, maxAgeSec: number | null, sameSite: "Lax" | "Strict" = "Lax") {
  return `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; Secure; SameSite=${sameSite}${maxAgeSec === null ? "" : `; Max-Age=${maxAgeSec}`}`;
}
const clientIp = (req: Request) => req.headers.get("CF-Connecting-IP") ?? "0.0.0.0";
async function readBody(req: Request): Promise<Row> {
  if (!(req.headers.get("Content-Type") ?? "").includes("application/json")) throw new HttpError(415, "Yêu cầu không hợp lệ.");
  const origin = req.headers.get("Origin");
  if (origin && origin !== new URL(req.url).origin) throw new HttpError(403, "Nguồn yêu cầu không hợp lệ.");
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
async function limit(key: string, max: number, win: number, msg = "Bạn thao tác quá nhiều lần. Vui lòng đợi ít phút rồi thử lại.") {
  const d = db(), t = now();
  const r = await d.prepare("SELECT COUNT(*) AS n FROM attempts WHERE key = ? AND at > ?").bind(key, t - win).first<{ n: number }>();
  if ((r?.n ?? 0) >= max) throw new HttpError(429, msg);
  await d.prepare("INSERT INTO attempts (key, at) VALUES (?, ?)").bind(key, t).run();
  if (crypto.getRandomValues(new Uint8Array(1))[0] < 4) await d.prepare("DELETE FROM attempts WHERE at < ?").bind(t - 2 * DAY).run();
}
function deviceLabel(req: Request) {
  const ua = req.headers.get("User-Agent") ?? "";
  const os = /iPhone/.test(ua) ? "iPhone" : /iPad/.test(ua) ? "iPad" : /Android/.test(ua) ? "Android" : /Windows/.test(ua) ? "Windows" : /Mac OS X/.test(ua) ? "macOS" : /Linux/.test(ua) ? "Linux" : "Thiết bị";
  const br = /Edg\//.test(ua) ? "Edge" : /OPR\//.test(ua) ? "Opera" : /CocCoc/.test(ua) ? "Cốc Cốc" : /SamsungBrowser/.test(ua) ? "Samsung Internet" : /Firefox\//.test(ua) ? "Firefox" : /Chrome\//.test(ua) ? "Chrome" : /Safari\//.test(ua) ? "Safari" : "Trình duyệt";
  return `${br} · ${os}`;
}

/* ---------------- gửi mã: SMS (Twilio Verify) & email ---------------- */
const smsReady = () => { const e = env(); return !!(e.TWILIO_ACCOUNT_SID && e.TWILIO_AUTH_TOKEN && e.TWILIO_VERIFY_SID); };
const mailReady = () => { const e = env(); return !!((e.BREVO_API_KEY || e.RESEND_API_KEY) && e.MAIL_FROM); };
async function twilio(path: string, form: Record<string, string>) {
  const e = env();
  const r = await fetch(`https://verify.twilio.com/v2/Services/${e.TWILIO_VERIFY_SID}/${path}`, {
    method: "POST",
    headers: { Authorization: "Basic " + btoa(`${e.TWILIO_ACCOUNT_SID}:${e.TWILIO_AUTH_TOKEN}`), "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(form).toString(),
  });
  let j: Row = {};
  try { j = (await r.json()) as Row; } catch { /* bỏ qua */ }
  return { ok: r.ok, status: r.status, j };
}
async function sendSmsCode(to: string): Promise<void> {
  const r = await twilio("Verifications", { To: to, Channel: "sms", Locale: "vi" });
  if (!r.ok) {
    console.error("twilio send", r.status, JSON.stringify(r.j).slice(0, 300));
    throw new HttpError(502, r.status === 429 ? "Số điện thoại này nhận mã quá nhiều lần. Vui lòng thử lại sau." : "Chưa gửi được SMS tới số này. Hãy kiểm tra lại số hoặc chọn nhận mã qua email.");
  }
}
async function checkSmsCode(to: string, code: string): Promise<boolean> {
  const r = await twilio("VerificationCheck", { To: to, Code: code });
  return r.ok && r.j.status === "approved";
}
function parseFrom(from: string) {
  const m = from.match(/^\s*(.*?)\s*<([^>]+)>\s*$/);
  return m ? { name: m[1] || "Hoàng Dũng Real Estate", email: m[2] } : { name: "Hoàng Dũng Real Estate", email: from.trim() };
}
async function sendMail(to: string, subject: string, html: string): Promise<boolean> {
  const e = env();
  if (!e.MAIL_FROM) return false;
  try {
    if (e.BREVO_API_KEY) {
      const r = await fetch("https://api.brevo.com/v3/smtp/email", {
        method: "POST",
        headers: { "api-key": e.BREVO_API_KEY, "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify({ sender: parseFrom(e.MAIL_FROM), to: [{ email: to }], subject, htmlContent: html }),
      });
      if (!r.ok) console.error("brevo", r.status, (await r.text()).slice(0, 300));
      return r.ok;
    }
    if (e.RESEND_API_KEY) {
      const r = await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: { Authorization: `Bearer ${e.RESEND_API_KEY}`, "Content-Type": "application/json" },
        body: JSON.stringify({ from: e.MAIL_FROM, to: [to], subject, html }),
      });
      if (!r.ok) console.error("resend", r.status, (await r.text()).slice(0, 300));
      return r.ok;
    }
  } catch (err) {
    console.error(err);
  }
  return false;
}
const escHtml = (s: string) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] as string);
function mailLayout(title: string, body: string, extra = "") {
  return `<!doctype html><html lang="vi"><body style="margin:0;background:#f2f0ec;font-family:Arial,Helvetica,sans-serif;color:#121417">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="padding:28px 12px"><tr><td align="center">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:520px;background:#ffffff;border-radius:14px;overflow:hidden">
<tr><td style="background:#0c0d0f;padding:22px 28px;color:#f2f3f4;font-size:18px;font-weight:bold">Hoàng Dũng <span style="color:#e9a27a;font-size:11px;letter-spacing:2px">REAL ESTATE</span></td></tr>
<tr><td style="padding:28px"><h2 style="margin:0 0 12px;font-size:20px">${title}</h2><div style="font-size:15px;line-height:1.6;color:#3b4048">${body}</div>${extra}</td></tr>
<tr><td style="padding:18px 28px;border-top:1px solid #eee;font-size:12px;color:#8a9099">Hoàng Dũng Real Estate · Kiến tạo mái ấm gia đình Việt<br>Hotline ${HOTLINE} · 37 Lê Thúc Hoạch, Phú Thọ Hoà, Tân Phú</td></tr>
</table></td></tr></table></body></html>`;
}
const PURPOSE_TEXT: Record<string, string> = { login: "đăng nhập", register: "xác minh tài khoản mới", reset: "khôi phục tài khoản" };

/* ---------------- người dùng, phiên, thiết bị ---------------- */
type User = {
  id: number; email: string; phone: string; phone_cc: string; name: string; role: string;
  email_verified: number; phone_verified: number; status: string; created_at: number;
  pass_hash: string; pass_salt: string; pass_iter: number;
};
type Admin = { id: number; email: string; name: string };
const publicUser = (u: User) => ({
  id: u.id, name: u.name, email: u.email, phone: u.phone, role: u.role,
  emailVerified: !!u.email_verified, phoneVerified: !!u.phone_verified,
});
const getUser = (id: number) => db().prepare("SELECT * FROM users WHERE id = ?").bind(id).first<User>();
function channelsOf(u: User) {
  const ch: { type: "sms" | "email"; masked: string; verified: boolean }[] = [];
  if (smsReady() && u.phone) ch.push({ type: "sms", masked: maskPhone(u.phone), verified: !!u.phone_verified });
  if (mailReady() && u.email) ch.push({ type: "email", masked: maskEmail(u.email), verified: !!u.email_verified });
  return ch;
}
async function newSession(kind: "user" | "admin", id: number, ttl: number) {
  const tok = randomToken(), t = now();
  await db().prepare("INSERT INTO sessions (token_hash, kind, subject_id, expires_at, created_at) VALUES (?, ?, ?, ?, ?)").bind(await sha256(tok), kind, id, t + ttl, t).run();
  return tok;
}
async function sessionSubject(req: Request, kind: "user" | "admin"): Promise<number | null> {
  const tok = getCookie(req, kind === "user" ? USER_COOKIE : ADMIN_COOKIE);
  if (!tok || tok.length > 100) return null;
  const r = await db().prepare("SELECT subject_id FROM sessions WHERE token_hash = ? AND kind = ? AND expires_at > ?").bind(await sha256(tok), kind, now()).first<{ subject_id: number }>();
  return r?.subject_id ?? null;
}
async function currentUser(req: Request): Promise<User | null> {
  const id = await sessionSubject(req, "user");
  if (!id) return null;
  const u = await getUser(id);
  return u && u.status === "active" ? u : null;
}
async function requireUser(req: Request): Promise<User> {
  const u = await currentUser(req);
  if (!u) throw new HttpError(401, "Phiên đăng nhập đã hết hạn. Vui lòng đăng nhập lại.");
  return u;
}
async function requireAdmin(req: Request): Promise<Admin> {
  const id = await sessionSubject(req, "admin");
  const a = id ? await db().prepare("SELECT id, email, name FROM admins WHERE id = ?").bind(id).first<Admin>() : null;
  if (!a) throw new HttpError(401, "Vui lòng đăng nhập quản trị.");
  return a;
}
async function dropSession(req: Request, kind: "user" | "admin") {
  const tok = getCookie(req, kind === "user" ? USER_COOKIE : ADMIN_COOKIE);
  if (tok) await db().prepare("DELETE FROM sessions WHERE token_hash = ?").bind(await sha256(tok)).run();
}
async function trustedFor(req: Request, userId: number): Promise<number | null> {
  const tok = getCookie(req, DEVICE_COOKIE);
  if (!tok || tok.length > 100) return null;
  const r = await db().prepare("SELECT id FROM trusted_devices WHERE token_hash = ? AND user_id = ? AND expires_at > ?").bind(await sha256(tok), userId, now()).first<{ id: number }>();
  if (r) await db().prepare("UPDATE trusted_devices SET last_used = ? WHERE id = ?").bind(now(), r.id).run();
  return r?.id ?? null;
}
async function trustDevice(req: Request, userId: number) {
  const tok = randomToken(), t = now();
  const old = getCookie(req, DEVICE_COOKIE);
  if (old) await db().prepare("DELETE FROM trusted_devices WHERE token_hash = ? AND user_id = ?").bind(await sha256(old), userId).run();
  await db().prepare("INSERT INTO trusted_devices (token_hash, user_id, label, created_at, last_used, expires_at) VALUES (?, ?, ?, ?, ?, ?)").bind(await sha256(tok), userId, deviceLabel(req), t, t, t + TRUST_DAYS * DAY).run();
  return cookie(DEVICE_COOKIE, tok, TRUST_DAYS * 86400);
}
async function loginCookies(req: Request, u: User, remember: boolean, trust: boolean) {
  await db().prepare("UPDATE users SET last_login = ? WHERE id = ?").bind(now(), u.id).run();
  const tok = await newSession("user", u.id, remember ? 30 * DAY : DAY);
  const cs = [cookie(USER_COOKIE, tok, remember ? 30 * 86400 : null)];
  if (trust) cs.push(await trustDevice(req, u.id));
  return cs;
}
async function newChallenge(u: User, purpose: "login" | "register" | "reset", remember = true) {
  const tok = randomToken(), t = now();
  await db().prepare("INSERT INTO otp_challenges (token_hash, user_id, purpose, remember, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)").bind(await sha256(tok), u.id, purpose, remember ? 1 : 0, t + 30 * MIN, t).run();
  return { need: "otp", challenge: tok, purpose, channels: channelsOf(u) };
}
async function findByIdentifier(b: Row): Promise<User | null> {
  const id = str(b.id, 160);
  if (id.includes("@")) return db().prepare("SELECT * FROM users WHERE email = ?").bind(id.toLowerCase()).first<User>();
  const e164 = toE164(b.cc, id);
  if (!e164) return null;
  return db().prepare("SELECT * FROM users WHERE phone = ?").bind(e164).first<User>();
}

/* ================= KHÁCH HÀNG ================= */
async function register(req: Request) {
  const b = await readBody(req);
  const name = str(b.name, 80), email = str(b.email, 160).toLowerCase();
  const phone = toE164(b.cc, b.phone), cc = str(b.ccIso, 3).toUpperCase();
  const pass = typeof b.pass === "string" ? b.pass : "";
  const role = ROLES.includes(str(b.role, 60)) ? str(b.role, 60) : "";
  if (name.length < 2) throw new HttpError(400, "Vui lòng nhập họ và tên.");
  if (!isEmail(email)) throw new HttpError(400, "Vui lòng nhập địa chỉ email hợp lệ, ví dụ ten@gmail.com.");
  if (!phone) throw new HttpError(400, "Số điện thoại chưa đúng. Hãy chọn mã quốc gia và nhập số, ví dụ 0901 234 567.");
  if (pass.length < 8 || pass.length > 128) throw new HttpError(400, "Mật khẩu cần từ 8 đến 128 ký tự.");
  await limit(`reg:${clientIp(req)}`, 8, HOUR);
  const d = db();
  if (await d.prepare("SELECT id FROM users WHERE email = ?").bind(email).first()) throw new HttpError(409, "Email này đã có tài khoản. Hãy đăng nhập hoặc dùng “Quên mật khẩu”.");
  if (await d.prepare("SELECT id FROM users WHERE phone = ?").bind(phone).first()) throw new HttpError(409, "Số điện thoại này đã được dùng cho một tài khoản khác.");
  const { salt, hash, iter } = await hashPass(pass);
  const t = now();
  const r = await d.prepare("INSERT INTO users (email, phone, phone_cc, name, role, pass_hash, pass_salt, pass_iter, marketing, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)").bind(email, phone, cc, name, role, hash, salt, iter, b.agree ? 1 : 0, t).run();
  const u = (await getUser(Number(r.meta?.last_row_id))) as User;
  if (channelsOf(u).length) return json(await newChallenge(u, "register"), 201);
  return json({ user: publicUser(u) }, 201, await loginCookies(req, u, true, false));
}

async function login(req: Request) {
  const b = await readBody(req);
  const pass = typeof b.pass === "string" ? b.pass.slice(0, 128) : "";
  if (!str(b.id, 160) || !pass) throw new HttpError(400, "Vui lòng nhập email (hoặc số điện thoại) và mật khẩu.");
  await limit(`login:${clientIp(req)}`, 12, 15 * MIN);
  const key = str(b.id, 160).includes("@") ? str(b.id, 160).toLowerCase() : toE164(b.cc, b.id) || str(b.id, 40);
  await limit(`login:${key}`, 8, 15 * MIN);
  const u = await findByIdentifier(b);
  if (!u || !(await checkPass(pass, u.pass_salt, u.pass_hash, u.pass_iter || 100_000))) throw new HttpError(401, "Email/số điện thoại hoặc mật khẩu chưa đúng.");
  if (u.status !== "active") throw new HttpError(403, `Tài khoản đang tạm khoá. Vui lòng liên hệ ${HOTLINE}.`);
  if ((u.pass_iter || 100_000) !== targetIter()) { // nâng cấp độ khó băm mật khẩu khi cấu hình thay đổi
    const h = await hashPass(pass);
    await db().prepare("UPDATE users SET pass_hash = ?, pass_salt = ?, pass_iter = ? WHERE id = ?").bind(h.hash, h.salt, h.iter, u.id).run();
  }
  const remember = b.remember !== false;
  const needCode = channelsOf(u).length > 0;
  const trusted = needCode ? await trustedFor(req, u.id) : null;
  if (needCode && !trusted) return json(await newChallenge(u, "login", remember));
  return json({ user: publicUser(u), trusted: !!trusted }, 200, await loginCookies(req, u, remember, false));
}

/* Đăng nhập bằng mã / khôi phục tài khoản: bắt đầu bằng email hoặc số điện thoại */
async function codeStart(req: Request) {
  const b = await readBody(req);
  const purpose = b.purpose === "reset" ? "reset" : "login";
  if (!str(b.id, 160)) throw new HttpError(400, "Vui lòng nhập email hoặc số điện thoại.");
  await limit(`cstart:${clientIp(req)}`, 15, HOUR);
  const u = await findByIdentifier(b);
  if (!u) throw new HttpError(404, "Không tìm thấy tài khoản với email hoặc số điện thoại này.");
  if (u.status !== "active") throw new HttpError(403, `Tài khoản đang tạm khoá. Vui lòng liên hệ ${HOTLINE}.`);
  if (!channelsOf(u).length) {
    if (purpose === "login") throw new HttpError(409, "Hệ thống chưa bật gửi mã. Vui lòng đăng nhập bằng mật khẩu.");
    const dup = await db().prepare("SELECT id FROM reset_requests WHERE user_id = ? AND status = 'pending' AND created_at > ?").bind(u.id, now() - DAY).first();
    if (!dup) await db().prepare("INSERT INTO reset_requests (user_id, email, phone, created_at) VALUES (?, ?, ?, ?)").bind(u.id, u.email, u.phone, now()).run();
    return json({ mode: "admin" });
  }
  return json(await newChallenge(u, purpose));
}

type Challenge = { token_hash: string; user_id: number; purpose: string; channel: string; dest: string; code_hash: string | null; sends: number; attempts: number; last_sent: number; remember: number; expires_at: number; verified_at: number | null };
async function loadChallenge(tok: unknown): Promise<Challenge> {
  const t = str(tok, 100);
  const c = t ? await db().prepare("SELECT * FROM otp_challenges WHERE token_hash = ?").bind(await sha256(t)).first<Challenge>() : null;
  if (!c || c.expires_at < now() || c.verified_at) throw new HttpError(410, "Phiên xác minh đã hết hạn. Vui lòng thực hiện lại.");
  return c;
}
async function otpSend(req: Request) {
  const b = await readBody(req);
  const c = await loadChallenge(b.challenge);
  const u = await getUser(c.user_id);
  if (!u) throw new HttpError(410, "Phiên xác minh đã hết hạn. Vui lòng thực hiện lại.");
  const channel = b.channel === "sms" ? "sms" : "email";
  if (!channelsOf(u).some((x) => x.type === channel)) throw new HttpError(400, channel === "sms" ? "Chưa thể gửi SMS lúc này, vui lòng chọn email." : "Chưa thể gửi email lúc này, vui lòng chọn SMS.");
  const wait = Math.ceil((c.last_sent + 45_000 - now()) / 1000);
  if (wait > 0) throw new HttpError(429, `Vui lòng đợi ${wait} giây rồi gửi lại mã.`, { wait });
  if (c.sends >= 5) throw new HttpError(429, "Bạn đã yêu cầu gửi mã quá nhiều lần. Vui lòng thực hiện lại sau.");
  const dest = channel === "sms" ? u.phone : u.email;
  await limit(`otpdest:${dest}`, 8, HOUR, "Địa chỉ nhận này đã nhận quá nhiều mã. Vui lòng thử lại sau 1 giờ.");
  await limit(`otpip:${clientIp(req)}`, 25, HOUR);
  let codeHash: string | null = null;
  if (channel === "sms") await sendSmsCode(dest);
  else {
    const code = randomCode();
    codeHash = await sha256(c.token_hash + code);
    const ok = await sendMail(dest, `${code} là mã xác minh Hoàng Dũng Real Estate`, mailLayout(
      `Mã ${PURPOSE_TEXT[c.purpose] ?? "xác minh"} của bạn`,
      `Chào ${escHtml(u.name)},<br>Nhập mã dưới đây để ${PURPOSE_TEXT[c.purpose] ?? "xác minh"}. Mã có hiệu lực trong 10 phút. Tuyệt đối không chia sẻ mã này cho bất kỳ ai, kể cả nhân viên Hoàng Dũng Real Estate.`,
      `<p style="margin:22px 0;font-size:34px;letter-spacing:10px;font-weight:bold;color:#121417">${code}</p><p style="font-size:12px;color:#8a9099">Nếu bạn không thực hiện yêu cầu này, hãy bỏ qua email và cân nhắc đổi mật khẩu.</p>`));
    if (!ok) throw new HttpError(502, "Chưa gửi được email. Vui lòng thử lại hoặc chọn nhận mã qua SMS.");
  }
  await db().prepare("UPDATE otp_challenges SET channel = ?, dest = ?, code_hash = ?, sends = sends + 1, attempts = 0, last_sent = ?, expires_at = ? WHERE token_hash = ?").bind(channel, dest, codeHash, now(), Math.max(c.expires_at, now() + OTP_TTL), c.token_hash).run();
  return json({ sent: true, channel, masked: channel === "sms" ? maskPhone(dest) : maskEmail(dest), wait: 45 });
}
async function otpVerify(req: Request) {
  const b = await readBody(req);
  const c = await loadChallenge(b.challenge);
  const code = str(b.code, 12).replace(/\D/g, "");
  if (!c.channel || !c.last_sent) throw new HttpError(400, "Vui lòng chọn nơi nhận mã và bấm gửi mã trước.");
  if (now() - c.last_sent > OTP_TTL) throw new HttpError(410, "Mã đã hết hạn. Vui lòng gửi lại mã mới.");
  if (c.attempts >= 5) throw new HttpError(429, "Bạn đã nhập sai quá 5 lần. Vui lòng gửi lại mã mới.");
  if (code.length !== 6) throw new HttpError(400, "Mã xác minh gồm 6 chữ số.");
  await db().prepare("UPDATE otp_challenges SET attempts = attempts + 1 WHERE token_hash = ?").bind(c.token_hash).run();
  const ok = c.channel === "sms" ? await checkSmsCode(c.dest, code) : !!c.code_hash && safeEq(await sha256(c.token_hash + code), c.code_hash);
  if (!ok) throw new HttpError(400, `Mã chưa đúng. Bạn còn ${Math.max(0, 4 - c.attempts)} lần thử.`);
  await db().prepare("UPDATE otp_challenges SET verified_at = ? WHERE token_hash = ?").bind(now(), c.token_hash).run();
  await db().prepare(`UPDATE users SET ${c.channel === "sms" ? "phone_verified" : "email_verified"} = 1 WHERE id = ?`).bind(c.user_id).run();
  const u = (await getUser(c.user_id)) as User;
  if (u.status !== "active") throw new HttpError(403, `Tài khoản đang tạm khoá. Vui lòng liên hệ ${HOTLINE}.`);
  if (c.purpose === "reset") {
    const rt = randomToken();
    await db().prepare("INSERT INTO tokens (token_hash, user_id, purpose, expires_at) VALUES (?, ?, 'reset', ?)").bind(await sha256(rt), u.id, now() + 15 * MIN).run();
    return json({ resetToken: rt });
  }
  return json({ user: publicUser(u) }, 200, await loginCookies(req, u, !!c.remember, b.trust === true));
}

async function reset(req: Request) {
  const b = await readBody(req);
  const tok = str(b.token, 100), pass = typeof b.pass === "string" ? b.pass : "";
  if (pass.length < 8 || pass.length > 128) throw new HttpError(400, "Mật khẩu mới cần từ 8 đến 128 ký tự.");
  await limit(`resetpw:${clientIp(req)}`, 10, HOUR);
  const th = await sha256(tok);
  const t = tok ? await db().prepare("SELECT user_id FROM tokens WHERE token_hash = ? AND purpose = 'reset' AND used_at IS NULL AND expires_at > ?").bind(th, now()).first<{ user_id: number }>() : null;
  if (!t) throw new HttpError(400, "Phiên đặt lại mật khẩu đã hết hạn. Vui lòng thực hiện lại.");
  const h = await hashPass(pass);
  const d = db();
  await d.batch([
    d.prepare("UPDATE users SET pass_hash = ?, pass_salt = ?, pass_iter = ? WHERE id = ?").bind(h.hash, h.salt, h.iter, t.user_id),
    d.prepare("UPDATE tokens SET used_at = ? WHERE token_hash = ?").bind(now(), th),
    d.prepare("DELETE FROM sessions WHERE kind = 'user' AND subject_id = ?").bind(t.user_id),
    d.prepare("DELETE FROM trusted_devices WHERE user_id = ?").bind(t.user_id),
    d.prepare("UPDATE reset_requests SET status = 'done', handled_at = ?, note = 'Khách tự khôi phục bằng mã xác minh' WHERE user_id = ? AND status = 'pending'").bind(now(), t.user_id),
  ]);
  return json({ ok: true }, 200, [cookie(DEVICE_COOKIE, "", 0)]);
}

async function changePassword(req: Request) {
  const u = await requireUser(req);
  const b = await readBody(req);
  const old = typeof b.old === "string" ? b.old : "", pass = typeof b.pass === "string" ? b.pass : "";
  if (pass.length < 8 || pass.length > 128) throw new HttpError(400, "Mật khẩu mới cần từ 8 đến 128 ký tự.");
  await limit(`chpw:${u.id}`, 8, 15 * MIN);
  if (!(await checkPass(old, u.pass_salt, u.pass_hash, u.pass_iter || 100_000))) throw new HttpError(400, "Mật khẩu hiện tại chưa đúng.");
  const h = await hashPass(pass);
  const keep = await sha256(getCookie(req, USER_COOKIE));
  const d = db();
  await d.batch([
    d.prepare("UPDATE users SET pass_hash = ?, pass_salt = ?, pass_iter = ? WHERE id = ?").bind(h.hash, h.salt, h.iter, u.id),
    d.prepare("DELETE FROM sessions WHERE kind = 'user' AND subject_id = ? AND token_hash != ?").bind(u.id, keep),
  ]);
  return json({ ok: true });
}

async function devices(req: Request) {
  const u = await requireUser(req);
  const cur = getCookie(req, DEVICE_COOKIE);
  const curHash = cur ? await sha256(cur) : "";
  if (req.method === "GET") {
    const rows = (await db().prepare("SELECT id, token_hash, label, created_at, last_used FROM trusted_devices WHERE user_id = ? AND expires_at > ? ORDER BY last_used DESC").bind(u.id, now()).all<{ id: number; token_hash: string; label: string; created_at: number; last_used: number }>()).results;
    return json({ rows: rows.map((r) => ({ id: r.id, label: r.label, created_at: r.created_at, last_used: r.last_used, current: r.token_hash === curHash })) });
  }
  const b = await readBody(req);
  if (b.id === "all") {
    await db().prepare("DELETE FROM trusted_devices WHERE user_id = ?").bind(u.id).run();
    return json({ ok: true }, 200, [cookie(DEVICE_COOKIE, "", 0)]);
  }
  if (b.id === "current") {
    if (curHash) await db().prepare("DELETE FROM trusted_devices WHERE user_id = ? AND token_hash = ?").bind(u.id, curHash).run();
    return json({ ok: true }, 200, [cookie(DEVICE_COOKIE, "", 0)]);
  }
  const row = await db().prepare("SELECT token_hash FROM trusted_devices WHERE user_id = ? AND id = ?").bind(u.id, Number(b.id)).first<{ token_hash: string }>();
  await db().prepare("DELETE FROM trusted_devices WHERE user_id = ? AND id = ?").bind(u.id, Number(b.id)).run();
  return json({ ok: true }, 200, row && row.token_hash === curHash ? [cookie(DEVICE_COOKIE, "", 0)] : []);
}
async function trustCurrent(req: Request) {
  await readBody(req);
  const u = await requireUser(req);
  return json({ ok: true }, 200, [await trustDevice(req, u.id)]);
}

async function favs(req: Request) {
  const u = await requireUser(req);
  if (req.method === "GET") {
    const r = await db().prepare("SELECT ids FROM favorites WHERE user_id = ?").bind(u.id).first<{ ids: string }>();
    return json({ ids: r ? JSON.parse(r.ids) : [] });
  }
  const b = await readBody(req);
  const ids = Array.isArray(b.ids) ? [...new Set(b.ids.filter((x) => Number.isInteger(x) && (x as number) > 0 && (x as number) < 1e6))].slice(0, 300) : [];
  await db().prepare("INSERT INTO favorites (user_id, ids, updated_at) VALUES (?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET ids = excluded.ids, updated_at = excluded.updated_at").bind(u.id, JSON.stringify(ids), now()).run();
  return json({ ok: true, ids });
}

async function lead(req: Request) {
  const b = await readBody(req);
  const form = str(b.form, 30) || "contact", kind = str(b.kind, 60) || "Yêu cầu";
  const raw = b.fields && typeof b.fields === "object" && !Array.isArray(b.fields) ? (b.fields as Row) : {};
  const fields: Record<string, string> = {};
  for (const [k, v] of Object.entries(raw).slice(0, 20)) fields[str(k, 30)] = str(v, 2000);
  const name = fields.name ?? "", phone = toE164("84", fields.phone ?? "") || (fields.phone ?? "").replace(/[^\d+]/g, "");
  if (name.length < 2) throw new HttpError(400, "Vui lòng nhập họ tên.");
  if (phone.replace(/\D/g, "").length < 9) throw new HttpError(400, "Số điện thoại chưa đúng.");
  await limit(`lead:${clientIp(req)}`, 15, HOUR);
  const u = await currentUser(req);
  const text = str(b.text, 4000);
  await db().prepare("INSERT INTO leads (form, kind, name, phone, fields, text, user_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)").bind(form, kind, name, phone, JSON.stringify(fields), text, u?.id ?? null, now(), now()).run();
  const to = env().NOTIFY_EMAIL;
  if (to && mailReady()) await sendMail(to, `[Website] ${kind} – ${name}`, mailLayout(`${escHtml(kind)} mới`, `<pre style="white-space:pre-wrap;font-family:inherit">${escHtml(text)}</pre>`, `<p><a href="${new URL(req.url).origin}/admin">Mở trang quản trị</a></p>`));
  return json({ ok: true }, 201);
}

/* ================= QUẢN TRỊ ================= */
async function adminState(req: Request) {
  const n = await db().prepare("SELECT COUNT(*) AS n FROM admins").first<{ n: number }>();
  let admin: Admin | null = null;
  try { admin = await requireAdmin(req); } catch { admin = null; }
  return json({ setup: (n?.n ?? 0) === 0, admin, mail: mailReady(), sms: smsReady() });
}
async function adminSetup(req: Request) {
  const b = await readBody(req);
  await limit(`asetup:${clientIp(req)}`, 5, HOUR);
  const n = await db().prepare("SELECT COUNT(*) AS n FROM admins").first<{ n: number }>();
  if ((n?.n ?? 0) > 0) throw new HttpError(403, "Hệ thống đã có quản trị viên.");
  if (!safeEq(await sha256(str(b.code, 100)), SETUP_HASH)) throw new HttpError(403, "Mã khởi tạo không đúng.");
  const email = str(b.email, 160).toLowerCase(), name = str(b.name, 80), pass = typeof b.pass === "string" ? b.pass : "";
  if (!isEmail(email) || name.length < 2 || pass.length < 10) throw new HttpError(400, "Thông tin quản trị viên chưa hợp lệ (mật khẩu tối thiểu 10 ký tự).");
  const { salt, hash, iter } = await hashPass(pass);
  await db().prepare("INSERT INTO admins (email, name, pass_hash, pass_salt, pass_iter, created_at) VALUES (?, ?, ?, ?, ?, ?)").bind(email, name, hash, salt, iter, now()).run();
  return json({ ok: true }, 201);
}
async function adminLogin(req: Request) {
  const b = await readBody(req);
  const email = str(b.email, 160).toLowerCase(), pass = typeof b.pass === "string" ? b.pass.slice(0, 128) : "";
  await limit(`alogin:${clientIp(req)}`, 8, 15 * MIN);
  const a = await db().prepare("SELECT * FROM admins WHERE email = ?").bind(email).first<Admin & { pass_hash: string; pass_salt: string; pass_iter: number }>();
  if (!a || !(await checkPass(pass, a.pass_salt, a.pass_hash, a.pass_iter || 100_000))) throw new HttpError(401, "Email hoặc mật khẩu quản trị chưa đúng.");
  await db().prepare("UPDATE admins SET last_login = ? WHERE id = ?").bind(now(), a.id).run();
  const tok = await newSession("admin", a.id, DAY / 2);
  return json({ admin: { id: a.id, email: a.email, name: a.name } }, 200, [cookie(ADMIN_COOKIE, tok, 12 * 3600, "Strict")]);
}
async function adminStats(req: Request) {
  await requireAdmin(req);
  const d = db(), t = now();
  const q = async (sql: string, ...v: unknown[]) => ((await d.prepare(sql).bind(...v).first<{ n: number }>())?.n ?? 0);
  const [users, users7, leads, leadsNew, leads7, resets, active30, trusted, daily] = await Promise.all([
    q("SELECT COUNT(*) AS n FROM users"),
    q("SELECT COUNT(*) AS n FROM users WHERE created_at > ?", t - 7 * DAY),
    q("SELECT COUNT(*) AS n FROM leads"),
    q("SELECT COUNT(*) AS n FROM leads WHERE status = 'new'"),
    q("SELECT COUNT(*) AS n FROM leads WHERE created_at > ?", t - 7 * DAY),
    q("SELECT COUNT(*) AS n FROM reset_requests WHERE status = 'pending'"),
    q("SELECT COUNT(*) AS n FROM users WHERE last_login > ?", t - 30 * DAY),
    q("SELECT COUNT(*) AS n FROM trusted_devices WHERE expires_at > ?", t),
    d.prepare("SELECT strftime('%Y-%m-%d', created_at / 1000, 'unixepoch', '+7 hours') AS day, COUNT(*) AS n FROM leads WHERE created_at > ? GROUP BY day ORDER BY day").bind(t - 14 * DAY).all<{ day: string; n: number }>(),
  ]);
  return json({ users, users7, leads, leadsNew, leads7, resets, active30, trusted, mail: mailReady(), sms: smsReady(), daily: daily.results });
}
const likeQ = (q: string) => `%${q.replace(/[%_\\]/g, (c) => "\\" + c)}%`;
async function adminUsers(req: Request) {
  await requireAdmin(req);
  const u = new URL(req.url), q = str(u.searchParams.get("q"), 80), off = Math.max(0, Math.floor(Number(u.searchParams.get("offset")) || 0));
  const where = q ? "WHERE u.email LIKE ?1 ESCAPE '\\' OR u.name LIKE ?1 ESCAPE '\\' OR u.phone LIKE ?1 ESCAPE '\\'" : "";
  const sql = `SELECT u.id, u.email, u.phone, u.name, u.role, u.email_verified, u.phone_verified, u.status, u.marketing, u.created_at, u.last_login, (SELECT COUNT(*) FROM trusted_devices t WHERE t.user_id = u.id AND t.expires_at > ${now()}) AS devices FROM users u ${where} ORDER BY u.id DESC LIMIT 50 OFFSET ${off}`;
  const rows = (q ? await db().prepare(sql).bind(likeQ(q)).all() : await db().prepare(sql).all()).results;
  const tsql = `SELECT COUNT(*) AS n FROM users u ${where}`;
  const n = (q ? await db().prepare(tsql).bind(likeQ(q)).first<{ n: number }>() : await db().prepare(tsql).first<{ n: number }>())?.n ?? 0;
  return json({ rows, total: n });
}
async function adminUserAction(req: Request) {
  const a = await requireAdmin(req);
  const b = await readBody(req);
  const id = Number(b.id), action = str(b.action, 20);
  const u = await getUser(id);
  if (!u) throw new HttpError(404, "Không tìm thấy tài khoản.");
  const d = db();
  if (action === "disable" || action === "enable") {
    await d.prepare("UPDATE users SET status = ? WHERE id = ?").bind(action === "disable" ? "disabled" : "active", id).run();
    if (action === "disable") await d.batch([d.prepare("DELETE FROM sessions WHERE kind = 'user' AND subject_id = ?").bind(id), d.prepare("DELETE FROM trusted_devices WHERE user_id = ?").bind(id)]);
    return json({ ok: true });
  }
  if (action === "verify") { await d.prepare("UPDATE users SET email_verified = 1 WHERE id = ?").bind(id).run(); return json({ ok: true }); }
  if (action === "revoke-devices") { await d.prepare("DELETE FROM trusted_devices WHERE user_id = ?").bind(id).run(); return json({ ok: true }); }
  if (action === "temp-password") {
    const temp = tempPassword();
    const h = await hashPass(temp);
    await d.batch([
      d.prepare("UPDATE users SET pass_hash = ?, pass_salt = ?, pass_iter = ? WHERE id = ?").bind(h.hash, h.salt, h.iter, id),
      d.prepare("DELETE FROM sessions WHERE kind = 'user' AND subject_id = ?").bind(id),
      d.prepare("DELETE FROM trusted_devices WHERE user_id = ?").bind(id),
      d.prepare("UPDATE reset_requests SET status = 'done', handled_at = ?, note = ? WHERE user_id = ? AND status = 'pending'").bind(now(), `Cấp mật khẩu tạm bởi ${a.email}`, id),
    ]);
    return json({ ok: true, temp });
  }
  throw new HttpError(400, "Thao tác không hợp lệ.");
}
const LEAD_STATUS = ["new", "contacted", "deal", "closed", "spam"];
async function adminLeads(req: Request) {
  await requireAdmin(req);
  const u = new URL(req.url), q = str(u.searchParams.get("q"), 80), s = str(u.searchParams.get("status"), 20), off = Math.max(0, Math.floor(Number(u.searchParams.get("offset")) || 0));
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
  await db().prepare("UPDATE leads SET status = COALESCE(NULLIF(?, ''), status), note = COALESCE(?, note), updated_at = ? WHERE id = ?").bind(status, note, now(), id).run();
  return json({ ok: true });
}
async function adminResets(req: Request) {
  await requireAdmin(req);
  const s = str(new URL(req.url).searchParams.get("status"), 20) || "pending";
  const rows = (await db().prepare("SELECT r.*, u.name AS user_name, u.phone AS user_phone FROM reset_requests r LEFT JOIN users u ON u.id = r.user_id WHERE r.status = ? ORDER BY r.id DESC LIMIT 100").bind(s === "done" ? "done" : "pending").all()).results;
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
  await limit(`apw:${a.id}`, 6, 15 * MIN);
  const row = await db().prepare("SELECT pass_hash, pass_salt, pass_iter FROM admins WHERE id = ?").bind(a.id).first<{ pass_hash: string; pass_salt: string; pass_iter: number }>();
  if (!row || !(await checkPass(old, row.pass_salt, row.pass_hash, row.pass_iter || 100_000))) throw new HttpError(400, "Mật khẩu hiện tại chưa đúng.");
  const { salt, hash, iter } = await hashPass(pass);
  const keep = await sha256(getCookie(req, ADMIN_COOKIE));
  const d = db();
  await d.batch([
    d.prepare("UPDATE admins SET pass_hash = ?, pass_salt = ?, pass_iter = ? WHERE id = ?").bind(hash, salt, iter, a.id),
    d.prepare("DELETE FROM sessions WHERE kind = 'admin' AND subject_id = ? AND token_hash != ?").bind(a.id, keep),
  ]);
  return json({ ok: true });
}
async function adminAdmins(req: Request) {
  await requireAdmin(req);
  if (req.method === "GET") return json({ rows: (await db().prepare("SELECT id, email, name, created_at, last_login FROM admins ORDER BY id").all()).results });
  const b = await readBody(req);
  const email = str(b.email, 160).toLowerCase(), name = str(b.name, 80), pass = typeof b.pass === "string" ? b.pass : "";
  if (!isEmail(email) || name.length < 2 || pass.length < 10) throw new HttpError(400, "Nhập đủ họ tên, email và mật khẩu (tối thiểu 10 ký tự).");
  if (await db().prepare("SELECT id FROM admins WHERE email = ?").bind(email).first()) throw new HttpError(409, "Email này đã là quản trị viên.");
  const { salt, hash, iter } = await hashPass(pass);
  await db().prepare("INSERT INTO admins (email, name, pass_hash, pass_salt, pass_iter, created_at) VALUES (?, ?, ?, ?, ?, ?)").bind(email, name, hash, salt, iter, now()).run();
  return json({ ok: true }, 201);
}
function csvCell(v: unknown) {
  let s = v === null || v === undefined ? "" : String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; // chặn công thức độc hại khi mở bằng Excel
  return `"${s.replace(/"/g, '""')}"`;
}
const fmtTime = (ms: unknown) => (typeof ms === "number" && ms > 0 ? new Date(ms + 7 * HOUR).toISOString().replace("T", " ").slice(0, 16) : "");
async function adminExport(req: Request) {
  await requireAdmin(req);
  const what = new URL(req.url).searchParams.get("what");
  let head: string[], rows: unknown[][];
  if (what === "users") {
    const r = (await db().prepare("SELECT * FROM users ORDER BY id").all<Row>()).results;
    head = ["ID", "Họ tên", "Email", "Điện thoại", "Vai trò", "Email đã xác minh", "SĐT đã xác minh", "Trạng thái", "Nhận tư vấn", "Ngày tạo", "Đăng nhập gần nhất"];
    rows = r.map((u) => [u.id, u.name, u.email, u.phone, u.role, u.email_verified ? "Có" : "Chưa", u.phone_verified ? "Có" : "Chưa", u.status === "active" ? "Hoạt động" : "Tạm khoá", u.marketing ? "Có" : "Không", fmtTime(u.created_at), fmtTime(u.last_login)]);
  } else {
    const SL: Record<string, string> = { new: "Mới", contacted: "Đã liên hệ", deal: "Đang thương lượng", closed: "Đã chốt", spam: "Rác" };
    const r = (await db().prepare("SELECT * FROM leads ORDER BY id").all<Row>()).results;
    head = ["ID", "Loại", "Họ tên", "Điện thoại", "Nội dung", "Trạng thái", "Ghi chú", "Thời gian"];
    rows = r.map((l) => [l.id, l.kind, l.name, l.phone, l.text, SL[l.status as string] ?? l.status, l.note, fmtTime(l.created_at)]);
  }
  return new Response("﻿" + [head, ...rows].map((r) => r.map(csvCell).join(",")).join("\r\n"), {
    headers: { "Content-Type": "text/csv; charset=utf-8", "Content-Disposition": `attachment; filename="${what === "users" ? "khach-hang" : "yeu-cau-tu-van"}.csv"`, "Cache-Control": "no-store" },
  });
}

/* ================= ĐIỀU HƯỚNG ================= */
type Handler = (req: Request) => Promise<Response>;
const ROUTES: Record<string, Partial<Record<"GET" | "POST", Handler>>> = {
  "health": { GET: async () => json({ ok: true, db: !!env().DB, mail: mailReady(), sms: smsReady() }) },
  "auth/config": { GET: async () => json({ mail: mailReady(), sms: smsReady() }) },
  "auth/me": { GET: async (r) => { const u = await currentUser(r); return json({ user: u ? publicUser(u) : null }); } },
  "auth/register": { POST: register },
  "auth/login": { POST: login },
  "auth/logout": { POST: async (r) => { await readBody(r); await dropSession(r, "user"); return json({ ok: true }, 200, [cookie(USER_COOKIE, "", 0)]); } },
  "auth/code/start": { POST: codeStart },
  "auth/otp/send": { POST: otpSend },
  "auth/otp/verify": { POST: otpVerify },
  "auth/reset": { POST: reset },
  "auth/password": { POST: changePassword },
  "auth/devices": { GET: devices, POST: devices },
  "auth/devices/trust": { POST: trustCurrent },
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

export async function handleApi(request: Request, path: string, environment: Env): Promise<Response> {
  ENV = environment; // cấu hình giống nhau cho mọi yêu cầu trong cùng Worker
  const route = ROUTES[path.replace(/^\/+|\/+$/g, "")];
  const method = request.method as "GET" | "POST";
  if (!route) return json({ error: "Không tìm thấy." }, 404);
  const fn = route[method];
  if (!fn) return json({ error: "Phương thức không được hỗ trợ." }, 405);
  try {
    await ensureSchema();
    return await fn(request);
  } catch (e) {
    if (e instanceof HttpError) return json({ error: e.message, ...e.extra }, e.status);
    console.error(e);
    return json({ error: "Hệ thống đang bận, vui lòng thử lại sau ít phút." }, 500);
  }
}
