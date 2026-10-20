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
  GOOGLE_CLIENT_ID?: string;
  GOOGLE_CLIENT_SECRET?: string;
  FACEBOOK_APP_ID?: string;
  FACEBOOK_APP_SECRET?: string;
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
export const COMMIT_VERSION = "1.1"; // phiên bản Cam kết bảo mật thông tin nguồn hàng (/cam-ket-nguon-hang)

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
  `CREATE TABLE IF NOT EXISTS change_requests (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, topic TEXT NOT NULL, message TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'pending', note TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL, handled_at INTEGER, handled_by TEXT NOT NULL DEFAULT '')`,
  `CREATE INDEX IF NOT EXISTS change_requests_status ON change_requests(status, created_at)`,
  `CREATE TABLE IF NOT EXISTS account_events (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, kind TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '', actor TEXT NOT NULL DEFAULT '', at INTEGER NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS account_events_user ON account_events(user_id, at)`,
  `CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '')`,
  `CREATE TABLE IF NOT EXISTS identities (provider TEXT NOT NULL, subject TEXT NOT NULL, user_id INTEGER NOT NULL, email TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL, PRIMARY KEY (provider, subject))`,
  `CREATE INDEX IF NOT EXISTS identities_user ON identities(user_id)`,
  `CREATE TABLE IF NOT EXISTS oauth_states (state_hash TEXT PRIMARY KEY, provider TEXT NOT NULL, verifier TEXT NOT NULL, link_user_id INTEGER, expires_at INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS listings (id INTEGER PRIMARY KEY AUTOINCREMENT, type TEXT NOT NULL DEFAULT 'ban', title TEXT NOT NULL, area TEXT NOT NULL DEFAULT '', price REAL NOT NULL DEFAULT 0, size REAL NOT NULL DEFAULT 0, dim TEXT NOT NULL DEFAULT '', beds INTEGER NOT NULL DEFAULT 0, floors INTEGER NOT NULL DEFAULT 0, legal TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '', images TEXT NOT NULL DEFAULT '[]', status TEXT NOT NULL DEFAULT 'published', featured INTEGER NOT NULL DEFAULT 0, sort INTEGER NOT NULL DEFAULT 0, created_by TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS listings_status ON listings(status, sort)`,
  `CREATE TABLE IF NOT EXISTS media (id TEXT PRIMARY KEY, mime TEXT NOT NULL, data TEXT NOT NULL, size INTEGER NOT NULL, created_by TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS creators (user_id INTEGER PRIMARY KEY, display_name TEXT NOT NULL, tiktok TEXT NOT NULL DEFAULT '', youtube TEXT NOT NULL DEFAULT '', facebook TEXT NOT NULL DEFAULT '', intro TEXT NOT NULL DEFAULT '', video TEXT NOT NULL DEFAULT '', followers TEXT NOT NULL DEFAULT '', cover TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'pending', featured INTEGER NOT NULL DEFAULT 0, sort INTEGER NOT NULL DEFAULT 0, note TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, reviewed_at INTEGER, reviewed_by TEXT NOT NULL DEFAULT '')`,
  `CREATE TABLE IF NOT EXISTS login_events (id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, subject_id INTEGER NOT NULL, ok INTEGER NOT NULL DEFAULT 1, method TEXT NOT NULL DEFAULT '', ip TEXT NOT NULL DEFAULT '', loc TEXT NOT NULL DEFAULT '', label TEXT NOT NULL DEFAULT '', sid TEXT NOT NULL DEFAULT '', at INTEGER NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS login_events_subject ON login_events(kind, subject_id, at)`,
  `CREATE TABLE IF NOT EXISTS visits (id INTEGER PRIMARY KEY AUTOINCREMENT, day TEXT NOT NULL, at INTEGER NOT NULL, vh TEXT NOT NULL, ev TEXT NOT NULL DEFAULT 'view', path TEXT NOT NULL DEFAULT '', ref TEXT NOT NULL DEFAULT '', country TEXT NOT NULL DEFAULT '', device TEXT NOT NULL DEFAULT '', lid INTEGER)`,
  `CREATE INDEX IF NOT EXISTS visits_day ON visits(day, ev)`,
  `CREATE INDEX IF NOT EXISTS visits_at ON visits(at)`,
];
const ADD_COLUMNS = [
  `ALTER TABLE users ADD COLUMN phone_cc TEXT NOT NULL DEFAULT ''`,
  `ALTER TABLE users ADD COLUMN phone_verified INTEGER NOT NULL DEFAULT 0`,
  `ALTER TABLE users ADD COLUMN pass_iter INTEGER NOT NULL DEFAULT 100000`,
  `ALTER TABLE admins ADD COLUMN pass_iter INTEGER NOT NULL DEFAULT 100000`,
  `ALTER TABLE users ADD COLUMN name_changes INTEGER NOT NULL DEFAULT 0`,
  `ALTER TABLE users ADD COLUMN profile TEXT NOT NULL DEFAULT ''`,
  `ALTER TABLE users ADD COLUMN profile_at INTEGER`,
  `ALTER TABLE otp_challenges ADD COLUMN meta TEXT NOT NULL DEFAULT ''`,
  `ALTER TABLE admins ADD COLUMN role TEXT NOT NULL DEFAULT 'director'`, // quản trị viên có sẵn trước khi phân quyền = Giám đốc
  `ALTER TABLE users ADD COLUMN has_pass INTEGER NOT NULL DEFAULT 1`,
  `ALTER TABLE users ADD COLUMN needs_onboarding INTEGER NOT NULL DEFAULT 0`,
  `ALTER TABLE users ADD COLUMN avatar TEXT NOT NULL DEFAULT ''`,
  `ALTER TABLE users ADD COLUMN creator TEXT NOT NULL DEFAULT ''`,
  `ALTER TABLE users ADD COLUMN terms_at INTEGER`,
  `ALTER TABLE users ADD COLUMN no_autolink INTEGER NOT NULL DEFAULT 0`,
  `CREATE INDEX IF NOT EXISTS visits_lid ON visits(ev, lid)`,
  `ALTER TABLE sessions ADD COLUMN ip TEXT NOT NULL DEFAULT ''`,
  `ALTER TABLE sessions ADD COLUMN label TEXT NOT NULL DEFAULT ''`,
  `ALTER TABLE sessions ADD COLUMN loc TEXT NOT NULL DEFAULT ''`,
  `ALTER TABLE sessions ADD COLUMN last_seen INTEGER`,
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
      await seedListings();
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
async function readBody(req: Request, max = 64_000): Promise<Row> {
  if (!(req.headers.get("Content-Type") ?? "").includes("application/json")) throw new HttpError(415, "Yêu cầu không hợp lệ.");
  const origin = req.headers.get("Origin");
  if (origin && origin !== new URL(req.url).origin) throw new HttpError(403, "Nguồn yêu cầu không hợp lệ.");
  const t = await req.text();
  if (t.length > max) throw new HttpError(413, "Dữ liệu gửi lên quá lớn.");
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

/** Vị trí gần đúng từ mạng (Cloudflare cung cấp), dùng cho lịch sử đăng nhập. */
function reqMeta(req: Request) {
  const cf = ((req as unknown as { cf?: Row }).cf ?? {}) as Row;
  const city = str(cf.city, 60), region = str(cf.region, 60), country = str(cf.country, 4);
  const loc = [city, region && region !== city ? region : "", country].filter(Boolean).join(", ");
  return { ip: clientIp(req).slice(0, 45), loc, label: deviceLabel(req), country };
}
async function logLogin(kind: "user" | "admin", id: number, ok: boolean, method: string, req: Request, sid = "") {
  const m = reqMeta(req);
  try {
    await db().prepare("INSERT INTO login_events (kind, subject_id, ok, method, ip, loc, label, sid, at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)").bind(kind, id, ok ? 1 : 0, method, m.ip, m.loc, m.label, sid, now()).run();
    if (crypto.getRandomValues(new Uint8Array(1))[0] < 3) await db().prepare("DELETE FROM login_events WHERE at < ?").bind(now() - 400 * DAY).run();
  } catch (e) { console.error("login log", e); }
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
const PURPOSE_TEXT: Record<string, string> = { login: "đăng nhập", register: "xác minh tài khoản mới", reset: "khôi phục tài khoản", "change-email": "xác minh email mới", "change-phone": "xác minh số điện thoại mới" };
/** Gửi mã 6 số tới một đích (SMS qua Twilio Verify, email qua Brevo/Resend). Trả về bản băm mã khi gửi email. */
async function deliverCode(challengeHash: string, channel: "sms" | "email", dest: string, purpose: string, name: string): Promise<string | null> {
  if (channel === "sms") { await sendSmsCode(dest); return null; }
  const code = randomCode();
  const text = PURPOSE_TEXT[purpose] ?? "xác minh";
  const ok = await sendMail(dest, `${code} là mã xác minh Hoàng Dũng Real Estate`, mailLayout(
    `Mã ${text} của bạn`,
    `Chào ${escHtml(name)},<br>Nhập mã dưới đây để ${text}. Mã có hiệu lực trong 10 phút. Tuyệt đối không chia sẻ mã này cho bất kỳ ai, kể cả nhân viên Hoàng Dũng Real Estate.`,
    `<p style="margin:22px 0;font-size:34px;letter-spacing:10px;font-weight:bold;color:#121417">${code}</p><p style="font-size:12px;color:#8a9099">Nếu bạn không thực hiện yêu cầu này, hãy bỏ qua email và cân nhắc đổi mật khẩu.</p>`));
  if (!ok) throw new HttpError(502, "Chưa gửi được email. Vui lòng thử lại sau ít phút.");
  return sha256(challengeHash + code);
}
async function logEvent(userId: number, kind: string, detail = "", actor = "") {
  try { await db().prepare("INSERT INTO account_events (user_id, kind, detail, actor, at) VALUES (?, ?, ?, ?, ?)").bind(userId, kind, detail.slice(0, 300), actor.slice(0, 160), now()).run(); } catch (e) { console.error("log", e); }
}
async function notifyAdmin(origin: string, subject: string, body: string) {
  const to = env().NOTIFY_EMAIL;
  if (to && mailReady()) await sendMail(to, subject, mailLayout(escHtml(subject), body, `<p><a href="${origin}/admin">Mở trang quản trị</a></p>`));
}

/* ---------------- người dùng, phiên, thiết bị ---------------- */
type User = {
  id: number; email: string; phone: string; phone_cc: string; name: string; role: string;
  email_verified: number; phone_verified: number; status: string; created_at: number;
  pass_hash: string; pass_salt: string; pass_iter: number;
  name_changes: number; profile: string; profile_at: number | null;
  has_pass: number; needs_onboarding: number; avatar: string; creator: string; terms_at: number | null; no_autolink: number;
};
const PLACEHOLDER_MAIL = "@social.invalid";
type Admin = { id: number; email: string; name: string; role: string };
/* Phân quyền quản trị: Trợ lý (1) < Quản lý (2) < Giám đốc (3) */
export const ADMIN_ROLES: Record<string, { level: number; label: string }> = { assistant: { level: 1, label: "Trợ lý" }, manager: { level: 2, label: "Quản lý" }, director: { level: 3, label: "Giám đốc" } };
export const PERMS: Record<string, number> = {
  stats: 1, leads: 1, "listings.edit": 1, media: 1, "users.view": 1, "requests.view": 1, "creators.view": 1,
  "listings.delete": 2, "users.manage": 2, "users.cccd": 2, "requests.handle": 2, resets: 2, "creators.manage": 2, analytics: 2, "logins.users": 2,
  "admins.manage": 3, export: 3, settings: 3, "logins.admins": 3,
};
const levelOf = (a: Admin) => ADMIN_ROLES[a.role]?.level ?? 1;
const canMap = (a: Admin) => Object.fromEntries(Object.entries(PERMS).map(([k, v]) => [k, levelOf(a) >= v]));
const adminOut = (a: Admin) => ({ id: a.id, email: a.email, name: a.name, role: ADMIN_ROLES[a.role] ? a.role : "assistant", roleLabel: ADMIN_ROLES[a.role]?.label ?? "Trợ lý", level: levelOf(a), can: canMap(a) });
const publicUser = (u: User) => ({
  id: u.id, name: u.name, email: u.email, phone: u.phone, phoneCc: u.phone_cc, role: u.role,
  emailVerified: !!u.email_verified, phoneVerified: !!u.phone_verified,
  nameLocked: (u.name_changes ?? 0) >= 1, profileLocked: !!u.profile_at,
  hasPass: u.has_pass !== 0, needsOnboarding: !!u.needs_onboarding, avatar: u.avatar || "", creator: u.creator || "",
  emailMissing: (u.email || "").endsWith(PLACEHOLDER_MAIL),
});

/* ---------------- hồ sơ cá nhân (bắt buộc có thông tin CCCD) ---------------- */
type PField = { k: string; max: number; req?: boolean; opts?: string[]; kind?: "date" | "cccd" | "text" };
export const PROFILE_FIELDS: PField[] = [
  { k: "fullName", max: 80, req: true },
  { k: "dob", max: 10, req: true, kind: "date" },
  { k: "gender", max: 10, req: true, opts: ["Nam", "Nữ", "Khác"] },
  { k: "cccd", max: 12, req: true, kind: "cccd" },
  { k: "cccdDate", max: 10, req: true, kind: "date" },
  { k: "cccdPlace", max: 120, req: true },
  { k: "address", max: 200, req: true },
  { k: "currentAddress", max: 200 },
  { k: "occupation", max: 80 },
  { k: "need", max: 40, opts: ["Mua để ở", "Mua đầu tư", "Thuê nhà", "Bán nhà", "Cho thuê", "Tìm hiểu thị trường"] },
  { k: "budget", max: 40, opts: ["Dưới 3 tỷ", "3 – 5 tỷ", "5 – 10 tỷ", "10 – 20 tỷ", "Trên 20 tỷ", "Thuê dưới 15 triệu/tháng", "Thuê từ 15 triệu/tháng"] },
  { k: "areas", max: 120 },
  { k: "contactTime", max: 40, opts: ["Giờ hành chính", "Buổi tối (18h – 21h)", "Cuối tuần", "Bất kỳ lúc nào"] },
];
const PROFILE_LABEL: Record<string, string> = {
  fullName: "Họ và tên theo CCCD", dob: "Ngày sinh", gender: "Giới tính", cccd: "Số CCCD/Căn cước", cccdDate: "Ngày cấp",
  cccdPlace: "Nơi cấp", address: "Địa chỉ thường trú", currentAddress: "Nơi ở hiện tại", occupation: "Nghề nghiệp",
  need: "Nhu cầu chính", budget: "Ngân sách dự kiến", areas: "Khu vực quan tâm", contactTime: "Thời gian liên hệ",
};
const isDate = (s: string) => /^\d{4}-\d{2}-\d{2}$/.test(s) && !Number.isNaN(Date.parse(s + "T00:00:00Z")) && new Date(s + "T00:00:00Z").toISOString().slice(0, 10) === s;
function cleanProfile(raw: unknown): Record<string, string> {
  const src = raw && typeof raw === "object" && !Array.isArray(raw) ? (raw as Row) : {};
  const p: Record<string, string> = {};
  for (const f of PROFILE_FIELDS) {
    let v = str(src[f.k], f.max).replace(/\s+/g, " ");
    if (f.kind === "cccd") v = v.replace(/\D/g, "");
    if (!v) { if (f.req) throw new HttpError(400, `Vui lòng nhập ${PROFILE_LABEL[f.k].toLowerCase()}.`); continue; }
    if (f.opts && !f.opts.includes(v)) throw new HttpError(400, `${PROFILE_LABEL[f.k]} chưa hợp lệ.`);
    if (f.kind === "date" && !isDate(v)) throw new HttpError(400, `${PROFILE_LABEL[f.k]} chưa đúng định dạng.`);
    if (f.kind === "cccd" && !/^0\d{11}$/.test(v)) throw new HttpError(400, "Số CCCD/Căn cước gồm đúng 12 chữ số, bắt đầu bằng số 0.");
    if (f.k === "fullName" && !/^[\p{L}][\p{L} .'-]{1,79}$/u.test(v)) throw new HttpError(400, "Họ và tên chỉ gồm chữ cái và khoảng trắng.");
    p[f.k] = v;
  }
  const today = new Date(now() + 7 * HOUR).toISOString().slice(0, 10);
  const age = (Date.parse(today) - Date.parse(p.dob)) / (365.2425 * DAY);
  if (!(age >= 14 && age <= 120)) throw new HttpError(400, "Ngày sinh chưa hợp lệ.");
  if (p.cccdDate > today) throw new HttpError(400, "Ngày cấp không thể ở tương lai.");
  if (p.cccdDate <= p.dob) throw new HttpError(400, "Ngày cấp phải sau ngày sinh.");
  return p;
}
const parseProfile = (s: string): Record<string, string> => { try { const v = JSON.parse(s || "{}"); return v && typeof v === "object" ? v : {}; } catch { return {}; } };
const maskCccd = (c: string) => (c ? `${c.slice(0, 3)} ••• ••• ${c.slice(-3)}` : "");
const getUser = (id: number) => db().prepare("SELECT * FROM users WHERE id = ?").bind(id).first<User>();
function channelsOf(u: User) {
  const ch: { type: "sms" | "email"; masked: string; verified: boolean }[] = [];
  if (smsReady() && u.phone) ch.push({ type: "sms", masked: maskPhone(u.phone), verified: !!u.phone_verified });
  if (mailReady() && u.email) ch.push({ type: "email", masked: maskEmail(u.email), verified: !!u.email_verified });
  return ch;
}
async function newSession(kind: "user" | "admin", id: number, ttl: number, req?: Request, method = "password") {
  const tok = randomToken(), t = now(), th = await sha256(tok);
  const m = req ? reqMeta(req) : { ip: "", loc: "", label: "" };
  await db().prepare("INSERT INTO sessions (token_hash, kind, subject_id, expires_at, created_at, ip, label, loc, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)").bind(th, kind, id, t + ttl, t, m.ip, m.label, m.loc, t).run();
  if (req) await logLogin(kind, id, true, method, req, th.slice(0, 16));
  return tok;
}
async function sessionSubject(req: Request, kind: "user" | "admin"): Promise<number | null> {
  const tok = getCookie(req, kind === "user" ? USER_COOKIE : ADMIN_COOKIE);
  if (!tok || tok.length > 100) return null;
  const th = await sha256(tok), t = now();
  const r = await db().prepare("SELECT subject_id, last_seen FROM sessions WHERE token_hash = ? AND kind = ? AND expires_at > ?").bind(th, kind, t).first<{ subject_id: number; last_seen: number | null }>();
  if (r && (!r.last_seen || r.last_seen < t - 10 * MIN)) await db().prepare("UPDATE sessions SET last_seen = ? WHERE token_hash = ?").bind(t, th).run();
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
async function requireAdmin(req: Request, perm?: string): Promise<Admin> {
  const id = await sessionSubject(req, "admin");
  const a = id ? await db().prepare("SELECT id, email, name, role FROM admins WHERE id = ?").bind(id).first<Admin>() : null;
  if (!a) throw new HttpError(401, "Vui lòng đăng nhập quản trị.");
  if (perm && levelOf(a) < (PERMS[perm] ?? 3)) throw new HttpError(403, `Vai trò ${ADMIN_ROLES[a.role]?.label ?? "Trợ lý"} chưa có quyền thực hiện thao tác này.`);
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
async function loginCookies(req: Request, u: User, remember: boolean, trust: boolean, method = "password") {
  await db().prepare("UPDATE users SET last_login = ? WHERE id = ?").bind(now(), u.id).run();
  const tok = await newSession("user", u.id, remember ? 30 * DAY : DAY, req, method);
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
  if (b.terms !== true) throw new HttpError(400, "Vui lòng đồng ý Điều khoản dịch vụ và Chính sách bảo mật để tạo tài khoản.");
  await limit(`reg:${clientIp(req)}`, 8, HOUR);
  const d = db();
  if (await d.prepare("SELECT id FROM users WHERE email = ?").bind(email).first()) throw new HttpError(409, "Email này đã có tài khoản. Hãy đăng nhập hoặc dùng “Quên mật khẩu”.");
  if (await d.prepare("SELECT id FROM users WHERE phone = ?").bind(phone).first()) throw new HttpError(409, "Số điện thoại này đã được dùng cho một tài khoản khác.");
  const { salt, hash, iter } = await hashPass(pass);
  const t = now();
  const r = await d.prepare("INSERT INTO users (email, phone, phone_cc, name, role, pass_hash, pass_salt, pass_iter, marketing, created_at, terms_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)").bind(email, phone, cc, name, role, hash, salt, iter, b.agree ? 1 : 0, t, t).run();
  const u = (await getUser(Number(r.meta?.last_row_id))) as User;
  if (channelsOf(u).length) return json(await newChallenge(u, "register"), 201);
  return json({ user: publicUser(u) }, 201, await loginCookies(req, u, true, false, "register"));
}

async function login(req: Request) {
  const b = await readBody(req);
  const pass = typeof b.pass === "string" ? b.pass.slice(0, 128) : "";
  if (!str(b.id, 160) || !pass) throw new HttpError(400, "Vui lòng nhập email (hoặc số điện thoại) và mật khẩu.");
  await limit(`login:${clientIp(req)}`, 12, 15 * MIN);
  const key = str(b.id, 160).includes("@") ? str(b.id, 160).toLowerCase() : toE164(b.cc, b.id) || str(b.id, 40);
  await limit(`login:${key}`, 8, 15 * MIN);
  const u = await findByIdentifier(b);
  if (!u || !u.has_pass || !(await checkPass(pass, u.pass_salt, u.pass_hash, u.pass_iter || 100_000))) {
    if (u) await logLogin("user", u.id, false, "password", req);
    throw new HttpError(401, "Email/số điện thoại hoặc mật khẩu chưa đúng.");
  }
  if (u.status !== "active") throw new HttpError(403, `Tài khoản đang tạm khoá. Vui lòng liên hệ ${HOTLINE}.`);
  if ((u.pass_iter || 100_000) !== targetIter()) { // nâng cấp độ khó băm mật khẩu khi cấu hình thay đổi
    const h = await hashPass(pass);
    await db().prepare("UPDATE users SET pass_hash = ?, pass_salt = ?, pass_iter = ? WHERE id = ?").bind(h.hash, h.salt, h.iter, u.id).run();
  }
  const remember = b.remember !== false;
  const needCode = channelsOf(u).length > 0;
  const trusted = needCode ? await trustedFor(req, u.id) : null;
  if (needCode && !trusted) return json(await newChallenge(u, "login", remember));
  return json({ user: publicUser(u), trusted: !!trusted }, 200, await loginCookies(req, u, remember, false, trusted ? "trusted" : "password"));
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

type Challenge = { token_hash: string; user_id: number; purpose: string; channel: string; dest: string; code_hash: string | null; sends: number; attempts: number; last_sent: number; remember: number; expires_at: number; verified_at: number | null; meta: string };
async function loadChallenge(tok: unknown): Promise<Challenge> {
  const t = str(tok, 100);
  const c = t ? await db().prepare("SELECT * FROM otp_challenges WHERE token_hash = ?").bind(await sha256(t)).first<Challenge>() : null;
  if (!c || c.expires_at < now() || c.verified_at) throw new HttpError(410, "Phiên xác minh đã hết hạn. Vui lòng thực hiện lại.");
  return c;
}
/** Chỉ dùng cho đăng nhập / đăng ký / khôi phục — phiên đổi email, SĐT có luồng riêng gắn với phiên đăng nhập. */
async function loadAuthChallenge(tok: unknown): Promise<Challenge> {
  const c = await loadChallenge(tok);
  if (c.purpose.startsWith("change-")) throw new HttpError(410, "Phiên xác minh đã hết hạn. Vui lòng thực hiện lại.");
  return c;
}
async function otpSend(req: Request) {
  const b = await readBody(req);
  const c = await loadAuthChallenge(b.challenge);
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
  const codeHash = await deliverCode(c.token_hash, channel, dest, c.purpose, u.name);
  await db().prepare("UPDATE otp_challenges SET channel = ?, dest = ?, code_hash = ?, sends = sends + 1, attempts = 0, last_sent = ?, expires_at = ? WHERE token_hash = ?").bind(channel, dest, codeHash, now(), Math.max(c.expires_at, now() + OTP_TTL), c.token_hash).run();
  return json({ sent: true, channel, masked: channel === "sms" ? maskPhone(dest) : maskEmail(dest), wait: 45 });
}
async function otpVerify(req: Request) {
  const b = await readBody(req);
  const c = await loadAuthChallenge(b.challenge);
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
  return json({ user: publicUser(u) }, 200, await loginCookies(req, u, !!c.remember, b.trust === true, c.purpose === "register" ? "register" : c.channel === "sms" ? "sms" : "email"));
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
    d.prepare("UPDATE users SET pass_hash = ?, pass_salt = ?, pass_iter = ?, has_pass = 1 WHERE id = ?").bind(h.hash, h.salt, h.iter, t.user_id),
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
  if (!u.has_pass) throw new HttpError(400, "Tài khoản đăng nhập bằng Google/Facebook chưa có mật khẩu. Hãy dùng “Đặt mật khẩu”.");
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

/* ---------------- hồ sơ tài khoản ---------------- */
const REQUEST_TOPICS = ["Cập nhật thông tin cá nhân", "Đổi tên hiển thị", "Đổi email hoặc số điện thoại", "Khác"];
async function profileGet(req: Request) {
  const u = await requireUser(req);
  const p = parseProfile(u.profile);
  const masked = { ...p, cccd: maskCccd(p.cccd ?? "") };
  const pending = (await db().prepare("SELECT id, topic, message, created_at FROM change_requests WHERE user_id = ? AND status = 'pending' ORDER BY id DESC").bind(u.id).all()).results;
  const ids = (await db().prepare("SELECT provider, email, created_at FROM identities WHERE user_id = ?").bind(u.id).all()).results;
  const creator = await db().prepare("SELECT display_name, tiktok, youtube, facebook, intro, video, followers, status, note, updated_at FROM creators WHERE user_id = ?").bind(u.id).first();
  return json({ user: publicUser(u), profile: u.profile_at ? masked : null, profileAt: u.profile_at, requests: pending, identities: ids, creator, channels: { mail: mailReady(), sms: smsReady(), google: googleReady(), facebook: facebookReady() } });
}
async function profileName(req: Request) {
  const u = await requireUser(req);
  const b = await readBody(req);
  const name = str(b.name, 80).replace(/\s+/g, " ");
  if ((u.name_changes ?? 0) >= 1) throw new HttpError(403, "Tên hiển thị chỉ được tự đổi 1 lần. Vui lòng gửi yêu cầu để quản trị viên hỗ trợ.");
  if (!/^[\p{L}][\p{L}\p{N} .'-]{1,79}$/u.test(name)) throw new HttpError(400, "Tên hiển thị cần 2–80 ký tự, gồm chữ cái và khoảng trắng.");
  if (name === u.name) throw new HttpError(400, "Tên mới đang trùng với tên hiện tại.");
  await db().prepare("UPDATE users SET name = ?, name_changes = name_changes + 1 WHERE id = ? AND name_changes < 1").bind(name, u.id).run();
  await logEvent(u.id, "name", `${u.name} → ${name}`, "khách");
  return json({ user: publicUser((await getUser(u.id)) as User) });
}
async function profileSave(req: Request) {
  const u = await requireUser(req);
  const b = await readBody(req);
  if (u.profile_at) throw new HttpError(403, "Thông tin cá nhân đã được lưu. Nếu cần thay đổi, vui lòng gửi yêu cầu để quản trị viên hỗ trợ.");
  if (b.consent !== true) throw new HttpError(400, "Vui lòng đồng ý với việc xử lý dữ liệu cá nhân để lưu hồ sơ.");
  await limit(`profile:${u.id}`, 10, HOUR);
  const p = cleanProfile(b.profile);
  p.consentAt = new Date(now()).toISOString();
  const r = await db().prepare("UPDATE users SET profile = ?, profile_at = ? WHERE id = ? AND profile_at IS NULL").bind(JSON.stringify(p), now(), u.id).run();
  if (!r.meta?.changes) throw new HttpError(409, "Thông tin cá nhân đã được lưu trước đó.");
  await logEvent(u.id, "profile", "Khách lưu thông tin cá nhân lần đầu", "khách");
  return profileGet(req);
}
/** Đổi email / số điện thoại: cần mật khẩu hiện tại + mã xác minh gửi tới địa chỉ MỚI (khi đã bật kênh gửi). */
async function contactStart(req: Request) {
  const u = await requireUser(req);
  const b = await readBody(req);
  const type = b.type === "phone" ? "phone" : "email";
  await limit(`contact:${u.id}`, 6, 15 * MIN);
  const pass = typeof b.pass === "string" ? b.pass.slice(0, 128) : "";
  if (!u.has_pass) throw new HttpError(400, "Vui lòng đặt mật khẩu cho tài khoản trước khi đổi email hoặc số điện thoại.");
  if (!pass || !(await checkPass(pass, u.pass_salt, u.pass_hash, u.pass_iter || 100_000))) throw new HttpError(400, "Mật khẩu hiện tại chưa đúng.");
  let value = "", iso = "";
  if (type === "email") {
    value = str(b.email, 160).toLowerCase();
    if (!isEmail(value)) throw new HttpError(400, "Vui lòng nhập địa chỉ email hợp lệ, ví dụ ten@gmail.com.");
    if (value === u.email) throw new HttpError(400, "Email mới đang trùng với email hiện tại.");
    if (await db().prepare("SELECT id FROM users WHERE email = ?").bind(value).first()) throw new HttpError(409, "Email này đã được dùng cho một tài khoản khác.");
  } else {
    value = toE164(b.cc, b.phone); iso = str(b.ccIso, 3).toUpperCase();
    if (!value) throw new HttpError(400, "Số điện thoại chưa đúng. Hãy chọn mã quốc gia và nhập số, ví dụ 0901 234 567.");
    if (value === u.phone) throw new HttpError(400, "Số điện thoại mới đang trùng với số hiện tại.");
    if (await db().prepare("SELECT id FROM users WHERE phone = ?").bind(value).first()) throw new HttpError(409, "Số điện thoại này đã được dùng cho một tài khoản khác.");
  }
  // Ưu tiên gửi mã tới địa chỉ MỚI (chứng minh sở hữu); nếu kênh đó chưa bật thì gửi tới kênh cũ còn hoạt động.
  let channel: "sms" | "email" | "" = type === "email" ? (mailReady() ? "email" : "") : (smsReady() ? "sms" : "");
  let dest = channel ? value : "";
  if (!channel && mailReady() && u.email) { channel = "email"; dest = u.email; }
  else if (!channel && smsReady() && u.phone) { channel = "sms"; dest = u.phone; }
  if (!channel) {
    // chưa bật dịch vụ gửi mã → đổi ngay bằng mật khẩu, đánh dấu "chưa xác minh"
    await applyContact(u, type, value, iso, false, "khách (chưa xác minh)");
    return json({ changed: true, verified: false, user: publicUser((await getUser(u.id)) as User) });
  }
  await limit(`otpdest:${dest}`, 8, HOUR, "Địa chỉ nhận này đã nhận quá nhiều mã. Vui lòng thử lại sau 1 giờ.");
  const tok = randomToken(), th = await sha256(tok), t = now();
  const codeHash = await deliverCode(th, channel, dest, `change-${type}`, u.name);
  await db().prepare("INSERT INTO otp_challenges (token_hash, user_id, purpose, channel, dest, code_hash, sends, last_sent, remember, expires_at, created_at, meta) VALUES (?, ?, ?, ?, ?, ?, 1, ?, 0, ?, ?, ?)")
    .bind(th, u.id, `change-${type}`, channel, dest, codeHash, t, t + 30 * MIN, t, JSON.stringify({ iso, value })).run();
  return json({ challenge: tok, type, toNew: dest === value, masked: channel === "email" ? maskEmail(dest) : maskPhone(dest), wait: 45 });
}
async function loadContactChallenge(req: Request, b: Row) {
  const u = await requireUser(req);
  const c = await loadChallenge(b.challenge);
  if (c.user_id !== u.id || !c.purpose.startsWith("change-")) throw new HttpError(410, "Phiên xác minh đã hết hạn. Vui lòng thực hiện lại.");
  return { u, c };
}
async function contactResend(req: Request) {
  const b = await readBody(req);
  const { u, c } = await loadContactChallenge(req, b);
  const wait = Math.ceil((c.last_sent + 45_000 - now()) / 1000);
  if (wait > 0) throw new HttpError(429, `Vui lòng đợi ${wait} giây rồi gửi lại mã.`, { wait });
  if (c.sends >= 5) throw new HttpError(429, "Bạn đã yêu cầu gửi mã quá nhiều lần. Vui lòng thực hiện lại sau.");
  await limit(`otpdest:${c.dest}`, 8, HOUR, "Địa chỉ nhận này đã nhận quá nhiều mã. Vui lòng thử lại sau 1 giờ.");
  const codeHash = await deliverCode(c.token_hash, c.channel === "sms" ? "sms" : "email", c.dest, c.purpose, u.name);
  await db().prepare("UPDATE otp_challenges SET code_hash = ?, sends = sends + 1, attempts = 0, last_sent = ? WHERE token_hash = ?").bind(codeHash, now(), c.token_hash).run();
  return json({ sent: true, wait: 45 });
}
async function contactVerify(req: Request) {
  const b = await readBody(req);
  const { u, c } = await loadContactChallenge(req, b);
  const code = str(b.code, 12).replace(/\D/g, "");
  if (now() - c.last_sent > OTP_TTL) throw new HttpError(410, "Mã đã hết hạn. Vui lòng gửi lại mã mới.");
  if (c.attempts >= 5) throw new HttpError(429, "Bạn đã nhập sai quá 5 lần. Vui lòng gửi lại mã mới.");
  if (code.length !== 6) throw new HttpError(400, "Mã xác minh gồm 6 chữ số.");
  await db().prepare("UPDATE otp_challenges SET attempts = attempts + 1 WHERE token_hash = ?").bind(c.token_hash).run();
  const ok = c.channel === "sms" ? await checkSmsCode(c.dest, code) : !!c.code_hash && safeEq(await sha256(c.token_hash + code), c.code_hash);
  if (!ok) throw new HttpError(400, `Mã chưa đúng. Bạn còn ${Math.max(0, 4 - c.attempts)} lần thử.`);
  await db().prepare("UPDATE otp_challenges SET verified_at = ? WHERE token_hash = ?").bind(now(), c.token_hash).run();
  const type = c.purpose === "change-phone" ? "phone" : "email";
  let meta: Row = {}; try { meta = JSON.parse(c.meta || "{}"); } catch { /* bỏ qua */ }
  const value = str(meta.value, 160);
  if (!value) throw new HttpError(410, "Phiên xác minh đã hết hạn. Vui lòng thực hiện lại.");
  const verified = value === c.dest; // mã gửi tới chính địa chỉ mới → địa chỉ mới đã được xác minh
  await applyContact(u, type, value, str(meta.iso, 3), verified, verified ? "khách (đã xác minh mã)" : "khách (xác minh qua kênh cũ)");
  return json({ changed: true, verified, user: publicUser((await getUser(u.id)) as User) });
}
async function applyContact(u: User, type: "email" | "phone", value: string, iso: string, verified: boolean, actor: string) {
  const col = type === "email" ? "email" : "phone";
  if (await db().prepare(`SELECT id FROM users WHERE ${col} = ? AND id != ?`).bind(value, u.id).first()) throw new HttpError(409, type === "email" ? "Email này đã được dùng cho một tài khoản khác." : "Số điện thoại này đã được dùng cho một tài khoản khác.");
  if (type === "email") await db().prepare("UPDATE users SET email = ?, email_verified = ? WHERE id = ?").bind(value, verified ? 1 : 0, u.id).run();
  else await db().prepare("UPDATE users SET phone = ?, phone_cc = ?, phone_verified = ? WHERE id = ?").bind(value, iso || u.phone_cc, verified ? 1 : 0, u.id).run();
  await logEvent(u.id, type, `${type === "email" ? u.email : u.phone} → ${value}`, actor);
  // báo cho email cũ để chủ tài khoản phát hiện thay đổi bất thường
  if (u.email && mailReady()) await sendMail(u.email, "Thông tin đăng nhập tài khoản vừa thay đổi", mailLayout(
    type === "email" ? "Email tài khoản đã được đổi" : "Số điện thoại tài khoản đã được đổi",
    `Chào ${escHtml(u.name)},<br>${type === "email" ? `Email đăng nhập đã đổi thành <b>${escHtml(maskEmail(value))}</b>.` : `Số điện thoại đã đổi thành <b>${escHtml(maskPhone(value))}</b>.`}<br>Nếu không phải bạn thực hiện, hãy gọi ngay ${HOTLINE} để được khoá tài khoản.`));
}
/** Khôi phục mật khẩu ngay trong trang tài khoản (không cần nhớ mật khẩu cũ). */
async function recover(req: Request) {
  await readBody(req);
  const u = await requireUser(req);
  await limit(`recover:${u.id}`, 6, HOUR);
  if (!channelsOf(u).length) {
    const dup = await db().prepare("SELECT id FROM reset_requests WHERE user_id = ? AND status = 'pending' AND created_at > ?").bind(u.id, now() - DAY).first();
    if (!dup) await db().prepare("INSERT INTO reset_requests (user_id, email, phone, created_at) VALUES (?, ?, ?, ?)").bind(u.id, u.email, u.phone, now()).run();
    return json({ mode: "admin" });
  }
  return json(await newChallenge(u, "reset"));
}
/** Yêu cầu quản trị viên hỗ trợ cập nhật (sau khi hồ sơ đã khoá, hoặc đã dùng hết lượt đổi tên). */
async function changeRequest(req: Request) {
  const u = await requireUser(req);
  const b = await readBody(req);
  const topic = REQUEST_TOPICS.includes(str(b.topic, 60)) ? str(b.topic, 60) : "Khác";
  const message = str(b.message, 1500);
  if (message.length < 10) throw new HttpError(400, "Vui lòng mô tả nội dung cần cập nhật (ít nhất 10 ký tự).");
  await limit(`creq:${u.id}`, 5, DAY, "Bạn đã gửi nhiều yêu cầu trong hôm nay. Quản trị viên sẽ sớm liên hệ.");
  if (await db().prepare("SELECT id FROM change_requests WHERE user_id = ? AND topic = ? AND status = 'pending'").bind(u.id, topic).first()) throw new HttpError(409, "Bạn đã có một yêu cầu cùng nội dung đang chờ xử lý.");
  await db().prepare("INSERT INTO change_requests (user_id, topic, message, created_at) VALUES (?, ?, ?, ?)").bind(u.id, topic, message, now()).run();
  await logEvent(u.id, "request", topic, "khách");
  await notifyAdmin(new URL(req.url).origin, `[Website] Yêu cầu cập nhật – ${u.name}`, `<b>${escHtml(topic)}</b><br>${escHtml(u.name)} · ${escHtml(u.email)} · ${escHtml(u.phone)}<pre style="white-space:pre-wrap;font-family:inherit">${escHtml(message)}</pre>`);
  return profileGet(req);
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
  // Đặt lịch xem / hỏi thông tin một căn đang chào: bắt buộc đồng ý "Cam kết bảo mật thông tin nguồn hàng" và lưu bằng chứng
  if (form === "viewing") {
    if (fields.camket !== "dong-y") throw new HttpError(400, "Vui lòng đọc và đồng ý Cam kết bảo mật thông tin nguồn hàng trước khi gửi yêu cầu.");
    const m = reqMeta(req);
    fields.camket = `Đồng ý Cam kết bảo mật thông tin nguồn hàng (phiên bản ${COMMIT_VERSION}) lúc ${fmtTime(now())} · IP ${m.ip} · ${m.label}${m.loc ? " · " + m.loc : ""}`;
  }
  await limit(`lead:${clientIp(req)}`, 15, HOUR);
  const u = await currentUser(req);
  const text = str(b.text, 4000) + (fields.camket && form === "viewing" ? `\n${fields.camket}` : "");
  await db().prepare("INSERT INTO leads (form, kind, name, phone, fields, text, user_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)").bind(form, kind, name, phone, JSON.stringify(fields), text, u?.id ?? null, now(), now()).run();
  const to = env().NOTIFY_EMAIL;
  if (to && mailReady()) await sendMail(to, `[Website] ${kind} – ${name}`, mailLayout(`${escHtml(kind)} mới`, `<pre style="white-space:pre-wrap;font-family:inherit">${escHtml(text)}</pre>`, `<p><a href="${new URL(req.url).origin}/admin">Mở trang quản trị</a></p>`));
  return json({ ok: true }, 201);
}

/* ================= ĐĂNG NHẬP GOOGLE / FACEBOOK (OAuth 2.0) ================= */
const googleReady = () => !!(env().GOOGLE_CLIENT_ID && env().GOOGLE_CLIENT_SECRET);
const facebookReady = () => !!(env().FACEBOOK_APP_ID && env().FACEBOOK_APP_SECRET);
const OAUTH_COOKIE = "hd_os";
const b64url = (b: ArrayBuffer | Uint8Array) => { let s = ""; for (const x of new Uint8Array(b as ArrayBuffer)) s += String.fromCharCode(x); return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); };
function redirect(to: string, cookies: string[] = []) {
  const h = new Headers({ Location: to, "Cache-Control": "no-store" });
  for (const c of cookies) h.append("Set-Cookie", c);
  return new Response(null, { status: 302, headers: h });
}
const stateCookie = (v: string, age: number) => `${OAUTH_COOKIE}=${encodeURIComponent(v)}; Path=/api/auth/oauth; HttpOnly; Secure; SameSite=Lax; Max-Age=${age}`;
type SocialProfile = { sub: string; email: string; emailVerified: boolean; name: string; picture: string };
async function oauthStart(req: Request, provider: string): Promise<Response> {
  const url = new URL(req.url), origin = url.origin;
  const ready = provider === "google" ? googleReady() : provider === "facebook" ? facebookReady() : false;
  if (!ready) return redirect(origin + "/#oauth-error=chua-bat");
  try { await limit(`oauth:${clientIp(req)}`, 30, HOUR); } catch { return redirect(origin + "/#oauth-error=qua-nhieu"); }
  const state = randomToken(), verifier = randomToken(48);
  const link = url.searchParams.get("link") === "1" ? await sessionSubject(req, "user") : null;
  await db().prepare("DELETE FROM oauth_states WHERE expires_at < ?").bind(now()).run();
  await db().prepare("INSERT INTO oauth_states (state_hash, provider, verifier, link_user_id, expires_at) VALUES (?, ?, ?, ?, ?)").bind(await sha256(state), provider, verifier, link, now() + 10 * MIN).run();
  const cb = `${origin}/api/auth/oauth/${provider}/callback`;
  let to: string;
  if (provider === "google") {
    const challenge = b64url(await crypto.subtle.digest("SHA-256", enc.encode(verifier)));
    to = "https://accounts.google.com/o/oauth2/v2/auth?" + new URLSearchParams({ client_id: env().GOOGLE_CLIENT_ID!, redirect_uri: cb, response_type: "code", scope: "openid email profile", state, code_challenge: challenge, code_challenge_method: "S256", prompt: "select_account" });
  } else {
    to = "https://www.facebook.com/dialog/oauth?" + new URLSearchParams({ client_id: env().FACEBOOK_APP_ID!, redirect_uri: cb, response_type: "code", scope: "email,public_profile", state });
  }
  return redirect(to, [stateCookie(state, 600)]);
}
async function googleProfile(code: string, verifier: string, cb: string): Promise<SocialProfile> {
  const r = await fetch("https://oauth2.googleapis.com/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ code, client_id: env().GOOGLE_CLIENT_ID!, client_secret: env().GOOGLE_CLIENT_SECRET!, redirect_uri: cb, grant_type: "authorization_code", code_verifier: verifier }).toString() });
  const j = (await r.json().catch(() => ({}))) as Row;
  if (!r.ok || typeof j.id_token !== "string") throw new Error("google token " + r.status);
  const part = (j.id_token as string).split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
  const c = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(part + "===".slice((part.length + 3) % 4)), (x) => x.charCodeAt(0)))) as Row;
  // id_token nhận trực tiếp từ Google qua kết nối bảo mật → chỉ cần kiểm tra đúng ứng dụng & nhà phát hành
  if (c.aud !== env().GOOGLE_CLIENT_ID || !["https://accounts.google.com", "accounts.google.com"].includes(String(c.iss))) throw new Error("google aud/iss");
  return { sub: String(c.sub), email: str(c.email, 160).toLowerCase(), emailVerified: c.email_verified === true || c.email_verified === "true", name: str(c.name, 80), picture: str(c.picture, 400) };
}
async function facebookProfile(code: string, cb: string): Promise<SocialProfile> {
  const e = env();
  const r = await fetch("https://graph.facebook.com/oauth/access_token?" + new URLSearchParams({ client_id: e.FACEBOOK_APP_ID!, client_secret: e.FACEBOOK_APP_SECRET!, redirect_uri: cb, code }));
  const j = (await r.json().catch(() => ({}))) as Row;
  if (!r.ok || typeof j.access_token !== "string") throw new Error("facebook token " + r.status);
  const key = await crypto.subtle.importKey("raw", enc.encode(e.FACEBOOK_APP_SECRET!), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const proof = hex(await crypto.subtle.sign("HMAC", key, enc.encode(j.access_token as string)));
  const m = await fetch("https://graph.facebook.com/me?" + new URLSearchParams({ fields: "id,name,email,picture.width(200).height(200)", access_token: j.access_token as string, appsecret_proof: proof }));
  const p = (await m.json().catch(() => ({}))) as Row;
  if (!m.ok || !p.id) throw new Error("facebook me " + m.status);
  const pic = ((p.picture as Row)?.data as Row)?.url;
  // Không tự gộp tài khoản theo email Facebook (chưa chắc email đã được xác minh) → emailVerified = false
  return { sub: String(p.id), email: str(p.email, 160).toLowerCase(), emailVerified: false, name: str(p.name, 80), picture: str(pic, 400) };
}
async function oauthCallback(req: Request, provider: string): Promise<Response> {
  const url = new URL(req.url), origin = url.origin, clear = stateCookie("", 0);
  const fail = (code: string) => redirect(`${origin}/#oauth-error=${code}`, [clear]);
  if (!["google", "facebook"].includes(provider)) return fail("loi");
  try {
    if (url.searchParams.get("error")) return fail("huy");
    const state = url.searchParams.get("state") ?? "", code = url.searchParams.get("code") ?? "";
    if (!state || !code || getCookie(req, OAUTH_COOKIE) !== state) return fail("phien");
    const sh = await sha256(state);
    const st = await db().prepare("SELECT * FROM oauth_states WHERE state_hash = ? AND provider = ? AND expires_at > ?").bind(sh, provider, now()).first<{ verifier: string; link_user_id: number | null }>();
    await db().prepare("DELETE FROM oauth_states WHERE state_hash = ?").bind(sh).run();
    if (!st) return fail("phien");
    const cb = `${origin}/api/auth/oauth/${provider}/callback`;
    const p = provider === "google" ? await googleProfile(code, st.verifier, cb) : await facebookProfile(code, cb);
    const d = db();
    const ident = await d.prepare("SELECT user_id FROM identities WHERE provider = ? AND subject = ?").bind(provider, p.sub).first<{ user_id: number }>();
    if (st.link_user_id) { // liên kết thêm Google/Facebook từ trang tài khoản
      if (ident && ident.user_id !== st.link_user_id) return fail("da-lien-ket");
      if (!ident) {
        await d.prepare("INSERT INTO identities (provider, subject, user_id, email, created_at) VALUES (?, ?, ?, ?, ?)").bind(provider, p.sub, st.link_user_id, p.email, now()).run();
        await logEvent(st.link_user_id, "identity", `Liên kết ${provider === "google" ? "Google" : "Facebook"}`, "khách");
      }
      return redirect(`${origin}/#oauth-linked=${provider}`, [clear]);
    }
    let u: User | null = ident ? await getUser(ident.user_id) : null;
    if (!u) {
      const existing = p.email ? await d.prepare("SELECT * FROM users WHERE email = ?").bind(p.email).first<User>() : null;
      if (existing) {
        if (!(provider === "google" && p.emailVerified) || existing.no_autolink) return fail("email-ton-tai");
        if (!existing.email_verified) {
          // email của tài khoản cũ chưa từng được xác minh → người tạo trước có thể không phải chủ email: thu hồi mọi cách đăng nhập cũ
          await d.batch([
            d.prepare("UPDATE users SET has_pass = 0, pass_hash = 'x', phone = '', phone_verified = 0, profile = '', profile_at = NULL, needs_onboarding = 1 WHERE id = ?").bind(existing.id),
            d.prepare("DELETE FROM sessions WHERE kind = 'user' AND subject_id = ?").bind(existing.id),
            d.prepare("DELETE FROM trusted_devices WHERE user_id = ?").bind(existing.id),
            d.prepare("DELETE FROM identities WHERE user_id = ?").bind(existing.id),
          ]);
          await logEvent(existing.id, "security", "Email chưa xác minh được chủ email (Google) nhận lại – đã thu hồi các cách đăng nhập cũ", "hệ thống");
        }
        await d.prepare("INSERT INTO identities (provider, subject, user_id, email, created_at) VALUES (?, ?, ?, ?, ?)").bind(provider, p.sub, existing.id, p.email, now()).run();
        await d.prepare("UPDATE users SET email_verified = 1 WHERE id = ?").bind(existing.id).run();
        await logEvent(existing.id, "identity", "Tự liên kết Google (email đã được Google xác minh)", "hệ thống");
        u = await getUser(existing.id);
      } else {
        await limit(`oauthnew:${clientIp(req)}`, 10, HOUR);
        const email = p.email || `${provider}-${p.sub}${PLACEHOLDER_MAIL}`;
        const r = await d.prepare("INSERT INTO users (email, phone, name, role, pass_hash, pass_salt, pass_iter, email_verified, has_pass, needs_onboarding, avatar, created_at) VALUES (?, '', ?, '', 'x', '', 100000, ?, 0, 1, ?, ?)").bind(email, p.name || "Khách hàng", p.email && p.emailVerified ? 1 : 0, p.picture, now()).run();
        const id = Number(r.meta?.last_row_id);
        await d.prepare("INSERT INTO identities (provider, subject, user_id, email, created_at) VALUES (?, ?, ?, ?, ?)").bind(provider, p.sub, id, p.email, now()).run();
        await logEvent(id, "identity", `Tạo tài khoản bằng ${provider === "google" ? "Google" : "Facebook"}`, "khách");
        u = await getUser(id);
      }
    }
    if (!u) return fail("loi");
    if (u.status !== "active") return fail("khoa");
    if (!u.avatar && p.picture) await d.prepare("UPDATE users SET avatar = ? WHERE id = ?").bind(p.picture, u.id).run();
    const cookies = await loginCookies(req, u, true, false, provider);
    return redirect(origin + (u.needs_onboarding ? "/#onboard" : "/#welcome"), [...cookies, clear]);
  } catch (e) {
    console.error("oauth", provider, e);
    return fail("loi");
  }
}
/** Bổ sung thông tin bắt buộc sau lần đầu đăng nhập bằng Google/Facebook. */
async function onboard(req: Request) {
  const u = await requireUser(req);
  const b = await readBody(req);
  if (!u.needs_onboarding) throw new HttpError(403, "Tài khoản đã hoàn tất thông tin. Hãy cập nhật trong trang Tài khoản.");
  const name = str(b.name, 80).replace(/\s+/g, " ");
  const phone = toE164(b.cc, b.phone), iso = str(b.ccIso, 3).toUpperCase();
  const role = ROLES.includes(str(b.role, 60)) ? str(b.role, 60) : "";
  if (name.length < 2) throw new HttpError(400, "Vui lòng nhập họ và tên.");
  if (!phone) throw new HttpError(400, "Số điện thoại chưa đúng. Hãy chọn mã quốc gia và nhập số, ví dụ 0901 234 567.");
  if (!role) throw new HttpError(400, "Vui lòng chọn bạn là ai để Dũng hỗ trợ đúng nhu cầu.");
  if (b.terms !== true) throw new HttpError(400, "Vui lòng đồng ý Điều khoản dịch vụ và Chính sách bảo mật.");
  let email = u.email;
  if (u.email.endsWith(PLACEHOLDER_MAIL)) {
    email = str(b.email, 160).toLowerCase();
    if (!isEmail(email)) throw new HttpError(400, "Vui lòng nhập email để nhận thông tin giao dịch, ví dụ ten@gmail.com.");
    if (await db().prepare("SELECT id FROM users WHERE email = ? AND id != ?").bind(email, u.id).first()) throw new HttpError(409, "Email này đã có tài khoản. Hãy đăng nhập bằng email đó rồi liên kết Google/Facebook trong trang tài khoản.");
  }
  if (phone !== u.phone && await db().prepare("SELECT id FROM users WHERE phone = ? AND id != ?").bind(phone, u.id).first()) throw new HttpError(409, "Số điện thoại này đã được dùng cho một tài khoản khác.");
  await db().prepare("UPDATE users SET name = ?, email = ?, email_verified = CASE WHEN email = ? THEN email_verified ELSE 0 END, phone_verified = CASE WHEN phone = ? THEN phone_verified ELSE 0 END, phone = ?, phone_cc = ?, role = ?, marketing = ?, terms_at = ?, needs_onboarding = 0 WHERE id = ?")
    .bind(name, email, email, phone, phone, iso, role, b.agree ? 1 : 0, now(), u.id).run();
  await logEvent(u.id, "onboard", "Hoàn tất thông tin sau khi đăng nhập bằng mạng xã hội", "khách");
  return json({ user: publicUser((await getUser(u.id)) as User) });
}
async function passwordSet(req: Request) {
  const u = await requireUser(req);
  const b = await readBody(req);
  const pass = typeof b.pass === "string" ? b.pass : "";
  if (u.has_pass) throw new HttpError(400, "Tài khoản đã có mật khẩu. Hãy dùng “Đổi mật khẩu”.");
  if (pass.length < 8 || pass.length > 128) throw new HttpError(400, "Mật khẩu cần từ 8 đến 128 ký tự.");
  const h = await hashPass(pass);
  await db().prepare("UPDATE users SET pass_hash = ?, pass_salt = ?, pass_iter = ?, has_pass = 1 WHERE id = ?").bind(h.hash, h.salt, h.iter, u.id).run();
  await logEvent(u.id, "password", "Đặt mật khẩu lần đầu", "khách");
  return json({ user: publicUser((await getUser(u.id)) as User) });
}
async function identityUnlink(req: Request) {
  const u = await requireUser(req);
  const b = await readBody(req);
  const provider = str(b.provider, 20);
  const n = (await db().prepare("SELECT COUNT(*) AS n FROM identities WHERE user_id = ?").bind(u.id).first<{ n: number }>())?.n ?? 0;
  if (!u.has_pass && n <= 1) throw new HttpError(400, "Hãy đặt mật khẩu trước khi gỡ cách đăng nhập duy nhất của tài khoản.");
  const mine = (await db().prepare("SELECT COUNT(*) AS n FROM identities WHERE user_id = ? AND provider = ?").bind(u.id, provider).first<{ n: number }>())?.n ?? 0;
  if (!u.has_pass && mine >= n) throw new HttpError(400, "Hãy đặt mật khẩu trước khi gỡ cách đăng nhập duy nhất của tài khoản.");
  await db().prepare("DELETE FROM identities WHERE user_id = ? AND provider = ?").bind(u.id, provider).run();
  if (provider === "google") await db().prepare("UPDATE users SET no_autolink = 1 WHERE id = ?").bind(u.id).run();
  await logEvent(u.id, "identity", `Gỡ liên kết ${provider === "google" ? "Google" : "Facebook"}`, "khách");
  return profileGet(req);
}

/* ================= PHIÊN ĐĂNG NHẬP & CẢNH BÁO ================= */
async function mySessions(req: Request) {
  const u = await requireUser(req);
  const cur = (await sha256(getCookie(req, USER_COOKIE))).slice(0, 16);
  if (req.method === "GET") {
    const ss = (await db().prepare("SELECT substr(token_hash, 1, 16) AS sid, ip, label, loc, created_at, last_seen FROM sessions WHERE kind = 'user' AND subject_id = ? AND expires_at > ? ORDER BY COALESCE(last_seen, created_at) DESC LIMIT 30").bind(u.id, now()).all<Row>()).results;
    const ev = (await db().prepare("SELECT id, ok, method, ip, loc, label, sid, at FROM login_events WHERE kind = 'user' AND subject_id = ? ORDER BY id DESC LIMIT 40").bind(u.id).all<Row>()).results;
    return json({ sessions: ss.map((x) => ({ ...x, current: x.sid === cur })), events: ev.map((x) => ({ ...x, current: x.sid === cur })) });
  }
  const b = await readBody(req);
  if (b.others === true) await db().prepare("DELETE FROM sessions WHERE kind = 'user' AND subject_id = ? AND substr(token_hash, 1, 16) != ?").bind(u.id, cur).run();
  else {
    const sid = str(b.sid, 16);
    if (!/^[0-9a-f]{16}$/.test(sid)) throw new HttpError(400, "Phiên không hợp lệ.");
    await db().prepare("DELETE FROM sessions WHERE kind = 'user' AND subject_id = ? AND substr(token_hash, 1, 16) = ?").bind(u.id, sid).run();
  }
  await logEvent(u.id, "sessions", b.others === true ? "Đăng xuất mọi thiết bị khác" : "Đăng xuất một thiết bị", "khách");
  return json({ ok: true, current: b.sid === cur });
}
async function securityReport(req: Request) {
  const u = await requireUser(req);
  const b = await readBody(req);
  const ev = Number(b.eventId) ? await db().prepare("SELECT * FROM login_events WHERE id = ? AND kind = 'user' AND subject_id = ?").bind(Number(b.eventId), u.id).first<Row>() : null;
  const steps = Array.isArray(b.steps) ? (b.steps as unknown[]).map((x) => str(x, 60)).filter(Boolean).slice(0, 8) : [];
  const msg = [ev ? `Lần đăng nhập lạ: ${fmtTime(ev.at)} · ${ev.label} · IP ${ev.ip}${ev.loc ? " · " + ev.loc : ""}` : "Khách báo có hoạt động đăng nhập lạ.", steps.length ? "Khách đã thực hiện: " + steps.join(", ") : "", str(b.note, 800)].filter(Boolean).join("\n");
  await limit(`secrep:${u.id}`, 5, DAY);
  await db().prepare("INSERT INTO change_requests (user_id, topic, message, created_at) VALUES (?, ?, ?, ?)").bind(u.id, "Cảnh báo đăng nhập lạ", msg, now()).run();
  await logEvent(u.id, "security", "Báo cáo đăng nhập lạ", "khách");
  await notifyAdmin(new URL(req.url).origin, `[Website] Cảnh báo đăng nhập lạ – ${u.name}`, `${escHtml(u.name)} · ${escHtml(u.email)} · ${escHtml(u.phone)}<pre style="white-space:pre-wrap;font-family:inherit">${escHtml(msg)}</pre>`);
  return json({ ok: true });
}

/* ================= TIN ĐĂNG BẤT ĐỘNG SẢN ================= */
const SEED_LISTINGS = [{"type":"ban","title":"Biệt thự tân cổ điển, hồ phun nước","area":"TP. Thủ Đức","price":450000,"size":2400,"dim":"40 × 60 m","beds":8,"floors":4,"legal":"Sổ hồng riêng","note":"Kiến trúc tân cổ điển, sân vườn và hồ phun nước nhiều tầng, lối vào riêng, hệ thống chiếu sáng cảnh quan toàn khuôn viên.","images":["/img/mansion.webp"],"featured":0,"sort":0},{"type":"ban","title":"Penthouse thông tầng view toàn thành phố","area":"Quận 7","price":38000,"size":320,"dim":"320 m²","beds":4,"floors":2,"legal":"Sổ hồng","note":"Phòng khách thông tầng, kính cao từ sàn tới trần, cầu thang đèn LED, đón hoàng hôn trọn vẹn.","images":["/img/penthouse.webp"],"featured":1,"sort":1},{"type":"thue","title":"Căn hộ cao cấp trần sao, nội thất trọn gói","area":"Bình Thạnh","price":85,"size":160,"dim":"160 m²","beds":3,"floors":1,"legal":"Hợp đồng 12 tháng","note":"Trần sao lấp lánh, sàn đá marble, nội thất cao cấp, dọn vào ở ngay.","images":["/img/starry.webp"],"featured":1,"sort":2},{"type":"ban","title":"Biệt thự nghỉ dưỡng ven biển, hồ bơi vô cực","area":"Cần Giờ","price":120000,"size":1200,"dim":"30 × 40 m","beds":6,"floors":3,"legal":"Sổ hồng riêng","note":"Mặt kính mở hoàn toàn ra biển, hồ bơi vô cực, phòng khách trũng sunken lounge.","images":["/img/ocean.webp"],"featured":1,"sort":3},{"type":"ban","title":"Căn hộ Duplex phong cách resort","area":"Quận 1","price":26000,"size":210,"dim":"210 m²","beds":3,"floors":2,"legal":"Sổ hồng","note":"Phòng ngủ bục nổi có đèn hắt, lò sưởi treo, tường đá tự nhiên, không gian như khu nghỉ dưỡng.","images":["/img/mountain.webp"],"featured":1,"sort":4},{"type":"thue","title":"Mặt bằng trung tâm thương mại, tầng trệt","area":"Quận 1","price":650,"size":500,"dim":"500 m²","beds":0,"floors":1,"legal":"Hợp đồng 3–5 năm","note":"Vị trí đắc địa trong trung tâm thương mại, lưu lượng khách lớn, phù hợp thương hiệu bán lẻ.","images":["/img/mall.webp"],"featured":0,"sort":5},{"type":"thue","title":"Sàn văn phòng xanh, giếng trời lớn","area":"Quận 3","price":280,"size":900,"dim":"900 m²","beds":0,"floors":1,"legal":"Hợp đồng 2–3 năm","note":"Trần gỗ, giếng trời, nhiều cây xanh, phù hợp trụ sở công ty 80–120 người.","images":["/img/atrium.webp"],"featured":0,"sort":6},{"type":"ban","title":"Khối đế thương mại có thác nước trong nhà","area":"Quận 5","price":980000,"size":12000,"dim":"12.000 m²","beds":0,"floors":4,"legal":"Sổ hồng","note":"Khối đế thương mại hoàn chỉnh, giếng trời tròn, thác nước trung tâm, đang có khách thuê ổn định.","images":["/img/fallmall.webp"],"featured":0,"sort":7},{"type":"ban","title":"Villa sân vườn bên suối, hồ bơi tràn","area":"Củ Chi","price":18500,"size":1500,"dim":"30 × 50 m","beds":5,"floors":2,"legal":"Sổ hồng riêng","note":"Thiết kế mái cong phủ cây xanh, hồ bơi tràn bờ, nhiều mảng xanh tự nhiên.","images":["/img/villa.webp"],"featured":0,"sort":8}];
async function seedListings() {
  const d = db();
  const done = await d.prepare("SELECT value FROM settings WHERE key = 'seeded_listings'").first();
  if (done) return;
  const n = (await d.prepare("SELECT COUNT(*) AS n FROM listings").first<{ n: number }>())?.n ?? 0;
  if (!n) {
    const t = now();
    await d.batch(SEED_LISTINGS.map((l: Row) => d.prepare("INSERT INTO listings (type, title, area, price, size, dim, beds, floors, legal, note, images, status, featured, sort, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'published', ?, ?, 'hệ thống', ?, ?)")
      .bind(l.type, l.title, l.area, l.price, l.size, l.dim, l.beds, l.floors, l.legal, l.note, JSON.stringify(l.images), l.featured, l.sort, t, t)));
  }
  await d.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('seeded_listings', '1')").run();
}
const LISTING_STATUS = ["published", "draft", "hidden", "sold"];
const IMG_REF = /^(\/img\/[a-z0-9_-]{1,40}\.webp|\/api\/media\/[A-Za-z0-9_-]{10,40})$/;
type Listing = Row & { id: number; images: string };
const listingOut = (l: Listing) => { let images: string[] = []; try { images = JSON.parse(l.images); } catch { /* bỏ qua */ } return { ...l, images }; };
async function listingsPublic(req: Request) {
  const rows = (await db().prepare("SELECT id, type, title, area, price, size, dim, beds, floors, legal, note, images, status, featured, sort, updated_at FROM listings WHERE status IN ('published', 'sold') ORDER BY status = 'sold', sort, id DESC LIMIT 300").all<Listing>()).results;
  return new Response(JSON.stringify({ rows: rows.map(listingOut) }), { headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "public, max-age=30" } });
}
function cleanListing(b: Row) {
  const type = b.type === "thue" ? "thue" : "ban";
  const title = str(b.title, 120), area = str(b.area, 60);
  const num = (v: unknown, max: number) => { const n = Number(v); return Number.isFinite(n) && n >= 0 && n <= max ? n : NaN; };
  const price = num(b.price, 1e9), size = num(b.size, 1e7), beds = Math.round(num(b.beds, 99)), floors = Math.round(num(b.floors, 200));
  if (title.length < 5) throw new HttpError(400, "Tiêu đề tin cần ít nhất 5 ký tự.");
  if (area.length < 2) throw new HttpError(400, "Vui lòng chọn khu vực.");
  if (!(price > 0)) throw new HttpError(400, type === "thue" ? "Giá thuê (triệu/tháng) chưa hợp lệ." : "Giá bán (triệu đồng) chưa hợp lệ.");
  if (Number.isNaN(size) || Number.isNaN(beds) || Number.isNaN(floors)) throw new HttpError(400, "Diện tích, số phòng ngủ hoặc số tầng chưa hợp lệ.");
  const images = Array.isArray(b.images) ? (b.images as unknown[]).map((x) => str(x, 80)).filter((x) => IMG_REF.test(x)).slice(0, 12) : [];
  if (!images.length) throw new HttpError(400, "Tin đăng cần ít nhất 1 ảnh.");
  const status = LISTING_STATUS.includes(str(b.status, 20)) ? str(b.status, 20) : "published";
  return { type, title, area, price, size, dim: str(b.dim, 40), beds, floors, legal: str(b.legal, 80), note: str(b.note, 2000), images: JSON.stringify(images), status, featured: b.featured ? 1 : 0, sort: Math.round(Number(b.sort) || 0) };
}
async function adminListings(req: Request) {
  await requireAdmin(req, "listings.edit");
  const u = new URL(req.url), q = str(u.searchParams.get("q"), 80), st = str(u.searchParams.get("status"), 20);
  const cond: string[] = [], v: unknown[] = [];
  if (LISTING_STATUS.includes(st)) { cond.push("status = ?"); v.push(st); }
  if (q) { cond.push("(title LIKE ? ESCAPE '\\' OR area LIKE ? ESCAPE '\\' OR note LIKE ? ESCAPE '\\')"); v.push(likeQ(q), likeQ(q), likeQ(q)); }
  const where = cond.length ? "WHERE " + cond.join(" AND ") : "";
  const rows = (await db().prepare(`SELECT l.*, (SELECT COUNT(*) FROM visits x WHERE x.ev = 'listing' AND x.lid = l.id) AS opens FROM listings l ${where} ORDER BY sort, id DESC LIMIT 500`).bind(...v).all<Listing>()).results;
  return json({ rows: rows.map(listingOut) });
}
async function adminListing(req: Request) {
  const a = await requireAdmin(req, "listings.edit");
  const b = await readBody(req);
  const id = Number(b.id) || 0, d = db(), t = now();
  if (b.action === "delete") {
    if (levelOf(a) < PERMS["listings.delete"]) throw new HttpError(403, "Chỉ Quản lý hoặc Giám đốc được xoá tin. Bạn có thể chuyển tin sang “Ẩn”.");
    await d.prepare("DELETE FROM listings WHERE id = ?").bind(id).run();
    return json({ ok: true });
  }
  if (b.action === "status") {
    const s2 = str(b.status, 20); if (!LISTING_STATUS.includes(s2)) throw new HttpError(400, "Trạng thái không hợp lệ.");
    await d.prepare("UPDATE listings SET status = ?, updated_at = ? WHERE id = ?").bind(s2, t, id).run();
    return json({ ok: true });
  }
  if (b.action === "feature") { await d.prepare("UPDATE listings SET featured = ?, updated_at = ? WHERE id = ?").bind(b.featured ? 1 : 0, t, id).run(); return json({ ok: true }); }
  const l = cleanListing(b);
  if (id) {
    await d.prepare("UPDATE listings SET type = ?, title = ?, area = ?, price = ?, size = ?, dim = ?, beds = ?, floors = ?, legal = ?, note = ?, images = ?, status = ?, featured = ?, sort = ?, updated_at = ? WHERE id = ?")
      .bind(l.type, l.title, l.area, l.price, l.size, l.dim, l.beds, l.floors, l.legal, l.note, l.images, l.status, l.featured, l.sort, t, id).run();
    return json({ ok: true, id });
  }
  const r = await d.prepare("INSERT INTO listings (type, title, area, price, size, dim, beds, floors, legal, note, images, status, featured, sort, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
    .bind(l.type, l.title, l.area, l.price, l.size, l.dim, l.beds, l.floors, l.legal, l.note, l.images, l.status, l.featured, l.sort, a.email, t, t).run();
  return json({ ok: true, id: Number(r.meta?.last_row_id) }, 201);
}
/* Ảnh tải lên được nén sẵn trên trình duyệt (WebP/JPEG) rồi lưu trong D1 dưới dạng base64 — không cần dịch vụ lưu trữ trả phí. */
const MEDIA_MIME: Record<string, number[]> = { "image/webp": [0x52, 0x49, 0x46, 0x46], "image/jpeg": [0xff, 0xd8, 0xff], "image/png": [0x89, 0x50, 0x4e, 0x47] };
async function adminMedia(req: Request) {
  const a = await requireAdmin(req, "media");
  const b = await readBody(req, 1_800_000);
  const mime = str(b.mime, 20), data = typeof b.data === "string" ? b.data.replace(/^data:[^,]+,/, "") : "";
  if (!MEDIA_MIME[mime]) throw new HttpError(400, "Chỉ nhận ảnh WebP, JPEG hoặc PNG.");
  let bytes: Uint8Array;
  try { bytes = Uint8Array.from(atob(data), (c) => c.charCodeAt(0)); } catch { throw new HttpError(400, "Dữ liệu ảnh không hợp lệ."); }
  if (bytes.length < 100 || bytes.length > 1_300_000) throw new HttpError(413, "Ảnh cần nhỏ hơn 1,3 MB sau khi nén.");
  if (!MEDIA_MIME[mime].every((x, i) => bytes[i] === x)) throw new HttpError(400, "Tệp không đúng định dạng ảnh.");
  await limit(`media:${a.id}`, 120, HOUR);
  const id = randomToken(15);
  await db().prepare("INSERT INTO media (id, mime, data, size, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?)").bind(id, mime, data, bytes.length, a.email, now()).run();
  return json({ id, url: `/api/media/${id}` }, 201);
}
async function mediaGetCached(req: Request, id: string): Promise<Response> {
  const cache = (globalThis as unknown as { caches?: { default?: { match(r: Request): Promise<Response | undefined>; put(r: Request, res: Response): Promise<void> } } }).caches?.default;
  const key = new Request(new URL(req.url).origin + "/api/media/" + id);
  if (cache) { const hit = await cache.match(key); if (hit) return hit; }
  const res = await mediaGet(id);
  if (cache && res.status === 200) { try { await cache.put(key, res.clone()); } catch { /* bỏ qua */ } }
  return res;
}
async function mediaGet(id: string): Promise<Response> {
  if (!/^[A-Za-z0-9_-]{10,40}$/.test(id)) return new Response("Không tìm thấy", { status: 404 });
  const m = await db().prepare("SELECT mime, data FROM media WHERE id = ?").bind(id).first<{ mime: string; data: string }>();
  if (!m) return new Response("Không tìm thấy", { status: 404 });
  const bytes = Uint8Array.from(atob(m.data), (c) => c.charCodeAt(0));
  return new Response(bytes, { headers: { "Content-Type": m.mime, "Cache-Control": "public, max-age=31536000, immutable", "Content-Disposition": "inline" } });
}

/* ================= CREATOR NỔI BẬT ================= */
const URL_HOSTS: Record<string, RegExp> = { tiktok: /(^|\.)tiktok\.com$/, youtube: /(^|\.)(youtube\.com|youtu\.be)$/, facebook: /(^|\.)(facebook\.com|fb\.watch|fb\.com)$/ };
function cleanUrl(v: unknown, kind: "tiktok" | "youtube" | "facebook" | "video") {
  const s = str(v, 300); if (!s) return "";
  let u: URL; try { u = new URL(/^https?:\/\//i.test(s) ? s : "https://" + s); } catch { throw new HttpError(400, "Đường dẫn chưa hợp lệ: " + s); }
  const host = u.hostname.toLowerCase();
  const ok = kind === "video" ? Object.values(URL_HOSTS).some((r) => r.test(host)) : URL_HOSTS[kind].test(host);
  if (!ok) throw new HttpError(400, kind === "video" ? "Video tiêu biểu cần là đường dẫn TikTok, YouTube hoặc Facebook." : `Đường dẫn ${kind === "tiktok" ? "TikTok" : kind === "youtube" ? "YouTube" : "Facebook"} chưa đúng.`);
  u.protocol = "https:"; u.hash = "";
  return u.toString().slice(0, 300);
}
async function creatorApply(req: Request) {
  const u = await requireUser(req);
  const b = await readBody(req);
  if (u.needs_onboarding) throw new HttpError(400, "Vui lòng hoàn tất thông tin tài khoản trước.");
  const name = str(b.displayName, 60).replace(/\s+/g, " ");
  if (name.length < 2) throw new HttpError(400, "Vui lòng nhập tên kênh / nghệ danh.");
  const tiktok = cleanUrl(b.tiktok, "tiktok"), youtube = cleanUrl(b.youtube, "youtube"), facebook = cleanUrl(b.facebook, "facebook"), video = cleanUrl(b.video, "video");
  if (!tiktok && !youtube && !facebook) throw new HttpError(400, "Cần ít nhất một kênh TikTok, YouTube hoặc Facebook.");
  const intro = str(b.intro, 400);
  if (intro.length < 20) throw new HttpError(400, "Giới thiệu ngắn về nội dung bạn làm (ít nhất 20 ký tự).");
  await limit(`creator:${u.id}`, 6, DAY);
  const t = now();
  await db().prepare("INSERT INTO creators (user_id, display_name, tiktok, youtube, facebook, intro, video, followers, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?) ON CONFLICT(user_id) DO UPDATE SET display_name = excluded.display_name, tiktok = excluded.tiktok, youtube = excluded.youtube, facebook = excluded.facebook, intro = excluded.intro, video = excluded.video, followers = excluded.followers, status = 'pending', updated_at = excluded.updated_at")
    .bind(u.id, name, tiktok, youtube, facebook, intro, video, str(b.followers, 40), t, t).run();
  await db().prepare("UPDATE users SET creator = 'pending' WHERE id = ?").bind(u.id).run();
  await logEvent(u.id, "creator", "Gửi đơn Creator", "khách");
  await notifyAdmin(new URL(req.url).origin, `[Website] Đơn Creator mới – ${name}`, `${escHtml(u.name)} · ${escHtml(u.email)}<br>${escHtml(intro)}`);
  return profileGet(req);
}
async function creatorWithdraw(req: Request) {
  const u = await requireUser(req);
  await readBody(req);
  await db().prepare("DELETE FROM creators WHERE user_id = ?").bind(u.id).run();
  await db().prepare("UPDATE users SET creator = '' WHERE id = ?").bind(u.id).run();
  await logEvent(u.id, "creator", "Rút khỏi chương trình Creator", "khách");
  return profileGet(req);
}
async function creatorsPublic() {
  const rows = (await db().prepare("SELECT c.display_name, c.tiktok, c.youtube, c.facebook, c.intro, c.video, c.followers, c.cover, c.featured, u.avatar FROM creators c JOIN users u ON u.id = c.user_id WHERE c.status = 'approved' AND u.status = 'active' ORDER BY c.featured DESC, c.sort, c.reviewed_at DESC LIMIT 24").all()).results;
  return new Response(JSON.stringify({ rows }), { headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "public, max-age=60" } });
}

/* ================= THỐNG KÊ LƯỢT TRUY CẬP (ẩn danh, không lưu IP) ================= */
const vnDay = (ms = now()) => new Date(ms + 7 * HOUR).toISOString().slice(0, 10);
async function daySalt(day: string) {
  const k = "salt:" + day, d = db();
  const r = await d.prepare("SELECT value FROM settings WHERE key = ?").bind(k).first<{ value: string }>();
  if (r) return r.value;
  const v = randomToken(16);
  await d.prepare("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)").bind(k, v).run();
  await d.prepare("DELETE FROM settings WHERE key LIKE 'salt:%' AND key < ?").bind("salt:" + vnDay(now() - 3 * DAY)).run();
  return ((await d.prepare("SELECT value FROM settings WHERE key = ?").bind(k).first<{ value: string }>())?.value) ?? v;
}
async function track(req: Request) {
  const ua = req.headers.get("User-Agent") ?? "";
  const b = await readBody(req, 2000);
  if (!ua || /bot|crawl|spider|slurp|preview|headless|lighthouse|monitor|curl|wget|python|node-fetch/i.test(ua)) return json({ ok: true });
  const ev = b.e === "listing" ? "listing" : "view";
  try { await limit(`track:${clientIp(req)}`, 120, HOUR); } catch { return json({ ok: true }); }
  const day = vnDay(), salt = await daySalt(day);
  const vh = (await sha256(salt + clientIp(req) + ua)).slice(0, 20);
  let ref = "";
  try { const r = new URL(str(b.r, 300)); if (r.hostname !== new URL(req.url).hostname) ref = r.hostname.replace(/^www\./, "").slice(0, 80); } catch { /* không có nguồn */ }
  const w = Number(b.w) || 0;
  const device = /iPad|Tablet/i.test(ua) || (/Android/i.test(ua) && !/Mobile/i.test(ua)) ? "tablet" : /Mobi|iPhone|Android/i.test(ua) || (w && w < 700) ? "mobile" : "desktop";
  const lid = ev === "listing" ? Math.round(Number(b.id)) || null : null;
  await db().prepare("INSERT INTO visits (day, at, vh, ev, path, ref, country, device, lid) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)").bind(day, now(), vh, ev, str(b.p, 120), ref, reqMeta(req).country, device, lid).run();
  if (crypto.getRandomValues(new Uint8Array(1))[0] < 2) await db().prepare("DELETE FROM visits WHERE at < ?").bind(now() - 400 * DAY).run();
  return json({ ok: true });
}
async function adminAnalytics(req: Request) {
  await requireAdmin(req, "analytics");
  const days = Math.min(365, Math.max(7, Math.round(Number(new URL(req.url).searchParams.get("days")) || 30)));
  const since = vnDay(now() - (days - 1) * DAY), today = vnDay(), d = db();
  const q = <T = Row>(sql: string, ...v: unknown[]) => d.prepare(sql).bind(...v).all<T>().then((r) => r.results);
  const [daily, refs, countries, devices, top, online, todayRow] = await Promise.all([
    q("SELECT day, COUNT(*) AS views, COUNT(DISTINCT vh) AS visitors FROM visits WHERE ev = 'view' AND day >= ? GROUP BY day ORDER BY day", since),
    q("SELECT ref, COUNT(*) AS n FROM visits WHERE ev = 'view' AND day >= ? AND ref != '' GROUP BY ref ORDER BY n DESC LIMIT 10", since),
    q("SELECT country, COUNT(DISTINCT day || vh) AS n FROM visits WHERE ev = 'view' AND day >= ? AND country != '' GROUP BY country ORDER BY n DESC LIMIT 10", since),
    q("SELECT device, COUNT(DISTINCT day || vh) AS n FROM visits WHERE ev = 'view' AND day >= ? GROUP BY device ORDER BY n DESC", since),
    q("SELECT v.lid AS id, l.title, COUNT(*) AS n FROM visits v LEFT JOIN listings l ON l.id = v.lid WHERE v.ev = 'listing' AND v.day >= ? GROUP BY v.lid ORDER BY n DESC LIMIT 10", since),
    d.prepare("SELECT COUNT(DISTINCT vh) AS n FROM visits WHERE at > ?").bind(now() - 5 * MIN).first<{ n: number }>(),
    d.prepare("SELECT COUNT(*) AS views, COUNT(DISTINCT vh) AS visitors FROM visits WHERE ev = 'view' AND day = ?").bind(today).first<{ views: number; visitors: number }>(),
  ]);
  const views = (daily as Row[]).reduce((s2, r) => s2 + Number(r.views), 0), visitors = (daily as Row[]).reduce((s2, r) => s2 + Number(r.visitors), 0);
  return json({ days, since, today: todayRow ?? { views: 0, visitors: 0 }, online: online?.n ?? 0, views, visitors, daily, refs, countries, devices, top });
}

/* ================= QUẢN TRỊ ================= */
async function adminState(req: Request) {
  const n = await db().prepare("SELECT COUNT(*) AS n FROM admins").first<{ n: number }>();
  let admin: Admin | null = null;
  try { admin = await requireAdmin(req); } catch { admin = null; }
  return json({ setup: (n?.n ?? 0) === 0, admin: admin ? adminOut(admin) : null, mail: mailReady(), sms: smsReady(), google: googleReady(), facebook: facebookReady() });
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
  await db().prepare("INSERT INTO admins (email, name, pass_hash, pass_salt, pass_iter, created_at, role) VALUES (?, ?, ?, ?, ?, ?, 'director')").bind(email, name, hash, salt, iter, now()).run();
  return json({ ok: true }, 201);
}
async function adminLogin(req: Request) {
  const b = await readBody(req);
  const email = str(b.email, 160).toLowerCase(), pass = typeof b.pass === "string" ? b.pass.slice(0, 128) : "";
  await limit(`alogin:${clientIp(req)}`, 8, 15 * MIN);
  const a = await db().prepare("SELECT * FROM admins WHERE email = ?").bind(email).first<Admin & { pass_hash: string; pass_salt: string; pass_iter: number }>();
  if (!a || !(await checkPass(pass, a.pass_salt, a.pass_hash, a.pass_iter || 100_000))) {
    if (a) await logLogin("admin", a.id, false, "password", req);
    throw new HttpError(401, "Email hoặc mật khẩu quản trị chưa đúng.");
  }
  await db().prepare("UPDATE admins SET last_login = ? WHERE id = ?").bind(now(), a.id).run();
  const tok = await newSession("admin", a.id, DAY / 2, req);
  return json({ admin: adminOut(a) }, 200, [cookie(ADMIN_COOKIE, tok, 12 * 3600, "Strict")]);
}
async function adminStats(req: Request) {
  await requireAdmin(req, "stats");
  const d = db(), t = now();
  const q = async (sql: string, ...v: unknown[]) => ((await d.prepare(sql).bind(...v).first<{ n: number }>())?.n ?? 0);
  const [users, users7, leads, leadsNew, leads7, resets, active30, trusted, daily, requests, profiles, creatorsPending, listingsLive, visitsToday] = await Promise.all([
    q("SELECT COUNT(*) AS n FROM users"),
    q("SELECT COUNT(*) AS n FROM users WHERE created_at > ?", t - 7 * DAY),
    q("SELECT COUNT(*) AS n FROM leads"),
    q("SELECT COUNT(*) AS n FROM leads WHERE status = 'new'"),
    q("SELECT COUNT(*) AS n FROM leads WHERE created_at > ?", t - 7 * DAY),
    q("SELECT COUNT(*) AS n FROM reset_requests WHERE status = 'pending'"),
    q("SELECT COUNT(*) AS n FROM users WHERE last_login > ?", t - 30 * DAY),
    q("SELECT COUNT(*) AS n FROM trusted_devices WHERE expires_at > ?", t),
    d.prepare("SELECT strftime('%Y-%m-%d', created_at / 1000, 'unixepoch', '+7 hours') AS day, COUNT(*) AS n FROM leads WHERE created_at > ? GROUP BY day ORDER BY day").bind(t - 14 * DAY).all<{ day: string; n: number }>(),
    q("SELECT COUNT(*) AS n FROM change_requests WHERE status = 'pending'"),
    q("SELECT COUNT(*) AS n FROM users WHERE profile_at IS NOT NULL"),
    q("SELECT COUNT(*) AS n FROM creators WHERE status = 'pending'"),
    q("SELECT COUNT(*) AS n FROM listings WHERE status = 'published'"),
    d.prepare("SELECT COUNT(*) AS views, COUNT(DISTINCT vh) AS visitors FROM visits WHERE ev = 'view' AND day = ?").bind(vnDay()).first<{ views: number; visitors: number }>(),
  ]);
  return json({ users, users7, leads, leadsNew, leads7, resets, active30, trusted, requests, profiles, creatorsPending, listingsLive, visitsToday: visitsToday ?? { views: 0, visitors: 0 }, mail: mailReady(), sms: smsReady(), google: googleReady(), facebook: facebookReady(), daily: daily.results });
}
const likeQ = (q: string) => `%${q.replace(/[%_\\]/g, (c) => "\\" + c)}%`;
async function adminUsers(req: Request) {
  await requireAdmin(req, "users.view");
  const u = new URL(req.url), q = str(u.searchParams.get("q"), 80), off = Math.min(1_000_000, Math.max(0, Math.floor(Number(u.searchParams.get("offset")) || 0)));
  const where = q ? "WHERE u.email LIKE ?1 ESCAPE '\\' OR u.name LIKE ?1 ESCAPE '\\' OR u.phone LIKE ?1 ESCAPE '\\'" : "";
  const sql = `SELECT u.id, u.email, u.phone, u.name, u.role, u.email_verified, u.phone_verified, u.status, u.marketing, u.created_at, u.last_login, u.profile_at, u.name_changes, u.creator, u.avatar, u.has_pass, (SELECT GROUP_CONCAT(provider) FROM identities i WHERE i.user_id = u.id) AS providers, (SELECT COUNT(*) FROM trusted_devices t WHERE t.user_id = u.id AND t.expires_at > ${now()}) AS devices FROM users u ${where} ORDER BY u.id DESC LIMIT 50 OFFSET ${off}`;
  const rows = (q ? await db().prepare(sql).bind(likeQ(q)).all() : await db().prepare(sql).all()).results;
  const tsql = `SELECT COUNT(*) AS n FROM users u ${where}`;
  const n = (q ? await db().prepare(tsql).bind(likeQ(q)).first<{ n: number }>() : await db().prepare(tsql).first<{ n: number }>())?.n ?? 0;
  return json({ rows, total: n });
}
async function adminUserAction(req: Request) {
  const a = await requireAdmin(req, "users.manage");
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
  if (action === "unlock-profile") { await d.prepare("UPDATE users SET profile_at = NULL WHERE id = ?").bind(id).run(); await logEvent(id, "profile", "Mở khoá để khách tự cập nhật thông tin 1 lần", a.email); return json({ ok: true }); }
  if (action === "allow-rename") { await d.prepare("UPDATE users SET name_changes = 0 WHERE id = ?").bind(id).run(); await logEvent(id, "name", "Cho phép khách tự đổi tên thêm 1 lần", a.email); return json({ ok: true }); }
  if (action === "update") {
    const name = str(b.name, 80).replace(/\s+/g, " "), email = str(b.email, 160).toLowerCase();
    const phone = b.phone !== undefined ? toE164(b.cc, b.phone) : u.phone;
    if (name.length < 2) throw new HttpError(400, "Tên hiển thị cần ít nhất 2 ký tự.");
    if (!isEmail(email)) throw new HttpError(400, "Email chưa hợp lệ.");
    if (!phone) throw new HttpError(400, "Số điện thoại chưa hợp lệ.");
    if (email !== u.email && await d.prepare("SELECT id FROM users WHERE email = ? AND id != ?").bind(email, id).first()) throw new HttpError(409, "Email này đã thuộc tài khoản khác.");
    if (phone !== u.phone && await d.prepare("SELECT id FROM users WHERE phone = ? AND id != ?").bind(phone, id).first()) throw new HttpError(409, "Số điện thoại này đã thuộc tài khoản khác.");
    const hasProfile = b.profile && typeof b.profile === "object" && Object.values(b.profile as Row).some((v) => typeof v === "string" && v.trim());
    let profileJson = u.profile, profileAt = u.profile_at;
    if (hasProfile) {
      const p = cleanProfile(b.profile);
      const old = parseProfile(u.profile);
      if (old.consentAt) p.consentAt = old.consentAt;
      profileJson = JSON.stringify(p); profileAt = profileAt ?? now();
    }
    await d.prepare("UPDATE users SET name = ?, email = ?, email_verified = CASE WHEN email = ? THEN email_verified ELSE 0 END, phone = ?, phone_cc = CASE WHEN ? != '' THEN ? ELSE phone_cc END, phone_verified = CASE WHEN phone = ? THEN phone_verified ELSE 0 END, profile = ?, profile_at = ? WHERE id = ?")
      .bind(name, email, email, phone, str(b.ccIso, 3).toUpperCase(), str(b.ccIso, 3).toUpperCase(), phone, profileJson, profileAt, id).run();
    const changed = [name !== u.name && "tên", email !== u.email && "email", phone !== u.phone && "SĐT", hasProfile && profileJson !== u.profile && "thông tin cá nhân"].filter(Boolean).join(", ");
    if (changed) await logEvent(id, "admin-update", `Quản trị viên cập nhật: ${changed}`, a.email);
    const rid = Number(b.requestId);
    if (rid) await d.prepare("UPDATE change_requests SET status = 'done', handled_at = ?, handled_by = ?, note = ? WHERE id = ? AND user_id = ?").bind(now(), a.email, changed ? `Đã cập nhật: ${changed}` : "Đã xử lý", rid, id).run();
    return json({ ok: true });
  }
  if (action === "set-role") {
    const role = str(b.role, 60);
    if (!ROLES.includes(role)) throw new HttpError(400, "Vai trò không hợp lệ.");
    await d.prepare("UPDATE users SET role = ? WHERE id = ?").bind(role, id).run();
    await logEvent(id, "role", `${u.role || "—"} → ${role}`, a.email);
    return json({ ok: true });
  }
  if (action === "revoke-devices") { await d.prepare("DELETE FROM trusted_devices WHERE user_id = ?").bind(id).run(); return json({ ok: true }); }
  if (action === "temp-password") {
    const temp = tempPassword();
    const h = await hashPass(temp);
    await d.batch([
      d.prepare("UPDATE users SET pass_hash = ?, pass_salt = ?, pass_iter = ?, has_pass = 1 WHERE id = ?").bind(h.hash, h.salt, h.iter, id),
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
  await requireAdmin(req, "leads");
  const u = new URL(req.url), q = str(u.searchParams.get("q"), 80), s = str(u.searchParams.get("status"), 20), off = Math.min(1_000_000, Math.max(0, Math.floor(Number(u.searchParams.get("offset")) || 0)));
  const cond: string[] = [], v: unknown[] = [];
  if (LEAD_STATUS.includes(s)) { cond.push("status = ?"); v.push(s); }
  if (q) { cond.push("(name LIKE ? ESCAPE '\\' OR phone LIKE ? ESCAPE '\\' OR text LIKE ? ESCAPE '\\')"); v.push(likeQ(q), likeQ(q), likeQ(q)); }
  const where = cond.length ? "WHERE " + cond.join(" AND ") : "";
  const rows = (await db().prepare(`SELECT * FROM leads ${where} ORDER BY id DESC LIMIT 50 OFFSET ${off}`).bind(...v).all()).results;
  const n = (await db().prepare(`SELECT COUNT(*) AS n FROM leads ${where}`).bind(...v).first<{ n: number }>())?.n ?? 0;
  return json({ rows, total: n });
}
async function adminLeadUpdate(req: Request) {
  await requireAdmin(req, "leads");
  const b = await readBody(req);
  const id = Number(b.id), status = str(b.status, 20), note = typeof b.note === "string" ? b.note.slice(0, 2000) : null;
  if (status && !LEAD_STATUS.includes(status)) throw new HttpError(400, "Trạng thái không hợp lệ.");
  await db().prepare("UPDATE leads SET status = COALESCE(NULLIF(?, ''), status), note = COALESCE(?, note), updated_at = ? WHERE id = ?").bind(status, note, now(), id).run();
  return json({ ok: true });
}
async function adminResets(req: Request) {
  await requireAdmin(req, "resets");
  const s = str(new URL(req.url).searchParams.get("status"), 20) || "pending";
  const rows = (await db().prepare("SELECT r.*, u.name AS user_name, u.phone AS user_phone FROM reset_requests r LEFT JOIN users u ON u.id = r.user_id WHERE r.status = ? ORDER BY r.id DESC LIMIT 100").bind(s === "done" ? "done" : "pending").all()).results;
  return json({ rows });
}
async function adminResetUpdate(req: Request) {
  const a = await requireAdmin(req, "resets");
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
  const me = await requireAdmin(req, req.method === "GET" ? undefined : "admins.manage");
  if (req.method === "GET" && levelOf(me) < PERMS["admins.manage"]) return json({ rows: (await db().prepare("SELECT id, name, role FROM admins ORDER BY CASE role WHEN 'director' THEN 0 WHEN 'manager' THEN 1 ELSE 2 END, id").all()).results, roles: ADMIN_ROLES });
  if (req.method === "GET") return json({ rows: (await db().prepare("SELECT id, email, name, role, created_at, last_login FROM admins ORDER BY CASE role WHEN 'director' THEN 0 WHEN 'manager' THEN 1 ELSE 2 END, id").all()).results, roles: ADMIN_ROLES });
  const b = await readBody(req);
  const email = str(b.email, 160).toLowerCase(), name = str(b.name, 80), pass = typeof b.pass === "string" ? b.pass : "";
  if (!isEmail(email) || name.length < 2 || pass.length < 10) throw new HttpError(400, "Nhập đủ họ tên, email và mật khẩu (tối thiểu 10 ký tự).");
  if (await db().prepare("SELECT id FROM admins WHERE email = ?").bind(email).first()) throw new HttpError(409, "Email này đã là quản trị viên.");
  const { salt, hash, iter } = await hashPass(pass);
  const role = ADMIN_ROLES[str(b.role, 20)] ? str(b.role, 20) : "assistant";
  await db().prepare("INSERT INTO admins (email, name, pass_hash, pass_salt, pass_iter, created_at, role) VALUES (?, ?, ?, ?, ?, ?, ?)").bind(email, name, hash, salt, iter, now(), role).run();
  return json({ ok: true }, 201);
}
async function adminUserGet(req: Request) {
  const adm = await requireAdmin(req, "users.view");
  const id = Number(new URL(req.url).searchParams.get("id"));
  const u = await getUser(id);
  if (!u) throw new HttpError(404, "Không tìm thấy tài khoản.");
  const d = db();
  const [events, requests, devices] = await Promise.all([
    d.prepare("SELECT kind, detail, actor, at FROM account_events WHERE user_id = ? ORDER BY id DESC LIMIT 30").bind(id).all(),
    d.prepare("SELECT * FROM change_requests WHERE user_id = ? ORDER BY id DESC LIMIT 20").bind(id).all(),
    d.prepare("SELECT COUNT(*) AS n FROM trusted_devices WHERE user_id = ? AND expires_at > ?").bind(id, now()).first<{ n: number }>(),
  ]);
  const { pass_hash: _h, pass_salt: _s, pass_iter: _i, profile, ...rest } = u;
  const p = parseProfile(profile);
  if (levelOf(adm) < PERMS["users.cccd"] && p.cccd) p.cccd = maskCccd(p.cccd); // Trợ lý chỉ thấy số CCCD đã che
  const ids = (await d.prepare("SELECT provider, email, created_at FROM identities WHERE user_id = ?").bind(id).all()).results;
  return json({ user: { ...rest, devices: devices?.n ?? 0 }, profile: p, identities: ids, events: events.results, requests: requests.results });
}
async function adminRequests(req: Request) {
  await requireAdmin(req, "requests.view");
  const s = str(new URL(req.url).searchParams.get("status"), 20) === "done" ? "done" : "pending";
  const rows = (await db().prepare(`SELECT r.*, u.name AS user_name, u.email AS user_email, u.phone AS user_phone FROM change_requests r LEFT JOIN users u ON u.id = r.user_id WHERE ${s === "done" ? "r.status != 'pending'" : "r.status = 'pending'"} ORDER BY r.id DESC LIMIT 100`).all()).results;
  return json({ rows });
}
async function adminRequestUpdate(req: Request) {
  const a = await requireAdmin(req, "requests.handle");
  const b = await readBody(req);
  const status = b.status === "rejected" ? "rejected" : "done";
  const note = str(b.note, 1000);
  const r = await db().prepare("SELECT user_id, topic FROM change_requests WHERE id = ?").bind(Number(b.id)).first<{ user_id: number; topic: string }>();
  if (!r) throw new HttpError(404, "Không tìm thấy yêu cầu.");
  await db().prepare("UPDATE change_requests SET status = ?, note = ?, handled_at = ?, handled_by = ? WHERE id = ?").bind(status, note, now(), a.email, Number(b.id)).run();
  await logEvent(r.user_id, "request", `${r.topic}: ${status === "done" ? "đã xử lý" : "từ chối"}${note ? " – " + note : ""}`, a.email);
  return json({ ok: true });
}
/** Tài khoản quản trị của chính mình: đổi tên hiển thị, email đăng nhập (cần mật khẩu hiện tại). */
async function adminMe(req: Request) {
  const a = await requireAdmin(req);
  if (req.method === "GET") return json({ admin: { ...(await db().prepare("SELECT id, email, name, created_at, last_login FROM admins WHERE id = ?").bind(a.id).first()), ...adminOut(a) } });
  const b = await readBody(req);
  const name = str(b.name, 80).replace(/\s+/g, " "), email = str(b.email, 160).toLowerCase(), pass = typeof b.pass === "string" ? b.pass.slice(0, 128) : "";
  if (name.length < 2) throw new HttpError(400, "Tên hiển thị cần ít nhất 2 ký tự.");
  if (!isEmail(email)) throw new HttpError(400, "Email chưa hợp lệ.");
  await limit(`ame:${a.id}`, 6, 15 * MIN);
  const row = await db().prepare("SELECT pass_hash, pass_salt, pass_iter FROM admins WHERE id = ?").bind(a.id).first<{ pass_hash: string; pass_salt: string; pass_iter: number }>();
  if (!row || !(await checkPass(pass, row.pass_salt, row.pass_hash, row.pass_iter || 100_000))) throw new HttpError(400, "Mật khẩu hiện tại chưa đúng.");
  if (email !== a.email && await db().prepare("SELECT id FROM admins WHERE email = ? AND id != ?").bind(email, a.id).first()) throw new HttpError(409, "Email này đã là quản trị viên khác.");
  await db().prepare("UPDATE admins SET name = ?, email = ? WHERE id = ?").bind(name, email, a.id).run();
  return json({ admin: adminOut({ ...a, email, name }) });
}
/* ---------- quản trị: Creator ---------- */
async function adminCreators(req: Request) {
  await requireAdmin(req, "creators.view");
  const s = str(new URL(req.url).searchParams.get("status"), 20);
  const where = ["pending", "approved", "rejected"].includes(s) ? "WHERE c.status = ?" : "";
  const sql = `SELECT c.*, u.name AS user_name, u.email AS user_email, u.phone AS user_phone, u.avatar FROM creators c JOIN users u ON u.id = c.user_id ${where} ORDER BY c.status = 'pending' DESC, c.featured DESC, c.sort, c.updated_at DESC LIMIT 200`;
  const rows = (where ? await db().prepare(sql).bind(s).all() : await db().prepare(sql).all()).results;
  return json({ rows });
}
async function adminCreator(req: Request) {
  const a = await requireAdmin(req, "creators.manage");
  const b = await readBody(req);
  const id = Number(b.userId), action = str(b.action, 20), d = db(), t = now();
  const c = await d.prepare("SELECT user_id, display_name FROM creators WHERE user_id = ?").bind(id).first<{ user_id: number; display_name: string }>();
  if (!c) throw new HttpError(404, "Không tìm thấy đơn Creator.");
  if (action === "approve" || action === "reject" || action === "revoke") {
    const st = action === "approve" ? "approved" : "rejected";
    await d.prepare("UPDATE creators SET status = ?, note = ?, reviewed_at = ?, reviewed_by = ?, featured = CASE WHEN ? = 'approved' THEN featured ELSE 0 END WHERE user_id = ?").bind(st, str(b.note, 400), t, a.email, st, id).run();
    await d.prepare("UPDATE users SET creator = ? WHERE id = ?").bind(st, id).run();
    await logEvent(id, "creator", action === "approve" ? "Được duyệt danh hiệu Creator" : action === "revoke" ? "Thu hồi danh hiệu Creator" : "Đơn Creator chưa được duyệt", a.email);
    return json({ ok: true });
  }
  if (action === "feature") { await d.prepare("UPDATE creators SET featured = ?, updated_at = ? WHERE user_id = ?").bind(b.featured ? 1 : 0, t, id).run(); return json({ ok: true }); }
  if (action === "update") {
    const cover = str(b.cover, 80);
    if (cover && !IMG_REF.test(cover)) throw new HttpError(400, "Ảnh bìa chưa hợp lệ.");
    await d.prepare("UPDATE creators SET display_name = ?, tiktok = ?, youtube = ?, facebook = ?, intro = ?, video = ?, followers = ?, cover = ?, sort = ?, updated_at = ? WHERE user_id = ?")
      .bind(str(b.displayName, 60) || c.display_name, cleanUrl(b.tiktok, "tiktok"), cleanUrl(b.youtube, "youtube"), cleanUrl(b.facebook, "facebook"), str(b.intro, 400), cleanUrl(b.video, "video"), str(b.followers, 40), cover, Math.round(Number(b.sort) || 0), t, id).run();
    return json({ ok: true });
  }
  throw new HttpError(400, "Thao tác không hợp lệ.");
}
/* ---------- quản trị: lịch sử đăng nhập ---------- */
async function adminLogins(req: Request) {
  const a = await requireAdmin(req);
  const u = new URL(req.url), uid = Number(u.searchParams.get("userId")), who = u.searchParams.get("admin");
  if (uid) {
    if (levelOf(a) < PERMS["logins.users"]) throw new HttpError(403, "Vai trò của bạn chưa xem được lịch sử đăng nhập của khách.");
    const ev = (await db().prepare("SELECT id, ok, method, ip, loc, label, at FROM login_events WHERE kind = 'user' AND subject_id = ? ORDER BY id DESC LIMIT 60").bind(uid).all()).results;
    const ss = (await db().prepare("SELECT substr(token_hash, 1, 16) AS sid, ip, label, loc, created_at, last_seen FROM sessions WHERE kind = 'user' AND subject_id = ? AND expires_at > ? ORDER BY COALESCE(last_seen, created_at) DESC").bind(uid, now()).all()).results;
    return json({ events: ev, sessions: ss });
  }
  if (who === "all") {
    if (levelOf(a) < PERMS["logins.admins"]) throw new HttpError(403, "Chỉ Giám đốc xem được lịch sử đăng nhập của mọi quản trị viên.");
    const ev = (await db().prepare("SELECT e.id, e.ok, e.method, e.ip, e.loc, e.label, e.at, a.name, a.email, a.role FROM login_events e LEFT JOIN admins a ON a.id = e.subject_id WHERE e.kind = 'admin' ORDER BY e.id DESC LIMIT 150").all()).results;
    return json({ events: ev });
  }
  const cur = (await sha256(getCookie(req, ADMIN_COOKIE))).slice(0, 16);
  const ev = (await db().prepare("SELECT id, ok, method, ip, loc, label, sid, at FROM login_events WHERE kind = 'admin' AND subject_id = ? ORDER BY id DESC LIMIT 60").bind(a.id).all<Row>()).results;
  const ss = (await db().prepare("SELECT substr(token_hash, 1, 16) AS sid, ip, label, loc, created_at, last_seen FROM sessions WHERE kind = 'admin' AND subject_id = ? AND expires_at > ? ORDER BY COALESCE(last_seen, created_at) DESC").bind(a.id, now()).all<Row>()).results;
  return json({ events: ev.map((x) => ({ ...x, current: x.sid === cur })), sessions: ss.map((x) => ({ ...x, current: x.sid === cur })) });
}
async function adminSessionRevoke(req: Request) {
  const a = await requireAdmin(req);
  const b = await readBody(req);
  const cur = (await sha256(getCookie(req, ADMIN_COOKIE))).slice(0, 16);
  if (b.userId) {
    if (levelOf(a) < PERMS["users.manage"]) throw new HttpError(403, "Vai trò của bạn chưa có quyền này.");
    await db().prepare("DELETE FROM sessions WHERE kind = 'user' AND subject_id = ?").bind(Number(b.userId)).run();
    await logEvent(Number(b.userId), "sessions", "Quản trị viên đăng xuất mọi thiết bị", a.email);
    return json({ ok: true });
  }
  if (b.others === true) await db().prepare("DELETE FROM sessions WHERE kind = 'admin' AND subject_id = ? AND substr(token_hash, 1, 16) != ?").bind(a.id, cur).run();
  else await db().prepare("DELETE FROM sessions WHERE kind = 'admin' AND subject_id = ? AND substr(token_hash, 1, 16) = ?").bind(a.id, str(b.sid, 16)).run();
  return json({ ok: true });
}
/* ---------- quản trị: phân quyền quản trị viên ---------- */
async function adminManage(req: Request) {
  const a = await requireAdmin(req, "admins.manage");
  const b = await readBody(req);
  const id = Number(b.id), d = db();
  const t = await d.prepare("SELECT id, role FROM admins WHERE id = ?").bind(id).first<{ id: number; role: string }>();
  if (!t) throw new HttpError(404, "Không tìm thấy quản trị viên.");
  const directors = (await d.prepare("SELECT COUNT(*) AS n FROM admins WHERE role = 'director'").first<{ n: number }>())?.n ?? 0;
  if (b.action === "set-role") {
    const role = str(b.role, 20);
    if (!ADMIN_ROLES[role]) throw new HttpError(400, "Vai trò không hợp lệ.");
    if (t.role === "director" && role !== "director" && directors <= 1) throw new HttpError(400, "Cần ít nhất một Giám đốc. Hãy chỉ định Giám đốc khác trước.");
    const r = await d.prepare("UPDATE admins SET role = ? WHERE id = ? AND (role != 'director' OR ? = 'director' OR (SELECT COUNT(*) FROM admins WHERE role = 'director') > 1)").bind(role, id, role).run();
    if (!r.meta?.changes && t.role !== role) throw new HttpError(409, "Cần ít nhất một Giám đốc. Vui lòng thử lại.");
    return json({ ok: true });
  }
  if (b.action === "remove") {
    if (id === a.id) throw new HttpError(400, "Bạn không thể tự xoá tài khoản của mình.");
    if (t.role === "director" && directors <= 1) throw new HttpError(400, "Cần ít nhất một Giám đốc.");
    await d.batch([d.prepare("DELETE FROM sessions WHERE kind = 'admin' AND subject_id = ?").bind(id), d.prepare("DELETE FROM admins WHERE id = ?").bind(id)]);
    return json({ ok: true });
  }
  throw new HttpError(400, "Thao tác không hợp lệ.");
}

function csvCell(v: unknown) {
  let s = v === null || v === undefined ? "" : String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; // chặn công thức độc hại khi mở bằng Excel
  return `"${s.replace(/"/g, '""')}"`;
}
const fmtTime = (ms: unknown) => (typeof ms === "number" && ms > 0 ? new Date(ms + 7 * HOUR).toISOString().replace("T", " ").slice(0, 16) : "");
async function adminExport(req: Request) {
  await requireAdmin(req, "export");
  const what = new URL(req.url).searchParams.get("what");
  let head: string[], rows: unknown[][];
  if (what === "users") {
    const r = (await db().prepare("SELECT * FROM users ORDER BY id").all<Row>()).results;
    head = ["ID", "Tên hiển thị", "Email", "Điện thoại", "Vai trò", "Email đã xác minh", "SĐT đã xác minh", "Trạng thái", "Nhận tư vấn", "Ngày tạo", "Đăng nhập gần nhất", ...PROFILE_FIELDS.map((f) => PROFILE_LABEL[f.k]), "Lưu hồ sơ lúc"];
    rows = r.map((u) => { const p = parseProfile(u.profile as string); return [u.id, u.name, u.email, u.phone, u.role, u.email_verified ? "Có" : "Chưa", u.phone_verified ? "Có" : "Chưa", u.status === "active" ? "Hoạt động" : "Tạm khoá", u.marketing ? "Có" : "Không", fmtTime(u.created_at), fmtTime(u.last_login), ...PROFILE_FIELDS.map((f) => p[f.k] ?? ""), fmtTime(u.profile_at)]; });
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
  "auth/config": { GET: async () => json({ mail: mailReady(), sms: smsReady(), google: googleReady(), facebook: facebookReady() }) },
  "auth/onboard": { POST: onboard },
  "auth/password/set": { POST: passwordSet },
  "auth/identity/unlink": { POST: identityUnlink },
  "auth/sessions": { GET: mySessions, POST: mySessions },
  "auth/security/report": { POST: securityReport },
  "creator/apply": { POST: creatorApply },
  "creator/withdraw": { POST: creatorWithdraw },
  "creators": { GET: creatorsPublic },
  "listings": { GET: listingsPublic },
  "track": { POST: track },
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
  "auth/profile": { GET: profileGet, POST: profileSave },
  "auth/profile/name": { POST: profileName },
  "auth/contact/start": { POST: contactStart },
  "auth/contact/resend": { POST: contactResend },
  "auth/contact/verify": { POST: contactVerify },
  "auth/recover": { POST: recover },
  "auth/request": { POST: changeRequest },
  "favs": { GET: favs, POST: favs },
  "leads": { POST: lead },
  "admin/state": { GET: adminState },
  "admin/setup": { POST: adminSetup },
  "admin/login": { POST: adminLogin },
  "admin/logout": { POST: async (r) => { await readBody(r); await dropSession(r, "admin"); return json({ ok: true }, 200, [cookie(ADMIN_COOKIE, "", 0, "Strict")]); } },
  "admin/stats": { GET: adminStats },
  "admin/users": { GET: adminUsers },
  "admin/user": { GET: adminUserGet, POST: adminUserAction },
  "admin/requests": { GET: adminRequests },
  "admin/request": { POST: adminRequestUpdate },
  "admin/me": { GET: adminMe, POST: adminMe },
  "admin/listings": { GET: adminListings },
  "admin/listing": { POST: adminListing },
  "admin/media": { POST: adminMedia },
  "admin/creators": { GET: adminCreators },
  "admin/creator": { POST: adminCreator },
  "admin/logins": { GET: adminLogins },
  "admin/sessions": { POST: adminSessionRevoke },
  "admin/admin": { POST: adminManage },
  "admin/analytics": { GET: adminAnalytics },
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
  const clean = path.replace(/^\/+|\/+$/g, "");
  const method = request.method as "GET" | "POST";
  // đường dẫn có tham số: ảnh tải lên, đăng nhập Google/Facebook
  const media = clean.match(/^media\/([A-Za-z0-9_-]+)$/);
  const oauth = clean.match(/^auth\/oauth\/(google|facebook)\/(start|callback)$/);
  if ((media || oauth) && method === "GET") {
    ENV = environment;
    try {
      await ensureSchema();
      if (media) return await mediaGetCached(request, media[1]);
      return oauth![2] === "start" ? await oauthStart(request, oauth![1]) : await oauthCallback(request, oauth![1]);
    } catch (e) { console.error(e); return new Response("Hệ thống đang bận", { status: 500 }); }
  }
  const route = ROUTES[clean];
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
