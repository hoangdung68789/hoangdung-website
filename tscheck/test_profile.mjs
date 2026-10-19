const B = 'http://localhost:8788';
const SETUP = process.env.SETUP, MODE = process.env.MODE || 'both';
function jar() { const c = {}; return { h: () => Object.entries(c).map(([k, v]) => `${k}=${v}`).join('; '), set: r => { for (const s of r.headers.getSetCookie()) { const [kv] = s.split(';'); const i = kv.indexOf('='); c[kv.slice(0, i)] = kv.slice(i + 1); } } }; }
const U = jar(), A = jar();
async function call(j, path, body) {
  const r = await fetch(B + '/api/' + path, { method: body ? 'POST' : 'GET', headers: { ...(body ? { 'content-type': 'application/json' } : {}), cookie: j.h() }, body: body ? JSON.stringify(body) : undefined });
  j.set(r); let d = {}; try { d = await r.json(); } catch {}
  return { s: r.status, d };
}
const codes = async () => (await fetch(B + '/__test/codes')).json();
let fails = 0; const ok = (c, m, extra = '') => { console.log((c ? 'PASS ' : 'FAIL ') + m + (c ? '' : ' ' + JSON.stringify(extra))); if (!c) fails++; };
const email = `kh${Date.now()}@test.vn`;
let r = await call(U, 'auth/register', { name: 'Nguyễn Văn Khách', email, phone: '0901234567', cc: '84', ccIso: 'VN', pass: 'matkhau123', role: 'Khách mua / thuê nhà', agree: true, terms: true });
if (r.d.need === 'otp') {
  const s = await call(U, 'auth/otp/send', { challenge: r.d.challenge, channel: 'email' }); ok(s.s === 200, 'otp send', s);
  const code = (await codes())[email];
  r = await call(U, 'auth/otp/verify', { challenge: r.d.challenge, code, trust: false });
}
ok(r.s === 200 || r.s === 201, 'register+login', r);
r = await call(U, 'auth/profile'); ok(r.s === 200 && r.d.profile === null && !r.d.user.nameLocked, 'profile empty', r.d);
r = await call(U, 'auth/profile/name', { name: 'Khách Hàng Mới' }); ok(r.s === 200 && r.d.user.nameLocked && r.d.user.name === 'Khách Hàng Mới', 'rename once', r);
r = await call(U, 'auth/profile/name', { name: 'Lần Hai' }); ok(r.s === 403, 'rename twice blocked', r);
const prof = { fullName: 'Nguyễn Văn Khách', dob: '1990-05-12', gender: 'Nam', cccd: '079090001234', cccdDate: '2021-04-10', cccdPlace: 'Cục Cảnh sát QLHC về TTXH', address: '12 Lê Lợi, Quận 1, TP.HCM', need: 'Mua để ở', budget: '5 – 10 tỷ' };
r = await call(U, 'auth/profile', { profile: { ...prof, cccd: '12345' }, consent: true }); ok(r.s === 400, 'bad cccd rejected', r);
r = await call(U, 'auth/profile', { profile: prof, consent: false }); ok(r.s === 400, 'consent required', r);
r = await call(U, 'auth/profile', { profile: { ...prof, cccdDate: '1980-01-01' }, consent: true }); ok(r.s === 400, 'cccdDate before dob rejected', r);
r = await call(U, 'auth/profile', { profile: prof, consent: true }); ok(r.s === 200 && r.d.profile.cccd === '079 ••• ••• 234' && r.d.user.profileLocked, 'profile saved+masked', r.d);
r = await call(U, 'auth/profile', { profile: prof, consent: true }); ok(r.s === 403, 'profile locked', r);
const email2 = 'moi' + email;
r = await call(U, 'auth/contact/start', { type: 'email', email: email2, pass: 'sai' }); ok(r.s === 400, 'contact wrong pass', r);
r = await call(U, 'auth/contact/start', { type: 'email', email: email2, pass: 'matkhau123' });
if (MODE === 'none') ok(r.s === 200 && r.d.changed && !r.d.verified && r.d.user.email === email2, 'email changed unverified (no provider)', r);
else {
  ok(r.s === 200 && r.d.challenge && r.d.toNew, 'email change challenge to new', r);
  const ch = r.d.challenge;
  let v = await call(U, 'auth/otp/verify', { challenge: ch, code: '000000' }); ok(v.s === 410, 'change challenge not usable for login', v);
  v = await call(U, 'auth/contact/verify', { challenge: ch, code: '000000' }); ok(v.s === 400, 'wrong code', v);
  v = await call(U, 'auth/contact/verify', { challenge: ch, code: (await codes())[email2] }); ok(v.s === 200 && v.d.verified && v.d.user.email === email2 && v.d.user.emailVerified, 'email changed verified', v);
  r = await call(U, 'auth/contact/start', { type: 'phone', phone: '0912345678', cc: '84', ccIso: 'VN', pass: 'matkhau123' }); ok(r.s === 200 && r.d.challenge, 'phone challenge', r);
  v = await call(U, 'auth/contact/verify', { challenge: r.d.challenge, code: '246810' }); ok(v.s === 200 && v.d.user.phone === '+84912345678' && v.d.user.phoneVerified, 'phone changed', v);
}
r = await call(U, 'auth/request', { topic: 'Cập nhật thông tin cá nhân', message: 'Tôi chuyển nhà, cần đổi địa chỉ thường trú.' }); ok(r.s === 200 && r.d.requests.length === 1, 'request sent', r);
r = await call(U, 'auth/request', { topic: 'Cập nhật thông tin cá nhân', message: 'Gửi lại lần nữa cho chắc chắn.' }); ok(r.s === 409, 'dup request blocked', r);
r = await call(U, 'auth/recover', {}); ok(r.s === 200 && (MODE === 'none' ? r.d.mode === 'admin' : r.d.need === 'otp'), 'recover', r);
// admin
r = await call(A, 'admin/state'); if (r.d.setup) { const s = await call(A, 'admin/setup', { code: SETUP, email: 'ad@test.vn', name: 'Quản Trị', pass: 'adminpass123' }); ok(s.s === 201, 'admin setup', s); }
r = await call(A, 'admin/login', { email: 'ad@test.vn', pass: 'adminpass123' }); ok(r.s === 200, 'admin login', r);
r = await call(A, 'admin/stats'); ok(r.s === 200 && r.d.requests >= 1 && r.d.profiles >= 1, 'stats', r.d);
r = await call(A, 'admin/requests'); const req = r.d.rows[0]; ok(r.s === 200 && req && req.user_email, 'requests list', r.d);
const uid = req.user_id;
r = await call(A, 'admin/user?id=' + uid); ok(r.s === 200 && r.d.profile.cccd === '079090001234' && r.d.events.length >= 3 && !r.d.user.pass_hash, 'admin user detail', r.d);
r = await call(A, 'admin/user', { id: uid, action: 'update', name: r.d.user.name, email: r.d.user.email, phone: r.d.user.phone, profile: { ...r.d.profile, address: '99 Nguyễn Huệ, Quận 1' }, requestId: req.id }); ok(r.s === 200, 'admin update user', r);
r = await call(A, 'admin/requests'); ok(r.d.rows.length === 0, 'request closed', r.d);
r = await call(A, 'admin/user', { id: uid, action: 'allow-rename' }); ok(r.s === 200, 'allow rename');
r = await call(U, 'auth/profile/name', { name: 'Tên Lần Hai' }); ok(r.s === 200, 'rename after admin allow', r);
r = await call(A, 'admin/user', { id: uid, action: 'unlock-profile' }); ok(r.s === 200, 'unlock profile');
r = await call(U, 'auth/profile'); ok(r.d.profile === null && !r.d.user.profileLocked, 'profile editable again', r.d);
r = await call(A, 'admin/me'); ok(r.s === 200 && r.d.admin.email === 'ad@test.vn', 'admin me get', r);
r = await call(A, 'admin/me', { name: 'Quản Trị Viên', email: 'ad@test.vn', pass: 'sai' }); ok(r.s === 400, 'admin me wrong pass', r);
r = await call(A, 'admin/me', { name: 'Quản Trị Viên', email: 'ad@test.vn', pass: 'adminpass123' }); ok(r.s === 200 && r.d.admin.name === 'Quản Trị Viên', 'admin me update', r);
const csv = await fetch(B + '/api/admin/export?what=users', { headers: { cookie: A.h() } }).then(r => r.text()); ok(csv.includes('Số CCCD/Căn cước'), 'export has profile cols');
console.log(fails ? `${fails} FAILED` : 'ALL PASS');
