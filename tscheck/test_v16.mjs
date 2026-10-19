const B = 'http://localhost:8788', SETUP = process.env.SETUP;
function jar() { const c = {}; return { c, h: () => Object.entries(c).map(([k, v]) => `${k}=${v}`).join('; '), set: r => { for (const s of r.headers.getSetCookie()) { const [kv] = s.split(';'); const i = kv.indexOf('='); const v = kv.slice(i + 1); if (v) c[kv.slice(0, i)] = v; else delete c[kv.slice(0, i)]; } } }; }
async function call(j, path, body, extra = {}) {
  const r = await fetch(B + '/api/' + path, { method: body ? 'POST' : 'GET', redirect: 'manual', headers: { ...(body ? { 'content-type': 'application/json' } : {}), cookie: j.h(), 'user-agent': extra.ua || 'Mozilla/5.0 (Windows NT 10.0) Chrome/130' }, body: body ? JSON.stringify(body) : undefined });
  j.set(r); let d = {}; try { d = await r.json(); } catch {}
  return { s: r.status, d, r };
}
const codes = async () => (await fetch(B + '/__test/codes')).json();
let fails = 0; const ok = (c, m, extra = '') => { console.log((c ? 'PASS ' : 'FAIL ') + m + (c ? '' : ' ' + JSON.stringify(extra).slice(0, 400))); if (!c) fails++; };
const D = jar();
let r = await call(D, 'listings'); ok(r.s === 200 && r.d.rows.length >= 9 && r.d.rows[0].images[0].startsWith('/img/'), 'seeded listings', r.d.rows?.length);
r = await call(D, 'admin/state'); if (r.d.setup) await call(D, 'admin/setup', { code: SETUP, email: 'gd@test.vn', name: 'Giám Đốc', pass: 'adminpass123' });
r = await call(D, 'admin/login', { email: 'gd@test.vn', pass: 'adminpass123' }); ok(r.s === 200 && r.d.admin.role === 'director' && r.d.admin.can['admins.manage'], 'director login', r.d);
await call(D, 'admin/admins', { name: 'Trợ Lý', email: 'tl@test.vn', pass: 'adminpass123', role: 'assistant' });
await call(D, 'admin/admins', { name: 'Quản Lý', email: 'ql@test.vn', pass: 'adminpass123', role: 'manager' });
r = await call(D, 'admin/admins'); ok(r.d.rows.length >= 3 && r.d.rows.some(x => x.role === 'assistant'), 'admins with roles', r.d);
const T = jar(), M = jar();
r = await call(T, 'admin/login', { email: 'tl@test.vn', pass: 'adminpass123' }); ok(r.d.admin.role === 'assistant' && !r.d.admin.can['listings.delete'], 'assistant login', r.d);
await call(M, 'admin/login', { email: 'ql@test.vn', pass: 'adminpass123' });
// media
const webp = Buffer.concat([Buffer.from('RIFF'), Buffer.alloc(4), Buffer.from('WEBPVP8 '), Buffer.alloc(300, 7)]);
r = await call(T, 'admin/media', { mime: 'image/webp', data: webp.toString('base64') }); ok(r.s === 201 && r.d.url, 'media upload', r.d);
const murl = r.d.url;
const mg = await fetch(B + murl); ok(mg.status === 200 && mg.headers.get('content-type') === 'image/webp' && (await mg.arrayBuffer()).byteLength === webp.length, 'media get');
r = await call(T, 'admin/media', { mime: 'image/png', data: webp.toString('base64') }); ok(r.s === 400, 'media magic check', r);
r = await call(T, 'admin/listing', { type: 'ban', title: 'Nhà phố hẻm xe hơi Tân Phú', area: 'Tân Phú', price: 6800, size: 60, dim: '4 × 15 m', beds: 3, floors: 3, legal: 'Sổ hồng riêng', note: 'Gần chợ', images: [murl], status: 'published', featured: true }); ok(r.s === 201 && r.d.id, 'assistant creates listing', r.d);
const lid = r.d.id;
r = await call(D, 'listings'); ok(r.d.rows.some(x => x.id === lid && x.images[0] === murl), 'public has new listing');
r = await call(T, 'admin/listing', { id: lid, action: 'delete' }); ok(r.s === 403, 'assistant cannot delete', r);
r = await call(T, 'admin/listing', { id: lid, action: 'status', status: 'hidden' }); ok(r.s === 200, 'assistant hides');
r = await call(D, 'listings'); ok(!r.d.rows.some(x => x.id === lid), 'hidden not public');
r = await call(M, 'admin/listing', { id: lid, action: 'delete' }); ok(r.s === 200, 'manager deletes');
r = await call(T, 'admin/listing', { title: 'x', images: [] }); ok(r.s === 400, 'listing validation');
r = await call(T, 'admin/export?what=users'); ok(r.s === 403, 'assistant export blocked');
r = await call(T, 'admin/analytics'); ok(r.s === 403, 'assistant analytics blocked');
// track
for (const ua of ['Mozilla/5.0 (iPhone) Mobile Safari', 'Mozilla/5.0 (Windows NT 10.0) Chrome/130', 'Mozilla/5.0 (Windows NT 10.0) Chrome/130']) await call(jar(), 'track', { p: '/', r: 'https://www.google.com/search?q=x' }, { ua });
await call(jar(), 'track', { e: 'listing', id: 1, p: '/' });
await call(jar(), 'track', { p: '/' }, { ua: 'Googlebot/2.1' });
r = await call(M, 'admin/analytics?days=30'); ok(r.s === 200 && r.d.today.views === 3 && r.d.today.visitors === 2 && r.d.refs[0]?.ref === 'google.com' && r.d.top[0]?.id === 1, 'analytics', r.d);
// user + login failure
const U = jar(); const email = `u${Date.now()}@test.vn`;
r = await call(U, 'auth/register', { name: 'Lê Văn A', email, phone: '0909111222', cc: '84', ccIso: 'VN', pass: 'matkhau123', role: 'Khách mua / thuê nhà' }); ok(r.s === 400, 'register needs terms', r.d);
r = await call(U, 'auth/register', { name: 'Lê Văn A', email, phone: '0909111222', cc: '84', ccIso: 'VN', pass: 'matkhau123', role: 'Khách mua / thuê nhà', terms: true });
await call(U, 'auth/otp/send', { challenge: r.d.challenge, channel: 'email' }); r = await call(U, 'auth/otp/verify', { challenge: r.d.challenge, code: (await codes())[email] }); ok(r.s === 200, 'register+verify');
await call(jar(), 'auth/login', { id: email, pass: 'saimatkhau' });
const U2 = jar(); r = await call(U2, 'auth/login', { id: email, pass: 'matkhau123' }); await call(U2, 'auth/otp/send', { challenge: r.d.challenge, channel: 'email' }); await call(U2, 'auth/otp/verify', { challenge: r.d.challenge, code: (await codes())[email] });
r = await call(U, 'auth/sessions'); ok(r.s === 200 && r.d.sessions.length === 2 && r.d.sessions.some(x => x.current) && r.d.events.some(e => e.ok === 0), 'sessions + failed login logged', r.d);
r = await call(U, 'auth/sessions', { others: true }); r = await call(U2, 'auth/me'); ok(r.d.user === null, 'other session revoked', r.d);
const ev = (await call(U, 'auth/sessions')).d.events.find(e => e.ok === 0);
r = await call(U, 'auth/security/report', { eventId: ev.id, steps: ['Đăng xuất thiết bị khác', 'Đổi mật khẩu'], note: 'Không phải tôi' }); ok(r.s === 200, 'security report');
r = await call(M, 'admin/requests'); ok(r.d.rows.some(x => x.topic === 'Cảnh báo đăng nhập lạ'), 'report reaches admin');
const uid = r.d.rows.find(x => x.topic === 'Cảnh báo đăng nhập lạ').user_id;
r = await call(M, 'admin/logins?userId=' + uid); ok(r.s === 200 && r.d.events.length >= 3, 'manager sees user logins');
r = await call(T, 'admin/logins?userId=' + uid); ok(r.s === 403, 'assistant cannot see user logins');
r = await call(M, 'admin/user', { id: uid, action: 'set-role', role: 'Chủ nhà cần bán / cho thuê' }); ok(r.s === 200, 'manager set user role');
r = await call(T, 'admin/user', { id: uid, action: 'set-role', role: 'Môi giới / đối tác' }); ok(r.s === 403, 'assistant cannot set role');
// creator
r = await call(U, 'creator/apply', { displayName: 'Dũng Review Nhà', tiktok: 'tiktok.com/@abc', intro: 'Review nhà phố Tân Phú mỗi tuần, chia sẻ kinh nghiệm mua nhà.', video: 'https://www.tiktok.com/@abc/video/123' }); ok(r.s === 200 && r.d.creator.status === 'pending' && r.d.user.creator === 'pending', 'creator apply', r.d);
r = await call(U, 'creator/apply', { displayName: 'X', tiktok: 'https://evil.com/x', intro: 'aaaaaaaaaaaaaaaaaaaaaaaaaa' }); ok(r.s === 400, 'creator url check');
r = await call(T, 'admin/creator', { userId: uid, action: 'approve' }); ok(r.s === 403, 'assistant cannot approve');
r = await call(M, 'admin/creator', { userId: uid, action: 'approve' }); ok(r.s === 200, 'manager approves');
r = await call(jar(), 'creators'); ok(r.d.rows.length === 1 && r.d.rows[0].display_name === 'Dũng Review Nhà', 'public creators', r.d);
// oauth google new user
const G = jar();
let rr = await call(G, 'auth/oauth/google/start'); const loc = rr.r.headers.get('location'); ok(rr.s === 302 && loc.startsWith('https://accounts.google.com/') && G.c.hd_os, 'google start', loc);
const state = new URL(loc).searchParams.get('state');
const gcode = Buffer.from(JSON.stringify({ sub: 'g-111', email: 'newg@test.vn', email_verified: true, name: 'Phạm Google', picture: 'https://lh3.googleusercontent.com/a/x' })).toString('base64url');
rr = await call(G, `auth/oauth/google/callback?state=${state}&code=${gcode}`); ok(rr.s === 302 && rr.r.headers.get('location').endsWith('/#onboard') && G.c.hd_sid, 'google callback new user', rr.r.headers.get('location'));
r = await call(G, 'auth/me'); ok(r.d.user.needsOnboarding && !r.d.user.hasPass, 'needs onboarding', r.d);
r = await call(G, 'auth/onboard', { name: 'Phạm Google', phone: '0912000111', cc: '84', ccIso: 'VN', role: 'Khách mua / thuê nhà', terms: true }); ok(r.s === 200 && !r.d.user.needsOnboarding, 'onboard', r.d);
r = await call(G, 'auth/password', { old: 'x', pass: 'matkhau999' }); ok(r.s === 400, 'social change pw blocked');
r = await call(G, 'auth/password/set', { pass: 'matkhau999' }); ok(r.s === 200 && r.d.user.hasPass, 'social set password');
// replay state
rr = await call(G, `auth/oauth/google/callback?state=${state}&code=${gcode}`); ok(rr.r.headers.get('location').includes('oauth-error'), 'state replay rejected');
// google auto-link existing verified email
const G2 = jar(); rr = await call(G2, 'auth/oauth/google/start'); const st2 = new URL(rr.r.headers.get('location')).searchParams.get('state');
rr = await call(G2, `auth/oauth/google/callback?state=${st2}&code=${Buffer.from(JSON.stringify({ sub: 'g-222', email, email_verified: true, name: 'A' })).toString('base64url')}`); ok(rr.r.headers.get('location').endsWith('/#welcome'), 'google links existing', rr.r.headers.get('location'));
// facebook existing email refused
const F = jar(); rr = await call(F, 'auth/oauth/facebook/start'); const st3 = new URL(rr.r.headers.get('location')).searchParams.get('state');
rr = await call(F, `auth/oauth/facebook/callback?state=${st3}&code=${Buffer.from(JSON.stringify({ id: 'fb-1', email, name: 'A' })).toString('base64url')}`); ok(rr.r.headers.get('location').includes('email-ton-tai'), 'facebook existing email refused', rr.r.headers.get('location'));
// facebook new without email
const F2 = jar(); rr = await call(F2, 'auth/oauth/facebook/start'); const st4 = new URL(rr.r.headers.get('location')).searchParams.get('state');
rr = await call(F2, `auth/oauth/facebook/callback?state=${st4}&code=${Buffer.from(JSON.stringify({ id: 'fb-2', name: 'Võ Facebook' })).toString('base64url')}`); r = await call(F2, 'auth/me'); ok(r.d.user?.emailMissing, 'facebook no email placeholder', r.d);
r = await call(F2, 'auth/onboard', { name: 'Võ Facebook', phone: '0912000222', cc: '84', ccIso: 'VN', role: 'Môi giới / đối tác', terms: true }); ok(r.s === 400, 'onboard requires email');
r = await call(F2, 'auth/onboard', { name: 'Võ Facebook', email: 'vofb@test.vn', phone: '0912000222', cc: '84', ccIso: 'VN', role: 'Môi giới / đối tác', terms: true }); ok(r.s === 200 && r.d.user.email === 'vofb@test.vn', 'onboard with email');
// link from account
rr = await call(U, 'auth/oauth/facebook/start?link=1'); const st5 = new URL(rr.r.headers.get('location')).searchParams.get('state');
rr = await call(U, `auth/oauth/facebook/callback?state=${st5}&code=${Buffer.from(JSON.stringify({ id: 'fb-9', name: 'A' })).toString('base64url')}`); ok(rr.r.headers.get('location').endsWith('#oauth-linked=facebook'), 'link facebook');
r = await call(U, 'auth/profile'); ok(r.d.identities.length === 2, 'identities listed', r.d.identities);
// admin manage
const dirId = (await call(D, 'admin/me')).d.admin.id;
r = await call(D, 'admin/admin', { id: dirId, action: 'set-role', role: 'manager' }); ok(r.s === 400, 'last director protected', r.d);
r = await call(T, 'admin/admin', { id: dirId, action: 'remove' }); ok(r.s === 403, 'assistant cannot manage admins');
r = await call(D, 'admin/logins?admin=all'); ok(r.s === 200 && r.d.events.length >= 3, 'director sees admin logins');
r = await call(T, 'admin/user?id=' + uid); ok(r.s === 200, 'assistant user detail');
r = await call(D, 'admin/stats'); ok(r.d.listingsLive >= 9 && r.d.creatorsPending === 0, 'stats v16', r.d);
console.log(fails ? `${fails} FAILED` : 'ALL PASS');
