const { chromium } = require('/usr/local/lib/node_modules/playwright');
const fs = require('fs'); const B = 'http://localhost:8788', SETUP = process.env.SETUP, O = { origin: B };
(async () => {
  const b = await chromium.launch(); const errs = []; let n = 0;
  const shot = async (p, name) => { await p.waitForTimeout(500); await p.screenshot({ path: `v16/s_${String(++n).padStart(2, '0')}_${name}.jpg`, quality: 55, type: 'jpeg' }); };
  const codes = async () => (await fetch(B + '/__test/codes')).json();
  const mk = async (w, h, scheme) => { const c = await b.newContext({ viewport: { width: w, height: h }, colorScheme: scheme, reducedMotion: 'reduce' }); const p = await c.newPage(); p.on('pageerror', e => errs.push('PE ' + e.message)); p.on('console', m => { if (m.type() === 'error' && !/favicon|ERR_NAME|accounts\.google/.test(m.text())) errs.push(m.text()); }); return [c, p]; };
  // dữ liệu: admin + ảnh + tin nổi bật nhiều ảnh
  const [ca, a] = await mk(1280, 800, 'light');
  const st = await (await a.request.get(B + '/api/admin/state')).json();
  if (st.setup) await a.request.post(B + '/api/admin/setup', { headers: O, data: { code: SETUP, email: 'gd@test.vn', name: 'Hoàng Dũng', pass: 'adminpass123' } });
  await a.request.post(B + '/api/admin/login', { headers: O, data: { email: 'gd@test.vn', pass: 'adminpass123' } });
  const urls = [];
  for (const f of ['qa_a.jpg', 'qa_b.jpg', 'qa_c.jpg']) { const r = await (await a.request.post(B + '/api/admin/media', { headers: O, data: { mime: 'image/jpeg', data: fs.readFileSync('v16/' + f).toString('base64') } })).json(); urls.push(r.url); }
  const L = await (await a.request.post(B + '/api/admin/listing', { headers: O, data: { type: 'ban', title: 'Nhà phố 3 tầng hẻm xe hơi, gần chợ Tân Hương', area: 'Tân Phú', price: 6800, size: 64, dim: '4 × 16 m', beds: 4, floors: 3, legal: 'Sổ hồng riêng', note: 'Hẻm 6m thông, nhà mới xây, nội thất cao cấp, gần chợ và trường học.', images: urls, status: 'published', featured: true, sort: -1 } })).json();
  console.log('listing', L.id, urls);
  // khách + creator đã duyệt
  const em = 'cr' + Date.now() + '@test.vn';
  let r = await (await a.request.post(B + '/api/auth/register', { headers: O, data: { name: 'Ngô Minh Creator', email: em, phone: '0907000111', cc: '84', ccIso: 'VN', pass: 'matkhau123', role: 'Môi giới / đối tác', terms: true } })).json();
  await a.request.post(B + '/api/auth/otp/send', { headers: O, data: { challenge: r.challenge, channel: 'email' } });
  await a.request.post(B + '/api/auth/otp/verify', { headers: O, data: { challenge: r.challenge, code: (await codes())[em] } });
  await a.request.post(B + '/api/creator/apply', { headers: O, data: { displayName: 'Minh Review Nhà Phố', tiktok: 'https://www.tiktok.com/@minhreview', youtube: 'https://www.youtube.com/@minhreview', intro: 'Review nhà phố Tân Phú, Tân Bình mỗi tuần; chia sẻ kinh nghiệm xem nhà và pháp lý cho người mua lần đầu.', followers: '48 nghìn', video: 'https://www.tiktok.com/@minhreview/video/1' } });
  const cr = (await (await a.request.get(B + '/api/admin/creators?status=pending')).json()).rows[0];
  await a.request.post(B + '/api/admin/creator', { headers: O, data: { userId: cr.user_id, action: 'approve' } });
  await a.request.post(B + '/api/admin/creator', { headers: O, data: { userId: cr.user_id, action: 'feature', featured: true } });
  await ca.close();
  // trang chủ máy tính
  const [c1, p] = await mk(1440, 900, 'light');
  await p.goto(B + '/', { waitUntil: 'networkidle' }); await p.waitForTimeout(800); await shot(p, 'hero_cards');
  const hc = await p.$$eval('.fcard', els => els.map(e => e.dataset.open + ':' + (e.querySelector('b') || {}).textContent));
  console.log('hero cards', hc);
  await p.click(`.fcard[data-open="${L.id}"]`).catch(async () => { await p.click('.fcard[data-open]'); });
  await p.waitForSelector('#modal:not([hidden]) .detail'); await shot(p, 'listing_modal');
  if (await p.$('[data-gi="1"]')) { await p.click('[data-gi="1"]'); await shot(p, 'listing_gallery2'); }
  await p.fill('#modal [name=name]', 'Khách Test'); await p.fill('#modal [name=phone]', '0901234567'); await p.fill('#modal [name=date]', new Date(Date.now() + 86400e3).toISOString().slice(0, 10));
  await p.click('#modal [data-form=viewing] button[type=submit]'); await shot(p, 'listing_need_commit');
  await p.click('[data-commit-sum]'); await shot(p, 'commit_summary'); await p.click('[data-mini-ok]');
  await p.click('#modal [data-form=viewing] button[type=submit]'); await p.waitForTimeout(800); await shot(p, 'listing_sent');
  await p.keyboard.press('Escape');
  await p.evaluate(() => document.querySelector('#creator').scrollIntoView()); await shot(p, 'creators');
  await p.evaluate(() => document.querySelector('#bat-dong-san').scrollIntoView()); await shot(p, 'grid');
  await p.evaluate(() => document.querySelector('.legal-links').scrollIntoView()); await p.click('[data-terms-sum]'); await shot(p, 'terms_summary'); await p.keyboard.press('Escape');
  await p.evaluate(() => scrollTo(0, 0)); await p.click('#acctBtn'); await p.waitForSelector('.auth-view'); await shot(p, 'login_view');
  await p.click('.auth-tabs [data-goto=register]'); await shot(p, 'register_view');
  await p.keyboard.press('Escape'); await c1.close();
  // Google: chuyển hướng giả lập
  const [c2, g] = await mk(1440, 900, 'light');
  await g.route('https://accounts.google.com/**', async route => { const u = new URL(route.request().url()); const code = Buffer.from(JSON.stringify({ sub: 'g-ui-' + Date.now(), email: 'ui' + Date.now() + '@gmail.com', email_verified: true, name: 'Đỗ Thị Hoa', picture: '' })).toString('base64url'); await route.fulfill({ status: 302, headers: { location: `${B}/api/auth/oauth/google/callback?state=${u.searchParams.get('state')}&code=${code}` } }); });
  await g.goto(B + '/', { waitUntil: 'networkidle' }); await g.click('#acctBtn'); await g.waitForSelector('[data-soc=google]'); await g.click('[data-soc=google]');
  await g.waitForSelector('form[data-acct=onboard]', { timeout: 15000 }); await shot(g, 'onboard');
  await g.keyboard.press('Escape'); await g.waitForTimeout(300); const still = await g.$('form[data-acct=onboard]'); if (!still) errs.push('onboard modal closed by Escape');
  await g.fill('form[data-acct=onboard] [name=phone]', '0916555777'); await g.click('form[data-acct=onboard] .auth-submit'); await shot(g, 'onboard_need_terms');
  await g.check('form[data-acct=onboard] [name=terms]'); await g.click('form[data-acct=onboard] .auth-submit'); await g.waitForSelector('#onbAcc'); await shot(g, 'onboard_done');
  await g.click('#onbAcc'); await g.waitForSelector('.acc-head'); await shot(g, 'acc_social');
  await g.click('[data-acc=setpw]'); await g.fill('[name=pass]', 'matkhau555'); await g.fill('[name=pass2]', 'matkhau555'); await g.click('form[data-acct=setpw] .auth-submit'); await g.waitForSelector('.acc-head');
  await g.click('[data-acc=creator]'); await shot(g, 'creator_form');
  await g.fill('[name=tiktok]', 'tiktok.com/@hoanha'); await g.fill('[name=intro]', 'Chia sẻ mẹo trang trí và cải tạo nhà phố nhỏ cho gia đình trẻ.'); await g.click('form[data-acct=creator] button[type=submit]'); await shot(g, 'creator_sent');
  await g.click('[data-acc=home]'); await g.waitForSelector('.acc-head'); await shot(g, 'acc_after_creator');
  await g.click('[data-acc=activity]'); await g.waitForSelector('.act-list'); await shot(g, 'activity');
  await c2.close();
  // khách có đăng nhập sai + "Không phải tôi"
  const [c3, u] = await mk(1440, 900, 'dark');
  await u.request.post(B + '/api/auth/login', { headers: O, data: { id: em, pass: 'sai-mat-khau' } });
  r = await (await u.request.post(B + '/api/auth/login', { headers: O, data: { id: em, pass: 'matkhau123' } })).json();
  await u.request.post(B + '/api/auth/otp/send', { headers: O, data: { challenge: r.challenge, channel: 'email' } }); await u.request.post(B + '/api/auth/otp/verify', { headers: O, data: { challenge: r.challenge, code: (await codes())[em] } });
  await u.goto(B + '/', { waitUntil: 'networkidle' }); await u.click('#acctBtn'); await u.waitForSelector('.acc-head'); await shot(u, 'acc_creator_dark');
  await u.click('[data-acc=activity]'); await u.waitForSelector('.act-list'); await shot(u, 'activity_dark');
  await u.click('li.bad [data-notme]'); await shot(u, 'secure_1');
  await u.click('[data-sec-do=out]'); await u.waitForTimeout(400); await u.click('[data-sec-do=dev]'); await u.waitForTimeout(400); await shot(u, 'secure_3');
  await u.fill('form[data-acct=secpw] [name=old]', 'matkhau123'); await u.fill('form[data-acct=secpw] [name=pass]', 'matkhau999'); await u.fill('form[data-acct=secpw] [name=pass2]', 'matkhau999'); await u.click('form[data-acct=secpw] .auth-submit'); await u.waitForSelector('[data-sec-next]');
  await u.click('[data-sec-next]'); await u.fill('form[data-acct=secreport] [name=note]', 'Tôi không đăng nhập lúc đó.'); await u.click('form[data-acct=secreport] button[type=submit]'); await u.waitForTimeout(600); await shot(u, 'secure_done');
  await u.keyboard.press('Escape'); await u.evaluate(() => document.querySelector('#creator').scrollIntoView()); await shot(u, 'creators_dark');
  await c3.close();
  // điện thoại
  const [c4, m] = await mk(390, 844, 'light');
  await m.goto(B + '/', { waitUntil: 'networkidle' }); await m.waitForTimeout(600); await shot(m, 'm_hero');
  await m.click('.fcard[data-open]'); await m.waitForSelector('#modal:not([hidden]) .detail'); await shot(m, 'm_listing');
  await m.evaluate(() => document.querySelector('#modalPanel').scrollTo(0, 99999)); await shot(m, 'm_listing_form');
  await m.keyboard.press('Escape'); await m.evaluate(() => document.querySelector('#creator').scrollIntoView()); await shot(m, 'm_creators');
  for (const pg of ['dieu-khoan', 'chinh-sach-bao-mat', 'cam-ket-nguon-hang']) { await m.goto(B + '/' + pg, { waitUntil: 'networkidle' }); await shot(m, 'm_' + pg); }
  const ov = await m.evaluate(() => document.documentElement.scrollWidth - innerWidth); if (ov > 0) errs.push('overflow terms ' + ov);
  await c4.close();
  const [c5, t] = await mk(1440, 900, 'dark'); await t.goto(B + '/cam-ket-nguon-hang', { waitUntil: 'networkidle' }); await shot(t, 'd_cam_ket_dark'); await c5.close();
  // khách đã gửi yêu cầu xem nhà → có bằng chứng cam kết
  const [c6, ad] = await mk(1280, 800, 'light'); await ad.request.post(B + '/api/admin/login', { headers: O, data: { email: 'gd@test.vn', pass: 'adminpass123' } });
  const leads = (await (await ad.request.get(B + '/api/admin/leads?status=')).json()).rows; const v = leads.find(x => x.form === 'viewing'); console.log('viewing lead camket:', v && JSON.parse(v.fields).camket);
  await c6.close();
  console.log(JSON.stringify(errs, null, 1)); await b.close();
})().catch(e => { console.error('FAIL', e.message); process.exit(1); });
