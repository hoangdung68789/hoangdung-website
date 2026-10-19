# API quản trị v16 (nguồn sự thật: cf/src/api.ts)

Tất cả gọi qua `api(path, body)` trong admin_src.html (prefix `/api/admin/`). GET khi không có body, POST JSON khi có body. Lỗi → `{error}` với status 4xx (403 = thiếu quyền, thông báo tiếng Việt sẵn, hiển thị nguyên văn).

## Vai trò & quyền
`GET state` / `POST login` / `GET me` trả `admin`:
```
{ id, email, name, role: 'assistant'|'manager'|'director', roleLabel: 'Trợ lý'|'Quản lý'|'Giám đốc', level: 1|2|3,
  can: { stats, leads, 'listings.edit', media, 'users.view', 'requests.view', 'creators.view',          // level 1
         'listings.delete', 'users.manage', 'users.cccd', 'requests.handle', resets, 'creators.manage', analytics, 'logins.users', // level 2
         'admins.manage', export, settings, 'logins.admins' } }                                          // level 3
```
`GET state` còn có `google`, `facebook` (bool: đã cấu hình đăng nhập mạng xã hội chưa), `mail`, `sms`.
UI phải ẩn/disable mục & nút theo `S.admin.can[...]` (máy chủ vẫn chặn 403).

## Thống kê
`GET stats` → `{ users, users7, leads, leadsNew, leads7, resets, active30, trusted, requests, profiles, creatorsPending, listingsLive, visitsToday:{views,visitors}, mail, sms, google, facebook, daily:[{day,n}] }`

## Tin đăng (perm listings.edit; xoá cần listings.delete)
- `GET listings?status=&q=` → `{ rows:[{ id, type:'ban'|'thue', title, area, price, size, dim, beds, floors, legal, note, images:[url...], status:'published'|'draft'|'hidden'|'sold', featured:0|1, sort, created_by, created_at, updated_at, opens }] }`
  - `price`: đơn vị **triệu đồng** (bán) hoặc **triệu đồng/tháng** (thuê). Hiển thị: bán ≥1000 → `x,y tỷ`; thuê → `x triệu/tháng`.
  - `images`: đường dẫn dùng trực tiếp làm `src` (`/img/mansion.webp` ảnh có sẵn, hoặc `/api/media/<id>` ảnh tải lên). Ảnh đầu tiên là ảnh bìa.
  - `featured=1`: ưu tiên hiện ở các "điểm" nổi trên ảnh đầu trang chủ (chọn ngẫu nhiên).
  - `opens`: số lần khách mở xem chi tiết tin.
- `POST listing { id?, type, title(≥5), area, price(>0), size, dim, beds, floors, legal, note, images:[...≥1, ≤12], status, featured:bool, sort:int }` → tạo (201 `{id}`) hoặc sửa (có id).
- `POST listing { id, action:'status', status }` · `{ id, action:'feature', featured:bool }` · `{ id, action:'delete' }` (Quản lý trở lên).
- Khu vực (area) chọn từ danh sách:
  Quận: Quận 1, Quận 3, Quận 4, Quận 5, Quận 6, Quận 7, Quận 8, Quận 10, Quận 11, Quận 12, Bình Tân, Bình Thạnh, Gò Vấp, Phú Nhuận, Tân Bình, Tân Phú · Thành phố: TP. Thủ Đức · Huyện: Bình Chánh, Cần Giờ, Củ Chi, Hóc Môn, Nhà Bè.
- Ảnh có sẵn có thể chọn lại: /img/mansion.webp, penthouse, starry, ocean, mountain, mall, atrium, fallmall, villa (.webp).

## Tải ảnh (perm media)
`POST media { mime:'image/webp'|'image/jpeg'|'image/png', data:<base64 không có tiền tố> }` → 201 `{ id, url }`. Giới hạn ≤1,3 MB sau nén, ≤120 ảnh/giờ.
**Trình duyệt phải nén trước khi gửi**: đọc file → `createImageBitmap` → canvas cạnh dài tối đa 1600px → `canvas.toBlob(cb,'image/webp',0.82)` (nếu trình duyệt không xuất webp được thì `image/jpeg` 0.85) → nếu >1,2MB giảm chất lượng/kích thước tiếp. Gửi tuần tự từng ảnh, hiện tiến độ.

## Creator (xem: creators.view; duyệt/sửa: creators.manage)
- `GET creators?status=pending|approved|rejected|` → `{ rows:[{ user_id, display_name, tiktok, youtube, facebook, intro, video, followers, cover, status, featured, sort, note, created_at, updated_at, reviewed_at, reviewed_by, user_name, user_email, user_phone, avatar }] }`
- `POST creator { userId, action:'approve'|'reject'|'revoke', note? }` · `{ userId, action:'feature', featured:bool }` · `{ userId, action:'update', displayName, tiktok, youtube, facebook, intro, video, followers, cover(url ảnh từ media hoặc ''), sort }`

## Khách hàng
- `GET users?q=&offset=` → rows có thêm `creator` (''|'pending'|'approved'|'rejected'), `avatar`, `has_pass`, `providers` ('google,facebook' hoặc null), `role`.
- `GET user?id=` → `{ user, profile (cccd đã che nếu là Trợ lý), identities:[{provider,email,created_at}], events, requests }`.
- `POST user { id, action:'set-role', role }` — role ∈ ['Khách mua / thuê nhà', 'Chủ nhà cần bán / cho thuê', 'Môi giới / đối tác'] (users.manage).
- Các action cũ giữ nguyên (temp-password, disable, enable, verify, revoke-devices, update, unlock-profile, allow-rename) — đều cần users.manage.

## Lịch sử đăng nhập
- `GET logins` → của chính admin: `{ events:[{id, ok(1|0), method, ip, loc, label, at, current}], sessions:[{sid, ip, label, loc, created_at, last_seen, current}] }`
- `GET logins?userId=` (logins.users) → `{ events, sessions }` của khách.
- `GET logins?admin=all` (logins.admins) → `{ events:[{..., name, email, role}] }`.
- `POST sessions { sid }` đăng xuất 1 phiên của mình · `{ others:true }` mọi phiên khác · `{ userId }` đăng xuất mọi thiết bị của khách (users.manage).
- `method`: password | trusted | email | sms | register | google | facebook. `ok=0` là đăng nhập sai mật khẩu. `loc` là vị trí gần đúng ("Ho Chi Minh City, VN"), có thể rỗng.

## Lượt truy cập (analytics)
`GET analytics?days=7|30|90` → `{ days, since, today:{views,visitors}, online (khách trong 5 phút), views, visitors (tổng khách theo ngày), daily:[{day:'YYYY-MM-DD',views,visitors}], refs:[{ref,n}], countries:[{country(ISO2),n}], devices:[{device:'mobile'|'desktop'|'tablet',n}], top:[{id,title,n}] }` (ngày có thể thiếu → coi là 0).

## Quản trị viên
- `GET admins` → `{ rows:[{id,email,name,role,created_at,last_login}], roles:{assistant:{level,label},...} }` (ai cũng xem được).
- `POST admins { name, email, pass(≥10), role }` (admins.manage).
- `POST admin { id, action:'set-role', role }` · `{ id, action:'remove' }` (admins.manage; không xoá chính mình; luôn phải còn ≥1 Giám đốc).

## Cài đặt (thông tin) — thêm phần Google/Facebook
Khoá bí mật đặt trong Cloudflare → Workers & Pages → hoangdung-realestate → Settings → Variables and Secrets (loại Secret):
`GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` (Google Cloud Console → APIs & Services → Credentials → OAuth client ID, loại Web application),
`FACEBOOK_APP_ID`, `FACEBOOK_APP_SECRET` (developers.facebook.com → My Apps → Facebook Login).
Authorized redirect URI phải khai báo: `<địa chỉ website>/api/auth/oauth/google/callback` và `<địa chỉ website>/api/auth/oauth/facebook/callback` — hiển thị đúng `location.origin` hiện tại + nút sao chép.
