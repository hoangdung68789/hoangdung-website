# Tiếp tục đợt v16 — Hoàng Dũng Real Estate (tạm dừng 19/10/2026 23:55)

## Đã xong (chưa đưa lên mạng)
- Backend `cf/src/api.ts` v16: tin đăng + ảnh (D1 base64), OAuth Google/Facebook, bổ sung thông tin sau đăng nhập MXH, đặt mật khẩu, liên kết/gỡ, vai trò khách (admin đổi), Creator (đăng ký/duyệt/công khai), phân quyền admin 3 cấp (Trợ lý/Quản lý/Giám đốc, admin cũ = Giám đốc), lịch sử đăng nhập + phiên + báo "Không phải tôi", lượt truy cập ẩn danh, bắt buộc đồng ý Điều khoản khi đăng ký, bắt buộc tick "Cam kết bảo mật nguồn hàng" (v1.1) khi đặt lịch xem nhà + lưu bằng chứng (thời điểm, IP, thiết bị).
  - Kiểm thử: `tscheck/test_v16.mjs` (ALL PASS) + `tscheck/test_profile.mjs` (ALL PASS, chạy trên DB mới).
- Trang điều khoản (agent biên soạn): `terms/dieu-khoan.html`, `terms/chinh-sach-bao-mat.html`, `terms/cam-ket-nguon-hang.html` (v1.1, không ngoại lệ bỏ qua môi giới), `terms/summary.json`. build.py đã copy vào cf/public.
- Giao diện khách `src.html` v16 (mã đã chèn, CHƯA QA trình duyệt): điểm tin trên ảnh đầu trang (ngẫu nhiên, ưu tiên tin ⭐, bấm xem chi tiết, tự đổi), tin từ máy chủ + thư viện ảnh, tick cam kết nguồn hàng, nút Google/Facebook, điều khoản ở đăng ký/đăng nhập/chân trang + tóm tắt, hộp "Hoàn tất tài khoản" bắt buộc, trang tài khoản (đặt mật khẩu, liên kết MXH, hoạt động đăng nhập, quy trình bảo vệ 5 bước, Creator), mục "Creator nổi bật", đếm truy cập. Đã bỏ keepalive ở beacon.

## Còn làm
1. Trang quản trị v16 (`cf/admin_src.html`): agent dừng giữa chừng (bản dở: bak/admin_v16_partial.html, bản gốc v15: bak/admin_v15.html). Spec: `API_V16_ADMIN.md`. Làm lại/hoàn thiện: Tin đăng (tải ảnh nén), Creator, Lượt truy cập, phân quyền + huy hiệu chữ 3D (vàng/xanh lam/xanh lục), lịch sử đăng nhập, cài đặt Google/Facebook.
2. QA giao diện khách: `v16/flow16.js` trong sandbox Higgsfield (bundle qua nhánh `qa-tmp`), xem ảnh chụp, sửa lỗi.
3. YÊU CẦU MỚI (23:55): các chữ tĩnh thêm hiệu ứng cho sinh động (ví dụ tiêu đề đầu trang "Kiến Tạo Mái Ấm Gia Đình Việt").
4. Reviewer độc lập 3–5 vòng → đẩy lên nhánh main (Cloudflare tự triển khai) → kiểm tra live → xoá nhánh qa-tmp.
5. Cần anh Dũng: tạo mã ứng dụng Google/Facebook (có thể làm qua Chrome khi anh đồng ý); xác nhận "5% tiền hoa hồng" và thời hạn 12 tháng; nhờ luật sư rà điều khoản; đổi mật khẩu admin tạm; mua tên miền hoangdungrealestate.id.vn.
