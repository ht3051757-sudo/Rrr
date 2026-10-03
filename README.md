# HOANG MOD — bản all-in-one

## Chức năng đã tích hợp
- Đăng ký/đăng nhập dùng chung qua Node API.
- Tên tài khoản 3–12 ký tự; mật khẩu tối thiểu 6 ký tự.
- Session server-side, tự gia hạn và hết hạn.
- Admin tạo từ biến môi trường `ADMIN_EMAIL`, `ADMIN_PASSWORD`, `ADMIN_USERNAME`. Không nhúng mật khẩu vào frontend.
- Danh sách thành viên chung, role, BAN tài khoản.
- BAN IP thật trên backend + gỡ BAN IP.
- Bài/menu: đăng, ẩn/hiện, xóa, lấy link. Mỗi lượt lấy link được ghi vào `link_claims.json` với username, mục và thời gian.
- KEY theo ngày và giới hạn lượt.
- Chat chung + ảnh + thông báo Admin.
- Trạng thái server/maintenance.
- TOP SERVER cho mini game khủng long.
- Đoán số, tung xu, kéo-búa-bao.
- Giao diện aura, Zalo và mobile.

## Chạy
```bash
npm install
npm start
```
Sau đó mở `http://localhost:3000`.

## Deploy
Frontend và backend nên chạy cùng Node server. GitHub Pages không chạy `server.js`.
Nếu deploy trên host có filesystem tạm thời, JSON có thể mất sau restart/redeploy; hãy dùng ổ đĩa persistent hoặc chuyển DATA_DIR sang volume/database bền vững.


## Quan trọng khi dùng GitHub Pages
GitHub Pages không chạy Node.js. Backend phải được deploy riêng. Bản này đã đặt URL mặc định là `https://hoang-mod-backend.onrender.com` và có thể override bằng `?api=https://...`.
