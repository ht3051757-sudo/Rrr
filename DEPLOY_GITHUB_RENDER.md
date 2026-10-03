# HOANG MOD — GitHub Pages + Render

## Mô hình
- GitHub Pages: giao diện.
- Render: Node.js API + users.json/sessions.json.
- `config.js` đã trỏ sẵn tới `https://hoang-mod-backend.onrender.com`.

## Deploy backend
1. Đưa thư mục `ug` (cả `server.js`, `package.json`, `render.yaml`, `data/`) lên một GitHub repository.
2. Vào Render → New → Blueprint/Existing Blueprint → chọn repository đó.
3. Render đọc `render.yaml`, cài Node 20 và chạy `npm start`.
4. Trong Environment của service, đặt `ADMIN_EMAIL`, `ADMIN_PASSWORD`, `ADMIN_USERNAME`.
5. Mở `https://hoang-mod-backend.onrender.com/api/health`. Phải thấy JSON có `"ok":true`.
6. Sau đó GitHub Pages frontend sẽ gọi đúng backend.

Nếu Render cấp URL khác, mở `config.js` và đổi `window.UG_API_BASE_URL` thành URL backend HTTPS đó.

### Lưu ý dữ liệu
Các JSON trong `data/` là lưu trữ phía server. Gói free/ephemeral của host có thể mất file khi redeploy/restart. Muốn dữ liệu tài khoản bền vững cần persistent disk hoặc database (Postgres/Supabase).
