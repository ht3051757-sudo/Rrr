# Deploy HOANG MOD

### Cách đơn giản nhất
1. Upload thư mục `ug` lên một host chạy Node.js 20+.
2. Chạy `npm install` rồi `npm start`.
3. Đặt các biến môi trường:
   - `ADMIN_EMAIL`
   - `ADMIN_PASSWORD`
   - `ADMIN_USERNAME` (tối đa 12 ký tự)
   - `SESSION_DAYS=30`
4. Mở `/api/health`. Phải trả JSON có `ok: true`.
5. Mở URL gốc. Frontend sẽ tự gọi `/api/*` vì `config.js` đang để URL rỗng (same-host).

### Nếu frontend vẫn ở GitHub Pages
Trong `config.js` đặt `window.UG_API_BASE_URL` thành URL HTTPS của backend Node.

### Quan trọng về dữ liệu
`data/*.json` phải nằm trên storage bền vững nếu muốn tài khoản tồn tại sau restart/redeploy. Không public mật khẩu/token trong GitHub.
