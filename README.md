# HOANG MOD / UGPHONE MOD — Shared multi-device Node version

This build does **not** require Supabase. Registration, login, members, admin, posts, chat, keys and server status use the same Node backend and JSON data store.

## Run
```bash
npm install
npm start
```
Open `http://localhost:3000`.

## Important for multiple devices
GitHub Pages cannot run `server.js`. Deploy this `ug` folder to a Node.js host/VPS/hosting service. Then either serve the frontend from that same Node server (recommended), or set `UG_API_BASE_URL` in `config.js` to the public backend URL.

## Admin
Set `ADMIN_SETUP_TOKEN`, `ADMIN_EMAIL`, `ADMIN_PASSWORD`, and optionally `ADMIN_USERNAME` in the server environment. Then call the bootstrap endpoint once with the setup token, or promote an existing account through the server-side data store. Never put the setup token or server secret in frontend code.

## Data
`data/users.json`, `sessions.json`, `posts.json`, `messages.json`, `keys.json`, and `server_state.json` are shared server-side data. Back them up. For serious production use, replace JSON storage with a real database and add HTTPS/rate limiting.
