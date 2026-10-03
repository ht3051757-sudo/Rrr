# HOANG MOD — Render backend fixed

## Render settings
- Root Directory: leave empty if this folder is the repository root
- Runtime: Node
- Build Command: `npm install`
- Start Command: `npm start`
- Health Check Path: `/api/health`

## Environment variables
Set these in Render Environment Variables (do NOT commit real passwords):
- `ADMIN_EMAIL` = your private admin email
- `ADMIN_PASSWORD` = your private admin password (at least 6 chars)
- `ADMIN_USERNAME` = admin (or another name <= 12 chars)

The server automatically creates/promotes this account as Admin on startup. There is NO demo admin account in the frontend.

## Verify after deploy
Open:
- `/` -> JSON service status
- `/api/health` -> `{"ok":true,...}`

The GitHub Pages frontend is configured to call:
`https://hoang-mod-backend.onrender.com`

If you change the backend URL, edit `config.js`.

## Important
This build uses JSON files under `data/` for shared state. They are shared while the same backend instance is running. For durable production persistence across infrastructure replacement/redeploy, move users/sessions/posts/chat/keys to a managed database or persistent disk.
