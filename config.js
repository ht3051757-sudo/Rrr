// HOANG MOD backend configuration.
// The GitHub Pages frontend needs the public Node backend URL.
// Default Render URL for the included render.yaml:
window.UG_API_BASE_URL = "https://hoang-mod-backend.onrender.com";

// Optional: override with ?api=https://your-backend.example.com
try {
  const p = new URLSearchParams(location.search).get('api');
  if (p && /^https:\/\//i.test(p)) window.UG_API_BASE_URL = p.replace(/\/$/, '');
} catch {}
