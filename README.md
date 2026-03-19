# Obscura Web App

Token-based Matcha LuaVM obfuscation service:
- User signup/login
- Credit purchase flow with custom amount selector
- Instant buy mode without Stripe (for now)
- Upload/paste Lua source and download `_obf.lua`

## Local run

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
python app.py
```

Open: `http://127.0.0.1:5000`

## Purchase mode

Default is instant mode (no Stripe):
- `AUTO_APPROVE_PURCHASES=1`

When you want real checkout later:
1. Set `AUTO_APPROVE_PURCHASES=0`
2. Configure Stripe keys
3. Add Stripe webhook for `checkout.session.completed`

## Render deploy

This repo includes `render.yaml` for Blueprint deploy.

1. Push repo to GitHub.
2. In Render: `New` -> `Blueprint` -> choose repo.
3. Render creates:
   - Web service: `obscura`
   - PostgreSQL database: `obscura-db`
4. Env vars for no-Stripe launch:
   - `BASE_URL` = temporary placeholder (`https://example.com`) on first deploy
   - Leave Stripe vars empty
   - `AUTO_APPROVE_PURCHASES=1`
   - `CREDIT_PRICE_CENTS=50`
5. Deploy.
6. After deploy, set `BASE_URL` to your real Render URL and redeploy.
