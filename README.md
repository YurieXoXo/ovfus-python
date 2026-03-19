# PythonObfus Web App

Token-based Python obfuscation service:
- User signup/login
- Credit purchase flow (instant mode now, Stripe optional later)
- `1 credit` consumed per obfuscation
- Download obfuscated `.py` file

## Local run

1. Create virtualenv and install deps:
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```
2. Copy env file:
```powershell
Copy-Item .env.example .env
```
3. Start server:
```powershell
python app.py
```
4. Open: `http://127.0.0.1:5000`

## No-Stripe mode (current)

If Stripe keys are missing, clicking Buy uses instant mode and immediately adds credits.
This is controlled by:
- `AUTO_APPROVE_PURCHASES=1`

Set it to `0` when you want to enforce real Stripe checkout only.

## Stripe setup (later)

1. Create products/prices in Stripe Dashboard:
- Starter: 10 credits
- Pro: 50 credits
- Max: 150 credits
2. Put each Stripe `price_...` id in:
- `STRIPE_PRICE_ID_STARTER`
- `STRIPE_PRICE_ID_PRO`
- `STRIPE_PRICE_ID_MAX`
3. Add `STRIPE_SECRET_KEY`.
4. Set webhook endpoint to:
- `https://<your-render-domain>/stripe/webhook`
5. Subscribe webhook to event:
- `checkout.session.completed`
6. Put webhook signing secret in `STRIPE_WEBHOOK_SECRET`.

## Render deployment

This repo includes `render.yaml`, so you can deploy as a Blueprint.

1. Push this folder to GitHub.
2. In Render: `New` -> `Blueprint` -> select repo.
3. Render creates:
- Web service (`pythonobfus`)
- PostgreSQL database (`pythonobfus-db`)
4. Fill environment variables in Render service:
- `BASE_URL` = your Render app URL, for example `https://pythonobfus.onrender.com`
- Stripe keys and price IDs.
5. Deploy.

## Notes

- Obfuscation raises reverse-engineering effort, but it is not perfect protection.
- If Stripe is not set and `AUTO_APPROVE_PURCHASES=1`, buying credits is instant (no payment).
- For local testing only, set `ENABLE_DEV_TOPUP=1` and use test-credit buttons on `/buy`.
