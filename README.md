# CHO SPOT — Telegram Food Ordering Mini App

A black, espresso-brown, caramel, and cream restaurant ordering experience with a Flask backend, Supabase persistence, Telegram Web App authentication for admin access, customer order tracking, Chapa initialization/verification hooks, editable menu, configurable delivery fees, Telegram notifications, and sales reports.

## Important

This is a deployable starter project, not connected to your actual Telegram bot, Supabase project, or Chapa merchant account until you supply those credentials and complete the setup below. The included menu/prices and contact details are examples. Chapa must be tested in your merchant account before taking real payments. Never commit secrets or put a Supabase service-role key in browser code.

## 1. Create database

1. Create a Supabase project.
2. Open **SQL Editor** and run `sql/schema.sql`.
3. In Supabase project settings, copy the Project URL and service-role/secret server key. Keep the key private.

## 2. Deploy to Render

1. Upload this folder to a private GitHub repository.
2. Create a new Render Web Service from that repository. The included `render.yaml` is a starting configuration.
3. Set these environment variables in Render:
   - `SUPABASE_URL`
   - `SUPABASE_SERVICE_ROLE_KEY`
   - `TELEGRAM_BOT_TOKEN`
   - `ADMIN_TELEGRAM_IDS` (only trusted numeric Telegram IDs, comma-separated)
   - `PUBLIC_APP_URL` (your public HTTPS Render URL)
   - `CHAPA_SECRET_KEY` (optional until Chapa is enabled)
4. Deploy and open `/health`; `database_configured` should be `true`.

## 3. Configure Telegram Mini App

1. Create/select your bot with `@BotFather`.
2. Configure the Mini App URL to your deployed HTTPS URL in BotFather.
3. Optionally run `python set_telegram_menu_button.py` after setting `TELEGRAM_BOT_TOKEN` and `PUBLIC_APP_URL` locally. This sets the bot's menu button to **Order Food**.
4. Open the app from Telegram. Admin pages must be opened in Telegram by a user ID listed in `ADMIN_TELEGRAM_IDS`; direct browser access is intentionally denied for admin APIs.

## 4. Configure restaurant

Open `/admin` from the Telegram Mini App. Use **Menu Editor** to change dishes, prices, photos, categories, availability, and pinned items. Use **Restaurant Settings** to configure phone, address, opening hours, delivery base fee and fee per kilometer, maximum delivery distance, service fee, and accepted advance-payment percentages. Configure actual delivery policy before going live.

## 5. Chapa

Set `CHAPA_SECRET_KEY` on Render and `PUBLIC_APP_URL` to the final HTTPS domain. The backend initializes transactions and verifies them against Chapa before marking them paid. First test with the correct Chapa test/live credentials and confirm callback/return URLs in your merchant setup. Do not treat a browser redirect alone as proof of payment. Add additional fraud/amount checks and reconcile against your Chapa dashboard before launch.

## 6. Before taking real orders

- Replace sample menu, prices, photo URLs, restaurant contact details, and sample delivery rates.
- Test guest checkout and Telegram-linked checkout on mobile.
- Test admin access from both an authorized and unauthorized Telegram account.
- Test every order status and customer notifications.
- Test Chapa with a small controlled transaction before enabling it for customers.
- Review privacy notices and local requirements; collect only information needed to fulfil orders.
- Set up database backups, monitoring, and rate limiting. Keep database service-role credentials only on the server.

## Included

- `app.py`: API/backend, Telegram Web App signature verification, admin authorization, orders, Chapa, reporting, notifications.
- `static/index.html`: customer Mini App UI.
- `static/admin.html`: admin dashboard, order tracking, menu editor, settings, and sales charts.
- `sql/schema.sql`: Supabase schema and starter menu/settings.
- `set_telegram_menu_button.py`: optional Telegram menu-button setup helper.
- `render.yaml`, `requirements.txt`, `.env.example`: deployment configuration.

## Notes and limitations

- Reports currently summarize up to the latest 5,000 orders returned by the reporting query; very large restaurants should move aggregation to database views/RPCs.
- Delivery distance is entered by the customer in this version; it is an estimate and must be checked by staff. A trusted route/distance provider and map integration are separate configuration work.
- The project has no card storage and never asks customers for card details.
- Set environment variables and test the app before using it for real orders.
