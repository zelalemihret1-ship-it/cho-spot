AMBAR Furniture — Phase 2 Orders, Delivery Areas & Sales Dashboard

PHASE 2 ADDITIONS
- Persistent order records in Supabase for standard orders submitted through the paymentorder flow.
- Customer “My Orders” panel showing the signed-in Telegram user's order reference, status, total, and date.
- Admin “Orders & delivery” dashboard with order counts, pending count, delivered count, delivered revenue, order list, and status updates.
- Admin-configurable delivery areas, ETB fees, activedisabled state, and estimated delivery days.
- Customer checkout displays configured delivery fee and estimated days when the selected area exactly matches an active configured delivery area.
- Existing product catalog, product galleryspecifications, category filters, search, favorites, sharing, language selector, and stock options are preserved.

REQUIRED INSTALLATION — READ BEFORE DEPLOYING
1. Back up the current GitHub repository and Supabase project.
2. In Supabase SQL Editor, run `phase2_orders_delivery_schema.sql` once using an authorized project owner account.
3. Keep `product_specifications_schema.sql` if needed for your existing product schema; this Phase 2 migration does not replace it.
4. Replace `bot.py`, `index.html`, `admin.html`, and `README.txt` from this ZIP in your existing repository. Keep `requirements.txt`, your image assets, and existing product files unless you have intentionally changed them.
5. Confirm Render has `SUPABASE_URL`, `SUPABASE_SECRET_KEY`, `BOT_TOKEN`, `WEBAPP_URL`, and `ADMIN_TELEGRAM_IDS` configured. Never expose the Supabase secret key in browser code.
6. Deploy and test inside Telegram. In admin, add each real delivery area and its actual fee before accepting orders that require delivery.

IMPORTANT DATABEHAVIOR NOTES
- No delivery prices are prefilled as real-world charges. Admin must configure the actual areas and fees.
- When no configured area exactly matches the customer's selected area, delivery remains “To be confirmed” and the app does not invent a fee.
- Existing orders created before this migration are not automatically imported and will not appear in trackingdashboard.
- A Telegram order notification is still sent to staff. If database persistence fails, the server logs the issue; run the migration and check Render logs.
- Sales dashboard revenue counts orders marked Delivered only. Payment screenshot submission is not treated as verified payment.
- Test area matching, order persistence, order status changes, customer-specific order visibility, and delivery fee calculations before public rollout.


Admin updates in this package Product Edit, Order Tracking, Delivery Fees, and Sales Dashboard are separate tabs. Recent orders support editing customer details, delivery fee, notes, status, and resetting status to Received. Delivery fees configured for a matching area are displayed at checkout and included in order totalsnotifications. Run phase2_orders_delivery_schema.sql in Supabase before enabling these features.


GPS DELIVERY PRICING AND CUSTOMER ORDER UPDATES
------------------------------------------------
1. Run the updated phase2_orders_delivery_schema.sql in Supabase SQL Editor. It is safe to re-run and adds GPS pricing settings plus GPS distancecoordinate columns to customer_orders.
2. In the admin page, open Delivery Fees and configure GPS delivery pricing shop latitude, shop longitude, price per kilometer (ETB), then enable GPS pricing. Use the exact coordinates for the AMBAR delivery origin.
3. Customers tap “Use my current GPS location” during checkout and select GPS coordinates. The server calculates distance from the configured shop origin and multiplies it by the configured ETBkm rate. Distance is straight-line GPS distance, not road-route distance; confirm the final fee for locations where road distance differs materially.
4. GPS pricing is used only when the customer shares GPS coordinates and GPS pricing is enabled. Otherwise the app uses a configured delivery-area fee or shows delivery as to be confirmed.
5. When an admin saves an order status or delivery fee update, the bot attempts to send the customer a Telegram message with the new status and order totals. The customer must have openedstarted the bot so Telegram can deliver direct messages.
6. My Orders displays order items, status, product total, delivery fee, total, and calculated GPS distance where available. Historical orders may not have item or GPS data.


My Orders troubleshooting and cancellation
- My Orders uses Telegram signed initData and only shows orders whose telegram_user_id matches the current Telegram account. Open the Mini App from @ambar_sels_bot, not a standalone browser tab.
- Ensure SUPABASE_URL and SUPABASE_SECRET_KEY are configured on the server and run phase2_orders_delivery_schema.sql in Supabase.
- Customer cancellation is available while an order is Received or Confirmed. After Preparing begins, the customer must contact AMBAR customer service.
- The My Orders panel refreshes automatically while open and also has a manual refresh button.

ORDER TRACKING FIX — PENDING + IMMEDIATE MY ORDERS
-------------------------------------------------
- Every new standard or checkout order is saved to Supabase before the server reports success. If the database is not configured or saving fails, checkout shows an error instead of falsely telling the customer the order was saved.
- New orders start with status `Pending`. Staff can change the status in Admin → Recent orders to Received, Confirmed, Preparing, Ready for Delivery, Delivered, or Cancelled. The same database status is displayed in My Orders, which refreshes while open.
- After a successful checkout, the app opens My Orders so the customer can immediately see the reference, items, totals, deliverycustomer details, payment status, and status timeline.
- Customer cancellation is available while Pending, Received, or Confirmed. Once preparation begins, they should contact AMBAR.
- IMPORTANT run the updated `phase2_orders_delivery_schema.sql` in Supabase SQL Editor. It updates existing installations to accept `Pending` as a status and makes it the database default. It is safe to re-run.
- Admin status edits require the updated `admin.html` and `bot.py`; customer display requires the updated `index.html`.
- Existing orders that were never saved to `customer_orders` cannot be displayed automatically. New orders will be persisted before checkout reports success.

MY ORDERS + ADMIN ORDER STATUS FIX (2026-10)
1. Replace bot.py, index.html, admin.html, and phase2_orders_delivery_schema.sql with the versions in this package.
2. In Supabase SQL Editor, run the complete phase2_orders_delivery_schema.sql file. It is designed to be re-run and upgrades older customer_orders tables with fields required for tracking.
3. In Render, confirm SUPABASE_URL and SUPABASE_SECRET_KEY are configured, and ADMIN_TELEGRAM_IDS contains the Telegram numeric ID(s) allowed to manage orders. Restartredeploy the service after updating files.
4. Open the Mini App from Telegram, place a test order, then check My Orders. New orders are saved with status Pending before the order submission is reported as successful.
5. In the admin panel, open Order Tracking, choose a status and click Save order edits. The customer's My Orders panel refreshes every 10 seconds while open; the server also attempts to send the customer a Telegram status notification.
6. My Orders is now a separate premium-style button between product search and language selection, not inside the profile menu.

If a customer's My Orders is empty, the order must have been saved to Supabase with the same verified Telegram user ID. Existing orders created before persistent tracking was enabled will not be reconstructed automatically. Live TelegramSupabase credentials are not included in this ZIP, so verify using a real Telegram test order after deployment.


SALES DASHBOARD REPORTS (updated)
- The admin Sales Dashboard includes Daily (last 7 days), Weekly (last 8 weeks), and Monthly (last 12 months) graph views.
- The bars show delivered revenue in ETB; the number above each bar shows orders created in that period. Revenue is counted only for orders whose status is Delivered.
- The chart uses the recent order records returned by the admin summary endpoint (up to 500). For a long-running store, increase paginationserver-side aggregation if reports must cover more than the latest 500 orders.
- My Orders requires opening the Mini App inside Telegram so the signed Telegram initData can identify the customer. Orders are filtered to the same Telegram user ID saved when the order was submitted.
LATEST UPDATE (2026-10-23): The Workshop ERP includes an English/Amharic language toggle. Main-admin-only Data Management supports downloading a full JSON backup, uploading/restoring a backup, and resetting operational data to zero while preserving staff permissions. Reset is enforced by the backend and requires explicit confirmation. Deploy the updated bot.py, workshop-admin.html, workshop-erp.html, and NotoSansEthiopic-Regular.ttf with the existing requirements. No new SQL migration is required.


WORKSHOP ERP BUG FIX (2026-10-23): Corrected a JavaScript scope error in daily production-stage reporting (`inRange is not defined`) that could be misreported as a shared cloud connection failure. The standalone ERP and embedded Telegram ERP are synchronized. This code fix does not change Supabase credentials or table permissions.
