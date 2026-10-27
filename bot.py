import asyncio
import base64
import datetime as dt
import hashlib
import html
import hmac
import json
import logging
import os
import re
import secrets
import threading
from zoneinfo import ZoneInfo
import time
from pathlib import Path
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

import requests
from io import BytesIO
try:
    from PIL import Image, ImageDraw, ImageFont, ImageOps
except ImportError:  # image card falls back to the original product photo
    Image = ImageDraw = ImageFont = ImageOps = None
from flask import Flask, g, jsonify, request, send_from_directory, send_file
from telegram import Update, WebAppInfo, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, ContextTypes
from werkzeug.utils import secure_filename

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
log = logging.getLogger("ambar-furniture")

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", "/tmp/ambar_custom_uploads"))
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
SERVICE_CHAT_ID = os.getenv("SERVICE_CHAT_ID", "").strip()
WORKERS_TELEGRAM_CHAT_ID = os.getenv("WORKERS_TELEGRAM_CHAT_ID", "").strip()
AMBAR_LOCATION_URL = "https://maps.app.goo.gl/fxCmYYKzLtYae5GeA"
CHAPA_SECRET_KEY = os.getenv("CHAPA_SECRET_KEY", "").strip()
CHAPA_WEBHOOK_SECRET = os.getenv("CHAPA_WEBHOOK_SECRET", "").strip()
CHAPA_API_BASE = os.getenv("CHAPA_API_BASE", "https://api.chapa.global").strip().rstrip("/")
WEBAPP_URL = os.getenv("WEBAPP_URL", "https://ambar-furniture-miniapp.onrender.com/").strip()
BOT_PUBLIC_USERNAME = os.getenv("BOT_PUBLIC_USERNAME", "ambar_sels_bot").strip().lstrip("@")
REQUIRE_TELEGRAM_AUTH = os.getenv("REQUIRE_TELEGRAM_AUTH", "true").strip().lower() in {"1", "true", "yes", "on"}
MAX_CONTENT_LENGTH = 4 * 8 * 1024 * 1024 + 1024 * 1024

CATEGORIES = ["Shoe Shelf", "Consul Table", "Center Table", "TV Stand", "Chest Drawer", "Dining Table", "Wardrobe", "Other"]
FINISHES = ["Full Oak", "Full White", "Oak with White", "White with Oak", "Black"]
# The seven legacy built-in shoe shelf products are intentionally removed.
# Only products created/managed by the admin are listed.
PRODUCTS = {}
BASE_PRODUCTS = dict(PRODUCTS)
PRODUCT_CATALOG_FILE = Path(os.getenv("PRODUCT_CATALOG_FILE", str(BASE_DIR / "products_catalog.json")))
PRODUCT_IMAGE_DIR = Path(os.getenv("PRODUCT_IMAGE_DIR", str(BASE_DIR / "products")))
PRODUCT_IMAGE_DIR.mkdir(parents=True, exist_ok=True)
ADMIN_TELEGRAM_IDS = {x.strip() for x in os.getenv("ADMIN_TELEGRAM_IDS", "").split(",") if x.strip()}
ADMIN_PASSWORD_MANAGER_TELEGRAM_ID = os.getenv("ADMIN_PASSWORD_MANAGER_TELEGRAM_ID", "").strip()
ADMIN_EMERGENCY_PASSWORD = os.getenv("ADMIN_EMERGENCY_PASSWORD", "")
ADMIN_EMERGENCY_SESSIONS = {}
WORKSHOP_STAFF_SESSIONS = {}
ADMIN_PASSWORD_ATTEMPTS = {}
ADMIN_PASSWORD_LOCK = threading.Lock()
MAX_PRODUCT_IMAGE_BYTES = 5 * 1024 * 1024
SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip().rstrip("/")
# Prefer the legacy service_role JWT for server-to-server Authorization. Some
# projects also provide a newer sb_secret_* API key; keep it as the apikey when
# configured, while the service-role JWT remains the Authorization credential.
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()
SUPABASE_SECRET_KEY = os.getenv("SUPABASE_SECRET_KEY", "").strip() or SUPABASE_SERVICE_ROLE_KEY
SUPABASE_AUTHORIZATION_KEY = SUPABASE_SERVICE_ROLE_KEY or SUPABASE_SECRET_KEY
SUPABASE_PRODUCTS_TABLE = os.getenv("SUPABASE_PRODUCTS_TABLE", "products").strip() or "products"
SUPABASE_STORAGE_BUCKET = os.getenv("SUPABASE_STORAGE_BUCKET", "product-images").strip() or "product-images"


def supabase_enabled():
    return bool(SUPABASE_URL and SUPABASE_SECRET_KEY)


def supabase_request(method, endpoint, *, params=None, payload=None, content=None, content_type=None, extra_headers=None, timeout=25):
    """Call Supabase REST/Storage with a server-only secret key."""
    if not supabase_enabled():
        raise RuntimeError("Supabase is not configured. Set SUPABASE_URL and SUPABASE_SECRET_KEY in Render.")
    headers = {
        "apikey": SUPABASE_SECRET_KEY,
        "Authorization": f"Bearer {SUPABASE_AUTHORIZATION_KEY}",
    }
    if payload is not None:
        headers["Content-Type"] = "application/json"
        headers["Prefer"] = "return=representation"
    if content_type:
        headers["Content-Type"] = content_type
    if extra_headers:
        headers.update(extra_headers)
    url = f"{SUPABASE_URL}{endpoint}"
    response = requests.request(method, url, params=params, json=payload, data=content, headers=headers, timeout=timeout)
    if not response.ok:
        detail = ""
        try:
            body = response.json()
            detail = body.get("message") or body.get("error") or body.get("hint") or ""
        except ValueError:
            detail = response.text[:300]
        # Keep a sanitized hint so admin-only diagnostics can distinguish missing
        # table/permissions from a bad API key. Never log or return request headers.
        detail = re.sub(r"[\r\n\t]+", " ", str(detail))[:240]
        log.error("Supabase request failed (%s %s): HTTP %s %s", method, endpoint, response.status_code, detail)
        hint = f" Supabase says: {detail}" if detail else ""
        raise RuntimeError(f"Supabase request failed (HTTP {response.status_code}).{hint} Check that Render uses the correct project URL and server-side service-role/secret key, and that the table exists with service_role permissions.")
    if response.status_code == 204 or not response.content:
        return None
    try:
        return response.json()
    except ValueError:
        return None


def write_security_event(event_type, *, actor_id=None, path=None, method=None, status_code=None, details=None):
    """Best-effort security audit logging. Never let audit storage break app requests."""
    if not supabase_enabled():
        return False
    try:
        payload = {
            "event_type": str(event_type or "unknown")[:60],
            "actor_telegram_id": str(actor_id)[:40] if actor_id else None,
            "request_path": str(path if path is not None else request.path)[:240],
            "request_method": str(method if method is not None else request.method)[:12],
            "status_code": int(status_code) if status_code is not None else None,
            # remote_addr is used rather than trusting a browser-supplied X-Forwarded-For header.
            "ip_address": str(request.remote_addr or "")[:64] or None,
            "user_agent": str(request.headers.get("User-Agent", ""))[:300] or None,
            "details": details if isinstance(details, dict) else {},
            "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        }
        supabase_request("POST", "/rest/v1/admin_security_events", payload=payload)
        return True
    except Exception as exc:
        log.warning("Security event could not be persisted (%s): %s", event_type, type(exc).__name__)
        return False


def supabase_product_to_item(row):
    image_url = str(row.get("image_url") or "").strip()
    return {
        "id": str(row.get("id", "")),
        "name": str(row.get("name") or "Unnamed product"),
        "name_am": str(row.get("name_am") or ""),
        "category": "Consul Table" if str(row.get("category") or "Other").strip().lower() == "console table" else str(row.get("category") or "Other"),
        "price": float(row.get("price") or 0),
        "description": str(row.get("description") or ""),
        "description_am": str(row.get("description_am") or ""),
        "specifications": row.get("specifications") if isinstance(row.get("specifications"), dict) else {},
        "measurements": ((row.get("specifications") or {}).get("measurements") or ("120 cm" if str(row.get("category") or "").strip().casefold() == "shoe shelf" else "Not specified")) if isinstance(row.get("specifications"), dict) else ("120 cm" if str(row.get("category") or "").strip().casefold() == "shoe shelf" else "Not specified"),
        "capacity": (row.get("specifications") or {}).get("capacity", "To be confirmed") if isinstance(row.get("specifications"), dict) else "To be confirmed",
        "material": (row.get("specifications") or {}).get("material", "To be confirmed") if isinstance(row.get("specifications"), dict) else "To be confirmed",
        "colors": ["As shown"],
        "images": row.get("images") if isinstance(row.get("images"), list) and row.get("images") else ([image_url] if image_url else []),
        "image_url": image_url,
        "active": bool(row.get("active", True)),
        "pinned": bool(row.get("pinned", False)),
        # Stock availability and order permission are separate settings:
        # out of stock + allow_order=True means customers may still place an order.
        "stock_status": "out_of_stock" if str(row.get("stock_status") or "in_stock").strip().lower() in ("out_of_stock", "out_of_stock_orderable") else "in_stock",
        "allow_order": str(row.get("allow_order", True)).strip().lower() not in ("false", "0", "no", "off", "none", ""),
    }


def supabase_list_products(include_inactive=False):
    filters = {"select": "*", "order": "created_at.asc", "limit": "1000"}
    if not include_inactive:
        filters["active"] = "eq.true"
    rows = supabase_request("GET", f"/rest/v1/{quote(SUPABASE_PRODUCTS_TABLE, safe='')}", params=filters) or []
    return [row for row in rows if isinstance(row, dict)]


def upload_product_image(filename, content, mime):
    bucket = quote(SUPABASE_STORAGE_BUCKET, safe="")
    object_name = quote(filename, safe="")
    supabase_request(
        "POST", f"/storage/v1/object/{bucket}/{object_name}",
        content=content, content_type=mime,
        extra_headers={"x-upsert": "true", "cache-control": "3600"},
        timeout=45,
    )
    return f"{SUPABASE_URL}/storage/v1/object/public/{bucket}/{object_name}"


def load_product_catalog():
    """Load the built-in catalogue plus admin products; Supabase is the persistent source."""
    global PRODUCTS
    merged = dict(BASE_PRODUCTS)
    if supabase_enabled():
        try:
            # Include inactive rows so a disabled original product stays hidden instead of
            # reappearing from the built-in catalogue after each refresh.
            for row in supabase_list_products(include_inactive=True):
                pid = str(row.get("id", ""))
                if pid in BASE_PRODUCTS and not bool(row.get("active", True)):
                    merged.pop(pid, None)
                elif pid in BASE_PRODUCTS and bool(row.get("active", True)):
                    base = dict(BASE_PRODUCTS[pid])
                    edited = supabase_product_to_item(row)
                    base.update({k: edited[k] for k in ("name", "name_am", "category", "price", "description", "description_am", "images", "image_url", "specifications", "stock_status", "allow_order", "active") if k in edited})
                    if not edited.get("images"):
                        base["images"] = BASE_PRODUCTS[pid].get("images", [])
                    merged[pid] = base
                elif pid.startswith("admin_"):
                    merged[pid] = supabase_product_to_item(row)
        except Exception as exc:
            log.exception("Could not load products from Supabase: %s", exc)
            # Keep built-in products available during a temporary Supabase outage.
    else:
        # Compatibility fallback for local development only. Render's ephemeral disk is not persistent.
        try:
            data = json.loads(PRODUCT_CATALOG_FILE.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                for pid, item in data.items():
                    if isinstance(pid, str) and pid.startswith("admin_") and isinstance(item, dict):
                        merged[pid] = item
        except FileNotFoundError:
            pass
        except (OSError, json.JSONDecodeError) as exc:
            log.error("Could not read local product catalogue: %s", exc)
    # Every active product can be ordered; stock status is informational only.
    for product in merged.values():
        if isinstance(product, dict):
            product["allow_order"] = True
    PRODUCTS = merged
    return merged


def save_product_catalog(items):
    """Compatibility helper for local development; Supabase writes use the REST API directly."""
    PRODUCT_CATALOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    temp = PRODUCT_CATALOG_FILE.with_suffix(".json.tmp")
    temp.write_text(json.dumps(items, ensure_ascii=False, indent=2), encoding="utf-8")
    temp.replace(PRODUCT_CATALOG_FILE)
    load_product_catalog()


def product_image_upload_from_request(product_id, image, *, updating=False):
    if not image or not image.filename:
        return None
    content = image.read(MAX_PRODUCT_IMAGE_BYTES + 1)
    if not content or len(content) > MAX_PRODUCT_IMAGE_BYTES:
        raise ValueError("Product photo must be smaller than 5 MB.")
    if content.startswith(b"\xff\xd8\xff"):
        mime, ext = "image/jpeg", ".jpg"
    elif content.startswith(b"\x89PNG\r\n\x1a\n"):
        mime, ext = "image/png", ".png"
    elif content[:4] == b"RIFF" and content[8:12] == b"WEBP":
        mime, ext = "image/webp", ".webp"
    else:
        raise ValueError("The uploaded file is not a valid JPG, PNG, or WebP image.")
    if supabase_enabled():
        suffix = "_" + secrets.token_hex(3) if updating else ""
        return upload_product_image(f"{product_id}{suffix}{ext}", content, mime)
    # Local fallback for development only; Render Free does not guarantee persistence.
    filename = f"{product_id}{'_' + secrets.token_hex(3) if updating else ''}{ext}"
    (PRODUCT_IMAGE_DIR / filename).write_bytes(content)
    return "/products/" + filename

app = Flask(__name__, static_folder=None)


def verified_telegram_admin():
    # Owner is fixed in Render. Staff are looked up in Supabase, so their IDs do not
    # need to be added to the Render allowlist individually.
    valid, user_id = validate_telegram_init_data(request.headers.get("X-Telegram-Init-Data", ""))
    if not valid or not user_id:
        write_security_event("failed_admin_auth", path=request.path, method=request.method, status_code=401,
                             details={"reason": "invalid_or_missing_telegram_auth"})
        return None, (jsonify(error="Open this admin page from the AMBAR Telegram bot."), 401)
    if ADMIN_PASSWORD_MANAGER_TELEGRAM_ID and user_id == ADMIN_PASSWORD_MANAGER_TELEGRAM_ID:
        return user_id, None
    role_data = admin_permissions_for(user_id)
    if not role_data or not role_data.get("active", False) or role_data.get("role") == "disabled":
        write_security_event("unauthorized_admin_access", actor_id=user_id, path=request.path,
                             method=request.method, status_code=403, details={"reason": "not_an_active_admin"})
        return None, (jsonify(error="You are not authorized to access AMBAR admin controls."), 403)
    return user_id, None


def emergency_password_hash(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310000)
    return "pbkdf2_sha256$310000$" + salt.hex() + "$" + digest.hex()


def emergency_password_matches(password, stored):
    if not stored:
        return False
    try:
        scheme, iterations, salt_hex, digest_hex = stored.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(iterations))
        return hmac.compare_digest(digest.hex(), digest_hex)
    except (ValueError, TypeError):
        return False

def stored_emergency_password_hash():
    if not supabase_enabled():
        return None
    try:
        rows = supabase_request("GET", "/rest/v1/admin_emergency_password", params={"id": "eq.1", "select": "password_hash", "limit": "1"}) or []
        return rows[0].get("password_hash") if rows else None
    except Exception:
        log.exception("Could not read emergency admin password")
        return None



# Stable signing key lets an emergency session be checked by any Render worker.
# Prefer an explicitly configured secret, then existing server-only credentials.
def emergency_session_signing_key():
    value = (os.getenv("SESSION_SIGNING_SECRET", "").strip()
             or SUPABASE_SECRET_KEY or BOT_TOKEN or ADMIN_EMERGENCY_PASSWORD)
    return value.encode("utf-8") if value else None


def make_emergency_session_token(user_id, expires_at):
    key = emergency_session_signing_key()
    if not key:
        return None
    payload = f"{user_id}|{int(expires_at)}"
    encoded = base64.urlsafe_b64encode(payload.encode("utf-8")).decode("ascii").rstrip("=")
    signature = hmac.new(key, encoded.encode("ascii"), hashlib.sha256).hexdigest()
    return f"v1.{encoded}.{signature}"


def valid_emergency_session(token, user_id):
    if not token:
        return False
    # Accept in-memory tokens created before or when no stable signing secret exists.
    with ADMIN_PASSWORD_LOCK:
        session = ADMIN_EMERGENCY_SESSIONS.get(token)
        if session and session.get("expires", 0) >= time.time() and str(session.get("user_id")) == str(user_id):
            return True
        if session and session.get("expires", 0) < time.time():
            ADMIN_EMERGENCY_SESSIONS.pop(token, None)
    key = emergency_session_signing_key()
    if not key:
        return False
    try:
        version, encoded, signature = token.split(".", 2)
        if version != "v1":
            return False
        expected = hmac.new(key, encoded.encode("ascii"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            return False
        padded = encoded + "=" * (-len(encoded) % 4)
        token_user_id, expires = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8").rsplit("|", 1)
        return str(token_user_id) == str(user_id) and int(expires) >= int(time.time())
    except (ValueError, UnicodeError, TypeError):
        return False


def admin_user_from_request():
    """Require verified Telegram identity, fresh emergency password, and route permission."""
    user_id, error = verified_telegram_admin()
    if error:
        return None, error
    token = request.headers.get("X-Admin-Emergency-Session", "")
    if not valid_emergency_session(token, user_id):
        return None, (jsonify(error="Emergency admin password required. Unlock the admin panel again."), 423)
    if is_main_admin_user(user_id):
        g.admin_user_id, g.admin_role, g.admin_permissions = user_id, "owner", ["*"]
        return user_id, None
    record = admin_permissions_for(user_id)
    if not record or not record.get("active") or record.get("role") == "disabled":
        return None, (jsonify(error="This admin account has been disabled by the main admin."), 403)
    permissions = normalize_admin_permissions(record.get("permissions"), record.get("role"))
    needed = permission_for_route(request.path, request.method)
    required = [needed] if isinstance(needed, str) else (needed or [])
    if required and not (set(required) & set(permissions)) and "*" not in permissions:
        write_security_event("unauthorized_admin_access", actor_id=user_id, path=request.path, method=request.method,
                             status_code=403, details={"reason":"missing_permission", "required_permission":required, "permissions_present":permissions, "request_path":request.path, "request_method":request.method})
        # Include the missing permission names so a real mismatch can be diagnosed from the staff screen.
        return None, (jsonify(error="Your account does not have permission for this section.", required_permissions=required, assigned_permissions=permissions, endpoint=request.path), 403)
    g.admin_user_id, g.admin_role, g.admin_permissions = user_id, record.get("role", "staff"), permissions
    return user_id, None


ADMIN_PERMISSION_ALIASES = {
    "order_management": "orders", "orders_management": "orders", "order": "orders",
    "product_management": "products", "products_management": "products", "product": "products",
    "delivery_fees": "delivery", "delivery_management": "delivery",
    "sales_dashboard": "dashboard", "dashboard_reports": "dashboard",
    "customer_information": "customers", "customer_management": "customers",
    "security_reports": "security", "activity_reports": "security",
    "customer_service": "service", "service_management": "service",
    "admin": "admin_management", "admin_management": "admin_management",
    "readymade_orders": "order_dispatch", "order_dispatch_management": "order_dispatch",
}

def normalize_admin_permissions(value, legacy_role=None):
    """Normalize saved permissions from old and new admin-role schemas."""
    if isinstance(value, str):
        try:
            import json as _json
            parsed = _json.loads(value)
            value = parsed if isinstance(parsed, list) else [value]
        except Exception:
            value = [part.strip() for part in value.replace(";", ",").split(",") if part.strip()]
    if not isinstance(value, (list, tuple, set)):
        value = []
    normalized = []
    for item in value:
        key = str(item).strip().lower().replace(" ", "_").replace("-", "_")
        key = ADMIN_PERMISSION_ALIASES.get(key, key)
        if key and key not in normalized:
            normalized.append(key)
    if not normalized and legacy_role == "orders":
        normalized = ["orders"]
    if legacy_role in {"owner", "super_admin"}:
        normalized = ["*"]
    return normalized

def admin_permissions_for(user_id):
    if not supabase_enabled():
        return None
    try:
        rows = supabase_request("GET", "/rest/v1/ambar_admin_roles", params={
            "select":"telegram_user_id,display_name,role,active,permissions,workshop_password_hash", "telegram_user_id":f"eq.{user_id}", "limit":"1"
        }) or []
        if not rows:
            return None
        row = rows[0]
        row["permissions"] = normalize_admin_permissions(row.get("permissions"), row.get("role"))
        return row
    except Exception:
        log.exception("Admin permission lookup failed")
        return None


def is_main_admin_user(user_id):
    """True for the fixed owner and any explicitly assigned second super-admin."""
    uid = str(user_id or "")
    if ADMIN_PASSWORD_MANAGER_TELEGRAM_ID and uid == str(ADMIN_PASSWORD_MANAGER_TELEGRAM_ID):
        return True
    record = admin_permissions_for(uid) or {}
    if not record or not record.get("active", False) or record.get("role") == "disabled":
        return False
    permissions = normalize_admin_permissions(record.get("permissions"), record.get("role"))
    return record.get("role") in {"super_admin", "owner"} or "*" in permissions


def admin_role_for(user_id):
    if ADMIN_PASSWORD_MANAGER_TELEGRAM_ID and user_id == ADMIN_PASSWORD_MANAGER_TELEGRAM_ID:
        return "owner"
    row = admin_permissions_for(user_id)
    if not row or not row.get("active", True) or row.get("role") == "disabled":
        return "disabled"
    return row.get("role", "staff")


def permission_for_route(path, method):
    """Return the required permission for a protected admin API route.

    Explicit exemptions are limited to reading one's own permissions and recording
    an authenticated sign-in. Unknown admin routes remain restricted to owners.
    """
    path = (path or "").split("?", 1)[0]
    method = (method or "GET").upper()

    # These endpoints are needed by every authenticated staff account and do not
    # reveal privileged data: own permission record / activity sign-in marker.
    if path == "/api/admin/roles/me":
        return None
    if path == "/api/admin/finance-inventory":
        return "finance_inventory"
    if path == "/api/admin/security/sign-in":
        return None

    # Main-admin-only controls.
    if path == "/api/admin/roles" or path.startswith("/api/admin/roles/"):
        return "admin_management"
    if path == "/api/admin/button-settings":
        return "admin_management"
    if path.startswith("/api/admin/emergency/"):
        return "admin_management"

    # Product catalogue and product editing.
    if path.startswith(("/api/admin/products", "/api/admin/product", "/api/admin/catalogue", "/api/admin/catalog")):
        return "products"

    # Delivery settings and area management.
    if path.startswith(("/api/admin/phase2/delivery-settings", "/api/admin/phase2/delivery-areas", "/api/admin/delivery", "/api/admin/gps")) or path == "/api/delivery-areas" or "gps-pricing" in path:
        return "delivery"

    # Order Dispatch: sending saved customer orders or readymade orders to Telegram.
    # Existing Order Management permission remains compatible with prior staff assignments.
    if path in {"/api/admin/order-dispatch/new-design", "/api/admin/order-dispatch/orders"} or (path.startswith("/api/admin/phase2/orders/") and path.endswith(("/send-to-workers", "/send-to-workshop"))):
        return ["order_dispatch", "orders"]

    # Order list, status changes, and deletion (server handlers apply further
    # restrictions where required).
    if path.startswith(("/api/admin/phase2/orders", "/api/admin/orders", "/api/admin/order")):
        return "orders"

    # Dashboard summary is intentionally available to either dashboard or order
    # managers because the existing order workspace loads summary data too.
    if path == "/api/admin/phase2/summary":
        return ["dashboard", "orders"]
    if "sales-report" in path or "dashboard" in path:
        return "dashboard"

    if path.startswith(("/api/admin/customers", "/api/admin/customer-directory")) or "customer-directory" in path:
        return "customers"
    if path.startswith("/api/admin/security/report") or "activity-report" in path or "security-events" in path:
        return "security"
    if path.startswith(("/api/admin/customer-service", "/api/admin/service-settings")) or path.startswith("/api/admin/service/"):
        return "service"

    # Never grant access to a new/unknown admin endpoint by accident.
    return "admin_management"


def is_orders_only_route(path, method):
    if path in {"/api/admin/security/sign-in", "/api/admin/phase2/summary"} and method == "GET" or path == "/api/admin/security/sign-in" and method == "POST":
        return True
    if path.startswith("/api/admin/phase2/orders/") and method in {"PATCH", "DELETE"}:
        return method == "PATCH"  # staff can update order details/status, but cannot permanently delete orders
    return False


@app.post("/api/admin/emergency/unlock")
def admin_emergency_unlock():
    user_id, error = verified_telegram_admin()
    if error:
        return error
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()
    key = user_id + ":" + ip
    now = time.time()
    with ADMIN_PASSWORD_LOCK:
        attempt = ADMIN_PASSWORD_ATTEMPTS.get(key, {"count": 0, "until": 0})
        if attempt["until"] > now:
            return jsonify(error="Too many attempts. Wait a few minutes and try again."), 429
    supplied = str((request.get_json(silent=True) or {}).get("password", ""))
    stored_hash = stored_emergency_password_hash()
    valid_password = False
    if stored_hash:
        valid_password = emergency_password_matches(supplied, stored_hash)
    elif ADMIN_EMERGENCY_PASSWORD:
        valid_password = hmac.compare_digest(supplied, ADMIN_EMERGENCY_PASSWORD)
    else:
        return jsonify(error="Emergency password is not configured. Set ADMIN_EMERGENCY_PASSWORD in Render and redeploy."), 503
    if not valid_password:
        with ADMIN_PASSWORD_LOCK:
            attempt = ADMIN_PASSWORD_ATTEMPTS.get(key, {"count": 0, "until": 0})
            attempt["count"] += 1
            if attempt["count"] >= 5:
                attempt = {"count": 0, "until": now + 300}
            ADMIN_PASSWORD_ATTEMPTS[key] = attempt
        write_security_event("failed_admin_auth", actor_id=user_id, path=request.path, method="POST", status_code=401,
                             details={"reason": "incorrect_emergency_password"})
        return jsonify(error="Incorrect emergency password."), 401
    with ADMIN_PASSWORD_LOCK:
        ADMIN_PASSWORD_ATTEMPTS.pop(key, None)
        # Session exists only in server memory; reopening/restarting requires password again.
        expires_at = now + 8 * 60 * 60
        token = make_emergency_session_token(user_id, expires_at) or secrets.token_urlsafe(32)
        # Keep an in-memory copy for compatibility; signed tokens also work across workers/restarts.
        ADMIN_EMERGENCY_SESSIONS[token] = {"user_id": user_id, "expires": expires_at}
    write_security_event("admin_password_unlock", actor_id=user_id, path=request.path, method="POST", status_code=200)
    return jsonify(ok=True, token=token, can_change_password=is_main_admin_user(user_id))


@app.post("/api/admin/emergency/change-password")
def admin_emergency_change_password():
    user_id, error = admin_user_from_request()
    if error:
        return error
    if not is_main_admin_user(user_id):
        return jsonify(error="Only the designated password manager can change the emergency password."), 403
    if not supabase_enabled():
        return jsonify(error="Password changes require Supabase persistence. Configure SUPABASE_URL and SUPABASE_SECRET_KEY, then apply admin_emergency_password_migration.sql."), 503
    data = request.get_json(silent=True) or {}
    current = str(data.get("current_password", ""))
    new_password = str(data.get("new_password", ""))
    stored_hash = stored_emergency_password_hash()
    if stored_hash:
        current_ok = emergency_password_matches(current, stored_hash)
    else:
        current_ok = bool(ADMIN_EMERGENCY_PASSWORD) and hmac.compare_digest(current, ADMIN_EMERGENCY_PASSWORD)
    if not current_ok:
        return jsonify(error="Current password is incorrect."), 401
    if len(new_password) < 12 or len(new_password) > 256:
        return jsonify(error="New password must be 12–256 characters long."), 400
    new_hash = emergency_password_hash(new_password)
    try:
        supabase_request("POST", "/rest/v1/admin_emergency_password", payload={"id": 1, "password_hash": new_hash},
                         extra_headers={"Prefer": "resolution=merge-duplicates,return=representation"})
    except Exception:
        log.exception("Could not save emergency admin password")
        return jsonify(error="Could not save password. Check the SQL migration and Supabase configuration."), 503
    # Revoke every currently unlocked session after a password change.
    with ADMIN_PASSWORD_LOCK:
        ADMIN_EMERGENCY_SESSIONS.clear()
    write_security_event("admin_password_changed", actor_id=user_id, path=request.path, method="POST", status_code=200)
    return jsonify(ok=True, message="Password changed. Reopen the admin panel and unlock with the new password.")


def public_admin_product(pid, item):
    return {"id": pid, "name": item.get("name", ""), "name_am": item.get("name_am", ""),
            "category": item.get("category", "Other"), "price": item.get("price", 0),
            "description": item.get("description", ""), "description_am": item.get("description_am", ""),
            "measurements": item.get("measurements", "120 cm available"),
            "capacity": item.get("capacity", "To be confirmed"), "material": item.get("material", "To be confirmed"),
            "specifications": item.get("specifications", {}),
            "stock_status": item.get("stock_status", "in_stock"), "allow_order": item.get("allow_order", True),
            "active": item.get("active", True), "pinned": bool(item.get("pinned", False)),
            "colors": item.get("colors", ["As shown"]), "images": item.get("images", [])}

ALLOWED_MIME = {"image/jpeg": ".jpg", "image/png": ".png", "image/webp": ".webp"}
NOTIFICATION_SUBSCRIBERS_FILE = Path(os.getenv("NOTIFICATION_SUBSCRIBERS_FILE", str(BASE_DIR / "notification_subscribers.json")))
CART_EVENTS_FILE = Path(os.getenv("CART_EVENTS_FILE", str(BASE_DIR / "cart_events.json")))
NOTIFICATION_HOUR = max(0, min(23, int(os.getenv("PRODUCT_NOTIFICATION_HOUR", "10"))))
NOTIFICATION_TIMEZONE = os.getenv("PRODUCT_NOTIFICATION_TIMEZONE", "Africa/Addis_Ababa")
SUBSCRIBER_LOCK = threading.Lock()
PRODUCT_NOTIFICATION_START = dt.date(2026, 10, 16)


@app.after_request
def audit_authorized_admin_api(response):
    """Record verified admin API access and mutating actions without logging request bodies."""
    actor_id = getattr(g, "admin_user_id", None)
    path = request.path
    if actor_id and path.startswith("/api/admin/") and path not in {
        "/api/admin/security/report", "/api/admin/security/sign-in"
    }:
        event_type = "admin_action" if request.method in {"POST", "PUT", "PATCH", "DELETE"} else "admin_api_access"
        write_security_event(event_type, actor_id=actor_id, path=path, method=request.method,
                             status_code=response.status_code,
                             details={"endpoint": path, "method": request.method})
    return response


app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
telegram_app = None
telegram_thread_started = False


load_product_catalog()


def clean_text(value, limit, field, required=False):
    if not isinstance(value, str):
        value = "" if value is None else str(value)
    value = value.strip()
    value = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", value)
    if required and not value:
        raise ValueError(f"{field} is required.")
    if len(value) > limit:
        raise ValueError(f"{field} must be {limit} characters or fewer.")
    return value


def validate_telegram_init_data(init_data):
    """Validate Telegram Web App initData using Telegram's documented HMAC scheme."""
    if not BOT_TOKEN or not init_data:
        return False, None
    try:
        pairs = dict(parse_qsl(init_data, keep_blank_values=True, strict_parsing=True))
        received_hash = pairs.pop("hash", None)
        if not received_hash or not re.fullmatch(r"[0-9a-f]{64}", received_hash):
            return False, None
        auth_date = int(pairs.get("auth_date", "0"))
        # Reject missing, future-dated, or stale initData (24-hour maximum age).
        now = int(time.time())
        if auth_date <= 0 or auth_date > now + 60 or now - auth_date > 86400:
            return False, None
        data_check_string = "\n".join(f"{key}={value}" for key, value in sorted(pairs.items()))
        secret_key = hmac.new(b"WebAppData", BOT_TOKEN.encode(), hashlib.sha256).digest()
        calculated = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(calculated, received_hash):
            return False, None
        user = json.loads(pairs.get("user", "{}"))
        user_id = user.get("id")
        return True, str(user_id) if user_id is not None else None
    except (ValueError, TypeError, json.JSONDecodeError):
        return False, None


def require_auth_from_request():
    init_data = request.headers.get("X-Telegram-Init-Data", "")
    if request.is_json:
        body = request.get_json(silent=True) or {}
        # Never trust a browser-supplied user id. Authentication comes only from signed initData.
    else:
        body = {}
    if not REQUIRE_TELEGRAM_AUTH:
        return True, None
    return validate_telegram_init_data(init_data), None


def auth_result(init_data):
    if not REQUIRE_TELEGRAM_AUTH:
        return True, None
    valid, user_id = validate_telegram_init_data(init_data)
    return valid, user_id


def telegram_username_from_init_data(init_data):
    """Return the Telegram username from signed initData after authentication succeeds."""
    if not init_data:
        return "Not available"
    try:
        pairs = dict(parse_qsl(init_data, keep_blank_values=True, strict_parsing=True))
        user = json.loads(pairs.get("user", "{}"))
        username = clean_text(user.get("username", ""), 100, "Telegram username")
        return f"@{username}" if username else "No Telegram username set"
    except (ValueError, TypeError, json.JSONDecodeError):
        return "Not available"


def telegram_language_from_init_data(init_data):
    """Return the language code from authenticated Telegram WebApp initData."""
    if not init_data:
        return "Not available"
    try:
        pairs = dict(parse_qsl(init_data, keep_blank_values=True, strict_parsing=True))
        user = json.loads(pairs.get("user", "{}"))
        return clean_text(user.get("language_code", ""), 30, "Telegram language") or "Not provided"
    except (ValueError, TypeError, json.JSONDecodeError):
        return "Not available"


def bot_api(method, data=None, files=None, timeout=25):
    if not BOT_TOKEN:
        raise RuntimeError("Bot is not configured. Set BOT_TOKEN in Render environment variables.")
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/{method}"
    response = requests.post(url, data=data or {}, files=files, timeout=timeout)
    try:
        payload = response.json()
    except ValueError:
        payload = {}
    if not response.ok or not payload.get("ok"):
        description = payload.get("description", f"Telegram API error ({response.status_code})")
        raise RuntimeError(description)
    return payload.get("result")


def send_service_message(text):
    if not SERVICE_CHAT_ID:
        raise RuntimeError("SERVICE_CHAT_ID is not configured in Render.")
    return bot_api("sendMessage", {"chat_id": SERVICE_CHAT_ID, "text": text, "disable_web_page_preview": True})


def send_service_photo(path, caption=None, reply_to_message_id=None):
    if not SERVICE_CHAT_ID:
        raise RuntimeError("SERVICE_CHAT_ID is not configured in Render.")
    data = {"chat_id": SERVICE_CHAT_ID}
    if caption:
        data["caption"] = caption[:1024]
    if reply_to_message_id:
        data["reply_to_message_id"] = reply_to_message_id
    with open(path, "rb") as handle:
        return bot_api("sendPhoto", data, {"photo": handle})


def send_service_photo_album(paths, caption=None, reply_to_message_id=None):
    """Send every customer reference photo to the service chat; fall back to individual photos if albums fail."""
    if not SERVICE_CHAT_ID:
        raise RuntimeError("SERVICE_CHAT_ID is not configured in Render.")
    paths = [str(path) for path in paths if path and Path(path).is_file()]
    if not paths:
        return []
    if len(paths) == 1:
        return [send_service_photo(paths[0], caption, reply_to_message_id)]
    opened, files, media = [], [], []
    try:
        for index, path in enumerate(paths[:10]):
            handle = open(path, "rb")
            opened.append(handle)
            field = f"photo{index}"
            item = {"type": "photo", "media": f"attach://{field}"}
            if index == 0 and caption:
                item["caption"] = caption[:1024]
            media.append(item)
            files.append((field, (os.path.basename(path), handle, "application/octet-stream")))
        data = {"chat_id": SERVICE_CHAT_ID, "media": json.dumps(media, ensure_ascii=False)}
        if reply_to_message_id:
            data["reply_to_message_id"] = reply_to_message_id
        try:
            return bot_api("sendMediaGroup", data, files)
        except Exception as album_error:
            log.warning("Telegram photo album failed; retrying photos individually: %s", album_error)
    finally:
        for handle in opened:
            handle.close()
    sent = []
    for index, path in enumerate(paths[:10]):
        photo_caption = caption if index == 0 else f"Reference photo {index + 1} of {len(paths)}"
        sent.append(send_service_photo(path, photo_caption, reply_to_message_id))
    return sent


def send_service_voice(path, caption=None, reply_to_message_id=None):
    if not SERVICE_CHAT_ID:
        raise RuntimeError("SERVICE_CHAT_ID is not configured in Render.")
    data = {"chat_id": SERVICE_CHAT_ID}
    if caption:
        data["caption"] = caption[:1024]
    if reply_to_message_id:
        data["reply_to_message_id"] = reply_to_message_id
    # Browser MediaRecorder commonly produces WebM/Opus. Telegram's sendVoice
    # endpoint may reject WebM, so preserve the original recording and fall back
    # to sendDocument rather than losing the customer's voice instructions.
    try:
        with open(path, "rb") as handle:
            return bot_api("sendVoice", data, {"voice": handle})
    except Exception as voice_error:
        log.warning("Telegram sendVoice rejected the uploaded recording; retrying as a document: %s", voice_error)
        with open(path, "rb") as handle:
            return bot_api("sendDocument", data, {"document": handle})


def ethiopian_datetime(moment=None):
    """Return local Addis Ababa date/time in the Ethiopian calendar."""
    moment = moment or dt.datetime.now(ZoneInfo("Africa/Addis_Ababa"))
    gregorian = moment.date()
    month = gregorian.month
    year = gregorian.year
    a = (14 - month) // 12
    gy = year + 4800 - a
    gm = month + 12 * a - 3
    jdn = gregorian.day + (153 * gm + 2) // 5 + 365 * gy + gy // 4 - gy // 100 + gy // 400 - 32045
    days = jdn - 1724221
    eth_year = max(1, (4 * days + 1462) // 1461)
    while 365 * (eth_year - 1) + (eth_year - 1) // 4 > days:
        eth_year -= 1
    while 365 * eth_year + eth_year // 4 <= days:
        eth_year += 1
    day_of_year = days - (365 * (eth_year - 1) + (eth_year - 1) // 4)
    eth_month = day_of_year // 30 + 1
    eth_day = day_of_year % 30 + 1
    eth_months = ["Meskerem", "Tikimt", "Hidar", "Tahsas", "Tir", "Yekatit", "Megabit", "Miazia", "Ginbot", "Sene", "Hamle", "Nehase", "Pagume"]
    return f"{eth_months[eth_month - 1]} {eth_day}, {eth_year} · {moment.strftime('%H:%M')} EAT"


PRODUCT_PHOTOS = {
    "shoe_design_1": "shoe-design-1.webp",
    "shoe_design_2": "shoe-design-2.webp",
    "shoe_design_3": "shoe-design-3.webp",
    "shoe_design_4": "shoe-design-4.webp",
    "shoe_design_5": "shoe-design-5.webp",
    "shoe_design_6": "shoe-design-6.webp",
    "shoe_design_7": "shoe-design-7.webp",
}


def _resolve_order_photo_paths(items):
    """Resolve built-in and admin-uploaded product photos to local files for Telegram."""
    paths = []
    temporary_paths = []
    seen = set()
    for item in items:
        sources = item.get("images") if isinstance(item.get("images"), list) else []
        if not sources:
            filename = PRODUCT_PHOTOS.get(item.get("id"))
            if filename:
                sources = [str(BASE_DIR / "products" / filename)]
        for source in sources:
            source = str(source or "").strip()
            if not source or source in seen:
                continue
            seen.add(source)
            try:
                local_path = None
                if source.startswith(("http://", "https://")):
                    response = requests.get(source, timeout=20, stream=True)
                    response.raise_for_status()
                    mime = (response.headers.get("content-type") or "").split(";", 1)[0].lower()
                    ext = {"image/jpeg": ".jpg", "image/png": ".png", "image/webp": ".webp"}.get(mime)
                    if not ext:
                        ext = Path(source.split("?", 1)[0]).suffix.lower()
                    if ext not in {".jpg", ".jpeg", ".png", ".webp"}:
                        response.close()
                        log.warning("Skipping unsupported product image type for %s", source)
                        continue
                    temp = UPLOAD_DIR / secure_filename(f"order_product_{secrets.token_hex(8)}{ext}")
                    total_bytes = 0
                    with temp.open("wb") as handle:
                        for chunk in response.iter_content(64 * 1024):
                            if not chunk:
                                continue
                            total_bytes += len(chunk)
                            if total_bytes > 8 * 1024 * 1024:
                                raise ValueError("Product image exceeds Telegram upload limit.")
                            handle.write(chunk)
                    response.close()
                    local_path = temp
                    temporary_paths.append(temp)
                else:
                    candidate = Path(source)
                    if not candidate.is_absolute():
                        candidate = BASE_DIR / candidate
                    if candidate.is_file():
                        local_path = candidate
                if local_path and local_path.is_file() and local_path not in paths:
                    paths.append(local_path)
            except Exception as exc:
                log.warning("Could not prepare product photo for order (%s): %s", item.get("id"), exc)
    return paths, temporary_paths


def send_order_album(caption, items, payment_path=None):
    """Send a short order summary with only the first product photo to the service channel."""
    photo_paths, temporary_paths = _resolve_order_photo_paths(items)
    photo_paths = photo_paths[:1]
    if not photo_paths:
        # Do not lose an order just because a product image is missing or unreachable.
        send_service_message(caption + "\n\nProduct photo unavailable.")
        for path in temporary_paths:
            try: path.unlink(missing_ok=True)
            except OSError: pass
        return
    try:
        photo_paths = photo_paths[:1]
        caption = caption[:1024]
        if len(photo_paths) == 1:
            send_service_photo(str(photo_paths[0]), caption)
            return
        media = []
        opened = []
        files = []
        try:
            for index, photo_path in enumerate(photo_paths):
                field_name = f"photo{index}"
                handle = photo_path.open("rb")
                opened.append(handle)
                media_item = {"type": "photo", "media": f"attach://{field_name}"}
                if index == 0:
                    media_item["caption"] = caption
                media.append(media_item)
                files.append((field_name, (photo_path.name, handle, "application/octet-stream")))
            bot_api("sendMediaGroup", {"chat_id": SERVICE_CHAT_ID, "media": json.dumps(media, ensure_ascii=False)}, files)
        finally:
            for handle in opened:
                handle.close()
    finally:
        for path in temporary_paths:
            try: path.unlink(missing_ok=True)
            except OSError: pass


def maybe_send_customer_confirmation(user_id, text):
    if not user_id:
        return False
    try:
        bot_api("sendMessage", {"chat_id": str(user_id), "text": text})
        return True
    except Exception as exc:
        # A service notification already delivered must not be treated as a failed submission.
        log.info("Customer private confirmation was not delivered: %s", exc)
        return False


def maybe_send_customer_confirmation_with_photos(user_id, text, photo_paths):
    """Send a compact confirmation with only the first product photo."""
    if not user_id:
        return False
    paths = [Path(path) for path in photo_paths if path and Path(path).is_file()][:1]
    if not paths:
        return maybe_send_customer_confirmation(user_id, text)
    # Telegram albums support 2–10 photos. A single photo is sent with the caption.
    paths = paths[:10]
    try:
        if len(paths) == 1:
            with paths[0].open("rb") as handle:
                bot_api("sendPhoto", {"chat_id": str(user_id), "caption": text[:1024]}, {"photo": handle})
            return True
        media = []
        opened = []
        files = []
        try:
            for index, path in enumerate(paths):
                field_name = f"photo{index}"
                handle = path.open("rb")
                opened.append(handle)
                media_item = {"type": "photo", "media": f"attach://{field_name}"}
                if index == 0:
                    media_item["caption"] = text[:1024]
                media.append(media_item)
                files.append((field_name, (path.name, handle, "application/octet-stream")))
            bot_api("sendMediaGroup", {"chat_id": str(user_id), "media": json.dumps(media, ensure_ascii=False)}, files)
        finally:
            for handle in opened:
                handle.close()
        return True
    except Exception as exc:
        # Customer notifications must not undo an order already delivered to staff.
        log.info("Customer photo confirmation was not delivered: %s", exc)
        # Fall back to a text confirmation if Telegram cannot deliver the photo album.
        return maybe_send_customer_confirmation(user_id, text)


def product_photo_paths(items):
    """Return product images for customer confirmations, including admin-added products."""
    paths, _temporary_paths = _resolve_order_photo_paths(items)
    # Keep downloaded temporary photos available for the caller's immediate send.
    # They are cleaned after the Telegram confirmation attempt below.
    return paths


def new_reference(prefix):
    # Customer-friendly reference: AF- plus six uppercase letters/digits (e.g. AF-7K29M4).
    # Check saved orders to avoid reusing an existing reference.
    if prefix == "AF":
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        for _ in range(100):
            suffix = "".join(secrets.choice(alphabet) for _ in range(6))
            reference = f"AF-{suffix}"
            try:
                rows = supabase_request("GET", "/rest/v1/customer_orders", params={"select": "reference", "reference": f"eq.{reference}", "limit": "1"}) or []
                if not rows:
                    return reference
            except Exception:
                # Keep checkout available if the database lookup is temporarily unavailable.
                return "AF-" + "".join(secrets.choice(alphabet) for _ in range(6))
        raise RuntimeError("Could not generate a unique order reference after 100 attempts")
    return f"{prefix}-{time.strftime('%Y%m%d')}-{secrets.token_hex(3).upper()}"


def validate_customer(customer):
    if not isinstance(customer, dict):
        raise ValueError("Customer details are missing.")
    phone = clean_text(customer.get("phone"), 30, "Phone number", True)
    normalized_phone = re.sub(r"[\s().-]", "", phone)
    # Accept Ethiopian mobile numbers (09/07 local or +251 international format)
    # and other international numbers in E.164-style +countrycode format.
    if not re.fullmatch(r"(?:\+251[79]\d{8}|0[79]\d{8}|\+[1-9]\d{7,14})", normalized_phone):
        raise ValueError("Enter a valid phone number, e.g. 0912345678 or +251912345678.")
    return {
        "name": clean_text(customer.get("name"), 100, "Full name", True),
        "phone": normalized_phone,
        "location": clean_text(customer.get("location"), 600, "Location", True),
        "contact_preference": clean_text(customer.get("contact_preference", "Phone call"), 30, "Contact preference", True),
    }


def parse_standard_order(data):
    load_product_catalog()
    customer = validate_customer(data.get("customer"))
    items = data.get("items")
    if not isinstance(items, list) or not items or len(items) > 20:
        raise ValueError("Add between 1 and 20 product line items.")
    normalized = []
    total = 0
    seen = set()
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("Invalid product item.")
        product_id = clean_text(item.get("product_id"), 50, "Product ID", True)
        if product_id in seen:
            raise ValueError("Please combine duplicate product lines.")
        seen.add(product_id)
        product = PRODUCTS.get(product_id)
        if not product:
            raise ValueError("One of the selected products is unavailable.")
        is_shoe_shelf = str(product.get("category", "")).strip().casefold() == "shoe shelf"
        requested_measurement = item.get("measurement", "")
        # Accept the customer's requested measurement for every product. A missing
        # price must not block an order: the order is a request and AMBAR confirms
        # the final measurement-specific price before asking for an advance.
        specs = product.get("specifications") if isinstance(product.get("specifications"), dict) else {}
        configured_measurement = specs.get("measurements") or product.get("measurements") or ""
        candidate = requested_measurement or configured_measurement or ("120 cm" if is_shoe_shelf else "Not specified")
        measurement = clean_text(candidate, 120, "Measurement") or "Not specified"
        try:
            quantity = int(item.get("quantity"))
        except (TypeError, ValueError):
            raise ValueError("Product quantity must be a whole number.")
        if quantity < 1 or quantity > 99:
            raise ValueError("Each quantity must be between 1 and 99.")
        line_total = product["price"] * quantity
        total += line_total
        product_images = product.get("images") if isinstance(product.get("images"), list) else []
        if not product_images and product.get("image_url"):
            product_images = [product.get("image_url")]
        normalized.append({"id": product_id, "name": product["name"], "quantity": quantity,
                           "measurement": measurement, "unit_price": product["price"], "line_total": line_total,
                           "stock_status": product.get("stock_status", "in_stock"),
                           "allow_order": product.get("allow_order", True),
                           "images": [str(src) for src in product_images if str(src).strip()]})
    finish = "Not selected"
    material = clean_text(data.get("material", ""), 120, "Material preference")
    notes = clean_text(data.get("notes", ""), 1000, "Notes")
    return customer, normalized, total, finish, material, notes


@app.get("/")
def home():
    return send_from_directory(BASE_DIR, "index.html")


@app.get("/admin")
def admin_page():
    return send_from_directory(BASE_DIR, "admin.html", max_age=0)


@app.get("/workshop-admin")
@app.get("/workshop-erp")
def workshop_admin_page():
    # Both paths serve the standalone Workshop ERP page. Keep the older
    # /workshop-admin path for the Profile button and /workshop-erp as an alias.
    return send_from_directory(BASE_DIR, "workshop-admin.html", max_age=0)


@app.get("/workshop-customers")
def workshop_customers_page():
    # Customer profiles belong to the Workshop ERP workspace, not the main Admin menu.
    return send_from_directory(BASE_DIR, "workshop-customers.html", max_age=0)


@app.get("/financial-inventory.html")
def financial_inventory_page():
    # This page is embedded as a modal inside Workshop ERP; access is checked by the Workshop ERP session and finance_inventory permission.
    return send_from_directory(BASE_DIR, "financial-inventory.html", max_age=0)


def workshop_observer_role(user_id):
    """True only for a Workshop ERP observer. Observer accounts are read-only."""
    if not user_id or str(user_id) == str(ADMIN_PASSWORD_MANAGER_TELEGRAM_ID or ""):
        return False
    row = admin_permissions_for(str(user_id)) or {}
    perms = normalize_admin_permissions(row.get("permissions"), row.get("role"))
    return bool(row.get("active") and "workshop_erp" in perms and "workshop_watch" in perms)

def deny_workshop_observer_write(user_id):
    if workshop_observer_role(user_id):
        write_security_event("workshop_observer_write_denied", actor_id=str(user_id), path=request.path, method=request.method, status_code=403)
        return jsonify(error="Workshop Activity Observer is read-only. You can view all Workshop ERP activity but cannot change anything."), 403
    return None

def workshop_session_user():
    """Validate signed Telegram identity, active admin status, and fresh admin unlock."""
    user_id, error = verified_telegram_admin()
    if error:
        return None, error
    owner_id = str(ADMIN_PASSWORD_MANAGER_TELEGRAM_ID or "")
    # Only the main owner needs the emergency-password session. Staff access is
    # authorized by signed Telegram identity + their active Workshop ERP role.
    if is_main_admin_user(user_id):
        token = request.headers.get("X-Admin-Emergency-Session", "")
        if not valid_emergency_session(token, user_id):
            return None, (jsonify(error="Main admin session expired. Reopen Workshop ERP and verify the emergency admin password."), 423)
        return user_id, None
    role_data = admin_permissions_for(user_id) or {}
    permissions = normalize_admin_permissions(role_data.get("permissions"), role_data.get("role"))
    if not role_data.get("active", False) or role_data.get("role") == "disabled" or "workshop_erp" not in permissions:
        return None, (jsonify(error="Workshop ERP permission is required. Ask the main admin to enable Workshop ERP in Admin Management."), 403)
    token = request.headers.get("X-Workshop-Session", "")
    with ADMIN_PASSWORD_LOCK:
        session = WORKSHOP_STAFF_SESSIONS.get(token) if token else None
        if session and session.get("expires", 0) < time.time():
            WORKSHOP_STAFF_SESSIONS.pop(token, None)
            session = None
    if not session or session.get("user_id") != user_id:
        return None, (jsonify(error="Your unique Workshop ERP password is required. Reopen Workshop ERP and sign in."), 423)
    return user_id, None


@app.post("/api/workshop/password/verify")
def workshop_staff_password_verify():
    """Verify the unique password set by the main admin for a staff Workshop ERP account."""
    user_id, error = verified_telegram_admin()
    if error:
        return error
    if is_main_admin_user(user_id):
        return jsonify(error="Main admins use the emergency administrator password."), 400
    role_data = admin_permissions_for(user_id) or {}
    permissions = normalize_admin_permissions(role_data.get("permissions"), role_data.get("role"))
    if not role_data.get("active", False) or role_data.get("role") == "disabled" or "workshop_erp" not in permissions:
        return jsonify(error="Workshop ERP permission has not been enabled for this account."), 403
    password = str((request.get_json(silent=True) or {}).get("password", ""))
    stored = role_data.get("workshop_password_hash")
    if not stored:
        return jsonify(error="The main admin must assign a unique Workshop ERP password to your account first."), 403
    if not emergency_password_matches(password, stored):
        return jsonify(error="Incorrect Workshop ERP password."), 401
    token = secrets.token_urlsafe(32)
    with ADMIN_PASSWORD_LOCK:
        WORKSHOP_STAFF_SESSIONS[token] = {"user_id": str(user_id), "expires": time.time() + 60 * 60 * 8}
    write_security_event("workshop_staff_password_login", actor_id=user_id, path=request.path, method="POST", status_code=200)
    return jsonify(ok=True, token=token, expires_in=60 * 60 * 8)


@app.post("/api/workshop/admin-password")
def workshop_staff_password_set():
    """Main-admin-only creation/update of an individual staff Workshop ERP password."""
    user_id, error = admin_user_from_request()
    if error:
        return error
    if not is_main_admin_user(user_id):
        return jsonify(error="Only a main AMBAR admin can set staff passwords."), 403
    if not supabase_enabled():
        return jsonify(error="Supabase is required to store staff passwords securely."), 503
    data = request.get_json(silent=True) or {}
    target = str(data.get("telegram_user_id", "")).strip()
    password = str(data.get("password", ""))
    if not target.isdigit() or target == str(user_id):
        return jsonify(error="Select a valid staff admin account."), 400
    if len(password) < 10 or len(password) > 256:
        return jsonify(error="Use a unique password with at least 10 characters."), 400
    record = admin_permissions_for(target) or {}
    perms = normalize_admin_permissions(record.get("permissions"), record.get("role"))
    if not record or not record.get("active", False) or record.get("role") == "disabled" or "workshop_erp" not in perms:
        return jsonify(error="Enable Workshop ERP for this admin in Admin Management before setting its password."), 400
    try:
        supabase_request("PATCH", "/rest/v1/ambar_admin_roles", params={"telegram_user_id": f"eq.{target}"}, payload={"workshop_password_hash": emergency_password_hash(password), "updated_at": dt.datetime.now(dt.timezone.utc).isoformat()}, extra_headers={"Prefer":"return=minimal"})
        with ADMIN_PASSWORD_LOCK:
            for token, session in list(WORKSHOP_STAFF_SESSIONS.items()):
                if session.get("user_id") == target:
                    WORKSHOP_STAFF_SESSIONS.pop(token, None)
        write_security_event("workshop_staff_password_set", actor_id=user_id, path=request.path, method="POST", status_code=200, details={"target_admin_id":target})
        return jsonify(ok=True, message="Unique Workshop ERP password saved.")
    except Exception:
        log.exception("Could not save staff Workshop ERP password")
        return jsonify(error="Could not save password. Apply workshop_staff_password_migration.sql and check Supabase."), 503


@app.post("/api/workshop/assignments")
def workshop_assignments_save():
    """Owner-only, server-side save of a staff member's real Workshop ERP role and task assignment."""
    user_id, error = workshop_session_user()
    if error:
        return error
    owner_id = str(ADMIN_PASSWORD_MANAGER_TELEGRAM_ID or "")
    if not is_main_admin_user(user_id):
        return jsonify(error="Only the main AMBAR admin can confirm Workshop ERP assignments."), 403
    if not supabase_enabled():
        return jsonify(error="Shared Supabase storage is not configured."), 503
    data = request.get_json(silent=True) or {}
    target = str(data.get("telegram_user_id", "")).strip()
    name = clean_text(data.get("display_name", ""), 100, "Admin name", False)
    permissions = data.get("permissions", [])
    allowed_tasks = {"workshop", "inventory", "materials", "sales", "reports", "dashboard",
                     "workshop_add", "workshop_edit", "workshop_advance", "workshop_delete", "workshop_watch",
                     "inventory_add", "inventory_edit", "inventory_delete",
                     "materials_add", "materials_receive", "materials_cut", "materials_edit", "materials_delete",
                     "sales_add", "sales_edit", "sales_delete"}
    allowed_workshop_stages = {"Cutting & Prep", "Assembly", "Finishing / Spray", "In Stock"}
    def valid_task_permission(value):
        if isinstance(value, str) and value in allowed_tasks:
            return True
        if isinstance(value, str) and value.startswith("workshop_stage:"):
            return value.split(":", 1)[1] in allowed_workshop_stages
        return False
    if not target.isdigit() or target == owner_id or target == str(user_id):
        return jsonify(error="Choose a valid staff admin."), 400
    if not isinstance(permissions, list) or any(not valid_task_permission(p) for p in permissions):
        return jsonify(error="Select valid Workshop ERP functions and production areas."), 400
    permissions = list(dict.fromkeys(permissions))
    observer_only = "workshop_watch" in permissions
    if observer_only:
        permissions = ["workshop_watch"]
    permission_parents = {
        "workshop_add":"workshop", "workshop_edit":"workshop", "workshop_advance":"workshop", "workshop_delete":"workshop",
        "inventory_add":"inventory", "inventory_edit":"inventory", "inventory_delete":"inventory",
        "materials_add":"materials", "materials_receive":"materials", "materials_cut":"materials", "materials_edit":"materials", "materials_delete":"materials",
        "sales_add":"sales", "sales_edit":"sales", "sales_delete":"sales",
    }
    for permission in list(permissions):
        parent = permission_parents.get(permission)
        if parent and parent not in permissions:
            permissions.append(parent)
    if any(isinstance(p, str) and p.startswith("workshop_stage:") for p in permissions) and "workshop" not in permissions:
        permissions.append("workshop")
    role_before = None
    role_after = None
    try:
        role_rows = supabase_request("GET", "/rest/v1/ambar_admin_roles", params={
            "select":"telegram_user_id,display_name,role,active,permissions", "telegram_user_id":f"eq.{target}", "limit":"1"
        }) or []
        if not role_rows or not role_rows[0].get("active", False) or role_rows[0].get("role") == "disabled":
            return jsonify(error="This admin is not active. Activate the account in Admin Management first."), 400
        role_before = role_rows[0]
        old_permissions = normalize_admin_permissions(role_before.get("permissions"), role_before.get("role"))
        role_permissions = [p for p in old_permissions if p not in {"workshop_erp", "workshop_watch"}]
        if permissions:
            role_permissions.append("workshop_erp")
        if observer_only:
            role_permissions.append("workshop_watch")
        role_after = {"telegram_user_id":target,"display_name":name or role_before.get("display_name") or "Staff admin",
                      "role":"orders" if role_permissions == ["orders"] else "staff", "active":True,
                      "permissions":role_permissions,"updated_at":dt.datetime.now(dt.timezone.utc).isoformat()}
        saved_role = supabase_request("POST", "/rest/v1/ambar_admin_roles", payload=role_after,
                                      extra_headers={"Prefer":"resolution=merge-duplicates,return=representation"})
        # Read and compare-and-swap the shared JSON state, retrying if another user saves concurrently.
        saved_row = None
        for _ in range(4):
            rows = supabase_request("GET", "/rest/v1/workshop_erp_state", params={"select":"id,state,updated_at","id":"eq.1","limit":"1"}) or []
            if not rows or not isinstance(rows[0].get("state"), dict):
                raise RuntimeError("Workshop ERP shared state is not initialized. Open Workshop ERP as the main admin and refresh first.")
            current = rows[0]
            state = current["state"]
            assignments = state.get("workshopAssignments", [])
            if not isinstance(assignments, list): assignments = []
            row = {"telegram_user_id":target,"display_name":role_after["display_name"],"permissions":permissions,
                   "updated_at":dt.datetime.now(dt.timezone.utc).isoformat()}
            assignments = [x for x in assignments if not (isinstance(x, dict) and str(x.get("telegram_user_id")) == target)]
            assignments.append(row)
            state["workshopAssignments"] = assignments
            updated = dt.datetime.now(dt.timezone.utc).isoformat()
            patched = supabase_request("PATCH", "/rest/v1/workshop_erp_state", params={
                "id":"eq.1", "updated_at":f"eq.{current.get('updated_at')}"
            }, payload={"state":state,"updated_at":updated,"updated_by":str(user_id)},
               extra_headers={"Prefer":"return=representation"}) or []
            if patched:
                saved_row = patched[0]
                break
        if not saved_row:
            raise RuntimeError("Workshop data changed repeatedly. Refresh and click Done again.")
        write_security_event("workshop_assignments_confirmed", actor_id=user_id, status_code=200,
                             details={"target_admin_id":target,"workshop_permissions":permissions})
        return jsonify(ok=True, state=saved_row.get("state", state), updated_at=saved_row.get("updated_at", updated),
                       admin_permissions=role_permissions, confirmed=True)
    except Exception as exc:
        log.exception("Could not save Workshop ERP assignment")
        # Best-effort role rollback when the task assignment did not complete.
        if role_before is not None:
            try:
                rollback = {k: role_before.get(k) for k in ("telegram_user_id", "display_name", "role", "active", "permissions")}
                rollback["updated_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
                supabase_request("POST", "/rest/v1/ambar_admin_roles", payload=rollback,
                                 extra_headers={"Prefer":"resolution=merge-duplicates,return=minimal"})
            except Exception:
                log.exception("Could not roll back role after failed Workshop ERP assignment")
        return jsonify(error=str(exc)[:300] or "Could not save Workshop ERP assignment."), 503


@app.post("/api/workshop/delete")
def workshop_record_delete():
    """Delete a Workshop ERP record from the latest shared state, with server-side owner checks."""
    user_id, error = workshop_session_user()
    if error:
        return error
    observer_denied = deny_workshop_observer_write(user_id)
    if observer_denied:
        return observer_denied
    owner_id = str(ADMIN_PASSWORD_MANAGER_TELEGRAM_ID or "")
    is_owner = is_main_admin_user(user_id)
    if not supabase_enabled():
        return jsonify(error="Shared Supabase storage is not configured."), 503
    data = request.get_json(silent=True) or {}
    collection = str(data.get("collection", ""))
    record_id = str(data.get("id", ""))
    keys = {"orders":"serial", "products":"id", "materials":"id", "materialTransactions":"id", "sales":"id"}
    if collection not in keys or not record_id:
        return jsonify(error="Invalid record type or ID."), 400
    key = keys[collection]
    try:
        for _ in range(5):
            rows = supabase_request("GET", "/rest/v1/workshop_erp_state", params={"select":"id,state,updated_at","id":"eq.1","limit":"1"}) or []
            if not rows or not isinstance(rows[0].get("state"), dict):
                return jsonify(error="No shared Workshop ERP data was found. Refresh and try again."), 404
            current = rows[0]
            state = current["state"]
            if not is_owner:
                assignment_rows = state.get("workshopAssignments", [])
                assignment = next((x for x in assignment_rows if isinstance(x, dict) and str(x.get("telegram_user_id")) == str(user_id)), {}) if isinstance(assignment_rows, list) else {}
                assigned = set(assignment.get("permissions", []) if isinstance(assignment.get("permissions", []), list) else [])
                required = {"orders": "workshop_delete", "products": "inventory_delete", "materials": "materials_delete", "materialTransactions": "materials_delete", "sales": "sales_delete"}.get(collection)
                if "*" not in assigned and (not required or required not in assigned):
                    return jsonify(error=f"This admin needs the {required or 'matching'} permission to delete this record."), 403
            arr = state.get(collection, [])
            if not isinstance(arr, list): arr = []
            def identity(item):
                value = item.get(key) if isinstance(item, dict) else None
                if value is None and collection == "orders" and isinstance(item, dict): value = item.get("productId")
                return None if value is None else str(value)
            item = next((x for x in arr if identity(x) == record_id), None)
            if item is None:
                return jsonify(error="This record no longer exists in shared data. Refresh the page."), 404
            state[collection] = [x for x in arr if identity(x) != record_id]
            if collection == "materialTransactions":
                for material in state.get("materials", []):
                    if isinstance(material, dict) and str(material.get("id")) == str(item.get("materialId")):
                        delta = -float(item.get("qty", 0) or 0) if item.get("type") == "receipt" else float(item.get("qty", 0) or 0)
                        material["stock"] = max(0, float(material.get("stock", 0) or 0) + delta)
                        break
            elif collection == "orders":
                state["products"] = [p for p in state.get("products", []) if str(p.get("workOrder", "")) != str(item.get("serial") or item.get("productId") or "")]
            elif collection == "products":
                product_record_id = str(item.get("id"))
                product_id = str(item.get("productId") or item.get("serial") or "")
                state["sales"] = [x for x in state.get("sales", []) if not (
                    str(x.get("productRecordId") or x.get("id")) == product_record_id
                    or (product_id and str(x.get("productId") or x.get("serial") or "") == product_id)
                )]
            elif collection == "materials":
                state["materialTransactions"] = [x for x in state.get("materialTransactions", []) if str(x.get("materialId")) != record_id]
            label = (item.get("productId") or item.get("serial") or "work order") if collection == "orders" else (item.get("model") or "record") if collection in {"products", "sales"} else item.get("name", "material") if collection == "materials" else item.get("materialName", "material movement")
            log_items = state.get("activityLog", [])
            if not isinstance(log_items, list): log_items = []
            log_items.append(f"Admin {user_id} deleted {label}")
            state["activityLog"] = log_items[-1000:]
            updated = dt.datetime.now(dt.timezone.utc).isoformat()
            patched = supabase_request("PATCH", "/rest/v1/workshop_erp_state", params={
                "id":"eq.1", "updated_at":f"eq.{current.get('updated_at')}"
            }, payload={"state":state,"updated_at":updated,"updated_by":str(user_id)},
               extra_headers={"Prefer":"return=representation"}) or []
            if patched:
                row = patched[0]
                write_security_event("workshop_record_deleted", actor_id=user_id, status_code=200,
                                     details={"collection":collection,"record_id":record_id})
                return jsonify(ok=True, collection=collection, id=record_id, state=row.get("state", state), updated_at=row.get("updated_at", updated), updated_by=row.get("updated_by", str(user_id)))
        return jsonify(error="Another admin is updating the data. Refresh and try deleting again."), 409
    except Exception as exc:
        log.exception("Could not delete Workshop ERP record")
        return jsonify(error=str(exc)[:300] or "Could not delete this record from shared storage."), 503


@app.get("/api/workshop/state")
def workshop_state_get():
    user_id, error = workshop_session_user()
    if error:
        return error
    if not supabase_enabled():
        return jsonify(error="Shared Workshop ERP storage is not configured. Set SUPABASE_URL and SUPABASE_SECRET_KEY in Render."), 503
    try:
        rows = supabase_request("GET", "/rest/v1/workshop_erp_state", params={
            "select": "id,state,updated_at,updated_by", "id": "eq.1", "limit": "1"
        }) or []
        row = rows[0] if rows else None
        return jsonify(state=(row.get("state") if row else None), updated_at=(row.get("updated_at") if row else None), updated_by=(row.get("updated_by") if row else None))
    except Exception as exc:
        log.exception("Could not load shared Workshop ERP state")
        return jsonify(error=f"Shared workshop database read failed: {str(exc)[:300]}"), 503


def _daily_report_pdf_bytes(data):
    """Build a multi-section PDF report from category sheets supplied by the ERP UI."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_LEFT
        from reportlab.lib.pagesizes import landscape, A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
    except ImportError as exc:
        raise RuntimeError("PDF export is not available on this deployment yet. Add reportlab to requirements.txt and redeploy.") from exc
    sheets = data.get("sheets")
    if not isinstance(sheets, list) or not sheets:
        raise ValueError("The PDF report has no category tables. Please generate it again.")
    # Use the bundled Ethiopic font for Amharic reports; English reports retain Helvetica.
    report_language = str(data.get("language") or "en").lower()
    pdf_font = "Helvetica"
    if report_language == "am":
        font_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "NotoSansEthiopic-Regular.ttf")
        if os.path.isfile(font_path):
            try:
                pdfmetrics.registerFont(TTFont("AmbarEthiopic", font_path))
                pdf_font = "AmbarEthiopic"
            except Exception:
                log.exception("Could not register the bundled Ethiopic PDF font; falling back to Helvetica")
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=landscape(A4), rightMargin=10*mm, leftMargin=10*mm, topMargin=12*mm, bottomMargin=12*mm, title="AMBAR Workshop Report")
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("ReportTitle", parent=styles["Title"], fontName=pdf_font, fontSize=17, leading=21, alignment=TA_LEFT, textColor=colors.HexColor("#183b35"), spaceAfter=5)
    section_style = ParagraphStyle("SectionTitle", parent=styles["Heading1"], fontName=pdf_font, fontSize=15, leading=19, textColor=colors.HexColor("#183b35"), spaceBefore=0, spaceAfter=9, borderColor=colors.HexColor("#20b7a3"), borderWidth=0, borderPadding=0)
    cell_style = ParagraphStyle("Cell", parent=styles["BodyText"], fontName=pdf_font, fontSize=7, leading=8.5, wordWrap="CJK")
    head_style = ParagraphStyle("Head", parent=cell_style, fontName=pdf_font, textColor=colors.white)
    story = []
    selected_date = str(data.get("selectedDate") or "Date not specified")
    prepared_by = str(data.get("preparedBy") or "Authorized Admin")
    recipient = str(data.get("recipientUsername") or "Not specified")
    note = str(data.get("note") or "—")
    period_start = str(data.get("periodStart") or "")
    period_end = str(data.get("periodEnd") or "")
    def _ethiopian_date(iso_value):
        try:
            from datetime import date
            current = date.fromisoformat(str(iso_value)[:10])
            def new_year(eth_year):
                gy = eth_year + 7
                return date(gy, 9, 12 if (gy + 1) % 4 == 0 else 11)
            year = current.year - 7
            start = new_year(year)
            if current < start:
                year -= 1
                start = new_year(year)
            offset = (current - start).days
            month, day = offset // 30 + 1, offset % 30 + 1
            return f"{day:02d}/{month:02d}/{year} ET"
        except Exception:
            return "Not available"
    def _calendar_pair(iso_value):
        try:
            from datetime import date
            d = date.fromisoformat(str(iso_value)[:10])
            return f"{d.strftime('%d %b %Y')} / {_ethiopian_date(iso_value)}"
        except Exception:
            return str(iso_value or "Not available")
    calendar_line = (f"Gregorian / Ethiopian: {_calendar_pair(period_start)}" if period_start and period_start == period_end else
                     f"Start (Gregorian / Ethiopian): {_calendar_pair(period_start)}  |  End (Gregorian / Ethiopian): {_calendar_pair(period_end)}" if period_start and period_end else
                     f"Gregorian / Ethiopian: {_calendar_pair(selected_date[:10])}" if len(selected_date) >= 10 else "")
    if report_language == "am":
        story.append(Paragraph("AMBAR FURNITURE — የወርክሾፕ ሪፖርት", title_style))
        meta_line = f"የሪፖርት ጊዜ፡ {selected_date} &nbsp;&nbsp; | &nbsp;&nbsp; ያዘጋጀው፡ {prepared_by} &nbsp;&nbsp; | &nbsp;&nbsp; ተቀባይ፡ {recipient}"
        note_label = "ማስታወሻ፡ "
    else:
        story.append(Paragraph("AMBAR FURNITURE — WORKSHOP REPORT", title_style))
        meta_line = f"Report Period: {selected_date} &nbsp;&nbsp; | &nbsp;&nbsp; Prepared By: {prepared_by} &nbsp;&nbsp; | &nbsp;&nbsp; Recipient: {recipient}"
        note_label = "Note: "
    story.append(Paragraph(meta_line, ParagraphStyle("ReportMeta", parent=styles["Normal"], fontName=pdf_font)))
    if calendar_line:
        story.append(Paragraph(calendar_line.replace("&", "&amp;"), ParagraphStyle("ReportCalendar", parent=styles["Normal"], fontName=pdf_font, fontSize=8, textColor=colors.HexColor("#52615d"), spaceBefore=3)))
    if note and note != "—":
        story.append(Paragraph(note_label + note.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"), ParagraphStyle("ReportNote", parent=styles["Normal"], fontName=pdf_font)))
    story.append(Spacer(1, 7*mm))
    for idx, sheet in enumerate(sheets):
        if not isinstance(sheet, dict):
            continue
        if idx > 0:
            story.append(PageBreak())
        name = str(sheet.get("name") or f"Category {idx+1}")[:100]
        rows = sheet.get("rows")
        if not isinstance(rows, list):
            rows = []
        story.append(Paragraph(name.replace("&", "&amp;"), section_style))
        page_width = landscape(A4)[0] - 20*mm
        # Category reports use named subsections so every table states what it contains.
        # In particular, the stock/sales report explicitly labels sold products and shows
        # both the count of recorded sales and their recorded value before the detail table.
        sheet_sections = sheet.get("sections")
        if isinstance(sheet_sections, list):
            subheading_style = ParagraphStyle("ReportSubheading", parent=styles["Heading2"], fontName=pdf_font, fontSize=10, leading=13, textColor=colors.HexColor("#244b43"), spaceBefore=4, spaceAfter=5)
            summary_style = ParagraphStyle("ReportSummary", parent=styles["BodyText"], fontName=pdf_font, fontSize=8, leading=11, textColor=colors.HexColor("#344640"), spaceAfter=2)
            for summary_item in sheet.get("summary", []) if isinstance(sheet.get("summary"), list) else []:
                if isinstance(summary_item, (list, tuple)) and len(summary_item) >= 2:
                    label = str(summary_item[0]).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                    value = str(summary_item[1]).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                    story.append(Paragraph(f"<b>{label}:</b> {value}", summary_style))
            if sheet.get("summary"):
                story.append(Spacer(1, 2*mm))
            subsection_labels = {
                "Production Stage Distribution": "PRODUCTION WORKFLOW ACTIVITY",
                "Sales & Payments": "SOLD PRODUCTS & SALES DETAILS",
                "Finished Goods Stock": "AVAILABLE FINISHED PRODUCT STOCK",
                "Restock Events": "RESTOCKED / RETURNED PRODUCTS",
                "Material Movements & Cut History": "MATERIAL RECEIPTS & USAGE",
                "Material Stock Health": "MATERIAL STOCK LEVEL & HEALTH",
            }
            for subsection in sheet_sections:
                if not isinstance(subsection, dict):
                    continue
                subname = str(subsection.get("name") or "Report details")
                label = subsection_labels.get(subname, subname.upper())
                if report_language == "am":
                    label = {"PRODUCTION WORKFLOW ACTIVITY":"የምርት ፍሰት እንቅስቃሴ", "SOLD PRODUCTS & SALES DETAILS":"የተሸጡ ምርቶች እና የሽያጭ ዝርዝር", "AVAILABLE FINISHED PRODUCT STOCK":"ያሉ ዝግጁ ምርቶች", "RESTOCKED / RETURNED PRODUCTS":"ወደ ክምችት የተመለሱ ምርቶች", "MATERIAL RECEIPTS & USAGE":"የቁሳቁስ ገቢ እና አጠቃቀም", "MATERIAL STOCK LEVEL & HEALTH":"የቁሳቁስ ክምችት መጠን እና ሁኔታ"}.get(label, label)
                story.append(Paragraph(label.replace("&", "&amp;"), subheading_style))
                subrows = subsection.get("rows") if isinstance(subsection.get("rows"), list) else []
                subrows = [row for row in subrows if isinstance(row, list) and row]
                if not subrows:
                    story.append(Paragraph("No records for the selected period." if report_language != "am" else "ለተመረጠው ጊዜ መዝገብ የለም።", summary_style))
                    continue
                max_cols = max(1, max(len(row) for row in subrows))
                headers = [str(v).lower() for v in subrows[0]]
                weights = [1.45 if any(k in (headers[i] if i < len(headers) else "") for k in ("notes", "action", "model", "customer", "material", "product", "recorded at", "event", "description", "phone", "salesperson")) else 1.0 for i in range(max_cols)]
                total = sum(weights) or max_cols
                col_widths = [page_width*w/total for w in weights]
                table_rows = []
                for ridx, row in enumerate(subrows):
                    style = head_style if ridx == 0 else cell_style
                    table_rows.append([Paragraph(str(cell if cell is not None else "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\n", "<br/>"), style) for cell in row] + [Paragraph("", style)] * (max_cols-len(row)))
                table = Table(table_rows, colWidths=col_widths, repeatRows=1, hAlign="LEFT")
                table.setStyle(TableStyle([
                    ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#244b43")),
                    ("GRID", (0,0), (-1,-1), 0.35, colors.HexColor("#cbd5d2")),
                    ("VALIGN", (0,0), (-1,-1), "TOP"),
                    ("LEFTPADDING", (0,0), (-1,-1), 4), ("RIGHTPADDING", (0,0), (-1,-1), 4),
                    ("TOPPADDING", (0,0), (-1,-1), 3), ("BOTTOMPADDING", (0,0), (-1,-1), 3),
                    ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#f2f6f5")]),
                ]))
                story.append(table)
                story.append(Spacer(1, 3*mm))
            story.append(Spacer(1, 5*mm))
            continue
        # The report header contains date/preparer/recipient once; skip repeated metadata
        # rows at the top of each category to keep the PDF compact and easy to scan.
        body_start = 4
        while body_start < len(rows) and isinstance(rows[body_start], list) and rows[body_start] and str(rows[body_start][0]).strip().lower() in {"snapshot recorded at"}:
            extra = rows[body_start]
            story.append(Paragraph(" &nbsp; | &nbsp; ".join(str(v if v is not None else "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;") for v in extra), styles["Normal"]))
            body_start += 1
        body_rows = [row for row in rows[body_start:] if isinstance(row, list)]
        groups, current = [], []
        for row in body_rows:
            if not row or all(str(v).strip() == "" for v in row):
                if current:
                    groups.append(current); current = []
            else:
                current.append(row)
        if current:
            groups.append(current)
        if not groups:
            groups = [[['No records for selected date']]]
        page_width = landscape(A4)[0] - 20*mm
        for group in groups:
            max_cols = max(1, max(len(row) for row in group))
            weights = []
            header = [str(v).lower() for v in group[0]]
            for i in range(max_cols):
                heading = header[i] if i < len(header) else ""
                weights.append(1.45 if any(k in heading for k in ("notes", "action", "model", "customer", "material", "product", "recorded at", "event", "description")) else 1.0)
            total = sum(weights) or max_cols
            col_widths = [page_width*w/total for w in weights]
            table_rows = []
            for ridx, row in enumerate(group):
                style = head_style if ridx == 0 else cell_style
                table_rows.append([Paragraph(str(cell if cell is not None else "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\n", "<br/>"), style) for cell in row] + [Paragraph("", style)] * (max_cols-len(row)))
            table = Table(table_rows, colWidths=col_widths, repeatRows=1, hAlign="LEFT")
            table.setStyle(TableStyle([
                ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#244b43")),
                ("GRID", (0,0), (-1,-1), 0.35, colors.HexColor("#cbd5d2")),
                ("VALIGN", (0,0), (-1,-1), "TOP"),
                ("LEFTPADDING", (0,0), (-1,-1), 4), ("RIGHTPADDING", (0,0), (-1,-1), 4),
                ("TOPPADDING", (0,0), (-1,-1), 3), ("BOTTOMPADDING", (0,0), (-1,-1), 3),
                ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#f2f6f5")]),
            ]))
            story.append(table)
            story.append(Spacer(1, 2*mm))
        story.append(Spacer(1, 5*mm))
    def footer(canvas, document):
        canvas.saveState()
        canvas.setFont(pdf_font, 7)
        canvas.setFillColor(colors.HexColor("#586763"))
        footer_dates = (f"{period_start} – {period_end}" if period_start and period_end else selected_date)
        try:
            if period_start and period_end:
                footer_dates = f"G {period_start}–{period_end} | E {_ethiopian_date(period_start)}–{_ethiopian_date(period_end)}"
            elif len(str(selected_date)) >= 10:
                footer_dates = f"G {str(selected_date)[:10]} | E {_ethiopian_date(str(selected_date)[:10])}"
        except Exception:
            pass
        footer_label = (f"AMBAR ERP · {footer_dates} · ያዘጋጀው {prepared_by}" if report_language == "am" else f"AMBAR ERP · {footer_dates} · Prepared by {prepared_by}")
        canvas.drawString(10*mm, 6*mm, footer_label)
        canvas.drawRightString(landscape(A4)[0]-10*mm, 6*mm, f"Page {document.page}")
        canvas.restoreState()
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()


def _verify_daily_report_permission(user_id):
    is_owner = is_main_admin_user(user_id)
    if is_owner:
        return True
    rows = supabase_request("GET", "/rest/v1/workshop_erp_state", params={"select":"state", "id":"eq.1", "limit":"1"}) or []
    state = rows[0].get("state", {}) if rows else {}
    assignments = state.get("workshopAssignments", []) if isinstance(state, dict) else []
    assignment = next((x for x in assignments if isinstance(x, dict) and str(x.get("telegram_user_id")) == str(user_id)), {}) if isinstance(assignments, list) else {}
    permissions = assignment.get("permissions", []) if isinstance(assignment.get("permissions", []), list) else []
    return "*" in permissions or "reports" in permissions


@app.post("/api/workshop/reports/pdf")
def workshop_daily_report_pdf():
    user_id, error = workshop_session_user()
    if error:
        return error
    if not supabase_enabled():
        return jsonify(error="Shared Workshop ERP storage is not configured."), 503
    try:
        if not _verify_daily_report_permission(user_id):
            return jsonify(error="Reports & Analytics permission is required to export daily reports."), 403
    except Exception:
        log.exception("Could not verify Workshop ERP PDF report permission")
        return jsonify(error="Could not verify report permissions. Please retry."), 503
    data = request.get_json(silent=True) or {}
    try:
        pdf_bytes = _daily_report_pdf_bytes(data)
    except ValueError as exc:
        return jsonify(error=str(exc)), 400
    except Exception as exc:
        log.exception("Could not build Workshop ERP daily PDF")
        return jsonify(error=str(exc)[:300] or "Could not generate the PDF report."), 500
    if not isinstance(pdf_bytes, (bytes, bytearray)) or not bytes(pdf_bytes).startswith(b"%PDF-") or len(pdf_bytes) < 500:
        return jsonify(error="The report generator did not produce a valid PDF. Please refresh the report and retry."), 500
    if len(pdf_bytes) > 7 * 1024 * 1024:
        return jsonify(error="The PDF report is too large to download. Reduce the selected date's report size and retry."), 413
    filename = secure_filename(f"ambar-daily-report-{data.get('selectedDate','date')}-{data.get('preparedBy','admin')}.pdf") or "ambar-daily-report.pdf"
    if not filename.lower().endswith(".pdf"):
        filename += ".pdf"
    return send_file(BytesIO(pdf_bytes), mimetype="application/pdf", as_attachment=True, download_name=filename)


@app.post("/api/workshop/reports/send")
def workshop_daily_report_send():
    """Send a clean PDF daily report through the AMBAR Telegram bot."""
    user_id, error = workshop_session_user()
    if error:
        return error
    if not BOT_TOKEN:
        return jsonify(error="Telegram sending is not configured: BOT_TOKEN is missing on the server."), 503
    if not supabase_enabled():
        return jsonify(error="Shared Workshop ERP storage is not configured."), 503
    data = request.get_json(silent=True) or {}
    report_format = str(data.get("format") or "pdf").lower()
    if report_format != "pdf":
        return jsonify(error="Only PDF daily reports are supported. Please export the PDF report."), 400
    filename = secure_filename(str(data.get("filename") or "ambar-daily-report.pdf"))
    if not filename.lower().endswith(".pdf"):
        filename = "ambar-daily-report.pdf"
    try:
        uploaded_bytes = _daily_report_pdf_bytes(data)
    except ValueError as exc:
        return jsonify(error=str(exc)), 400
    except Exception as exc:
        log.exception("Could not build PDF for Telegram send")
        return jsonify(error=str(exc)[:300] or "Could not generate the PDF report."), 500
    if not isinstance(uploaded_bytes, (bytes, bytearray)) or not bytes(uploaded_bytes).startswith(b"%PDF-") or len(uploaded_bytes) < 500:
        return jsonify(error="The report generator did not produce a valid PDF. Please refresh the report and retry."), 500
    upload_mime = "application/pdf"
    if len(uploaded_bytes) > 7 * 1024 * 1024:
        return jsonify(error="The daily report is too large to send. Reduce the selected date's report size and retry."), 413
    # Enforce Reports & Analytics permission server-side for staff accounts.
    try:
        if not _verify_daily_report_permission(user_id):
            return jsonify(error="Reports & Analytics permission is required to send daily reports."), 403
    except Exception:
        log.exception("Could not verify Workshop ERP report permission")
        return jsonify(error="Could not verify report permissions. Please retry."), 503
    recipient_id = str(data.get("recipientTelegramId") or "").strip()
    if recipient_id and not re.fullmatch(r"\d{4,20}", recipient_id):
        return jsonify(error="Recipient Telegram ID must contain only digits."), 400
    # A blank recipient means send to the currently signed-in admin, whose ID comes from signed initData.
    target_chat_id = recipient_id or str(user_id)
    try:
        selected_date = clean_text(data.get("selectedDate", ""), 80, "Selected date", False)
        prepared_by = clean_text(data.get("preparedBy", ""), 100, "Prepared by", False)
        recipient_username = clean_text(data.get("recipientUsername", ""), 100, "Recipient username", False)
        note = clean_text(data.get("note", ""), 500, "Report note", False)
    except ValueError as exc:
        return jsonify(ok=False, error=str(exc)), 400
    period_start = str(data.get("periodStart") or "").strip()
    period_end = str(data.get("periodEnd") or "").strip()
    caption_parts = [f"AMBAR Workshop Report — {selected_date or 'Date not specified'}", f"Prepared by: {prepared_by or ('Telegram user ' + str(user_id))}"]
    if period_start and period_end:
        caption_parts.append(f"Gregorian dates: {period_start} to {period_end}")
    if recipient_username:
        caption_parts.append(f"Recipient username (label): {recipient_username if recipient_username.startswith('@') else '@' + recipient_username}")
    if note:
        caption_parts.append(f"Note: {note}")
    caption = "\n".join(caption_parts)[:1024]
    def send_to(chat_id):
        uploaded = BytesIO(uploaded_bytes)
        uploaded.name = filename
        # PDF upload can take longer on Render or slower connections; avoid timing out
        # before Telegram has finished receiving the document.
        return bot_api("sendDocument", {"chat_id": chat_id, "caption": caption},
                       {"document": (filename, uploaded, upload_mime)}, timeout=60)

    try:
        result = send_to(target_chat_id)
        sent_target = target_chat_id
        sent_label = ("your Telegram account" if target_chat_id == str(user_id) else
                      ("@" + recipient_username.lstrip("@") if recipient_username else "Telegram ID " + target_chat_id))
    except Exception as exc:
        log.exception("Could not send Workshop ERP daily report to requested Telegram recipient")
        reason = str(exc)
        # If the user chose the default personal destination, fall back to the configured AMBAR
        # service channel when the bot cannot message that user. Never redirect an explicitly
        # selected recipient's report to a different chat.
        personal_chat_error = any(term in reason.lower() for term in ("chat not found", "bot was blocked", "user is deactivated", "can't initiate conversation"))
        if not recipient_id and SERVICE_CHAT_ID and str(SERVICE_CHAT_ID) != str(target_chat_id) and personal_chat_error:
            try:
                result = send_to(SERVICE_CHAT_ID)
                sent_target = str(SERVICE_CHAT_ID)
                sent_label = "AMBAR report channel (personal chat unavailable)"
            except Exception as fallback_exc:
                log.exception("Could not send Workshop ERP daily report to the AMBAR service channel fallback")
                return jsonify(error=("Could not send to your Telegram account or the AMBAR report channel. " + str(fallback_exc)[:220] + ". Open/start the AMBAR bot and retry, or ask the main admin to check SERVICE_CHAT_ID and BOT_TOKEN.")), 502
        else:
            message = reason[:300] or "Telegram could not send the PDF report."
            if personal_chat_error:
                message += " Open/start the AMBAR bot first, or configure SERVICE_CHAT_ID for channel fallback."
            return jsonify(error=message), 502

    write_security_event("workshop_daily_report_sent", actor_id=str(user_id), status_code=200,
                         details={"selected_date": selected_date, "recipient_chat_id": sent_target, "filename": filename, "format": report_format})
    return jsonify(ok=True, messageId=(result.get("message_id") if isinstance(result, dict) else None), sentToLabel=sent_label)


@app.post("/api/workshop/state/reset")
def workshop_state_reset():
    """Permanently clear operational Workshop ERP records; main admin only."""
    user_id, error = workshop_session_user()
    if error:
        return error
    observer_denied = deny_workshop_observer_write(user_id)
    if observer_denied:
        return observer_denied
    owner_id = str(ADMIN_PASSWORD_MANAGER_TELEGRAM_ID or "")
    if not is_main_admin_user(user_id):
        write_security_event("workshop_state_reset_denied", actor_id=str(user_id), path=request.path, method="POST", status_code=403)
        return jsonify(error="Only the main AMBAR admin can reset all Workshop ERP data."), 403
    body = request.get_json(silent=True) or {}
    if body.get("confirm") != "RESET":
        return jsonify(error="Reset confirmation is required."), 400
    if not supabase_enabled():
        return jsonify(error="Shared Workshop ERP storage is not configured."), 503
    try:
        rows = supabase_request("GET", "/rest/v1/workshop_erp_state", params={
            "select": "state,updated_at", "id": "eq.1", "limit": "1"
        }) or []
        current = rows[0] if rows else {}
        old_state = current.get("state") if isinstance(current.get("state"), dict) else {}
        reset_state = {
            "orders": [], "products": [], "materials": [], "materialTransactions": [],
            "sales": [], "dailyStockSnapshots": [], "restockHistory": [],
            "activityLog": [], "activityEvents": [],
            # Preserve account permissions so the owner does not lock out the team.
            "workshopAssignments": old_state.get("workshopAssignments", []) if isinstance(old_state.get("workshopAssignments", []), list) else [],
            "nextId": 10
        }
        now = dt.datetime.now(dt.timezone.utc).isoformat()
        if current.get("updated_at"):
            updated = supabase_request("PATCH", "/rest/v1/workshop_erp_state", params={
                "id": "eq.1", "updated_at": f"eq.{current['updated_at']}"
            }, payload={"state": reset_state, "updated_at": now, "updated_by": str(user_id)},
                extra_headers={"Prefer": "return=representation"}) or []
            if not updated:
                return jsonify(error="Workshop data changed during reset. Refresh and confirm the reset again."), 409
            row = updated[0]
        else:
            payload = {"id": 1, "state": reset_state, "updated_at": now, "updated_by": str(user_id)}
            updated = supabase_request("POST", "/rest/v1/workshop_erp_state", params={"on_conflict": "id"}, payload=payload,
                extra_headers={"Prefer": "resolution=merge-duplicates,return=representation"}) or []
            row = updated[0] if updated else payload
        # Remove only finance rows that were auto-generated from Workshop ERP sales.
        # Manual finance ledger entries are intentionally preserved. With the sales
        # array now empty, dashboard refresh cannot recreate the removed entries.
        finance_cleanup_warning = None
        try:
            supabase_request("DELETE", "/rest/v1/ambar_finance_entries",
                params={"source_ref": "like.workshop-sale:*"},
                extra_headers={"Prefer": "return=minimal"})
        except Exception as cleanup_exc:
            finance_cleanup_warning = "Workshop ERP data was reset, but ERP-linked finance entries could not be cleared. Check the finance table and retry cleanup."
            log.exception("Workshop ERP reset completed but linked finance cleanup failed: %s", cleanup_exc)
        write_security_event("workshop_state_reset", actor_id=str(user_id), path=request.path, method="POST", status_code=200,
                             details={"preserved_assignments": len(reset_state["workshopAssignments"]), "finance_cleanup_warning": bool(finance_cleanup_warning)})
        response = {"ok": True, "state": reset_state, "updated_at": row.get("updated_at", now), "updated_by": row.get("updated_by", str(user_id))}
        if finance_cleanup_warning:
            response["warning"] = finance_cleanup_warning
        return jsonify(response)
    except Exception:
        log.exception("Could not reset shared Workshop ERP data")
        return jsonify(error="Could not reset shared Workshop ERP data. Check the Supabase connection and retry."), 503


@app.post("/api/workshop/state")
def workshop_state_save():
    user_id, error = workshop_session_user()
    if error:
        return error
    observer_denied = deny_workshop_observer_write(user_id)
    if observer_denied:
        return observer_denied
    if not supabase_enabled():
        return jsonify(error="Shared Workshop ERP storage is not configured. Set SUPABASE_URL and SUPABASE_SECRET_KEY in Render."), 503
    body = request.get_json(silent=True) or {}
    state = body.get("state")
    if not isinstance(state, dict) or not all(isinstance(state.get(k), list) for k in ("orders", "products", "materials")):
        return jsonify(error="Invalid workshop data format."), 400
    if len(request.get_data(cache=True) or b"") > 2 * 1024 * 1024:
        return jsonify(error="Workshop data is too large to save."), 413
    now = dt.datetime.now(dt.timezone.utc).isoformat()
    expected = body.get("expected_updated_at")
    # Enforce each assigned task on the server, not only by hiding buttons in the browser.
    try:
        current_rows = supabase_request("GET", "/rest/v1/workshop_erp_state", params={"select":"state,updated_at","id":"eq.1","limit":"1"}) or []
        current_state = (current_rows[0] or {}).get("state") if current_rows else None
        if isinstance(current_state, dict):
            owner_id = str(ADMIN_PASSWORD_MANAGER_TELEGRAM_ID or "")
            is_owner = is_main_admin_user(user_id)
            if not is_owner:
                def identity_key_for(collection):
                    return {"orders":"serial","products":"id","materials":"id","materialTransactions":"id","sales":"id"}.get(collection, "id")
                def item_id(item, collection):
                    if not isinstance(item, dict): return None
                    val = item.get(identity_key_for(collection))
                    if val is None and collection == "orders": val = item.get("productId")
                    return None if val is None else str(val)
                if state.get("workshopAssignments", []) != current_state.get("workshopAssignments", []):
                    return jsonify(error="Only a main AMBAR admin can change Workshop ERP task assignments."), 403
                assignment = next((x for x in (current_state.get("workshopAssignments", []) if isinstance(current_state.get("workshopAssignments", []), list) else []) if isinstance(x, dict) and str(x.get("telegram_user_id")) == str(user_id)), {})
                permissions = set(assignment.get("permissions", []) if isinstance(assignment.get("permissions", []), list) else [])
                if "*" not in permissions:
                    before_tx = current_state.get("materialTransactions", []) if isinstance(current_state.get("materialTransactions", []), list) else []
                    after_tx = state.get("materialTransactions", []) if isinstance(state.get("materialTransactions", []), list) else []
                    before_tx_ids = {item_id(x, "materialTransactions") for x in before_tx}
                    added_tx = [x for x in after_tx if item_id(x, "materialTransactions") not in before_tx_ids]
                    new_workshop_stages = set()
                    before_orders = current_state.get("orders", []) if isinstance(current_state.get("orders", []), list) else []
                    after_orders = state.get("orders", []) if isinstance(state.get("orders", []), list) else []
                    old_orders = {item_id(x, "orders"): x for x in before_orders}
                    for order in after_orders:
                        old = old_orders.get(item_id(order, "orders"))
                        if old and old != order and (old.get("stage") != order.get("stage") or old.get("stageHistory") != order.get("stageHistory")):
                            new_workshop_stages.add(str(order.get("serial") or order.get("productId") or ""))
                    def require(permission, message):
                        if permission not in permissions:
                            raise PermissionError(message)
                    def check_collection(collection, added_permission, edit_permission=None, special=None):
                        before = current_state.get(collection, []) if isinstance(current_state.get(collection, []), list) else []
                        after = state.get(collection, []) if isinstance(state.get(collection, []), list) else []
                        old_map = {item_id(x, collection): x for x in before if item_id(x, collection) is not None}
                        new_map = {item_id(x, collection): x for x in after if item_id(x, collection) is not None}
                        if set(old_map)-set(new_map):
                            raise PermissionError("Use the authorized Delete button; record deletions are separately permission-checked.")
                        for key, item in new_map.items():
                            old = old_map.get(key)
                            if old is None:
                                allowed = special(item, None) if special else False
                                if not allowed: require(added_permission, f"Missing permission: {added_permission}.")
                            elif old != item:
                                allowed = special(item, old) if special else False
                                if not allowed: require(edit_permission or added_permission, f"Missing permission: {edit_permission or added_permission}.")
                    # Work orders: creation, ordinary edit, and stage advance are separate tasks.
                    assigned_stage_permissions = {x.split(":", 1)[1] for x in permissions if isinstance(x, str) and x.startswith("workshop_stage:")}
                    def order_special(new, old):
                        if not old or not (old.get("stage") != new.get("stage") or old.get("stageHistory") != new.get("stageHistory")):
                            return False
                        return "workshop_advance" in permissions and old.get("stage") in assigned_stage_permissions
                    check_collection("orders", "workshop_add", "workshop_edit", order_special)
                    # Finished units can also be auto-created when an assigned work order reaches In Stock.
                    before_sales = current_state.get("sales", []) if isinstance(current_state.get("sales", []), list) else []
                    after_sales = state.get("sales", []) if isinstance(state.get("sales", []), list) else []
                    before_sales_ids = {item_id(x, "sales") for x in before_sales}
                    added_sales = [x for x in after_sales if item_id(x, "sales") not in before_sales_ids]
                    before_restock_history = current_state.get("restockHistory", []) if isinstance(current_state.get("restockHistory", []), list) else []
                    after_restock_history = state.get("restockHistory", []) if isinstance(state.get("restockHistory", []), list) else []
                    before_restock_ids = {str(x.get("restockId") or x.get("restock_id") or "") for x in before_restock_history if isinstance(x, dict)}
                    added_restock_events = [x for x in after_restock_history if isinstance(x, dict) and str(x.get("restockId") or x.get("restock_id") or "") not in before_restock_ids]
                    sale_fields = ("status","customer","phone","rep","soldAt","soldAtISO","paymentStatus","saleNotes","paymentFullyPaidAt","paymentNote","price")
                    def product_special(new, old):
                        if old is None:
                            return str(new.get("workOrder") or "") in new_workshop_stages and "workshop_advance" in permissions
                        old_status = str(old.get("status") or "").upper()
                        new_status = str(new.get("status") or "").upper()
                        if old_status != new_status:
                            if old_status != "SOLD" and new_status == "SOLD":
                                linked_sale = any(
                                    str(x.get("productRecordId") or x.get("id")) == str(new.get("id"))
                                    or (str(new.get("productId") or new.get("serial") or "") and str(x.get("productId") or x.get("serial") or "") == str(new.get("productId") or new.get("serial") or ""))
                                    for x in added_sales
                                )
                                if "sales_add" not in permissions or not linked_sale:
                                    raise PermissionError("A unit can only be marked SOLD by the Record sale action with a matching Sales Archive entry.")
                                return True
                            if old_status == "SOLD" and new_status == "AVAILABLE":
                                product_key = str(new.get("productId") or new.get("serial") or "")
                                event_key = str(new.get("restockEventId") or "")
                                valid_restock = any(
                                    str(x.get("productId") or x.get("product_id") or "") == product_key
                                    and (not event_key or str(x.get("restockId") or x.get("restock_id") or "") == event_key)
                                    for x in added_restock_events
                                )
                                if "inventory_edit" not in permissions or not valid_restock:
                                    raise PermissionError("A sold unit can only return to AVAILABLE through the Restock action with a matching restock history record.")
                                return True
                            raise PermissionError("Use Record sale or Restock to change a finished unit's status.")
                        if not any(old.get(k) != new.get(k) for k in sale_fields):
                            return False
                        if old_status == "SOLD" and new_status == "SOLD":
                            return "sales_edit" in permissions or ("sales_add" in permissions and any(str(x.get("productRecordId") or x.get("id")) == str(new.get("id")) for x in added_sales))
                        return False
                    check_collection("products", "inventory_add", "inventory_edit", product_special)
                    # Material receipts/cuts authorize the associated stock changes; descriptive edits remain separate.
                    check_collection("materials", "materials_add", "materials_edit", lambda new, old: bool(old and all(old.get(k) == new.get(k) for k in ("name","unit","threshold","supplier","notes")) and (old.get("stock") != new.get("stock") or old.get("cost") != new.get("cost")) and added_tx and all(("materials_receive" if x.get("type") == "receipt" else "materials_cut") in permissions for x in added_tx)))
                    # New movements require the matching Receive Stock or Cut / Use Material permission.
                    check_collection("materialTransactions", "materials_receive", "materials_edit", lambda new, old: bool(old is None and ((new.get("type") == "receipt" and "materials_receive" in permissions) or (new.get("type") != "receipt" and "materials_cut" in permissions))))
                    check_collection("sales", "sales_add", "sales_edit")
                    changed_names = [name for name in ("orders","products","materials","materialTransactions","sales") if state.get(name, []) != current_state.get(name, [])]
                    if not changed_names and state.get("activityLog", []) != current_state.get("activityLog", []) and not permissions.intersection({"workshop_add","workshop_edit","workshop_advance","inventory_add","inventory_edit","materials_add","materials_receive","materials_cut","materials_edit","sales_add","sales_edit"}):
                        return jsonify(error="You do not have permission to update this activity."), 403
    except PermissionError as exc:
        return jsonify(error=str(exc)), 403
    except Exception:
        log.exception("Could not verify Workshop ERP permissions")
        return jsonify(error="Could not verify Workshop ERP permissions. Please retry."), 503
    payload = {"id": 1, "state": state, "updated_at": now, "updated_by": str(user_id)}
    try:
        if expected:
            rows = supabase_request("PATCH", "/rest/v1/workshop_erp_state", params={
                "id": "eq.1", "updated_at": f"eq.{expected}"
            }, payload={"state": state, "updated_at": now, "updated_by": str(user_id)},
                extra_headers={"Prefer": "return=representation"}) or []
            if not rows:
                latest = supabase_request("GET", "/rest/v1/workshop_erp_state", params={
                    "select": "state,updated_at,updated_by", "id": "eq.1", "limit": "1"
                }) or []
                row = latest[0] if latest else {}
                return jsonify(error="Another admin updated the workshop data first. The latest shared data has been loaded; please reapply your change.", state=row.get("state"), updated_at=row.get("updated_at"), updated_by=row.get("updated_by")), 409
            row = rows[0]
        else:
            rows = supabase_request("POST", "/rest/v1/workshop_erp_state", params={"on_conflict": "id"}, payload=payload,
                extra_headers={"Prefer": "resolution=merge-duplicates,return=representation"}) or []
            row = rows[0] if rows else payload
        finance_sync = {"synced": 0, "receivables": 0}
        try:
            finance_sync = sync_workshop_sales_into_finance(state, user_id)
        except Exception:
            # Keep the workshop save successful; report the sync failure to logs so it can be retried on Finance refresh.
            log.exception("Workshop ERP saved but automatic Finance sale sync failed")
        write_security_event("workshop_state_saved", actor_id=user_id, path=request.path, method="POST", status_code=200,
                             details={"finance_synced": finance_sync.get("synced", 0), "finance_receivables": finance_sync.get("receivables", 0)})
        return jsonify(ok=True, updated_at=row.get("updated_at", now), updated_by=row.get("updated_by", str(user_id)), finance_sync=finance_sync)
    except Exception:
        log.exception("Could not save shared Workshop ERP state")
        return jsonify(error="Could not save shared workshop data. Check the Supabase migration and connection."), 503


def get_gps_delivery_settings():
    """Return the single GPS pricing configuration, or None when not configured."""
    if not supabase_enabled():
        return None
    rows = supabase_request("GET", "/rest/v1/delivery_settings", params={"select":"id,origin_lat,origin_lon,price_per_km,active", "id":"eq.1", "limit":"1"}) or []
    return rows[0] if rows else None


def haversine_km(lat1, lon1, lat2, lon2):
    from math import radians, sin, cos, asin, sqrt
    values = [float(lat1), float(lon1), float(lat2), float(lon2)]
    if not (-90 <= values[0] <= 90 and -180 <= values[1] <= 180 and -90 <= values[2] <= 90 and -180 <= values[3] <= 180):
        raise ValueError("GPS coordinates are outside valid ranges.")
    dlat = radians(values[2] - values[0]); dlon = radians(values[3] - values[1])
    a = sin(dlat / 2) ** 2 + cos(radians(values[0])) * cos(radians(values[2])) * sin(dlon / 2) ** 2
    return 6371.0088 * 2 * asin(sqrt(min(1, a)))


@app.get("/api/admin/phase2/delivery-settings")
def phase2_get_delivery_settings():
    _, error = admin_user_from_request()
    if error: return error
    try:
        return jsonify(settings=get_gps_delivery_settings() or {"id":1,"origin_lat":None,"origin_lon":None,"price_per_km":0,"base_fee_etb":0,"active":False})
    except Exception:
        log.exception("Could not load GPS delivery settings")
        return jsonify(error="Could not load GPS delivery settings. Run the updated Phase 2 SQL migration."), 503


@app.post("/api/admin/phase2/delivery-settings")
def phase2_save_delivery_settings():
    _, error = admin_user_from_request()
    if error: return error
    if not supabase_enabled(): return jsonify(error="Supabase is not configured."), 503
    data = request.get_json(silent=True) or {}
    try:
        lat, lon, rate = float(data.get("origin_lat")), float(data.get("origin_lon")), float(data.get("price_per_km"))
        base_fee = 0.0  # Legacy UI/database field retained for compatibility; no fixed fee is charged.
        if not (-90 <= lat <= 90 and -180 <= lon <= 180) or rate < 0 or base_fee < 0: raise ValueError()
    except (TypeError, ValueError):
        return jsonify(error="Enter valid shop GPS coordinates and a non-negative price per kilometer."), 400
    payload = {"id":1,"origin_lat":lat,"origin_lon":lon,"price_per_km":rate,"base_fee_etb":0,"active":bool(data.get("active", True)),"updated_at":dt.datetime.now(dt.timezone.utc).isoformat()}
    try:
        existing = supabase_request("GET", "/rest/v1/delivery_settings", params={"select":"id","id":"eq.1","limit":"1"}) or []
        rows = supabase_request("PATCH", "/rest/v1/delivery_settings", params={"id":"eq.1"}, payload=payload) if existing else supabase_request("POST", "/rest/v1/delivery_settings", payload=payload)
        return jsonify(ok=True, settings=(rows[0] if rows else payload))
    except Exception:
        log.exception("Could not save GPS delivery settings")
        return jsonify(error="Could not save GPS delivery settings. Run the updated Phase 2 SQL migration."), 503


@app.get("/api/delivery-areas")
def public_delivery_areas():
    """Return active delivery areas and their configured fee; never invent a fee."""
    if not supabase_enabled():
        return jsonify(areas=[], configured=False)
    try:
        rows = supabase_request("GET", "/rest/v1/delivery_areas", params={"select":"id,area_name,fee_etb,estimated_days", "active":"eq.true", "order":"area_name.asc"}) or []
        gps = get_gps_delivery_settings()
        return jsonify(areas=rows, configured=True, gps_settings=({"active":bool(gps.get("active")),"origin_lat":gps.get("origin_lat"),"origin_lon":gps.get("origin_lon"),"base_fee_etb":0,"price_per_km":float(gps.get("price_per_km",10) or 0)} if gps else {"active":False,"origin_lat":None,"origin_lon":None,"base_fee_etb":50,"price_per_km":10}))
    except Exception:
        log.exception("Could not load delivery areas")
        return jsonify(error="Delivery fees are temporarily unavailable."), 503


@app.route("/api/my-app-state", methods=["GET", "PUT"])
def my_app_state():
    """Synchronize a customer's cart and favorites across devices using signed Telegram identity."""
    init_data = request.headers.get("X-Telegram-Init-Data", "")
    valid, user_id = validate_telegram_init_data(init_data)
    if not valid or not user_id:
        return jsonify(error="Open AMBAR from your Telegram bot to sync your account across devices."), 401
    if not supabase_enabled():
        return jsonify(error="Cross-device sync is not configured. Run the supplied SQL migration."), 503
    try:
        if request.method == "GET":
            rows = supabase_request("GET", "/rest/v1/customer_app_state", params={
                "select": "telegram_user_id,cart,favorites,updated_at",
                "telegram_user_id": f"eq.{user_id}", "limit": "1"
            }) or []
            if not rows:
                return jsonify(exists=False, cart={}, favorites=[])
            row = rows[0]
            return jsonify(exists=True, cart=row.get("cart") if isinstance(row.get("cart"), dict) else {},
                           favorites=row.get("favorites") if isinstance(row.get("favorites"), list) else [],
                           updated_at=row.get("updated_at"))
        data = request.get_json(silent=True) or {}
        cart_in = data.get("cart", {})
        favorites_in = data.get("favorites", [])
        if not isinstance(cart_in, dict) or len(cart_in) > 200:
            return jsonify(error="Cart data is invalid."), 400
        if not isinstance(favorites_in, list) or len(favorites_in) > 500:
            return jsonify(error="Favorites data is invalid."), 400
        cart = {}
        for product_id, quantity in cart_in.items():
            pid = clean_text(product_id, 100, "Product ID", True)
            if isinstance(quantity, bool) or not isinstance(quantity, int) or quantity < 1 or quantity > 99:
                return jsonify(error="Cart quantity is invalid."), 400
            cart[pid] = quantity
        favorites = list(dict.fromkeys(clean_text(pid, 100, "Favorite product ID", True) for pid in favorites_in))
        now = dt.datetime.now(dt.timezone.utc).isoformat()
        supabase_request("POST", "/rest/v1/customer_app_state", params={"on_conflict": "telegram_user_id"},
                         payload={"telegram_user_id": str(user_id), "cart": cart, "favorites": favorites, "updated_at": now},
                         extra_headers={"Prefer": "resolution=merge-duplicates,return=representation"})
        return jsonify(ok=True, cart=cart, favorites=favorites, updated_at=now)
    except Exception:
        log.exception("Could not synchronize customer app state")
        return jsonify(error="Could not synchronize cart and favorites. Check the supplied Supabase SQL migration."), 503


@app.post("/api/my-orders/<reference>/confirm-delivered")
def confirm_delivered_order(reference):
    """Let the authenticated customer confirm actual receipt even if staff have not yet marked Delivered."""
    init_data = request.headers.get("X-Telegram-Init-Data", "")
    valid, user_id = validate_telegram_init_data(init_data)
    if not valid or not user_id:
        return jsonify(error="Open AMBAR from your Telegram bot to confirm delivery."), 401
    if not supabase_enabled():
        return jsonify(error="Order tracking is not configured yet."), 503
    try:
        reference = clean_text(reference, 40, "Order reference", True)
        rows = supabase_request("GET", "/rest/v1/customer_orders", params={
            "select": "reference,status,customer_confirmed_at,telegram_user_id",
            "reference": f"eq.{reference}", "telegram_user_id": f"eq.{user_id}", "limit": "1"
        }) or []
        if not rows:
            return jsonify(error="Order not found in your Telegram account."), 404
        order = rows[0]
        current_status = str(order.get("status") or "Pending")
        if current_status == "Cancelled":
            return jsonify(error="Cancelled orders cannot be confirmed as delivered."), 409
        if order.get("customer_confirmed_at") and current_status == "Delivered":
            return jsonify(ok=True, already_confirmed=True, customer_confirmed_at=order["customer_confirmed_at"])
        now = dt.datetime.now(dt.timezone.utc).isoformat()
        updated = supabase_request("PATCH", "/rest/v1/customer_orders", params={
            "reference": f"eq.{reference}", "telegram_user_id": f"eq.{user_id}", "status": f"eq.{current_status}"
        }, payload={"status": "Delivered", "customer_confirmed_at": now, "updated_at": now}) or []
        if not updated:
            return jsonify(error="Could not save receipt confirmation. Refresh and try again."), 409
        try:
            send_service_message(f"✅ Customer confirmed delivery\nOrder: {reference}\nTelegram ID: {user_id}\nConfirmed at: {now}")
        except Exception:
            log.exception("Could not notify staff of delivery confirmation %s", reference)
        return jsonify(ok=True, customer_confirmed_at=now)
    except Exception:
        log.exception("Could not confirm delivery")
        return jsonify(error="Could not save delivery confirmation. Run the supplied SQL migration."), 503


@app.get("/api/my-orders")
def my_orders():
    init_data = request.headers.get("X-Telegram-Init-Data", "")
    # Order ownership must always come from Telegram's signed initData, even if
    # REQUIRE_TELEGRAM_AUTH is disabled for local development elsewhere in the app.
    valid, user_id = validate_telegram_init_data(init_data)
    if not valid or not user_id:
        return jsonify(error="Open AMBAR from its Telegram bot to view your orders. If you are already in Telegram, close and reopen the Mini App."), 401
    if not supabase_enabled():
        return jsonify(orders=[], configured=False)
    try:
        rows = supabase_request("GET", "/rest/v1/customer_orders", params={"select":"*", "telegram_user_id":f"eq.{user_id}", "order":"created_at.desc", "limit":"100"}) or []
        return jsonify(orders=rows, configured=True)
    except Exception:
        log.exception("Could not load customer orders")
        return jsonify(error="Order tracking is temporarily unavailable."), 503


@app.post("/api/my-orders/<reference>/cancel")
def cancel_my_order(reference):
    """Allow a customer to cancel only their own order before preparation starts."""
    init_data = request.headers.get("X-Telegram-Init-Data", "")
    valid, user_id = validate_telegram_init_data(init_data)
    if not valid or not user_id:
        return jsonify(error="Open AMBAR from your Telegram bot to manage your orders."), 401
    if not supabase_enabled():
        return jsonify(error="Order tracking is not configured yet."), 503
    reference = clean_text(reference, 40, "Order reference", True)
    try:
        rows = supabase_request("GET", "/rest/v1/customer_orders", params={"select":"*", "reference":f"eq.{reference}", "telegram_user_id":f"eq.{user_id}", "limit":"1"}) or []
        if not rows:
            return jsonify(error="Order not found in your account."), 404
        order = rows[0]
        if order.get("status") not in ("Pending", "Received", "Confirmed"):
            return jsonify(error="This order can no longer be cancelled in the app. Please contact AMBAR customer service."), 409
        # Calculate the 5% cancellation fee on the server from the saved order total.
        # The customer cannot submit or override the fee amount.
        try:
            order_total = max(0.0, float(order.get("total_etb") or order.get("product_total_etb") or 0))
        except (TypeError, ValueError):
            order_total = 0.0
        cancellation_fee = round(order_total * 0.05, 2)
        refund_after_fee = round(max(0.0, order_total - cancellation_fee), 2)
        updated = supabase_request("PATCH", "/rest/v1/customer_orders", params={"reference":f"eq.{reference}", "telegram_user_id":f"eq.{user_id}", "status":"in.(Pending,Received,Confirmed)"}, payload={"status":"Cancelled", "cancellation_fee_etb":cancellation_fee, "cancellation_refund_etb":refund_after_fee, "cancellation_fee_status":"Pending manual payment", "updated_at":dt.datetime.now(dt.timezone.utc).isoformat()}) or []
        if not updated:
            return jsonify(error="The order status has changed. Refresh My Orders and try again."), 409
        message = (f"❌ Customer cancelled order {reference}\nCustomer Telegram ID: {user_id}\n"
                   f"Order total: {order_total:,.2f} ETB\nCancellation fee (5%): {cancellation_fee:,.2f} ETB\n"
                   f"Amount after fee: {refund_after_fee:,.2f} ETB\nFee status: Pending manual payment")
        try: send_service_message(message)
        except Exception: log.exception("Could not notify staff of customer cancellation %s", reference)
        if BOT_TOKEN:
            try:
                bot_api("sendMessage", {"chat_id":str(user_id), "text":(
                    f"Order cancelled / ትዕዛዝ ተሰርዟል: {reference}\n"
                    f"Total / ጠቅላላ: {order_total:,.2f} ETB\n"
                    f"Cancellation fee / የስረዛ ክፍያ: {cancellation_fee:,.2f} ETB\n"
                    f"After fee / ከክፍያ በኋላ: {refund_after_fee:,.2f} ETB\n"
                    "AMBAR will contact you about the fee. / ስለ ክፍያው AMBAR ያነጋግርዎታል።")})
            except Exception: log.exception("Could not send cancellation confirmation for %s", reference)
        return jsonify(ok=True, order=updated[0], cancellation_fee_etb=cancellation_fee, cancellation_refund_etb=refund_after_fee, cancellation_fee_status="Pending manual payment")
    except Exception:
        log.exception("Customer cancellation failed for %s", reference)
        return jsonify(error="Could not cancel this order right now. Please refresh and try again."), 503


@app.get("/api/admin/customer-service")
def admin_get_customer_service():
    _, error = admin_user_from_request()
    if error: return error
    defaults = {"title":"Customer Service","option1_label":"Customer Service 1","option1_url":"https://t.me/ambarhome1","option2_label":"Customer Service 2","option2_url":"https://t.me/ambarhome2","phone":"","whatsapp_url":""}
    if not supabase_enabled(): return jsonify(settings=defaults, needs_migration=True, warning="Default contact details are shown. Configure Supabase and run admin_enhancements_migration.sql to save edits permanently.")
    try:
        rows = supabase_request("GET", "/rest/v1/customer_service_settings", params={"select":"id,title,option1_label,option1_url,option2_label,option2_url,phone,whatsapp_url", "id":"eq.1", "limit":"1"}) or []
        return jsonify(settings={**defaults, **(rows[0] if rows else {})})
    except Exception:
        # Keep the admin usable when the optional settings table has not been migrated yet.
        # Saving still requires the included SQL migration; the response tells the UI that.
        log.exception("Could not load customer service settings; using defaults until migration is applied")
        return jsonify(settings=defaults, needs_migration=True, warning="Default contact details are shown. Run admin_enhancements_migration.sql to save customer service edits permanently."), 200

@app.post("/api/customer/app-open")
def customer_app_open():
    """Record a mini-app open from a Telegram identity verified by signed initData."""
    init_data = request.headers.get("X-Telegram-Init-Data", "")
    valid, user_id = validate_telegram_init_data(init_data)
    if not valid or not user_id:
        return jsonify(error="Valid Telegram sign-in is required."), 401
    try:
        pairs = dict(parse_qsl(init_data, keep_blank_values=True, strict_parsing=True))
        user = json.loads(pairs.get("user", "{}"))
        details = {
            "source": "telegram_mini_app_open",
            "username": str(user.get("username") or "")[:100],
            "first_name": str(user.get("first_name") or "")[:100],
            "last_name": str(user.get("last_name") or "")[:100],
            "language_code": str(user.get("language_code") or "")[:30],
        }
        stored = write_security_event("mini_app_open", actor_id=user_id, status_code=200, details=details)
        if not stored:
            return jsonify(ok=False, error="Visit logging is not configured. Apply admin_security_reports_migration.sql and check Supabase."), 503
        return jsonify(ok=True), 200
    except Exception:
        log.exception("Could not record customer mini-app open")
        return jsonify(error="Could not record app visit."), 500


@app.get("/api/customer-service")
def public_customer_service():
    defaults = {"title":"Customer Service","option1_label":"Customer Service 1","option1_url":"https://t.me/ambarhome1","option2_label":"Customer Service 2","option2_url":"https://t.me/ambarhome2","phone":"","whatsapp_url":""}
    if not supabase_enabled(): return jsonify(settings=defaults)
    try:
        rows = supabase_request("GET", "/rest/v1/customer_service_settings", params={"select":"title,option1_label,option1_url,option2_label,option2_url,phone,whatsapp_url", "id":"eq.1", "limit":"1"}) or []
        return jsonify(settings={**defaults, **(rows[0] if rows else {})})
    except Exception:
        log.exception("Could not load public customer service settings")
        return jsonify(settings=defaults)

@app.post("/api/admin/customer-service")
def admin_save_customer_service():
    _, error = admin_user_from_request()
    if error: return error
    if not supabase_enabled(): return jsonify(error="Supabase is required to save customer service settings persistently."), 503
    data = request.get_json(silent=True) or {}
    def service_text(key, default="", limit=300): return clean_text(data.get(key, default), limit, key.replace("_", " ").title())
    payload = {"id":1,"title":service_text("title","Customer Service",80) or "Customer Service", "option1_label":service_text("option1_label","Customer Service 1",80), "option1_url":service_text("option1_url","",300), "option2_label":service_text("option2_label","Customer Service 2",80), "option2_url":service_text("option2_url","",300), "phone":service_text("phone","",40), "whatsapp_url":service_text("whatsapp_url","",300), "updated_at":dt.datetime.now(dt.timezone.utc).isoformat()}
    for key in ("option1_url","option2_url","whatsapp_url"):
        value = payload[key]
        if value and not value.startswith(("https://", "http://", "tg://")): return jsonify(error=f"{key.replace('_',' ').title()} must be a valid http(s) or Telegram URL."), 400
    try:
        existing = supabase_request("GET", "/rest/v1/customer_service_settings", params={"select":"id", "id":"eq.1", "limit":"1"}) or []
        rows = supabase_request("PATCH", "/rest/v1/customer_service_settings", params={"id":"eq.1"}, payload=payload) if existing else supabase_request("POST", "/rest/v1/customer_service_settings", payload=payload)
        return jsonify(ok=True, settings=(rows[0] if rows else payload))
    except Exception:
        log.exception("Could not save customer service settings")
        return jsonify(error="Could not save customer service settings. Run the AMBAR admin enhancements SQL migration."), 503

ADMIN_SECTION_BUTTONS = [
    {"id":"products","label":"Product Edit","tab":"products","permission":"products"},
    {"id":"tracking","label":"Order Tracking","tab":"tracking","permission":"orders"},
    {"id":"delivery","label":"Delivery Fees","tab":"delivery","permission":"delivery"},
    {"id":"dashboard","label":"Sales Dashboard","tab":"dashboard","permission":"dashboard"},
    {"id":"service","label":"Customer Service","tab":"service","permission":"service"},
    {"id":"customers","label":"Customers","tab":"customers","permission":"customers"},
    {"id":"security","label":"Security Reports","tab":"security","permission":"security"},
    {"id":"admins","label":"Admin Management","tab":"admins","permission":"admin_management"},
    {"id":"adminpassword","label":"🔑 Change Admin Password","tab":"adminpassword","permission":"admin_management"},
]

@app.get("/api/interface-settings")
def public_interface_settings_get():
    """Expose only the published visual configuration, never admin history or secrets."""
    if not supabase_enabled():
        return jsonify(settings={})
    try:
        rows = supabase_request("GET", "/rest/v1/ambar_interface_settings", params={"select":"settings", "id":"eq.1", "limit":"1"}) or []
        return jsonify(settings=(rows[0].get("settings") or {}) if rows else {})
    except Exception:
        log.exception("Could not load published interface settings")
        return jsonify(settings={})

@app.get("/api/admin/interface-settings")
def admin_interface_settings_get():
    user_id, error = admin_user_from_request()
    if error: return error
    if not is_main_admin_user(user_id):
        return jsonify(error="Only Main Admin 1 or Main Admin 2 can edit the published interface."), 403
    if not supabase_enabled(): return jsonify(error="Supabase is required to save interface settings."), 503
    try:
        rows = supabase_request("GET", "/rest/v1/ambar_interface_settings", params={"select":"settings,version_history,updated_at", "id":"eq.1", "limit":"1"}) or []
        row = rows[0] if rows else {}
        return jsonify(settings=row.get("settings") or {}, history=row.get("version_history") or [], updated_at=row.get("updated_at"), needs_migration=not bool(rows))
    except Exception:
        log.exception("Could not load interface designer settings")
        return jsonify(error="Could not load interface settings. Apply AMBAR_INTERFACE_DESIGNER_MIGRATION.sql."), 503

@app.post("/api/admin/interface-settings")
def admin_interface_settings_save():
    user_id, error = admin_user_from_request()
    if error: return error
    if not is_main_admin_user(user_id):
        return jsonify(error="Only Main Admin 1 or Main Admin 2 can publish interface settings."), 403
    if not supabase_enabled(): return jsonify(error="Supabase is required to publish interface settings."), 503
    data = request.get_json(silent=True) or {}
    settings = data.get("settings")
    if not isinstance(settings, dict): return jsonify(error="Send a valid settings object."), 400
    if len(json.dumps(settings, ensure_ascii=False)) > 200000: return jsonify(error="Interface settings are too large."), 413
    # Strictly whitelist editable visual fields; never accept HTML, scripts, URLs, or business logic.
    def color(value, fallback):
        value = str(value or fallback)
        return value if re.fullmatch(r"#[0-9a-fA-F]{6}", value) else fallback
    incoming_a = settings.get("appearance") if isinstance(settings.get("appearance"), dict) else {}
    incoming_l = settings.get("labels") if isinstance(settings.get("labels"), dict) else {}
    incoming_v = settings.get("visibility") if isinstance(settings.get("visibility"), dict) else {}
    defaults = {"background":"#f7f8fa","text":"#20242a","accent":"#ff7417","card":"#ffffff","border":"#e1e5eb","buttonText":"#171717","opacity":0.76,"blur":18,"radius":19,"fontScale":1}
    appearance = {key:color(incoming_a.get(key), fallback) for key,fallback in defaults.items() if isinstance(fallback,str)}
    for key, low, high, fallback in [("opacity",0.25,0.95,0.76),("blur",0,32,18),("radius",8,32,19),("fontScale",0.9,1.2,1)]:
        try: appearance[key] = max(low, min(high, float(incoming_a.get(key, fallback))))
        except (TypeError, ValueError): appearance[key] = fallback
    label_defaults = {"storeTitle":"AMBAR Furniture","tagline":"Modern living · Timeless design","trackOrders":"Track Orders","categoryHint":"Tap any product to see photos and specifications.","customOrder":"＋ Send a custom product photo","about":"About AMBAR Furniture"}
    labels = {key:clean_text(incoming_l.get(key, fallback), 150, "Interface label", False) for key,fallback in label_defaults.items()}
    content_defaults = {
      "deliveryTitle":"Delivery arrangements","deliveryTitleAm":"የማድረሻ ዝግጅት","deliverySubtitle":"A considered delivery experience, tailored to you.","deliverySubtitleAm":"ለእርስዎ የተዘጋጀ የማድረስ አገልግሎት።",
      "pickupTitle":"Pickup","pickupTitleAm":"በራስዎ መውሰድ","pickupDesc":"Collect your order yourself · No delivery fee","pickupDescAm":"ትዕዛዝዎን በራስዎ ይውሰዱ · የማድረሻ ክፍያ የለም",
      "deliveryOptionTitle":"Delivery","deliveryOptionTitleAm":"ማድረስ","deliveryOptionDesc":"Our team brings your furniture to your selected address.","deliveryOptionDescAm":"ቡድናችን የቤት ዕቃዎን ወደመረጡት አድራሻ ያደርሳል።",
      "deliveryAddressLabel":"Delivery address / landmark *","deliveryAddressLabelAm":"የማድረሻ አድራሻ / መለያ ቦታ *","useGpsLabel":"📍 Use my current GPS","useGpsLabelAm":"📍 ያሁኑን GPS ይጠቀሙ","selectMapLabel":"🗺️ Select on map","selectMapLabelAm":"🗺️ በካርታ ላይ ይምረጡ",
      "locationStatus":"Use GPS or tap the map to place a pin. You can add a landmark above.","locationStatusAm":"GPS ይጠቀሙ ወይም በካርታው ላይ ፒን ያስቀምጡ። ከላይ መለያ ቦታ ማከል ይችላሉ።","mapSearchPlaceholder":"Search map by place or address","mapSearchPlaceholderAm":"በቦታ ወይም በአድራሻ ካርታ ይፈልጉ","mapSearchButton":"Search","mapSearchButtonAm":"ፈልግ",
      "distanceText":"Choose a location to calculate distance and delivery fee.","distanceTextAm":"ርቀትና የማድረሻ ክፍያ ለማስላት ቦታ ይምረጡ።","summaryTitle":"YOUR ORDER SUMMARY","summaryTitleAm":"የትዕዛዝዎ ማጠቃለያ","subtotalLabel":"Products subtotal","subtotalLabelAm":"የምርቶች ንዑስ ድምር","deliveryFeeLabel":"Delivery fee","deliveryFeeLabelAm":"የማድረሻ ክፍያ","estimatedTotalLabel":"Estimated total","estimatedTotalLabelAm":"ግምታዊ ጠቅላላ","pickupNote":"Customer pickup selected — no delivery fee.","pickupNoteAm":"ደንበኛው በራሱ ይወስዳል — የማድረሻ ክፍያ የለም።",
      "paymentChoiceTitle":"Choose your first payment","paymentChoiceTitleAm":"የመጀመሪያ ክፍያዎን ይምረጡ","paymentSummaryTitle":"PAYMENT BREAKDOWN","paymentSummaryTitleAm":"የክፍያ ዝርዝር","paymentFinalNote":"Final amounts are confirmed by AMBAR when your order is reviewed.","paymentFinalNoteAm":"ትዕዛዝዎ ሲገመገም የመጨረሻ መጠኖች በAMBAR ይረጋገጣሉ።",
      "aboutTitle":"AMBAR FURNITURE","aboutTitleAm":"AMBAR FURNITURE","aboutSubtitle":"Modern Footwear Storage & Custom Furniture","aboutSubtitleAm":"ዘመናዊ የጫማ ማስቀመጫና በትዕዛዝ የሚሠሩ የቤት ዕቃዎች","aboutIntro":"At Ambar Furniture, we design modern shoe storage solutions that bring order, elegance, and space-saving efficiency to your home.","aboutIntroAm":"በAmbar Furniture ውስጥ ሥርዓት፣ ውበትና ቦታ ቆጣቢነት የሚያመጡ ዘመናዊ የጫማ ማስቀመጫዎችን እንነድፋለን።","aboutCustomTitle":"Custom Furniture Beyond Footwear Storage","aboutCustomTitleAm":"ከጫማ ማስቀመጫ በላይ በትዕዛዝ የሚሠሩ የቤት ዕቃዎች","aboutCustomText":"We craft a wide variety of custom furniture tailored to your needs and style preferences.","aboutCustomTextAm":"ከፍላጎትዎና ከቅጥ ምርጫዎ ጋር የሚስማሙ የተለያዩ በትዕዛዝ የሚሠሩ የቤት ዕቃዎችን እንሠራለን።","aboutWhyTitle":"Why Choose Ambar Furniture","aboutWhyTitleAm":"ለምን Ambar Furnitureን ይመርጣሉ","aboutPromiseTitle":"Our Promise","aboutPromiseTitleAm":"ቃል ኪዳናችን","aboutPromiseText":"Simple organization, modern design, and flexible custom craftsmanship crafted to elevate your home.","aboutPromiseTextAm":"ቤትዎን የሚያሳምሩ ቀላል አደረጃጀት፣ ዘመናዊ ንድፍና በትዕዛዝ የሚሠሩ ዕቃዎች።",
      "checkoutHeading":"Delivery & Payment","checkoutHeadingAm":"ማድረሻ እና ክፍያ","checkoutIntro":"Choose delivery and payment.","checkoutIntroAm":"የማድረሻና የክፍያ ዘዴ ይምረጡ።","chapaButton":"Pay with Chapa","chapaButtonAm":"በChapa ይክፈሉ","payLaterButton":"Pay Later","payLaterButtonAm":"በኋላ ይክፈሉ","backToProductsLabel":"← Back to products","backToProductsLabelAm":"← ወደ ምርቶች ተመለስ",
      "aboutSecondParagraph":"Whether you need personalized living room pieces, bedroom sets, or bespoke storage solutions, our team works with you to bring your vision to life.","aboutSecondParagraphAm":"ለሳሎን፣ ለመኝታ ክፍል ወይም ለልዩ ማስቀመጫ መፍትሔዎች ቡድናችን ሐሳብዎን እውን ለማድረግ ከእርስዎ ጋር ይሠራል።",
      "benefit1Title":"Space-Saving Engineering:","benefit1TitleAm":"ቦታ ቆጣቢ ንድፍ፦","benefit1Text":"Ultra-slim profiles designed for narrow hallways, foyers, and closets.","benefit1TextAm":"በጠባብ ኮሪደሮችና መግቢያዎች የሚስማሙ ቀጭን ዲዛይኖች።",
      "benefit2Title":"Smart & Flexible Organization:","benefit2TitleAm":"ብልህና ተለዋዋጭ አደረጃጀት፦","benefit2Text":"Flexible shelving for everyday sneakers, heels, and boots.","benefit2TextAm":"ለስኒከር፣ ለተረከዝ ጫማና ለቦት ተለዋዋጭ መደርደሪያዎች።",
      "benefit3Title":"Tailored Customization:","benefit3TitleAm":"ለእርስዎ የተስተካከለ አሠራር፦","benefit3Text":"Custom dimensions and finishes matched to your needs.","benefit3TextAm":"ከፍላጎትዎ ጋር የሚስማሙ መጠኖችና አጨራረሶች።",
      "benefit4Title":"Premium Quality Materials:","benefit4TitleAm":"ከፍተኛ ጥራት ያላቸው ቁሳቁሶች፦","benefit4Text":"Durable materials and finishes designed for daily use.","benefit4TextAm":"ለዕለታዊ አጠቃቀም የተዘጋጁ ዘላቂ ቁሳቁሶችና አጨራረሶች።",
      "benefit5Title":"Integrated Ventilation:","benefit5TitleAm":"የአየር ዝውውር ያለው ንድፍ፦","benefit5Text":"Airflow-friendly designs help keep shoes fresh.","benefit5TextAm":"አየር የሚያስገቡ ዲዛይኖች ጫማዎች ትኩስ እንዲቆዩ ያግዛሉ።",
      "benefit6Title":"Functional Modern Aesthetics:","benefit6TitleAm":"ተግባራዊ ዘመናዊ ውበት፦","benefit6Text":"Clean lines and modern finishes complement your home.","benefit6TextAm":"ንጹህ መስመሮችና ዘመናዊ አጨራረሶች ቤትዎን ያስውባሉ።",
      "storeFooterNote":"Before you submit, double-check your selected products and order details.","storeFooterNoteAm":"ከማስገባትዎ በፊት የመረጧቸውን ምርቶችና የትዕዛዝ ዝርዝሮች ያረጋግጡ።","measurementsLabel":"MEASUREMENTS","measurementsLabelAm":"መጠኖች","capacityLabel":"CAPACITY","capacityLabelAm":"አቅም","materialLabel":"MATERIAL","materialLabelAm":"ቁሳቁስ","categoryLabel":"PRODUCT CATEGORY","categoryLabelAm":"የምርት ምድብ"
    }
    incoming_content = settings.get("content") if isinstance(settings.get("content"), dict) else {}
    content = {key:clean_text(incoming_content.get(key, fallback), 500, "Interface page copy", False) for key,fallback in content_defaults.items()}
    visibility = {key:bool(incoming_v.get(key, True)) for key in ("favorites","service","about","track")}
    incoming_layout = settings.get("layout") if isinstance(settings.get("layout"), dict) else {}
    allowed_layout = ["navigation", "category_title", "product_grid", "footer"]
    requested_order = incoming_layout.get("order", allowed_layout)
    if not isinstance(requested_order, list): requested_order = allowed_layout
    layout_order = []
    for item in requested_order:
        item = str(item)
        if item in allowed_layout and item not in layout_order: layout_order.append(item)
    for item in allowed_layout:
        if item not in layout_order: layout_order.append(item)
    incoming_elements = settings.get("elements") if isinstance(settings.get("elements"), list) else []
    elements = []
    for item in incoming_elements[:100]:
        if not isinstance(item, dict): continue
        selector = clean_text(item.get("selector", ""), 250, "Element selector", False)
        # Selectors are used only with querySelector; forbid markup, pseudo-URL tricks, and excessively complex selectors.
        if not selector or re.search(r"[<>]|javascript:|url\s*\(", selector, re.I): continue
        if not re.fullmatch(r"""[A-Za-z0-9_#.*\[\]\s=\-'"():>+~^$|,]+""", selector): continue
        if selector.strip() in ("*", "body", "html", "#app", "#appRoot", "#productsView"): continue
        requested_visibility = item.get("visibility") if item.get("visibility") in ("default","show","hide") else "default"
        if requested_visibility == "hide" and re.search(r"\b(button|input|form|pay|payment|checkout|order|submit|cart|finance|workshop|admin)\b", selector, re.I): requested_visibility = "default"
        def element_color(value):
            value = str(value or "")
            return value if re.fullmatch(r"#[0-9a-fA-F]{6}", value) else ""
        try: font_size = max(0, min(48, int(float(item.get("fontSize", 0) or 0))))
        except (TypeError, ValueError): font_size = 0
        try: element_radius = max(0, min(40, int(float(item.get("radius", 0) or 0))))
        except (TypeError, ValueError): element_radius = 0
        try: element_padding = max(0, min(48, int(float(item.get("padding", 0) or 0))))
        except (TypeError, ValueError): element_padding = 0
        elements.append({"selector":selector,"name":clean_text(item.get("name", ""),80,"Element name",False),"text":clean_text(item.get("text", ""),500,"Element text",False),"textAm":clean_text(item.get("textAm", ""),500,"Element Amharic text",False),"visibility":requested_visibility,"background":element_color(item.get("background")),"color":element_color(item.get("color")),"fontSize":font_size,"radius":element_radius,"padding":element_padding})
    clean = {"appearance":appearance,"labels":labels,"content":content,"visibility":visibility,"elements":elements,"layout":{"order":layout_order}}
    try:
        existing = supabase_request("GET", "/rest/v1/ambar_interface_settings", params={"select":"settings,version_history", "id":"eq.1", "limit":"1"}) or []
        old = existing[0] if existing else {}
        history = old.get("version_history") or []
        if not isinstance(history, list): history = []
        if old.get("settings"):
            history.insert(0, {"version":len(history)+1,"published_at":dt.datetime.now(dt.timezone.utc).isoformat(),"published_by":str(user_id),"settings":old.get("settings")})
        history = history[:10]
        payload = {"id":1,"settings":clean,"version_history":history,"updated_at":dt.datetime.now(dt.timezone.utc).isoformat(),"updated_by":str(user_id)}
        rows = supabase_request("POST", "/rest/v1/ambar_interface_settings", payload=payload, extra_headers={"Prefer":"resolution=merge-duplicates,return=representation"}) or []
        write_security_event("interface_settings_published", actor_id=user_id, status_code=200, details={"version_history_count":len(history)})
        return jsonify(ok=True, settings=clean, history=history, saved=True)
    except Exception:
        log.exception("Could not publish interface settings")
        return jsonify(error="Could not publish interface settings. Apply AMBAR_INTERFACE_DESIGNER_MIGRATION.sql and verify Render's Supabase settings."), 503

@app.get("/api/admin/button-settings")
def admin_button_settings_get():
    user_id, error = admin_user_from_request()
    if error: return error
    if not supabase_enabled(): return jsonify(error="Supabase is required for persistent button settings."), 503
    try:
        rows = supabase_request("GET", "/rest/v1/ambar_admin_button_settings", params={"select":"button_id,label,visible,disabled,removed,custom_url,sort_order", "order":"sort_order.asc"}) or []
        return jsonify(buttons=rows, defaults=ADMIN_SECTION_BUTTONS)
    except Exception:
        log.exception("Could not load admin button settings")
        return jsonify(error="Could not load button settings. Run admin_button_settings_migration.sql."), 503

@app.post("/api/admin/button-settings")
def admin_button_settings_save():
    user_id, error = admin_user_from_request()
    if error: return error
    if not is_main_admin_user(user_id):
        return jsonify(error="Only the main admin can edit admin menu buttons."), 403
    if not supabase_enabled(): return jsonify(error="Supabase is required for persistent button settings."), 503
    data = request.get_json(silent=True) or {}; rows = data.get("buttons")
    if not isinstance(rows, list) or len(rows) > 30: return jsonify(error="Send a valid button list (maximum 30)."), 400
    defaults = {x["id"]:x for x in ADMIN_SECTION_BUTTONS}; clean=[]
    for index,row in enumerate(rows):
        if not isinstance(row,dict): return jsonify(error="Invalid button entry."),400
        bid=str(row.get("button_id"," ")).strip(); custom=bid.startswith("custom_")
        if bid not in defaults and not (custom and re.fullmatch(r"custom_[a-zA-Z0-9_-]{1,32}",bid)): return jsonify(error="Unknown button ID: "+bid),400
        label=clean_text(row.get("label",defaults.get(bid,{}).get("label","Custom link")),60,"Button label",True)
        url=str(row.get("custom_url","")).strip()
        if custom and not url.startswith(("https://","http://","tg://")): return jsonify(error="Custom buttons need a valid https://, http://, or tg:// link."),400
        clean.append({"button_id":bid,"label":label,"visible":bool(row.get("visible",True)),"disabled":bool(row.get("disabled",False)),"removed":bool(row.get("removed",False)),"custom_url":url if custom else None,"sort_order":index})
    try:
        for row in clean: supabase_request("POST","/rest/v1/ambar_admin_button_settings",payload=row,extra_headers={"Prefer":"resolution=merge-duplicates,return=minimal"})
        write_security_event("admin_button_settings_changed",actor_id=user_id,status_code=200,details={"button_count":len(clean)})
        return jsonify(ok=True,saved=len(clean))
    except Exception:
        log.exception("Could not save admin button settings")
        return jsonify(error="Could not save button settings. Run admin_button_settings_migration.sql."),503

@app.get("/api/admin/roles/me")
def admin_roles_me():
    """Return only the signed-in user's own permissions after Telegram verification."""
    user_id, error = verified_telegram_admin()
    if error: return error
    if is_main_admin_user(user_id):
        return jsonify(owner=True, permissions=["*"])
    record = admin_permissions_for(user_id) or {}
    active = bool(record.get("active")) and record.get("role") != "disabled"
    permissions = normalize_admin_permissions(record.get("permissions"), record.get("role")) if active else []
    return jsonify(owner=False, active=active, permissions=permissions)


@app.get("/api/admin/roles")
def admin_roles_list():
    user_id, error = admin_user_from_request()
    if error: return error
    if not is_main_admin_user(user_id):
        return jsonify(error="Only the main admin can manage admin accounts."), 403
    if not supabase_enabled(): return jsonify(error="Supabase is required for persistent admin roles."), 503
    try:
        rows = supabase_request("GET", "/rest/v1/ambar_admin_roles", params={"select":"telegram_user_id,display_name,role,active,permissions,created_at,updated_at","order":"created_at.asc"}) or []
        return jsonify(admins=rows, owner_telegram_id=user_id)
    except Exception:
        log.exception("Could not load admin roles")
        return jsonify(error="Could not load admins. Apply the updated admin_roles_and_activity_migration.sql."), 503


@app.post("/api/admin/roles")
def admin_roles_save():
    user_id, error = admin_user_from_request()
    if error: return error
    if not is_main_admin_user(user_id):
        return jsonify(error="Only the main admin can manage admin accounts."), 403
    if not supabase_enabled(): return jsonify(error="Supabase is required for persistent admin roles."), 503
    data = request.get_json(silent=True) or {}
    target = str(data.get("telegram_user_id", "")).strip()
    name = clean_text(data.get("display_name", ""), 100, "Admin name", False)
    active = bool(data.get("active", True))
    make_super_admin = bool(data.get("main_admin2", False))
    permissions = ["*"] if make_super_admin and active else normalize_admin_permissions(data.get("permissions", []))
    allowed = {"orders", "order_dispatch", "products", "delivery", "dashboard", "customers", "security", "service", "workshop_erp", "finance_inventory", "admin_management"}
    if not target.isdigit(): return jsonify(error="Enter the admin's numeric Telegram ID."), 400
    if target == ADMIN_PASSWORD_MANAGER_TELEGRAM_ID: return jsonify(error="The original main admin account is protected."), 400
    if target == str(user_id): return jsonify(error="You cannot edit or remove your own administrator account here."), 400
    if not isinstance(permissions, list) or (not make_super_admin and any(x not in allowed for x in permissions)):
        return jsonify(error="Select one or more valid permissions."), 400
    if not permissions and active: return jsonify(error="Select at least one permission or disable the account."), 400
    role = "disabled" if not active else ("super_admin" if make_super_admin else ("orders" if permissions == ["orders"] else "staff"))
    payload={"telegram_user_id":target,"display_name":name,"role":role,"active":active,"permissions":permissions,"updated_at":dt.datetime.now(dt.timezone.utc).isoformat()}
    try:
        if make_super_admin and active:
            existing_super_admins = supabase_request("GET", "/rest/v1/ambar_admin_roles", params={"select":"telegram_user_id", "role":"eq.super_admin", "active":"eq.true", "limit":"20"}) or []
            if any(str(x.get("telegram_user_id") or "") != target for x in existing_super_admins):
                return jsonify(error="Main Admin 2 is already assigned. Edit that account to change the full-control administrator."), 409
        rows=supabase_request("POST","/rest/v1/ambar_admin_roles",payload=payload,extra_headers={"Prefer":"resolution=merge-duplicates,return=representation"}) or []
        write_security_event("admin_role_changed",actor_id=user_id,status_code=200,details={"target_admin_id":target,"permissions":permissions,"active":active,"role":role})
        return jsonify(ok=True,admin=(rows[0] if rows else payload))
    except Exception as exc:
        log.exception("Could not save admin role")
        # Surface a sanitized database hint so the owner can distinguish a missing column,
        # schema-cache issue, or insufficient Supabase service-role grants.
        safe_error = re.sub(r"[\r\n\t]+", " ", str(exc))[:360]
        return jsonify(error="Could not save admin role. " + safe_error + " If the migration has not been run in the same Supabase project used by Render, apply admin_roles_and_activity_migration.sql."), 503


@app.delete("/api/admin/roles/<target>")
def admin_roles_delete(target):
    user_id, error = admin_user_from_request()
    if error: return error
    if not is_main_admin_user(user_id):
        return jsonify(error="Only the main admin can remove admin accounts."), 403
    if not target.isdigit() or target == ADMIN_PASSWORD_MANAGER_TELEGRAM_ID or target == str(user_id):
        return jsonify(error="Invalid target, the original main admin, or your own account cannot be removed here."), 400
    try:
        supabase_request("DELETE", "/rest/v1/ambar_admin_roles", params={"telegram_user_id":f"eq.{target}"})
        write_security_event("admin_removed", actor_id=user_id, status_code=200, details={"target_admin_id":target})
        return jsonify(ok=True, removed=target)
    except Exception:
        log.exception("Could not remove admin")
        return jsonify(error="Could not remove admin account."), 503


@app.get("/api/admin/order-dispatch/orders")
def admin_order_dispatch_orders():
    """Return only the customer-order fields needed for Telegram dispatch; no finance summary."""
    _, error = admin_user_from_request()
    if error: return error
    if not supabase_enabled(): return jsonify(error="Supabase is required for saved customer orders."), 503
    try:
        orders = supabase_request("GET", "/rest/v1/customer_orders", params={
            "select":"reference,status,total_etb,customer_name,created_at,items",
            "order":"created_at.desc", "limit":"500"
        }) or []
        return jsonify(orders=orders)
    except Exception:
        log.exception("Could not load customer orders for Telegram dispatch")
        return jsonify(error="Could not load customer orders for dispatch. Check Supabase and Render logs."), 503


@app.get("/api/admin/phase2/summary")
def phase2_admin_summary():
    _, error = admin_user_from_request()
    if error: return error
    if not supabase_enabled(): return jsonify(error="Supabase is required for persistent orders and dashboard data."), 503
    try:
        orders = supabase_request("GET", "/rest/v1/customer_orders", params={"select":"reference,status,product_total_etb,delivery_fee_etb,total_etb,cancellation_fee_etb,cancellation_refund_etb,cancellation_fee_status,delivery_area,delivery_distance_km,delivery_fee_mode,telegram_user_id,customer_name,phone,delivery_location,notes,created_at,items", "order":"created_at.desc", "limit":"500"}) or []
        areas = supabase_request("GET", "/rest/v1/delivery_areas", params={"select":"id,area_name,fee_etb,estimated_days,active", "order":"area_name.asc"}) or []
        # Show whether each customer order has already been manually sent to Workshop ERP.
        try:
            workshop_rows = supabase_request("GET", "/rest/v1/workshop_erp_state", params={"select":"state", "id":"eq.1", "limit":"1"}) or []
            workshop_state = workshop_rows[0].get("state", {}) if workshop_rows and isinstance(workshop_rows[0].get("state"), dict) else {}
            imported_refs = {str(x.get("sourceCustomerOrderReference") or "") for x in workshop_state.get("orders", []) if isinstance(x, dict) and x.get("sourceCustomerOrderReference")}
        except Exception:
            log.exception("Could not load Workshop ERP links for order-management display")
            imported_refs = set()
        for order in orders:
            order["workshop_workflow_created"] = str(order.get("reference") or "") in imported_refs
        completed = [o for o in orders if o.get("status") == "Delivered"]
        return jsonify(orders=orders, areas=areas, gps_settings=get_gps_delivery_settings() or {"id":1,"origin_lat":None,"origin_lon":None,"price_per_km":0,"base_fee_etb":0,"active":False}, metrics={"orders":len(orders),"pending":sum(o.get("status") not in ("Delivered","Cancelled") for o in orders),"completed":len(completed),"revenue_etb":sum(float(o.get("total_etb") or 0) for o in completed)})
    except Exception:
        log.exception("Phase 2 admin summary failed")
        return jsonify(error="Could not load Phase 2 dashboard. Run phase2_orders_delivery_schema.sql first."), 503


def _finance_record_date(value):
    """Normalize common Workshop ERP date values to YYYY-MM-DD."""
    raw = str(value or "").strip()
    if not raw:
        return ""
    try:
        return dt.datetime.fromisoformat(raw.replace("Z", "+00:00")).date().isoformat()
    except Exception:
        pass
    for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y", "%Y/%m/%d"):
        try:
            return dt.datetime.strptime(raw[:10], fmt).date().isoformat()
        except Exception:
            continue
    return ""


def sync_workshop_sales_into_finance(workshop_state, user_id):
    """Idempotently mirror sold products and material receipts into the Finance ledger."""
    if not supabase_enabled() or not isinstance(workshop_state, dict):
        return {"synced": 0, "receivables": 0, "material_expenses": 0}
    finance_start_date = "2026-10-26"
    sales = workshop_state.get("sales", [])
    products = workshop_state.get("products", [])
    movements = workshop_state.get("materialTransactions", [])
    if not isinstance(sales, list): sales = []
    if not isinstance(products, list): products = []
    if not isinstance(movements, list): movements = []
    sales = _merge_legacy_sold_products(sales, products)
    existing = supabase_request("GET", "/rest/v1/ambar_finance_entries", params={"select":"source_ref", "source_ref":"not.is.null", "limit":"5000"}) or []
    refs = {str(x.get("source_ref")) for x in existing if x.get("source_ref")}
    synced = receivables = material_expenses = 0

    for sale in sales:
        if not isinstance(sale, dict) or str(sale.get("status", "")).strip().upper() != "SOLD":
            continue
        sale_id = str(sale.get("saleId") or sale.get("sale_id") or sale.get("id") or sale.get("saleNumber") or sale.get("sale_number") or sale.get("receiptNumber") or sale.get("receipt_number") or sale.get("reference") or sale.get("serial") or sale.get("productId") or sale.get("product_id") or "").strip()
        if not sale_id: continue
        sold_at = str(sale.get("soldAtISO") or sale.get("soldAt") or sale.get("sold_at") or sale.get("date") or sale.get("createdAt") or sale.get("created_at") or "").strip()
        sale_date = _finance_record_date(sold_at)
        if not sale_date or sale_date < finance_start_date: continue
        sale_key = sale_id + (":" + sold_at if sold_at else ":" + sale_date)
        money_ref = "workshop-sale:" + sale_key
        receivable_ref = "workshop-sale-receivable:" + sale_key
        legacy_money_ref = "workshop-sale:" + sale_id
        price = 0.0
        for k in ("price", "salePrice", "sale_price", "total", "totalAmount", "total_amount"):
            try: value = float(sale.get(k) or 0)
            except (TypeError, ValueError): continue
            if value > 0: price = round(value, 2); break
        paid = 0.0
        for k in ("paidAmount", "paid_amount", "amountPaid", "amount_paid"):
            try: value = float(sale.get(k) or 0)
            except (TypeError, ValueError): continue
            if value > 0: paid = round(value, 2); break
        if price <= 0: price = paid
        if price <= 0: continue
        label = str(sale.get("model") or sale.get("productId") or sale.get("product_id") or sale_id)
        status = re.sub(r"\s+", " ", re.sub(r"[_-]+", " ", str(sale.get("paymentStatus", sale.get("payment_status", ""))).strip().lower()))
        fully_paid = status in {"paid", "paid in full", "fully paid", "fully paid in full", "complete", "completed"}
        if fully_paid:
            if receivable_ref in refs:
                supabase_request("DELETE", "/rest/v1/ambar_finance_entries", params={"source_ref":"eq." + receivable_ref})
                refs.discard(receivable_ref)
            if money_ref in refs or legacy_money_ref in refs: continue
            payload = {"direction":"in", "category":"Workshop ERP Sale", "amount_etb":round(paid if paid > 0 else price, 2), "description":"Workshop ERP paid sale · " + label, "entry_date":sale_date, "created_by":str(user_id), "source_ref":money_ref}
            supabase_request("POST", "/rest/v1/ambar_finance_entries", params={"on_conflict":"source_ref"}, payload=payload, extra_headers={"Prefer":"resolution=ignore-duplicates,return=minimal"})
            refs.add(money_ref); synced += 1
        else:
            outstanding = round(max(0.0, price-paid), 2)
            if outstanding <= 0: continue
            status_label = str(sale.get("paymentStatus") or sale.get("payment_status") or "Payment waiting")
            payload = {"direction":"in", "category":"Workshop ERP Sale Receivable", "amount_etb":outstanding, "description":"SOLD · payment due (not cash received) · " + label + " · " + status_label, "entry_date":sale_date, "created_by":str(user_id), "source_ref":receivable_ref}
            supabase_request("POST", "/rest/v1/ambar_finance_entries", params={"on_conflict":"source_ref"}, payload=payload, extra_headers={"Prefer":"resolution=merge-duplicates,return=minimal"})
            refs.add(receivable_ref); receivables += 1

    # A received material movement is a purchase/expense; cutting or using stock is not
    # a second expense. Use qty × recorded unit cost and a stable reference to prevent duplicates.
    active_material_refs = set()
    for movement in movements:
        if not isinstance(movement, dict) or str(movement.get("type", "")).strip().lower() != "receipt":
            continue
        movement_id = str(movement.get("id") or movement.get("transactionId") or movement.get("transaction_id") or "").strip()
        date_value = movement.get("date") or movement.get("createdAt") or movement.get("created_at") or ""
        movement_date = _finance_record_date(date_value)
        if not movement_id or not movement_date or movement_date < finance_start_date:
            continue
        try: qty = float(movement.get("qty") or movement.get("quantity") or 0)
        except (TypeError, ValueError): qty = 0.0
        try: unit_cost = float(movement.get("unitCost") or movement.get("unit_cost") or movement.get("cost") or 0)
        except (TypeError, ValueError): unit_cost = 0.0
        amount = round(qty * unit_cost, 2)
        if qty <= 0 or unit_cost <= 0 or amount <= 0:
            continue
        ref = "workshop-material-receipt:" + movement_id + ":" + movement_date
        active_material_refs.add(ref)
        material_name = str(movement.get("materialName") or movement.get("material_name") or movement.get("name") or movement.get("materialId") or "Material")
        notes = str(movement.get("notes") or "").strip()
        description = f"Workshop ERP material purchase · {material_name} · {qty:g} {movement.get('unit') or ''}".strip()
        if notes: description += " · " + notes
        payload = {"direction":"out", "category":"Workshop ERP Material Purchase", "amount_etb":amount, "description":description, "entry_date":movement_date, "created_by":str(user_id), "source_ref":ref}
        supabase_request("POST", "/rest/v1/ambar_finance_entries", params={"on_conflict":"source_ref"}, payload=payload, extra_headers={"Prefer":"resolution=merge-duplicates,return=minimal"})
        refs.add(ref); material_expenses += 1

    # If a receipt is edited/deleted or changed to usage in Workshop ERP, remove its linked
    # auto-entry so the ledger continues to reflect the single source of truth.
    for old_ref in list(refs):
        old_date = old_ref.rsplit(":", 1)[-1] if old_ref.startswith("workshop-material-receipt:") else ""
        if old_ref.startswith("workshop-material-receipt:") and old_date >= finance_start_date and old_ref not in active_material_refs:
            supabase_request("DELETE", "/rest/v1/ambar_finance_entries", params={"source_ref":"eq." + old_ref})
            refs.discard(old_ref)
    return {"synced": synced, "receivables": receivables, "material_expenses": material_expenses}


@app.route("/api/admin/finance-inventory", methods=["GET", "POST", "DELETE"])
def admin_finance_inventory():
    """Finance workspace sourced only from the shared Workshop ERP state."""
    # Finance is launched only inside Workshop ERP. Reuse the authenticated Workshop ERP session:
    # owner uses the emergency admin session; staff use their unique Workshop ERP session.
    user_id, error = workshop_session_user()
    if error:
        return error
    owner_id = str(ADMIN_PASSWORD_MANAGER_TELEGRAM_ID or "")
    if not is_main_admin_user(user_id):
        write_security_event("finance_inventory_owner_only_denied", actor_id=str(user_id), path=request.path, method=request.method, status_code=403)
        return jsonify(error="This financial workspace is restricted to the Main Admin. Enter the Main Admin password in Workshop ERP."), 403
    # The financial period starts on Monday 26 October 2026 with zero opening balance.
    finance_start_date = "2026-10-26"
    if not supabase_enabled():
        return jsonify(error="Supabase is required. Configure SUPABASE_URL and SUPABASE_SECRET_KEY in Render."), 503
    try:
        if request.method == "GET":
            # Workshop ERP is the single source of truth for workshop sales and stock.
            try:
                workshop_rows = supabase_request("GET", "/rest/v1/workshop_erp_state", params={"select":"state,updated_at", "id":"eq.1", "limit":"1"}) or []
            except Exception as exc:
                log.exception("Finance dashboard could not read Workshop ERP shared state")
                return jsonify(error="Could not read Workshop ERP data. Run workshop_erp_state_migration.sql in the same Supabase project. Details: " + str(exc)[:220]), 503
            workshop_state = (workshop_rows[0] or {}).get("state") if workshop_rows else {}
            if not isinstance(workshop_state, dict):
                workshop_state = {}
            workshop_sales = workshop_state.get("sales", [])
            workshop_products = workshop_state.get("products", [])
            workshop_materials = workshop_state.get("materials", [])
            if not isinstance(workshop_sales, list): workshop_sales = []
            if not isinstance(workshop_products, list): workshop_products = []
            if not isinstance(workshop_materials, list): workshop_materials = []
            # Merge any unmatched legacy SOLD units even when newer Sales Archive entries already exist.
            workshop_sales = _merge_legacy_sold_products(workshop_sales, workshop_products)

            # Sync sales and material receipts on every Finance load as well as each Workshop save.
            # This repairs missed entries and uses stable source references to prevent duplicates.
            try:
                sync_workshop_sales_into_finance(workshop_state, user_id)
            except Exception:
                log.exception("Finance dashboard loaded, but automatic Workshop ERP finance sync failed")

            entries = supabase_request("GET", "/rest/v1/ambar_finance_entries", params={"select":"id,direction,category,amount_etb,description,entry_date,created_by,created_at,source_ref", "entry_date":"gte." + finance_start_date, "order":"entry_date.desc,created_at.desc", "limit":"5000"}) or []
            assignments = workshop_state.get("workshopAssignments", []) if isinstance(workshop_state.get("workshopAssignments", []), list) else []
            recipients = [{"id": owner_id, "name": "Main Admin"}] if owner_id else []
            seen_recipient_ids = {str(owner_id)} if owner_id else set()
            for assignment in assignments:
                if not isinstance(assignment, dict) or assignment.get("active") is False:
                    continue
                rid = str(assignment.get("telegram_user_id") or "").strip()
                if not rid.isdigit() or rid in seen_recipient_ids:
                    continue
                recipients.append({"id": rid, "name": str(assignment.get("display_name") or assignment.get("name") or ("Telegram user " + rid))[:100]})
                seen_recipient_ids.add(rid)
            return jsonify(entries=entries, finance_start_date=finance_start_date, opening_balance_etb=0, workshop={"stateFound":bool(workshop_rows), "sales":workshop_sales, "products":workshop_products, "materials":workshop_materials, "materialTransactions":workshop_state.get("materialTransactions", []) if isinstance(workshop_state.get("materialTransactions", []), list) else [], "dailyStockSnapshots":workshop_state.get("dailyStockSnapshots", []) if isinstance(workshop_state.get("dailyStockSnapshots", []), list) else [], "restockHistory":workshop_state.get("restockHistory", []) if isinstance(workshop_state.get("restockHistory", []), list) else [], "recipients":recipients, "updated_at":(workshop_rows[0] or {}).get("updated_at") if workshop_rows else None})
        if request.method == "POST":
            data = request.get_json(silent=True) or {}
            direction = str(data.get("direction", "")).lower().strip()
            category = clean_text(data.get("category", "Other"), 80, "Category", True)
            description = clean_text(data.get("description", ""), 500, "Description", True)
            entry_date = str(data.get("entry_date", ""))[:10]
            try:
                amount = float(data.get("amount_etb"))
                dt.date.fromisoformat(entry_date)
                if entry_date < finance_start_date:
                    return jsonify(error="The new financial period starts Monday 26 October 2026. Choose that date or a later date."), 400
                if amount <= 0 or amount > 1_000_000_000_000: raise ValueError()
            except (TypeError, ValueError):
                return jsonify(error="Enter a valid date and a positive amount in ETB."), 400
            if direction not in {"in", "out"}:
                return jsonify(error="Direction must be in (Money In) or out (Money Out)."), 400
            payload = {"direction": direction, "category": category, "amount_etb": amount, "description": description, "entry_date": entry_date, "created_by": str(user_id), "created_at": dt.datetime.now(dt.timezone.utc).isoformat(), "source_ref": None}
            rows = supabase_request("POST", "/rest/v1/ambar_finance_entries", payload=payload) or []
            write_security_event("finance_entry_created", actor_id=user_id, path=request.path, method="POST", status_code=200, details={"direction":direction,"amount_etb":amount,"category":category})
            return jsonify(ok=True, entry=(rows[0] if rows else payload))
        data = request.get_json(silent=True) or {}
        entry_id = str(data.get("id", ""))
        if not entry_id.isdigit():
            return jsonify(error="A valid ledger entry ID is required."), 400
        # ERP-generated entries are audit records. They must be corrected in Workshop ERP,
        # not removed from the finance ledger through a crafted DELETE request.
        linked = supabase_request("GET", "/rest/v1/ambar_finance_entries", params={"select":"id,source_ref", "id":f"eq.{entry_id}", "limit":"1"}) or []
        if not linked:
            return jsonify(error="Ledger entry was not found."), 404
        if linked[0].get("source_ref"):
            return jsonify(error="This entry is automatically linked to Workshop ERP. Correct the source sale in Workshop ERP instead of deleting the synced ledger entry."), 409
        rows = supabase_request("DELETE", "/rest/v1/ambar_finance_entries", params={"id":f"eq.{entry_id}", "source_ref":"is.null"}) or []
        write_security_event("finance_entry_deleted", actor_id=user_id, path=request.path, method="DELETE", status_code=200, details={"entry_id":entry_id})
        return jsonify(ok=True, deleted=entry_id)
    except Exception as exc:
        log.exception("Financial & Inventory dashboard request failed")
        detail = str(exc)[:260] or "Unknown database error"
        if "ambar_finance_entries" in detail or "source_ref" in detail or "schema cache" in detail.lower():
            hint = "Run the included ambar_finance_entries_migration.sql in Supabase, then wait for the schema cache to refresh."
        elif "workshop_erp_state" in detail:
            hint = "Run workshop_erp_state_migration.sql in the same Supabase project used by Render."
        else:
            hint = "Check SUPABASE_URL / SUPABASE_SECRET_KEY in Render and the latest Render logs."
        return jsonify(error="Finance dashboard database request failed. " + hint + " Details: " + detail), 503


def _finance_period_range(period, selected_date, finance_start="2026-10-26"):
    """Resolve a daily/weekly/monthly/yearly reporting window, respecting zero-start."""
    period = str(period or "daily").strip().lower()
    if period not in {"daily", "weekly", "monthly", "yearly"}:
        raise ValueError("Choose daily, weekly, monthly, or yearly report period.")
    try:
        selected = dt.date.fromisoformat(str(selected_date or "")[:10])
    except (TypeError, ValueError):
        selected = max(dt.date.today(), dt.date.fromisoformat(finance_start))
    if selected.isoformat() < finance_start:
        raise ValueError("The reporting period starts on Monday 26 October 2026. Select that date or later.")
    if period == "daily":
        start = end = selected
    elif period == "weekly":
        start = selected - dt.timedelta(days=selected.weekday())
        end = start + dt.timedelta(days=6)
    elif period == "monthly":
        start = selected.replace(day=1)
        end = (selected.replace(day=28) + dt.timedelta(days=4)).replace(day=1) - dt.timedelta(days=1)
    else:
        start = selected.replace(month=1, day=1)
        end = selected.replace(month=12, day=31)
    minimum = dt.date.fromisoformat(finance_start)
    if start < minimum:
        start = minimum
    return period, start.isoformat(), end.isoformat(), selected.isoformat()


def _finance_date_key(record):
    raw = str((record or {}).get("soldAtISO") or (record or {}).get("soldAt") or (record or {}).get("sold_at") or (record or {}).get("date") or (record or {}).get("createdAt") or (record or {}).get("created_at") or "")
    match = re.match(r"^(\d{4}-\d{2}-\d{2})", raw)
    return match.group(1) if match else ""


def _merge_legacy_sold_products(sales, products):
    """Keep Sales Archive entries authoritative while including unmatched legacy SOLD units."""
    merged = [x for x in sales if isinstance(x, dict)] if isinstance(sales, list) else []
    for product in products if isinstance(products, list) else []:
        if not isinstance(product, dict) or str(product.get("status") or "").upper() != "SOLD":
            continue
        product_record_id = str(product.get("id") or "")
        product_id = str(product.get("productId") or product.get("serial") or "")
        product_time = str(product.get("soldAtISO") or product.get("soldAt") or product.get("sold_at") or "")
        matched = False
        for sale in merged:
            sale_record_id = str(sale.get("productRecordId") or sale.get("id") or "")
            sale_product_id = str(sale.get("productId") or sale.get("serial") or "")
            sale_time = str(sale.get("soldAtISO") or sale.get("soldAt") or sale.get("sold_at") or "")
            same_unit = bool(product_record_id and sale_record_id == product_record_id) or bool(product_id and sale_product_id == product_id)
            same_sale_time = not product_time or not sale_time or product_time == sale_time
            if same_unit and same_sale_time:
                matched = True
                break
        if not matched:
            merged.append(product)
    return merged


@app.post("/api/admin/finance-inventory/pdf")
def admin_finance_inventory_pdf():
    """Generate a period-specific PDF or send it to a selected Telegram admin."""
    user_id, error = workshop_session_user()
    if error:
        return error
    owner_id = str(ADMIN_PASSWORD_MANAGER_TELEGRAM_ID or "")
    if not is_main_admin_user(user_id):
        return jsonify(error="PDF reports and Telegram delivery are restricted to the Main Admin."), 403
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from io import BytesIO
        if not supabase_enabled():
            return jsonify(error="Supabase is not configured. Check SUPABASE_URL and SUPABASE_SECRET_KEY in Render."), 503
        request_data = request.get_json(silent=True) or {}
        action = str(request_data.get("action") or "download").lower()
        if action not in {"download", "send"}:
            return jsonify(error="Report action must be download or send."), 400
        try:
            period, start_date, end_date, selected_date = _finance_period_range(request_data.get("reportPeriod"), request_data.get("selectedDate"))
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        state_rows = supabase_request("GET", "/rest/v1/workshop_erp_state", params={"select":"state,updated_at", "id":"eq.1", "limit":"1"}) or []
        state = (state_rows[0] or {}).get("state") if state_rows else {}
        if not isinstance(state, dict): state = {}
        products = state.get("products", []) if isinstance(state.get("products", []), list) else []
        materials = state.get("materials", []) if isinstance(state.get("materials", []), list) else []
        sales = state.get("sales", []) if isinstance(state.get("sales", []), list) else []
        # Sales Archive is authoritative, while unmatched legacy SOLD units remain visible in reports.
        sales = _merge_legacy_sold_products(sales, products)
        ledger_all = supabase_request("GET", "/rest/v1/ambar_finance_entries", params={"select":"id,direction,category,amount_etb,description,entry_date,source_ref,created_at", "entry_date":"gte.2026-10-26", "order":"entry_date.desc,created_at.desc", "limit":"5000"}) or []
        ledger = [x for x in ledger_all if start_date <= str(x.get("entry_date") or "") <= end_date]
        paid_statuses = {"paid", "paid in full", "fully paid", "fully paid in full", "complete", "completed"}
        period_sales = []
        for sale in sales:
            if not isinstance(sale, dict) or str(sale.get("status", "")).upper() != "SOLD":
                continue
            sale_date = _finance_date_key(sale)
            if not sale_date or not (start_date <= sale_date <= end_date):
                continue
            period_sales.append(sale)
        paid_sales = [x for x in period_sales if re.sub(r"\s+", " ", re.sub(r"[_-]+", " ", str(x.get("paymentStatus", x.get("payment_status", ""))).strip().lower())) in paid_statuses]
        def amount_for(x):
            for key in ("paidAmount", "paid_amount", "amountPaid", "amount_paid", "price", "salePrice", "sale_price"):
                try:
                    amount = float(x.get(key) or 0)
                except (TypeError, ValueError):
                    continue
                if amount > 0:
                    return amount
            return 0.0
        revenue = sum(amount_for(x) for x in paid_sales)
        available_products = [p for p in products if isinstance(p, dict) and str(p.get("status") or "").strip().upper() not in {"SOLD", "DELETED", "REMOVED", "ARCHIVED"}]
        def report_product_id(sale):
            direct = sale.get("productId") or sale.get("product_id") or sale.get("serial")
            if direct: return str(direct)
            sid = sale.get("id")
            by_id = [p for p in products if isinstance(p, dict) and sid is not None and str(p.get("id")) == str(sid)]
            if len(by_id) == 1: return str(by_id[0].get("productId") or by_id[0].get("product_id") or ("PR-" + str(by_id[0].get("id")).zfill(5)))
            model = str(sale.get("model") or "").strip()
            by_model = [p for p in products if isinstance(p, dict) and model and str(p.get("model") or "").strip() == model]
            if len(by_model) == 1: return str(by_model[0].get("productId") or by_model[0].get("product_id") or ("PR-" + str(by_model[0].get("id")).zfill(5)))
            return "—"
        manual_in = sum(float(x.get("amount_etb") or 0) for x in ledger if x.get("direction") == "in" and not x.get("source_ref"))
        money_out = sum(float(x.get("amount_etb") or 0) for x in ledger if x.get("direction") == "out")
        balance = revenue + manual_in - money_out
        # Authorized Telegram recipients are the Main Admin and active Workshop ERP assignments.
        assignments = state.get("workshopAssignments", []) if isinstance(state.get("workshopAssignments", []), list) else []
        recipient_ids = {owner_id}
        recipient_labels = {owner_id: "Main Admin 1"}
        try:
            super_admin_rows = supabase_request("GET", "/rest/v1/ambar_admin_roles", params={"select":"telegram_user_id,display_name,role,active,permissions", "active":"eq.true", "limit":"500"}) or []
            for admin_row in super_admin_rows:
                if admin_row.get("role") == "super_admin" and str(admin_row.get("telegram_user_id") or "").isdigit():
                    sid = str(admin_row["telegram_user_id"])
                    recipient_ids.add(sid)
                    recipient_labels[sid] = (str(admin_row.get("display_name") or "Main Admin 2")[:80])
        except Exception:
            log.exception("Could not load additional main-admin report recipients")
        for assignment in assignments:
            if not isinstance(assignment, dict) or assignment.get("active") is False:
                continue
            rid = str(assignment.get("telegram_user_id") or "").strip()
            if rid.isdigit():
                recipient_ids.add(rid)
                recipient_labels[rid] = str(assignment.get("display_name") or assignment.get("name") or ("Telegram user " + rid))[:100]
        target_chat_id = str(request_data.get("recipientTelegramId") or "").strip()
        if action == "send":
            if not target_chat_id or target_chat_id not in recipient_ids:
                return jsonify(error="Choose a Telegram recipient listed in the dashboard. Only the Main Admin and assigned Workshop ERP users can receive these reports."), 400
            if not BOT_TOKEN:
                return jsonify(error="Telegram sending is not configured. Add BOT_TOKEN to Render environment variables."), 503
        def safe(v, limit=180):
            return str(v if v is not None else "—").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")[:limit]
        period_names = {"daily":"Daily", "weekly":"Weekly", "monthly":"Monthly", "yearly":"Yearly"}
        period_label = period_names[period]
        buf = BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=landscape(A4), rightMargin=10*mm, leftMargin=10*mm, topMargin=10*mm, bottomMargin=12*mm, title=f"AMBAR {period_label} Financial and Inventory Report")
        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(name="AmbarTitle", parent=styles["Title"], textColor=colors.HexColor("#805b26"), fontSize=17, spaceAfter=7))
        styles.add(ParagraphStyle(name="SmallCell", parent=styles["BodyText"], fontSize=7, leading=9))
        sender_role = admin_permissions_for(user_id) or {}
        prepared_by_label = "Main Admin 1" if str(user_id) == owner_id else (str(sender_role.get("display_name") or "Main Admin 2")[:80])
        story = [Paragraph("AMBAR FURNITURE — FINANCIAL &amp; INVENTORY REPORT", styles["AmbarTitle"]),
                 Paragraph(f"{period_label} report · {start_date} to {end_date} · Opening balance: ETB 0.00 from Monday, 26 October 2026", styles["Normal"]),
                 Paragraph("Source: Workshop ERP shared state and its finance ledger · Prepared by: " + safe(prepared_by_label, 80) + " · Generated: " + dt.datetime.now().strftime("%Y-%m-%d %H:%M"), styles["Normal"]), Spacer(1, 8)]
        def add_table(rows, widths, font=7):
            table = Table(rows, colWidths=widths, repeatRows=1, hAlign="LEFT")
            table.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#183b35")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),0.35,colors.HexColor("#d6d0c4")),("BACKGROUND",(0,1),(-1,-1),colors.HexColor("#faf7f0")),("TEXTCOLOR",(0,1),(-1,-1),colors.HexColor("#222222")),("FONTSIZE",(0,0),(-1,-1),font),("VALIGN",(0,0),(-1,-1),"TOP"),("PADDING",(0,0),(-1,-1),4)]))
            story.append(table)
        summary = [["Metric", "Amount / Count"], ["Opening balance", "ETB 0.00"], ["Fully paid Workshop ERP sales", f"ETB {revenue:,.2f}"], ["Manual Money In", f"ETB {manual_in:,.2f}"], ["Money Out", f"ETB {money_out:,.2f}"], ["Indicative net movement", f"ETB {balance:,.2f}"], ["All sales in period", str(len(period_sales))], ["Fully paid sales", str(len(paid_sales))], ["Available finished units", str(len(available_products))], ["Raw materials", str(len(materials))]]
        add_table(summary, [75*mm, 65*mm], 8)
        story += [Spacer(1, 10), Paragraph("Workshop ERP sales", styles["Heading2"])]
        rows_sales = [["Date", "Product ID", "Model", "Customer", "Salesperson", "Payment", "Sale ETB"]]
        for x in sorted(period_sales, key=_finance_date_key, reverse=True):
            rows_sales.append([_finance_date_key(x) or "—", safe(report_product_id(x), 28), safe(x.get("model") or x.get("name") or "—", 45), safe(x.get("customer"), 32), safe(x.get("rep") or x.get("salesperson"), 22), safe(x.get("paymentStatus") or x.get("payment_status"), 22), f"{amount_for(x):,.2f}"])
        if len(rows_sales) == 1: rows_sales.append(["—", "—", "No sales recorded in this period", "—", "—", "—", "0.00"])
        add_table(rows_sales, [20*mm, 28*mm, 40*mm, 32*mm, 25*mm, 28*mm, 25*mm], 6)
        story += [Spacer(1, 10), Paragraph("Finished-unit inventory (live Workshop ERP stock)", styles["Heading2"])]
        rows_inv = [["Product ID", "Model / Product", "Category", "Stock Type", "Status", "Price ETB"]]
        for p in available_products:
            rows_inv.append([safe(p.get("productId") or p.get("product_id") or ("PR-" + str(p.get("id")).zfill(5) if p.get("id") is not None else "—"), 28), safe(p.get("model") or p.get("name") or p.get("title"), 50), safe(p.get("category"), 25), safe(p.get("stockType") or p.get("stock_type"), 15), safe(p.get("status"), 20), f"{float(p.get('price', p.get('salePrice', p.get('sale_price', 0))) or 0):,.2f}"])
        if len(rows_inv) == 1: rows_inv.append(["—", "No available finished units", "—", "—", "—", "0.00"])
        add_table(rows_inv, [55*mm, 32*mm, 36*mm, 25*mm, 30*mm, 25*mm], 7)
        story += [Spacer(1, 10), Paragraph("Raw-material inventory", styles["Heading2"])]
        rows_mat = [["Material ID", "Material", "On hand", "Unit", "Reorder threshold", "Unit cost ETB", "Stock value ETB", "Stock status"]]
        def stock_value(m):
            for key in ("on_hand", "onHand", "stock", "quantity", "qty", "stock_quantity", "stockQuantity", "available_stock"):
                if m.get(key) is not None and str(m.get(key)).strip() != "":
                    try: return max(0, float(m[key]))
                    except (ValueError, TypeError): pass
            return 0.0
        for m in materials:
            if not isinstance(m, dict): continue
            stock = stock_value(m); cost = float(m.get("cost", m.get("unitCost", m.get("unit_cost", 0))) or 0)
            threshold = float(m.get("threshold", m.get("reorderLevel", m.get("reorder_level", m.get("minimumStock", m.get("minimum_stock", 0))))) or 0)
            material_id = m.get("id", m.get("materialId", m.get("material_id", "—")))
            rows_mat.append([safe(material_id, 20), safe(m.get("name") or m.get("materialName") or m.get("material_name"), 40), f"{stock:g}", safe(m.get("unit"), 12), f"{threshold:g}", f"{cost:,.2f}", f"{stock*cost:,.2f}", "LOW STOCK" if threshold > 0 and stock <= threshold else "OK"])
        if len(rows_mat) == 1: rows_mat.append(["—", "No raw materials", "0", "—", "0", "0.00", "0.00", "—"])
        add_table(rows_mat, [20*mm, 42*mm, 18*mm, 16*mm, 25*mm, 25*mm, 28*mm, 22*mm], 6)
        story += [Spacer(1, 10), Paragraph("Raw-material movements in selected period", styles["Heading2"])]
        movements = state.get("materialTransactions", []) if isinstance(state.get("materialTransactions", []), list) else []
        movements = [m for m in movements if isinstance(m, dict) and start_date <= str(m.get("date") or _finance_date_key(m) or "") <= end_date]
        rows_moves = [["Date", "Material", "Movement", "Quantity", "Unit", "Notes"]]
        for m in sorted(movements, key=lambda x: str(x.get("date") or _finance_date_key(x)), reverse=True):
            rows_moves.append([safe(m.get("date") or _finance_date_key(m), 12), safe(m.get("materialName") or m.get("name"), 42), "Stock added" if m.get("type") == "receipt" else "Usage / cut", str(m.get("qty") or 0), safe(m.get("unit"), 12), safe(m.get("notes"), 75)])
        if len(rows_moves) == 1: rows_moves.append(["—", "No material movements", "—", "0", "—", "—"])
        add_table(rows_moves, [25*mm, 45*mm, 35*mm, 22*mm, 20*mm, 70*mm], 7)
        story += [Spacer(1, 10), Paragraph("Money ledger in selected period", styles["Heading2"])]
        rows_ledger = [["Date", "Direction", "Category", "Description", "Amount ETB"]]
        for x in ledger: rows_ledger.append([safe(x.get("entry_date"), 12), safe(x.get("direction"), 12).upper(), safe(x.get("category"), 30), safe(x.get("description"), 85), f"{float(x.get('amount_etb') or 0):,.2f}"])
        if len(rows_ledger) == 1: rows_ledger.append(["—", "—", "No ledger entries", "Opening balance is zero", "0.00"])
        add_table(rows_ledger, [25*mm, 25*mm, 38*mm, 135*mm, 28*mm], 7)
        doc.build(story)
        pdf_bytes = buf.getvalue()
        if not pdf_bytes.startswith(b"%PDF-") or len(pdf_bytes) < 500:
            return jsonify(error="The finance report generator did not produce a valid PDF. Please retry."), 500
        filename = f"AMBAR_Financial_Inventory_{period}_{start_date}_to_{end_date}.pdf"
        if action == "send":
            if len(pdf_bytes) > 7 * 1024 * 1024:
                return jsonify(error="This PDF is too large for Telegram. Narrow the report period and retry."), 413
            upload = BytesIO(pdf_bytes); upload.name = filename
            caption = f"AMBAR {period_label} Financial & Inventory Report\nPeriod: {start_date} to {end_date}\nOpening balance: ETB 0.00 from Monday, 26 October 2026\nPrepared by: {prepared_by_label}"
            try:
                result = bot_api("sendDocument", {"chat_id": target_chat_id, "caption": caption[:1024]}, {"document": (filename, upload, "application/pdf")}, timeout=60)
            except Exception as exc:
                log.exception("Could not send finance PDF to selected Telegram user %s", target_chat_id)
                reason = str(exc)[:240]
                if any(term in reason.lower() for term in ("chat not found", "bot was blocked", "can't initiate conversation", "user is deactivated")):
                    reason += " The selected user must open/start the AMBAR Telegram bot before receiving files."
                return jsonify(error="Telegram could not send the PDF. " + reason), 502
            write_security_event("finance_inventory_pdf_sent", actor_id=str(user_id), path=request.path, method="POST", status_code=200, details={"period":period,"start_date":start_date,"end_date":end_date,"recipient_chat_id":target_chat_id,"message_id":(result or {}).get("message_id")})
            return jsonify(ok=True, message=f"{period_label} PDF sent to {recipient_labels.get(target_chat_id, target_chat_id)}.", messageId=(result or {}).get("message_id"))
        write_security_event("finance_inventory_pdf_downloaded", actor_id=str(user_id), path=request.path, method="POST", status_code=200, details={"period":period,"start_date":start_date,"end_date":end_date})
        return send_file(BytesIO(pdf_bytes), mimetype="application/pdf", as_attachment=True, download_name=filename)
    except Exception as exc:
        log.exception("Could not generate finance dashboard PDF")
        detail = str(exc)[:220] or "Unknown error"
        return jsonify(error="Could not generate the finance PDF. Check Render logs. Details: " + detail), 500


@app.post("/api/admin/phase2/delivery-areas")
def phase2_save_delivery_area():
    _, error = admin_user_from_request()
    if error: return error
    if not supabase_enabled(): return jsonify(error="Supabase is not configured."), 503
    data = request.get_json(silent=True) or {}
    name = clean_text(data.get("area_name"), 120, "Delivery area", True)
    try:
        fee = float(data.get("fee_etb", 0)); days = int(data.get("estimated_days", 5))
        if fee < 0 or days < 1 or days > 90: raise ValueError()
    except (TypeError, ValueError): return jsonify(error="Enter a non-negative fee and delivery estimate from 1 to 90 days."), 400
    payload = {"area_name":name,"fee_etb":fee,"estimated_days":days,"active":bool(data.get("active", True)),"updated_at":dt.datetime.now(dt.timezone.utc).isoformat()}
    try:
        area_id = data.get("id")
        if area_id:
            rows = supabase_request("PATCH", "/rest/v1/delivery_areas", params={"id":f"eq.{int(area_id)}"}, payload=payload) or []
        else:
            rows = supabase_request("POST", "/rest/v1/delivery_areas", payload=payload) or []
        return jsonify(ok=True, area=(rows[0] if rows else payload))
    except Exception:
        log.exception("Could not save delivery area")
        return jsonify(error="Could not save delivery area. Check that the Phase 2 SQL migration has been run and area names are unique."), 503


@app.delete("/api/admin/phase2/orders/<reference>")
def phase2_delete_order(reference):
    """Permanently remove an order from the admin tracking database."""
    _, error = admin_user_from_request()
    if error: return error
    if not supabase_enabled(): return jsonify(error="Supabase is not configured."), 503
    try:
        existing = supabase_request("GET", "/rest/v1/customer_orders", params={
            "select": "reference", "reference": f"eq.{reference}", "limit": "1"
        }) or []
        if not existing:
            return jsonify(error="Order not found."), 404
        supabase_request("DELETE", "/rest/v1/customer_orders", params={"reference": f"eq.{reference}"})
        return jsonify(ok=True, reference=reference, message="Order permanently deleted.")
    except Exception:
        log.exception("Admin could not delete order %s", reference)
        return jsonify(error="Could not delete this order. Check Supabase configuration and try again."), 503


def sync_confirmed_customer_order_to_workshop(order):
    """Idempotently import one saved Mini App customer order into Workshop ERP when an admin explicitly requests it."""
    if not isinstance(order, dict):
        raise RuntimeError("The customer order could not be read.")
    reference = str(order.get("reference") or "").strip()
    if not reference:
        raise RuntimeError("The customer order has no reference number.")
    items = order.get("items")
    if not isinstance(items, list) or not items:
        raise RuntimeError("This customer order has no saved product line items to send to production.")
    if not supabase_enabled():
        raise RuntimeError("Supabase is not configured.")

    # Use the same catalogue metadata that the Mini App uses, but do not require
    # a catalogue lookup to succeed: the saved order line remains the source of truth.
    try:
        load_product_catalog()
    except Exception:
        log.exception("Could not refresh product catalogue while importing order %s", reference)

    for attempt in range(5):
        rows = supabase_request("GET", "/rest/v1/workshop_erp_state", params={
            "select": "id,state,updated_at", "id": "eq.1", "limit": "1"
        }) or []
        if not rows or not isinstance(rows[0].get("state"), dict):
            raise RuntimeError("Workshop ERP shared state is not initialized. Open Workshop ERP as Main Admin, refresh it, then click Create Workshop Workflow Order again.")
        current = rows[0]
        state = current["state"]
        work_orders = state.get("orders", [])
        if not isinstance(work_orders, list): work_orders = []
        existing_source_items = {
            (str(x.get("sourceCustomerOrderReference") or ""), str(x.get("sourceCustomerOrderItemIndex") or ""))
            for x in work_orders if isinstance(x, dict)
        }
        now = dt.datetime.now(dt.timezone.utc).isoformat()
        created = 0
        for index, item in enumerate(items, start=1):
            if not isinstance(item, dict):
                continue
            source_key = (reference, str(index))
            if source_key in existing_source_items:
                continue
            catalog_id = str(item.get("id") or item.get("product_id") or item.get("productId") or "").strip()
            catalog_product = PRODUCTS.get(catalog_id, {}) if isinstance(PRODUCTS, dict) else {}
            model = str(item.get("name") or item.get("product_name") or item.get("title") or catalog_product.get("name") or catalog_id or "Customer order product").strip()
            category = str(item.get("category") or catalog_product.get("category") or "Other").strip() or "Other"
            try:
                quantity = int(item.get("quantity", 1))
            except (TypeError, ValueError):
                quantity = 1
            quantity = max(1, min(99, quantity))
            serial = f"WEB-{reference}-{index:02d}"
            # If a manually-created record happens to use the same serial, keep
            # the import deterministic while avoiding overwriting that record.
            used_ids = {str(x.get("serial") or x.get("productId") or "") for x in work_orders if isinstance(x, dict)}
            if serial in used_ids:
                serial = f"WEB-{reference}-{index:02d}-MINIAPP"
                if serial in used_ids:
                    raise RuntimeError(f"A different workshop record already uses the generated ID for order {reference}, item {index}.")
            measurement = str(item.get("measurement") or "Not specified").strip()
            line_notes = str(order.get("notes") or "").strip()
            description_parts = [f"Mini App customer order {reference}", f"Customer: {order.get('customer_name') or 'Not provided'}"]
            if order.get("phone"): description_parts.append(f"Phone: {order.get('phone')}")
            description_parts.append(f"Measurement: {measurement}")
            if line_notes: description_parts.append(f"Customer notes: {line_notes}")
            if catalog_id: description_parts.append(f"Catalogue product ID: {catalog_id}")
            work_orders.append({
                "productId": serial,
                "serial": serial,
                "model": model,
                "category": category,
                "description": " · ".join(description_parts)[:1500],
                "priority": "MEDIUM",
                "rep": "",
                "location": str(order.get("delivery_location") or "Workshop · confirm delivery requirements")[:300],
                "qty": quantity,
                "stockType": "O",
                "orderType": "ORDER",
                "stage": "Cutting & Prep",
                "startedAt": now,
                "finishedAt": "",
                "stageHistory": [{"stage": "Cutting & Prep", "at": now, "action": "manually imported from Mini App customer order"}],
                "sourceCustomerOrderReference": reference,
                "sourceCustomerOrderItemIndex": index,
                "catalogProductId": catalog_id,
                "customerName": str(order.get("customer_name") or "")[:120],
                "customerPhone": str(order.get("phone") or "")[:30],
                "customerTelegramUserId": str(order.get("telegram_user_id") or ""),
                "customerDeliveryLocation": str(order.get("delivery_location") or "")[:300],
                "customerPaymentStatus": str(order.get("payment_status") or "Pending review")[:100],
                "customerOrderTotalEtb": order.get("total_etb", 0),
                "importedFromMiniApp": True,
            })
            existing_source_items.add(source_key)
            created += 1
        if created == 0:
            return {"ok": True, "created": 0, "total_items": len(items), "already_imported": True}

        state["orders"] = work_orders
        activity = state.get("activityLog", [])
        if not isinstance(activity, list): activity = []
        activity.append(f"Admin manually sent Mini App customer order {reference} to Workshop ERP; created {created} production workflow item(s)")
        state["activityLog"] = activity[-1000:]
        patched = supabase_request("PATCH", "/rest/v1/workshop_erp_state", params={
            "id": "eq.1", "updated_at": f"eq.{current.get('updated_at')}"
        }, payload={"state": state, "updated_at": now, "updated_by": "main-admin-order-sync"},
            extra_headers={"Prefer": "return=representation"}) or []
        if patched:
            return {"ok": True, "created": created, "total_items": len(items), "already_imported": False}
    raise RuntimeError("Workshop data changed while importing this order. Click Create Workshop Workflow Order again to retry safely.")


@app.post("/api/admin/order-dispatch/new-design")
def admin_send_new_design_to_telegram():
    """Send an admin-created readymade order idea directly to a chosen Telegram chat; no order/ERP/finance record is created."""
    _, error = admin_user_from_request()
    if error: return error
    if not BOT_TOKEN:
        return jsonify(error="Telegram sending is not configured: BOT_TOKEN is missing on the server."), 503
    data = request.get_json(silent=True) or {}
    target_chat = str(data.get("chat_id") or "").strip()
    name = str(data.get("name") or "").strip()[:150]
    photo_url = str(data.get("photo_url") or "").strip()[:1500]
    photo_base64 = str(data.get("photo_base64") or "").strip()
    photo_mime = str(data.get("photo_mime") or "image/jpeg").strip().lower()
    photo_name = secure_filename(str(data.get("photo_name") or "ambar-design.jpg"))[:120] or "ambar-design.jpg"
    product_id = str(data.get("product_id") or "").strip()[:100]
    model = str(data.get("model") or "").strip()[:120]
    salesperson = str(data.get("salesperson") or "").strip()[:120]
    measurement_type = str(data.get("measurement_type") or "").strip()[:40]
    measurements = str(data.get("measurements") or "").strip()[:300]
    handle_type = str(data.get("handle_type") or "").strip()[:120]
    color = str(data.get("color") or "").strip()[:120]
    description = str(data.get("description") or "").strip()[:1800]
    additional_text = str(data.get("additional_text") or "").strip()[:1200]
    if not target_chat:
        return jsonify(error="Enter a Telegram group/channel username or chat ID."), 400
    if not re.fullmatch(r"@[A-Za-z0-9_]{5,}|-?\d{5,20}", target_chat):
        return jsonify(error="Telegram destination must be a public @username or numeric chat ID."), 400
    if photo_url and not re.match(r"^https?://", photo_url, re.I):
        return jsonify(error="Photo URL must start with http:// or https://."), 400
    uploaded_photo = None
    if photo_base64:
        if photo_mime not in {"image/jpeg", "image/png", "image/webp"}:
            return jsonify(error="Upload a JPG, PNG, or WebP photo."), 400
        try:
            raw_photo = base64.b64decode(photo_base64, validate=True)
        except Exception:
            return jsonify(error="Uploaded photo data is invalid."), 400
        if not raw_photo or len(raw_photo) > 5 * 1024 * 1024:
            return jsonify(error="Photo must be 5 MB or smaller."), 400
        uploaded_photo = (photo_name, BytesIO(raw_photo), photo_mime)
    # Modern production ticket. Every optional field is omitted completely when blank.
    lines = ["<b>AMBAR FURNITURE</b>", "<b>READYMADE ORDER</b>"]
    if name: lines.extend(["", f"<b>Product:</b> {html.escape(name)}"])
    work_lines = []
    if product_id: work_lines.append(f"<b>Product ID:</b> {html.escape(product_id)}")
    if model: work_lines.append(f"<b>Model:</b> {html.escape(model)}")
    if handle_type: work_lines.append(f"<b>Handle type:</b> {html.escape(handle_type)}")
    if color: work_lines.append(f"<b>Color:</b> {html.escape(color)}")
    if measurement_type: work_lines.append(f"<b>Measurement type:</b> {html.escape(measurement_type)}")
    if measurements: work_lines.append(f"<b>Measurements:</b> {html.escape(measurements)}")
    if salesperson: work_lines.append(f"<b>Salesman:</b> {html.escape(salesperson)}")
    if description: work_lines.append(f"<b>Work instructions:</b> {html.escape(description)}")
    if additional_text: work_lines.append(f"<b>Additional text:</b> {html.escape(additional_text)}")
    if work_lines: lines.extend(["", "━━━━━━━━━━━━━━━━━━", "<b>WORK DETAILS</b>", "", *work_lines])
    message = "\n".join(lines)
    try:
        if uploaded_photo:
            telegram_result = bot_api("sendPhoto", {"chat_id": target_chat, "caption": message[:1000], "parse_mode": "HTML"}, files={"photo": uploaded_photo})
            if len(message) > 1000:
                bot_api("sendMessage", {"chat_id": target_chat, "text": message[1000:], "parse_mode": "HTML", "disable_web_page_preview": True})
        elif photo_url:
            telegram_result = bot_api("sendPhoto", {"chat_id": target_chat, "photo": photo_url, "caption": message[:1000], "parse_mode": "HTML"})
            if len(message) > 1000:
                bot_api("sendMessage", {"chat_id": target_chat, "text": message[1000:], "parse_mode": "HTML", "disable_web_page_preview": True})
        else:
            telegram_result = bot_api("sendMessage", {"chat_id": target_chat, "text": message, "parse_mode": "HTML", "disable_web_page_preview": True})
        return jsonify(ok=True, sent=True, message="New readymade order sent to the selected Telegram destination.", telegram_message_id=(telegram_result or {}).get("message_id")), 200
    except Exception as exc:
        log.exception("Could not send AMBAR readymade order to Telegram destination %s", target_chat)
        return jsonify(error=(str(exc) or "Telegram message failed.")[:300]), 502


@app.post("/api/admin/phase2/orders/<reference>/send-to-workers")
def phase2_send_order_to_workers(reference):
    """Send one saved customer order to the configured private workers group, without changing ERP/finance data."""
    _, error = admin_user_from_request()
    if error: return error
    if not supabase_enabled(): return jsonify(error="Supabase is not configured."), 503
    if not BOT_TOKEN: return jsonify(error="Telegram sending is not configured: BOT_TOKEN is missing on the server."), 503
    try:
        dispatch_options = request.get_json(silent=True) or {}
        target_chat = str(dispatch_options.get("chat_id") or WORKERS_TELEGRAM_CHAT_ID).strip()
        if not target_chat:
            return jsonify(error="Enter a Telegram group/channel username or chat ID in Order Dispatch, or configure WORKERS_TELEGRAM_CHAT_ID in Render."), 400
        if not re.fullmatch(r"@[A-Za-z0-9_]{5,}|-?\d{5,20}", target_chat):
            return jsonify(error="Telegram destination must be a public @username or numeric chat ID (private groups usually begin with -100)."), 400
        product_id = str(dispatch_options.get("product_id") or "").strip()[:100]
        model = str(dispatch_options.get("model") or "").strip()[:120]
        description = str(dispatch_options.get("description") or "").strip()[:1200]
        salesperson = str(dispatch_options.get("salesperson") or "").strip()[:120]
        measurement_type = str(dispatch_options.get("measurement_type") or "").strip()[:40]
        measurements = str(dispatch_options.get("measurements") or "").strip()[:300]
        raw_item_details = dispatch_options.get("item_details") if isinstance(dispatch_options.get("item_details"), list) else []
        item_details = {}
        for detail in raw_item_details[:30]:
            if isinstance(detail, dict):
                try: idx = int(detail.get("index", -1))
                except (TypeError, ValueError): continue
                if idx >= 0: item_details[idx] = {
                    "product_id": str(detail.get("product_id") or "").strip()[:100],
                    "model": str(detail.get("model") or "").strip()[:120],
                    "salesperson": str(detail.get("salesperson") or "").strip()[:120],
                    "measurement_type": str(detail.get("measurement_type") or "").strip()[:40],
                    "measurements": str(detail.get("measurements") or "").strip()[:300],
                    "handle_type": str(detail.get("handle_type") or "").strip()[:120],
                    "color": str(detail.get("color") or "").strip()[:120],
                    "description": str(detail.get("description") or "").strip()[:1200],
                    "additional_text": str(detail.get("additional_text") or "").strip()[:1000],
                }
        rows = supabase_request("GET", "/rest/v1/customer_orders", params={"select":"*", "reference":f"eq.{reference}", "limit":"1"}) or []
        if not rows: return jsonify(error="Customer order not found."), 404
        order = rows[0]
        status = str(order.get("status") or "Received").strip().casefold()
        if status in {"cancelled", "canceled", "delivered"}:
            return jsonify(error=f"A {order.get('status')} customer order cannot be dispatched to workers."), 409
        # Dispatch-history writes are best-effort. A missing/unapplied optional migration must
        # never prevent the actual Telegram send from happening.
        dispatch_history_available = True
        try:
            prior = supabase_request("GET", "/rest/v1/worker_order_dispatches", params={"select":"reference,status", "reference":f"eq.{reference}", "limit":"1"}) or []
            if prior:
                supabase_request("PATCH", "/rest/v1/worker_order_dispatches", params={"reference":f"eq.{reference}"}, payload={"status":"sending", "last_error":None, "updated_at":dt.datetime.now(dt.timezone.utc).isoformat()})
            else:
                supabase_request("POST", "/rest/v1/worker_order_dispatches", payload={"reference":str(reference), "status":"sending", "last_error":None})
        except Exception:
            dispatch_history_available = False
            log.exception("Dispatch history unavailable for order %s; continuing with Telegram send", reference)
        items = order.get("items") if isinstance(order.get("items"), list) else []
        dispatch_item_index = dispatch_options.get("dispatch_item_index")
        single_product_dispatch = dispatch_item_index is not None
        if single_product_dispatch:
            try:
                source_item_index = int(dispatch_item_index)
            except (TypeError, ValueError):
                return jsonify(error="Invalid product index for dispatch."), 400
            if source_item_index < 0 or source_item_index >= len(items) or not isinstance(items[source_item_index], dict):
                return jsonify(error="The selected product was not found in this customer order."), 400
            items = [items[source_item_index]]
            item_details = {0: item_details.get(0, {})}
        lines = []
        first_photo = ""
        first_item = items[0] if items and isinstance(items[0], dict) else {}
        for item_index, item in enumerate(items[:30]):
            if not isinstance(item, dict): continue
            name = str(item.get("name") or item.get("product_name") or item.get("title") or "Product")[:150]
            qty = item.get("quantity", 1)
            unit = item.get("unit_price", item.get("unit_price_etb", item.get("price_etb", item.get("price", 0))))
            measurement = item.get("measurement") or item.get("measurements")
            line = f"• {name} × {qty} — {unit} ETB each"
            if measurement: line += f" · Measurement: {str(measurement)[:120]}"
            detail = item_details.get(item_index, {})
            item_product_id = detail.get("product_id") or str(item.get("product_id") or item.get("id") or "").strip()[:100]
            item_model = detail.get("model") or str(item.get("model") or item.get("product_model") or "").strip()[:120]
            if item_product_id: line += f" · Product ID: {item_product_id}"
            if item_model: line += f" · Model: {item_model}"
            lines.append(line)
        # If no item lines are available, omit the section rather than sending placeholder text.
        for candidate in (first_item.get("image_url"), first_item.get("image"), first_item.get("photo_url"), first_item.get("product_image"), first_item.get("photo")):
            if isinstance(candidate, str) and candidate.startswith(("https://", "http://")):
                first_photo = candidate.strip(); break
        if not first_photo and isinstance(first_item.get("images"), list):
            for candidate in first_item["images"]:
                if isinstance(candidate, str) and candidate.startswith(("https://", "http://")):
                    first_photo = candidate.strip(); break
        customer = html.escape(str(order.get("customer_name") or "Not provided")[:120])
        phone = html.escape(str(order.get("phone") or "Not provided")[:60])
        location = html.escape(str(order.get("delivery_location") or order.get("delivery_area") or "To be confirmed")[:300])
        notes = html.escape(str(order.get("notes") or "None")[:500])
        items_text = "\n".join(html.escape(line) for line in lines)
        selected_detail = item_details.get(0, {}) if single_product_dispatch else {}
        # Product-specific details are optional; only entered values are included.
        detail_values = {
            "Product ID": selected_detail.get("product_id") or product_id,
            "Model": selected_detail.get("model") or model,
            "Salesman": selected_detail.get("salesperson") or salesperson,
            "Handle type": selected_detail.get("handle_type") or str(dispatch_options.get("handle_type") or "").strip(),
            "Color": selected_detail.get("color") or str(dispatch_options.get("color") or "").strip(),
            "Measurement type": selected_detail.get("measurement_type") or measurement_type,
            "Measurements": selected_detail.get("measurements") or measurements,
            "Work instructions": selected_detail.get("description") or description,
            "Additional text": selected_detail.get("additional_text") or str(dispatch_options.get("additional_text") or "").strip(),
        }
        optional_lines = [f"<b>{html.escape(label)}:</b> {html.escape(str(value))}" for label, value in detail_values.items() if value and str(value).strip()]
        # Build a clean, modern production ticket; omit all blank optional fields.
        product_name = str(first_item.get("name") or first_item.get("product_name") or first_item.get("title") or "").strip()
        message_lines = ["<b>AMBAR FURNITURE</b>", "<b>CUSTOMER ORDER</b>", "", f"<b>Order reference:</b> {html.escape(str(reference))}"]
        if product_name: message_lines.extend([f"<b>Product:</b> {html.escape(product_name)}"])
        message_lines.extend(["", "━━━━━━━━━━━━━━━━━━", "<b>WORK DETAILS</b>", ""])
        if optional_lines: message_lines.extend(optional_lines)
        else: message_lines = message_lines[:-3]  # No empty work-details section when no optional details are entered.
        # Privacy boundary: never forward customer identity/contact/address/payment/notes to workers.
        message = "\n".join(message_lines)
        try:
            if first_photo:
                caption = message[:1000]
                telegram_result = bot_api("sendPhoto", {"chat_id": target_chat, "photo": first_photo, "caption": caption, "parse_mode":"HTML"})
                if len(message) > 1000:
                    bot_api("sendMessage", {"chat_id": target_chat, "text": message[1000:], "parse_mode":"HTML", "disable_web_page_preview":True})
            else:
                telegram_result = bot_api("sendMessage", {"chat_id": target_chat, "text": message, "parse_mode":"HTML", "disable_web_page_preview":True})
        except Exception as send_exc:
            try:
                if dispatch_history_available:
                    supabase_request("PATCH", "/rest/v1/worker_order_dispatches", params={"reference":f"eq.{reference}"}, payload={"status":"failed", "last_error":str(send_exc)[:300], "updated_at":dt.datetime.now(dt.timezone.utc).isoformat()})
            except Exception: log.exception("Could not record failed worker dispatch for order %s", reference)
            log.exception("Could not send order %s to workers Telegram group", reference)
            return jsonify(error=(str(send_exc) or "Telegram message failed.")[:300]), 502
        if dispatch_history_available:
            try:
                supabase_request("PATCH", "/rest/v1/worker_order_dispatches", params={"reference":f"eq.{reference}"}, payload={"status":"sent", "telegram_message_id":str((telegram_result or {}).get("message_id", "")), "last_error":None, "sent_at":dt.datetime.now(dt.timezone.utc).isoformat(), "updated_at":dt.datetime.now(dt.timezone.utc).isoformat()})
            except Exception:
                log.exception("Telegram sent for order %s but dispatch history could not be updated", reference)
        return jsonify(ok=True, sent=True, already_sent=False, reference=reference, message=f"Order sent to Telegram destination {target_chat}.", dispatch_history_saved=dispatch_history_available), 200
    except Exception as exc:
        log.exception("Worker dispatch failed for customer order %s", reference)
        return jsonify(error=(str(exc) or "Could not dispatch order to workers.")[:300]), 503


@app.post("/api/admin/phase2/orders/<reference>/send-to-workshop")
def phase2_send_order_to_workshop(reference):
    """Manually create Workshop ERP workflow items for one saved customer order."""
    _, error = admin_user_from_request()
    if error: return error
    if not supabase_enabled(): return jsonify(error="Supabase is not configured."), 503
    try:
        rows = supabase_request("GET", "/rest/v1/customer_orders", params={
            "select":"*", "reference":f"eq.{reference}", "limit":"1"
        }) or []
        if not rows:
            return jsonify(error="Customer order not found."), 404
        order = rows[0]
        status = str(order.get("status") or "Received").strip().casefold()
        if status in {"cancelled", "canceled", "delivered"}:
            return jsonify(error=f"A {order.get('status')} customer order cannot be sent to Workshop ERP."), 409
        result = sync_confirmed_customer_order_to_workshop(order)
        if result.get("already_imported") or result.get("created", 0) == 0:
            return jsonify(ok=True, reference=reference, already_imported=True, created=0,
                           message="This customer order is already linked to Workshop ERP. No duplicate workflow was created.")
        return jsonify(ok=True, reference=reference, already_imported=False,
                       created=result.get("created", 0), total_items=result.get("total_items", 0),
                       message=f"Created {result.get('created', 0)} Workshop ERP workflow item(s) for customer order {reference}.")
    except Exception as exc:
        log.exception("Admin could not send customer order %s to Workshop ERP", reference)
        return jsonify(error=(str(exc) or "Could not create Workshop ERP workflow order.")[:300]), 503


@app.patch("/api/admin/phase2/orders/<reference>")
def phase2_update_order(reference):
    _, error = admin_user_from_request()
    if error: return error
    if not supabase_enabled(): return jsonify(error="Supabase is not configured."), 503
    data = request.get_json(silent=True) or {}
    allowed = {"Pending", "Received", "Confirmed", "Preparing", "Ready for Delivery", "Delivered", "Cancelled"}
    payload = {"updated_at": dt.datetime.now(dt.timezone.utc).isoformat()}
    if "status" in data:
        status = str(data.get("status", ""))
        if status not in allowed: return jsonify(error="Invalid order status."), 400
        payload["status"] = status
    for field, limit in (("customer_name", 120), ("phone", 30), ("delivery_location", 300), ("notes", 1000)):
        if field in data: payload[field] = clean_text(data.get(field), limit, field.replace("_", " "), False)
    if "delivery_fee_etb" in data:
        try: fee = float(data["delivery_fee_etb"])
        except (TypeError, ValueError): return jsonify(error="Delivery fee must be a number."), 400
        if fee < 0: return jsonify(error="Delivery fee cannot be negative."), 400
        payload["delivery_fee_etb"] = fee

    try:
        # Read the saved status first so we only send a status message when the admin
        # actually changes the status, and use the exact persisted order as the source.
        before_rows = supabase_request("GET", "/rest/v1/customer_orders", params={
            "select": "reference,status,product_total_etb,delivery_fee_etb,total_etb,delivery_area,delivery_distance_km,telegram_user_id,customer_name,phone,delivery_location,notes",
            "reference": f"eq.{reference}", "limit": "1"
        }) or []
        if not before_rows: return jsonify(error="Order not found."), 404
        before = before_rows[0]
        if "delivery_fee_etb" in payload:
            payload["total_etb"] = float(before.get("product_total_etb") or 0) + payload["delivery_fee_etb"]

        rows = supabase_request("PATCH", "/rest/v1/customer_orders", params={"reference": f"eq.{reference}"}, payload=payload) or []
        if not rows: return jsonify(error="Order not found."), 404
        updated = rows[0]

        status_changed = "status" in payload and str(before.get("status") or "Pending") != str(updated.get("status") or "Pending")
        fee_changed = "delivery_fee_etb" in payload and float(before.get("delivery_fee_etb") or 0) != float(updated.get("delivery_fee_etb") or 0)
        # Customer orders are NOT automatically converted to Workshop ERP workflows.
        # An authorized admin must use the explicit "Create Workshop Workflow Order" button.
        customer_notification_sent = False
        customer_notification_error = None
        if (status_changed or fee_changed) and before.get("telegram_user_id") and BOT_TOKEN:
            try:
                o = {**before, **updated}
                status = str(o.get("status") or "Pending")
                customer = str(o.get("customer_name") or "Valued Customer").strip()
                status_messages = {
                    "Pending": ("🛎️ Order received", "ትዕዛዝዎ ደርሷል"),
                    "Received": ("📥 Order received", "ትዕዛዝዎ ተቀብለናል"),
                    "Confirmed": ("✅ Order confirmed", "ትዕዛዝዎ ተረጋግጧል"),
                    "Preparing": ("🛠️ Preparing your order", "ትዕዛዝዎ እየተዘጋጀ ነው"),
                    "Ready for Delivery": ("🚚 Ready for delivery", "ለማድረስ ዝግጁ ነው"),
                    "Delivered": ("🎉 Order delivered", "ትዕዛዝዎ ደርሷል"),
                    "Cancelled": ("⚠️ Order cancelled", "ትዕዛዝዎ ተሰርዟል"),
                }
                heading, status_am = status_messages.get(status, ("🔔 Order status updated", "የትዕዛዝዎ ሁኔታ ተዘምኗል"))
                if fee_changed and not status_changed:
                    heading, status_am = ("💳 Delivery fee updated", "የማድረሻ ክፍያ ተዘምኗል")
                lines = [
                    f"Hi {customer},",
                    f"{heading} / {status_am}",
                    f"🆔 Order ID: {o.get('reference')}",
                    f"📦 Status: {status} / {status_am}",
                ]
                if fee_changed:
                    lines.append(f"Delivery fee: {float(o.get('delivery_fee_etb') or 0):,.2f} ETB")
                bot_api("sendMessage", {"chat_id": str(o["telegram_user_id"]), "text": "\n".join(lines), "disable_web_page_preview": True})
                customer_notification_sent = True
            except Exception as notify_exc:
                customer_notification_error = str(notify_exc)[:240]
                log.exception("Order %s saved but customer Telegram update could not be sent", reference)
        elif (status_changed or fee_changed) and not before.get("telegram_user_id"):
            customer_notification_error = "This order has no linked Telegram customer ID."
        elif (status_changed or fee_changed) and not BOT_TOKEN:
            customer_notification_error = "BOT_TOKEN is not configured on the server."
        return jsonify(ok=True, order=updated, status_changed=status_changed,
                       customer_notification_sent=customer_notification_sent,
                       customer_notification_error=customer_notification_error)
    except Exception:
        log.exception("Could not update order status")
        return jsonify(error="Could not update order status. Run the Phase 2 SQL migration first."), 503


@app.get("/api/products")
def public_products():
    catalog = load_product_catalog()
    overrides = []
    deleted_ids = []
    if supabase_enabled():
        try:
            for row in supabase_list_products(include_inactive=True):
                pid = str(row.get("id", ""))
                if pid in BASE_PRODUCTS:
                    if not bool(row.get("active", True)):
                        deleted_ids.append(pid)
                    else:
                        overrides.append(public_admin_product(pid, supabase_product_to_item(row)))
        except Exception:
            log.exception("Could not load built-in product overrides")
    overrides.extend(public_admin_product(pid, item) for pid, item in catalog.items()
                     if pid.startswith("admin_") and item.get("active", True))
    overrides.sort(key=lambda p: (not bool(p.get("pinned", False)), str(p.get("name", "")).lower()))
    return jsonify(products=overrides, deleted_ids=deleted_ids)


@app.post("/api/admin/security/sign-in")
def admin_security_sign_in():
    """Record a verified admin sign-in from the admin UI."""
    user_id, error = admin_user_from_request()
    if error:
        return error
    stored = write_security_event("admin_sign_in", actor_id=user_id, status_code=200,
                                  details={"source": "telegram_mini_app_admin"})
    if not stored:
        return jsonify(ok=True, warning="Sign-in verified, but audit logging is unavailable. Apply admin_security_reports_migration.sql and check Supabase configuration."), 200
    return jsonify(ok=True), 200


@app.get("/api/admin/security/report")
def admin_security_report():
    """Return recent sign-ins, failed attempts, suspicious access and admin activity to the main admin only."""
    user_id, error = admin_user_from_request()
    if error:
        return error
    if not is_main_admin_user(user_id):
        return jsonify(error="Only the main admin can view the full activity report."), 403
    if not supabase_enabled():
        return jsonify(error="Supabase is not configured; security reports require persistent Supabase storage."), 503
    try:
        raw_days = request.args.get("days", "30")
        days = int(raw_days)
        if days not in {7, 30, 90, 365}:
            return jsonify(error="Choose a report period of 7, 30, 90, or 365 days."), 400
        since = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)).isoformat()
        rows = supabase_request("GET", "/rest/v1/admin_security_events", params={
            "select": "id,event_type,actor_telegram_id,request_path,request_method,status_code,ip_address,user_agent,details,created_at",
            "created_at": f"gte.{since}", "order": "created_at.desc", "limit": "1000"
        }) or []
        counts = {
            "total": len(rows),
            "sign_ins": sum(1 for row in rows if row.get("event_type") == "admin_sign_in"),
            "customer_sign_ins": sum(1 for row in rows if row.get("event_type") == "customer_sign_in"),
            "failed": sum(1 for row in rows if row.get("event_type") in {"failed_admin_auth", "failed_customer_auth"}),
            "unauthorized": sum(1 for row in rows if row.get("event_type") == "unauthorized_admin_access"),
            "admin_actions": sum(1 for row in rows if row.get("event_type") == "admin_action"),
        }
        # Build a small daily series in UTC; the UI labels dates in Ethiopia time.
        daily = {}
        for row in rows:
            stamp = str(row.get("created_at") or "")[:10]
            if stamp:
                daily[stamp] = daily.get(stamp, 0) + 1
        return jsonify(days=days, counts=counts, events=rows,
                       daily=[{"date": key, "count": daily[key]} for key in sorted(daily)])
    except Exception:
        log.exception("Could not load admin security report")
        return jsonify(error="Could not load security report. Run admin_security_reports_migration.sql in Supabase, then refresh."), 503


@app.get("/api/admin/customers")
def admin_customer_directory():
    """Admin-only customer directory built from customer-submitted orders and verified activity logs."""
    _, error = admin_user_from_request()
    if error:
        return error
    if not supabase_enabled():
        return jsonify(error="Supabase is required to load customer information."), 503
    try:
        orders = supabase_request("GET", "/rest/v1/customer_orders", params={
            "select": "reference,telegram_user_id,telegram_username,customer_name,phone,delivery_location,contact_preference,status,total_etb,created_at,updated_at",
            "order": "created_at.desc", "limit": "5000"
        }) or []
        try:
            events = supabase_request("GET", "/rest/v1/admin_security_events", params={
                "select": "actor_telegram_id,ip_address,user_agent,created_at,event_type",
                "event_type": "in.(customer_sign_in,mini_app_open)", "order": "created_at.desc", "limit": "5000"
            }) or []
        except Exception:
            log.warning("Customer directory loaded without security activity metadata")
            events = []

        def blank_customer(user_id):
            return {
                "telegram_user_id": user_id, "username": "", "name": "", "phone": "",
                "delivery_location": "", "contact_preference": "", "orders": 0,
                "delivered_orders": 0, "total_order_value_etb": 0.0,
                "delivered_spend_etb": 0.0, "last_order_at": None, "first_order_at": None,
                "last_order_status": "", "order_references": [], "app_opens": 0
            }

        customers = {}
        for order in orders:
            user_id = str(order.get("telegram_user_id") or "").strip()
            if not user_id:
                continue
            customer = customers.setdefault(user_id, blank_customer(user_id))
            customer["orders"] += 1
            if order.get("status") == "Delivered":
                customer["delivered_orders"] += 1
                customer["delivered_spend_etb"] += float(order.get("total_etb") or 0)
            if order.get("status") != "Cancelled":
                customer["total_order_value_etb"] += float(order.get("total_etb") or 0)
            for source, target in (("telegram_username", "username"), ("customer_name", "name"),
                                   ("phone", "phone"), ("delivery_location", "delivery_location"),
                                   ("contact_preference", "contact_preference")):
                value = str(order.get(source) or "").strip()
                if value and not customer[target]:
                    customer[target] = value
            created = order.get("created_at")
            if created:
                customer["last_order_at"] = customer["last_order_at"] or created
                customer["first_order_at"] = created
            if not customer["last_order_status"]:
                customer["last_order_status"] = str(order.get("status") or "")
            if order.get("reference") and len(customer["order_references"]) < 20:
                customer["order_references"].append(str(order["reference"]))

        seen = set()
        for event in events:
            user_id = str(event.get("actor_telegram_id") or "").strip()
            if not user_id:
                continue
            customer = customers.setdefault(user_id, blank_customer(user_id))
            if event.get("event_type") == "mini_app_open":
                customer["app_opens"] += 1
            if user_id in seen:
                continue
            seen.add(user_id)
            details = event.get("details") if isinstance(event.get("details"), dict) else {}
            customer["last_seen_at"] = event.get("created_at")
            customer["last_ip_address"] = event.get("ip_address") or ""
            customer["device_browser"] = event.get("user_agent") or ""
            if details.get("username") and not customer["username"]:
                customer["username"] = str(details["username"])[:100]
            profile_name = " ".join(str(details.get(key) or "").strip() for key in ("first_name", "last_name")).strip()
            if profile_name and not customer["name"]:
                customer["name"] = profile_name[:200]
        result = sorted(customers.values(), key=lambda item: str(item.get("last_order_at") or ""), reverse=True)
        for customer in result:
            customer["total_order_value_etb"] = round(customer["total_order_value_etb"], 2)
            customer["delivered_spend_etb"] = round(customer["delivered_spend_etb"], 2)
            customer["phone_available"] = bool(customer.get("phone"))
        return jsonify(customers=result, counts={
            "customers": len(result),
            "with_phone": sum(1 for c in result if c.get("phone")),
            "with_ip": sum(1 for c in result if c.get("last_ip_address")),
            "orders": sum(c["orders"] for c in result)
        })
    except Exception:
        log.exception("Could not load admin customer directory")
        return jsonify(error="Could not load customers. Check that phase2_orders_delivery_schema.sql and admin_security_reports_migration.sql have been applied."), 503


@app.get("/api/admin/customer-profiles")
def admin_customer_profiles_list():
    _, error = admin_user_from_request()
    if error: return error
    if not supabase_enabled(): return jsonify(error="Supabase is required."), 503
    try:
        profiles = supabase_request("GET", "/rest/v1/customer_profiles", params={"select":"*", "order":"created_at.desc", "limit":"5000"}) or []
        orders = supabase_request("GET", "/rest/v1/customer_orders", params={"select":"reference,telegram_user_id,customer_name,phone,delivery_location,status,total_etb,payment_status,remaining_balance_etb,items,created_at", "order":"created_at.desc", "limit":"5000"}) or []
        workshop_rows = supabase_request("GET", "/rest/v1/workshop_erp_state", params={"select":"state", "id":"eq.1", "limit":"1"}) or []
        state = (workshop_rows[0] or {}).get("state") if workshop_rows else {}
        if not isinstance(state, dict): state = {}
        sales = state.get("sales", []) if isinstance(state.get("sales", []), list) else []
        products = state.get("products", []) if isinstance(state.get("products", []), list) else []
        # The Sales Archive is authoritative. Include legacy SOLD units only when no matching sale exists.
        sales = _merge_legacy_sold_products(sales, products)
        # Auto-register customers when a checkout order or Workshop ERP sale is saved.
        for source, kind in [(o, "order") for o in orders] + [(x, "workshop") for x in sales if str(x.get("status") or "").upper() == "SOLD"]:
            name = str(source.get("customer_name") or source.get("customer") or "").strip()
            phone = str(source.get("phone") or "").strip()
            telegram_id = str(source.get("telegram_user_id") or "").strip()
            if not name: continue
            exists = next((c for c in profiles if (phone and str(c.get("phone") or "").strip() == phone) or (telegram_id and str(c.get("telegram_user_id") or "") == telegram_id)), None)
            if exists: continue
            payload = {"full_name":name[:200], "phone":(phone or "Not provided")[:50], "location":str(source.get("delivery_location") or source.get("location") or "")[:500], "telegram_user_id":telegram_id or None, "telegram_username":str(source.get("telegram_username") or "")[:100], "customer_type":"Individual", "customer_status":"Active", "sex":"", "secondary_phone":"", "service_notes":"", "measurements_notes":""}
            try:
                created = supabase_request("POST", "/rest/v1/customer_profiles", payload=payload) or []
                if created: profiles.insert(0, created[0])
            except Exception:
                log.exception("Could not auto-create customer profile from saved sale/order")
        for profile in profiles:
            pid=str(profile.get("customer_id") or "")
            phone=str(profile.get("phone") or "").strip()
            tid=str(profile.get("telegram_user_id") or "")
            matching_orders=[o for o in orders if (tid and str(o.get("telegram_user_id") or "")==tid) or (phone and str(o.get("phone") or "").strip()==phone) or (pid and str(o.get("customer_id") or "")==pid)]
            matching_sales=[x for x in sales if str(x.get("status") or "").upper()=="SOLD" and ((phone and str(x.get("phone") or "").strip()==phone) or (str(x.get("customer") or "").strip().lower()==str(profile.get("full_name") or "").strip().lower()))]
            order_total=sum(float(o.get("total_etb") or 0) for o in matching_orders if str(o.get("status") or "").lower()!="cancelled")
            workshop_total=sum(float(x.get("price") or 0) for x in matching_sales)
            profile["sales_orders"]=len(matching_orders)+len(matching_sales)
            profile["sales_total_etb"]=round(order_total+workshop_total,2)
            profile["paid_or_delivered_etb"]=round(sum(float(o.get("total_etb") or 0) for o in matching_orders if str(o.get("status") or "").lower()=="delivered")+sum(float(x.get("price") or 0) for x in matching_sales if str(x.get("paymentStatus") or "").lower() in ("paid","fully paid","fully_paid")),2)
            history=[{"reference":o.get("reference"),"status":o.get("status"),"total_etb":o.get("total_etb"),"payment_status":o.get("payment_status"),"remaining_balance_etb":o.get("remaining_balance_etb"),"created_at":o.get("created_at"),"items":o.get("items"),"source":"Mini App Order"} for o in matching_orders]
            history += [{"reference":x.get("productId") or x.get("serial") or x.get("id") or "Workshop Sale", "status":"SOLD", "total_etb":x.get("price"), "payment_status":x.get("paymentStatus") or "Unknown", "remaining_balance_etb":"", "created_at":x.get("soldAtISO") or x.get("soldAt") or x.get("date") or "", "items":[{"name":x.get("model") or x.get("name") or x.get("productId") or "Workshop product"}], "source":"Workshop ERP Sales Archive"} for x in matching_sales]
            profile["order_history"]=sorted(history,key=lambda x:str(x.get("created_at") or ""),reverse=True)[:100]
        return jsonify(customers=profiles)
    except Exception:
        log.exception("Could not load customer profiles and sales history")
        return jsonify(error="Customer profiles could not load. Apply customer_profiles_migration.sql and refresh."),503

@app.post("/api/admin/customer-profiles")
def admin_customer_profiles_save():
    _, error = admin_user_from_request()
    if error: return error
    if not supabase_enabled(): return jsonify(error="Supabase is required."),503
    data=request.get_json(silent=True) or {}
    def clean(v, limit=500): return str(v or "").strip()[:limit]
    name=clean(data.get("full_name"),200)
    phone=clean(data.get("phone"),50)
    if not name or not phone: return jsonify(error="Full name and phone number are required."),400
    telegram_id=clean(data.get("telegram_user_id"),80)
    payload={"full_name":name,"sex":clean(data.get("sex"),40),"phone":phone,"secondary_phone":clean(data.get("secondary_phone"),50),"location":clean(data.get("location"),500),"telegram_user_id":telegram_id or None,"telegram_username":clean(data.get("telegram_username"),100),"customer_type":clean(data.get("customer_type"),40) or "Individual","service_notes":clean(data.get("service_notes"),3000),"measurements_notes":clean(data.get("measurements_notes"),3000),"customer_status":clean(data.get("customer_status"),40) or "Active","updated_at":dt.datetime.now(dt.timezone.utc).isoformat()}
    try:
        existing=[]
        if data.get("customer_id"):
            existing=supabase_request("GET","/rest/v1/customer_profiles",params={"select":"customer_id","customer_id":f"eq.{clean(data.get('customer_id'),40)}","limit":"1"}) or []
        if existing:
            rows=supabase_request("PATCH","/rest/v1/customer_profiles",params={"customer_id":f"eq.{clean(data.get('customer_id'),40)}"},payload=payload) or []
        else:
            payload["created_at"]=dt.datetime.now(dt.timezone.utc).isoformat()
            rows=supabase_request("POST","/rest/v1/customer_profiles",payload=payload) or []
        return jsonify(ok=True,customer=(rows[0] if rows else {}))
    except Exception:
        log.exception("Could not save customer profile")
        return jsonify(error="Could not save customer. Apply customer_profiles_migration.sql and check required fields."),503


@app.post("/api/admin/customer-profiles/export")
def admin_customer_profiles_export():
    user_id, error = admin_user_from_request()
    if error: return error
    if not supabase_enabled(): return jsonify(error="Supabase is required."),503
    data=request.get_json(silent=True) or {}
    fmt=str(data.get("format") or "pdf").lower()
    action=str(data.get("action") or "download").lower()
    recipient=str(data.get("recipientTelegramId") or "").strip()
    if fmt not in ("pdf","xlsx"): return jsonify(error="Choose PDF or Excel (.xlsx)."),400
    if action not in ("download","send"): return jsonify(error="Invalid export action."),400
    if action=="send" and not re.fullmatch(r"\d{4,20}",recipient): return jsonify(error="Enter a numeric Telegram user ID."),400
    try:
        profiles=supabase_request("GET","/rest/v1/customer_profiles",params={"select":"*","order":"created_at.desc","limit":"5000"}) or []
        orders=supabase_request("GET","/rest/v1/customer_orders",params={"select":"reference,telegram_user_id,customer_name,phone,status,total_etb,payment_status,created_at","order":"created_at.desc","limit":"5000"}) or []
        wrows=supabase_request("GET","/rest/v1/workshop_erp_state",params={"select":"state","id":"eq.1","limit":"1"}) or []
        state=(wrows[0] or {}).get("state") if wrows else {}; state=state if isinstance(state,dict) else {}
        ws_sales=state.get("sales",[]) if isinstance(state.get("sales",[]),list) else []
        ws_products=state.get("products",[]) if isinstance(state.get("products",[]),list) else []
        ws_sales=_merge_legacy_sold_products(ws_sales,ws_products)
        columns=["Customer ID","Full Name","Sex","Phone","Secondary Phone","Location","Telegram User ID","Telegram Username","Customer Type","Customer Status","Measurements / Preferences","Service / Warranty / Delivery Notes","Mini App Orders","Workshop Sales","Total Sales ETB","Delivered / Paid ETB","Registered At"]
        records=[]
        for c in profiles:
            ph=str(c.get("phone") or "").strip(); tid=str(c.get("telegram_user_id") or "")
            co=[o for o in orders if (tid and str(o.get("telegram_user_id") or "")==tid) or (ph and str(o.get("phone") or "").strip()==ph)]
            ws=[x for x in ws_sales if str(x.get("status") or "").upper()=="SOLD" and ((ph and str(x.get("phone") or "").strip()==ph) or str(x.get("customer") or "").strip().lower()==str(c.get("full_name") or "").strip().lower())]
            total=sum(float(o.get("total_etb") or 0) for o in co if str(o.get("status") or "").lower()!="cancelled")+sum(float(x.get("price") or 0) for x in ws)
            paid=sum(float(o.get("total_etb") or 0) for o in co if str(o.get("status") or "").lower()=="delivered")+sum(float(x.get("price") or 0) for x in ws if str(x.get("paymentStatus") or "").lower() in ("paid","fully paid","fully_paid"))
            records.append([c.get("customer_id",""),c.get("full_name",""),c.get("sex",""),c.get("phone",""),c.get("secondary_phone",""),c.get("location",""),c.get("telegram_user_id") or "",c.get("telegram_username",""),c.get("customer_type",""),c.get("customer_status",""),c.get("measurements_notes",""),c.get("service_notes",""),len(co),len(ws),round(total,2),round(paid,2),c.get("created_at","")])
        filename="AMBAR_Customer_Information_"+dt.datetime.now().strftime("%Y%m%d_%H%M%S")+(".pdf" if fmt=="pdf" else ".xlsx")
        buf=BytesIO()
        if fmt=="xlsx":
            from openpyxl import Workbook
            from openpyxl.styles import Font, PatternFill, Alignment
            wb=Workbook(); ws=wb.active; ws.title="Customer Information"; ws.append(columns)
            for row in records: ws.append(row)
            for cell in ws[1]: cell.font=Font(bold=True,color="FFFFFF"); cell.fill=PatternFill("solid",fgColor="242424"); cell.alignment=Alignment(wrap_text=True)
            ws.freeze_panes="A2"; ws.auto_filter.ref=ws.dimensions
            for col in ws.columns:
                letter=col[0].column_letter; maxlen=max((len(str(cell.value or "")) for cell in col[:200]),default=12); ws.column_dimensions[letter].width=min(max(maxlen+2,12),38)
            wb.save(buf); mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        else:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import landscape, A3
            from reportlab.lib.styles import getSampleStyleSheet
            from reportlab.lib.units import mm
            from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
            from reportlab.lib.utils import simpleSplit
            styles=getSampleStyleSheet(); doc=SimpleDocTemplate(buf,pagesize=landscape(A3),rightMargin=10*mm,leftMargin=10*mm,topMargin=10*mm,bottomMargin=10*mm)
            table_data=[[Paragraph(str(v).replace('&','&amp;').replace('<','&lt;'),styles['BodyText']) for v in columns]]
            for row in records: table_data.append([Paragraph(str(v if v is not None else '').replace('&','&amp;').replace('<','&lt;')[:180],styles['BodyText']) for v in row])
            story=[Paragraph("AMBAR Furniture · Customer Information & Sales",styles['Title']),Paragraph("Editable source records remain in the Customer Information workspace. Export generated "+dt.datetime.now().strftime("%Y-%m-%d %H:%M UTC"),styles['Normal']),Spacer(1,5*mm)]
            widths=[23*mm,28*mm,12*mm,22*mm,22*mm,28*mm,19*mm,20*mm,18*mm,17*mm,30*mm,30*mm,14*mm,14*mm,20*mm,20*mm,24*mm]
            t=Table(table_data,colWidths=widths,repeatRows=1); t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#242424')),('TEXTCOLOR',(0,0),(-1,0),colors.white),('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),('FONTSIZE',(0,0),(-1,-1),6),('LEADING',(0,0),(-1,-1),7),('GRID',(0,0),(-1,-1),0.25,colors.HexColor('#aaaaaa')),('VALIGN',(0,0),(-1,-1),'TOP'),('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white,colors.HexColor('#f3f3f3')])]))
            story.append(t); doc.build(story); mime="application/pdf"
        content=buf.getvalue()
        if action=="send":
            if len(content)>48*1024*1024: return jsonify(error="Report exceeds Telegram's file-size limit; narrow the export."),413
            upload=BytesIO(content); upload.name=filename
            try: result=bot_api("sendDocument",{"chat_id":recipient,"caption":"AMBAR Customer Information & Sales report · "+str(len(records))+" customer(s)"},{"document":(filename,upload,mime)},timeout=60)
            except Exception as exc:
                log.exception("Could not send customer report to Telegram")
                return jsonify(error="Telegram could not send this file. The recipient must open/start the AMBAR bot first. Details: "+str(exc)[:180]),502
            return jsonify(ok=True,message="Customer "+fmt.upper()+" report sent to Telegram user "+recipient+".",messageId=(result or {}).get("message_id"))
        return send_file(BytesIO(content),mimetype=mime,as_attachment=True,download_name=filename)
    except Exception as exc:
        log.exception("Could not export customer information")
        return jsonify(error="Could not generate customer export. Check Render logs. Details: "+str(exc)[:180]),500


@app.get("/api/admin/products")
def admin_list_products():
    _, error = admin_user_from_request()
    if error:
        return error
    catalog = load_product_catalog()
    # Include inactive products in admin so visibility can be switched back on.
    for pid, item in BASE_PRODUCTS.items():
        catalog.setdefault(pid, dict(item, active=True))
    if supabase_enabled():
        try:
            for row in supabase_list_products(include_inactive=True):
                pid = str(row.get("id", ""))
                if pid in BASE_PRODUCTS:
                    base = dict(BASE_PRODUCTS[pid])
                    base.update(supabase_product_to_item(row))
                    catalog[pid] = base
                elif pid.startswith("admin_"):
                    catalog[pid] = supabase_product_to_item(row)
        except Exception:
            log.exception("Could not load full admin product list")
    products = [public_admin_product(pid, item) for pid, item in catalog.items()]
    return jsonify(products=products)


@app.post("/api/admin/products")
def admin_create_product():
    _, error = admin_user_from_request()
    if error:
        return error
    try:
        if supabase_enabled():
            name = clean_text(request.form.get("name", ""), 100, "Product name", True)
            description = clean_text(request.form.get("description", ""), 1000, "Description", True)
            category = clean_text(request.form.get("category", "Other"), 80, "Category", True)
            if category.strip().lower() == "console table": category = "Consul Table"
            price = float(request.form.get("price", "0"))
            try:
                specifications = json.loads(request.form.get("specifications", "{}") or "{}")
            except (TypeError, json.JSONDecodeError):
                raise ValueError("Product specifications are invalid.")
            if not isinstance(specifications, dict):
                raise ValueError("Product specifications must be a JSON object.")
            specifications = {str(k)[:60]: clean_text(str(v), 250, "Product detail") for k, v in specifications.items() if str(v).strip()}
            if not (price >= 0 and price <= 100000000):
                raise ValueError("Price must be zero (to be confirmed) or no more than 100,000,000 ETB.")
            pid = "admin_" + secrets.token_hex(8)
            uploaded_files = [f for f in request.files.getlist("photos") if f and f.filename]
            if not uploaded_files and request.files.get("photo") and request.files.get("photo").filename:
                uploaded_files = [request.files.get("photo")]
            if not uploaded_files:
                raise ValueError("Please upload at least one product photo.")
            if len(uploaded_files) > 8:
                raise ValueError("Please upload no more than 8 product photos.")
            image_urls = [product_image_upload_from_request(pid + (f"_{i+1}" if len(uploaded_files)>1 else ""), f) for i, f in enumerate(uploaded_files)]
            image_urls = [u for u in image_urls if u]
            if not image_urls:
                raise ValueError("Please upload at least one valid product photo.")
            image_url = image_urls[0]
            row = {
                "id": pid, "name": name, "name_am": clean_text(request.form.get("name_am", ""), 100, "Amharic product name"),
                "price": round(price, 2), "category": category, "description": description,
                "description_am": clean_text(request.form.get("description_am", ""), 1000, "Amharic description"),
                "image_url": image_url, "images": image_urls, "specifications": specifications,
                "stock_status": "out_of_stock" if request.form.get("stock_status") in ("out_of_stock", "out_of_stock_orderable") else "in_stock",
                "allow_order": (request.form.get("stock_status") == "out_of_stock_orderable") if request.form.get("stock_status") in ("out_of_stock", "out_of_stock_orderable") else request.form.get("allow_order", "true").strip().lower() == "true",
                "active": request.form.get("active", "true").lower() == "true",
            }
            result = supabase_request("POST", f"/rest/v1/{quote(SUPABASE_PRODUCTS_TABLE, safe='')}", payload=row)
            saved = result[0] if isinstance(result, list) and result else row
            item = supabase_product_to_item(saved)
            load_product_catalog()
            return jsonify(product=public_admin_product(pid, item)), 201

        # Local development fallback if Supabase is not configured.
        name = clean_text(request.form.get("name", ""), 100, "Product name", True)
        description = clean_text(request.form.get("description", ""), 1000, "Description", True)
        category = clean_text(request.form.get("category", "Other"), 80, "Category", True)
        if category.strip().lower() == "console table": category = "Consul Table"
        price = float(request.form.get("price", "0"))
        try:
            specifications = json.loads(request.form.get("specifications", "{}") or "{}")
        except (TypeError, json.JSONDecodeError):
            raise ValueError("Product specifications are invalid.")
        if not isinstance(specifications, dict):
            raise ValueError("Product specifications must be a JSON object.")
        specifications = {str(k)[:60]: clean_text(str(v), 250, "Product detail") for k, v in specifications.items() if str(v).strip()}
        if not (price >= 0 and price <= 100000000):
            raise ValueError("Price must be zero (to be confirmed) or no more than 100,000,000 ETB.")
        pid = "admin_" + secrets.token_hex(8)
        uploaded_files = [f for f in request.files.getlist("photos") if f and f.filename]
        if not uploaded_files and request.files.get("photo") and request.files.get("photo").filename:
            uploaded_files = [request.files.get("photo")]
        if not uploaded_files:
            raise ValueError("Please upload at least one product photo.")
        if len(uploaded_files) > 8:
            raise ValueError("Please upload no more than 8 product photos.")
        image_urls = [product_image_upload_from_request(pid + (f"_{i+1}" if len(uploaded_files)>1 else ""), f) for i, f in enumerate(uploaded_files)]
        image_urls = [u for u in image_urls if u]
        if not image_urls:
            raise ValueError("Please upload at least one valid product photo.")
        stock_choice = request.form.get("stock_status", "in_stock")
        item = {"name": name, "category": category, "price": round(price, 2), "description": description,
                "measurements": specifications.get("measurements", "Not specified"), "capacity": specifications.get("capacity", "Not specified"), "material": specifications.get("material", "Not specified"),
                "specifications": specifications, "colors": ["As shown"], "images": image_urls, "image_url": image_urls[0],
                "stock_status": "out_of_stock" if stock_choice in ("out_of_stock", "out_of_stock_orderable") else "in_stock",
                "allow_order": (stock_choice == "out_of_stock_orderable") if stock_choice in ("out_of_stock", "out_of_stock_orderable") else request.form.get("allow_order", "true").strip().lower() == "true",
                "active": request.form.get("active", "true").lower() == "true", "pinned": request.form.get("pinned", "false").lower() == "true"}
        stored = {}
        try:
            existing = json.loads(PRODUCT_CATALOG_FILE.read_text(encoding="utf-8"))
            if isinstance(existing, dict): stored = existing
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        stored[pid] = item
        save_product_catalog(stored)
        return jsonify(product=public_admin_product(pid, item)), 201
    except ValueError as exc:
        return jsonify(error=str(exc)), 400
    except Exception:
        log.exception("Could not save admin product")
        return jsonify(error="Could not save the product. Check Supabase configuration, table columns, and Storage bucket."), 500


@app.put("/api/admin/products/<product_id>")
def admin_update_product(product_id):
    _, error = admin_user_from_request()
    if error:
        return error
    if not (re.fullmatch(r"admin_[a-f0-9]{16}", product_id) or product_id in BASE_PRODUCTS):
        return jsonify(error="Invalid product ID."), 400
    try:
        name = clean_text(request.form.get("name", ""), 100, "Product name", True)
        description = clean_text(request.form.get("description", ""), 1000, "Description", True)
        category = clean_text(request.form.get("category", "Other"), 80, "Category", True)
        if category.strip().lower() == "console table": category = "Consul Table"
        price = float(request.form.get("price", "0"))
        try:
            specifications = json.loads(request.form.get("specifications", "{}") or "{}")
        except (TypeError, json.JSONDecodeError):
            raise ValueError("Product specifications are invalid.")
        if not isinstance(specifications, dict):
            raise ValueError("Product specifications must be a JSON object.")
        specifications = {str(k)[:60]: clean_text(str(v), 250, "Product detail") for k, v in specifications.items() if str(v).strip()}
        if not (price >= 0 and price <= 100000000):
            raise ValueError("Price must be zero (to be confirmed) or no more than 100,000,000 ETB.")
        uploaded_files = [f for f in request.files.getlist("photos") if f and f.filename]
        if not uploaded_files and request.files.get("photo") and request.files.get("photo").filename:
            uploaded_files = [request.files.get("photo")]
        if len(uploaded_files) > 8:
            raise ValueError("Please upload no more than 8 product photos.")
        if supabase_enabled():
            rows = supabase_request("GET", f"/rest/v1/{quote(SUPABASE_PRODUCTS_TABLE, safe='')}",
                                    params={"select": "*", "id": f"eq.{product_id}", "limit": "1"}) or []
            old = rows[0] if rows else {}
            if not rows and product_id not in BASE_PRODUCTS:
                return jsonify(error="Product not found."), 404
            row = {"id": product_id, "name": name, "price": round(price, 2), "category": category, "description": description,
                   "name_am": clean_text(request.form.get("name_am", old.get("name_am") or ""), 100, "Amharic product name"),
                   "description_am": clean_text(request.form.get("description_am", old.get("description_am") or ""), 1000, "Amharic description"),
                   "specifications": specifications,
                   "stock_status": "out_of_stock" if request.form.get("stock_status") in ("out_of_stock", "out_of_stock_orderable") else "in_stock",
                   "allow_order": (request.form.get("stock_status") == "out_of_stock_orderable") if request.form.get("stock_status") in ("out_of_stock", "out_of_stock_orderable") else request.form.get("allow_order", "true").strip().lower() == "true",
                   "active": request.form.get("active", "true").lower() == "true", "pinned": request.form.get("pinned", "false").lower() == "true", "updated_at": dt.datetime.now(dt.timezone.utc).isoformat()}
            if uploaded_files:
                image_urls = [product_image_upload_from_request(product_id + (f"_{i+1}" if len(uploaded_files)>1 else ""), f, updating=True) for i, f in enumerate(uploaded_files)]
                image_urls = [u for u in image_urls if u]
                if image_urls:
                    row["image_url"] = image_urls[0]
                    row["images"] = image_urls
            if rows:
                result = supabase_request("PATCH", f"/rest/v1/{quote(SUPABASE_PRODUCTS_TABLE, safe='')}",
                                          params={"id": f"eq.{product_id}"}, payload=row)
            else:
                # First edit of a built-in product creates a persistent Supabase override.
                result = supabase_request("POST", f"/rest/v1/{quote(SUPABASE_PRODUCTS_TABLE, safe='')}", payload=row)
            saved = result[0] if isinstance(result, list) and result else {**old, **row}
            item = supabase_product_to_item(saved)
            load_product_catalog()
            return jsonify(product=public_admin_product(product_id, item))

        catalog = load_product_catalog()
        if product_id not in catalog:
            return jsonify(error="Product not found."), 404
        stock_choice = request.form.get("stock_status", "in_stock")
        item = dict(catalog[product_id]); item.update(name=name, description=description, category=category, price=round(price, 2), specifications=specifications, measurements=specifications.get("measurements", "Not specified"), capacity=specifications.get("capacity", "Not specified"), material=specifications.get("material", "Not specified"), stock_status="out_of_stock" if stock_choice in ("out_of_stock", "out_of_stock_orderable") else "in_stock", allow_order=((stock_choice == "out_of_stock_orderable") if stock_choice in ("out_of_stock", "out_of_stock_orderable") else request.form.get("allow_order", "true").strip().lower() == "true"), active=request.form.get("active", "true").lower() == "true", pinned=request.form.get("pinned", "false").lower() == "true")
        if uploaded_files:
            image_urls = [product_image_upload_from_request(product_id + (f"_{i+1}" if len(uploaded_files)>1 else ""), f, updating=True) for i, f in enumerate(uploaded_files)]
            item["images"] = [u for u in image_urls if u]
            if item["images"]: item["image_url"] = item["images"][0]
        catalog[product_id] = item
        save_product_catalog({k:v for k,v in catalog.items() if k.startswith("admin_")})
        return jsonify(product=public_admin_product(product_id, item))
    except ValueError as exc:
        return jsonify(error=str(exc)), 400
    except Exception:
        log.exception("Could not update admin product")
        return jsonify(error="Could not save changes. Check Supabase configuration, table columns, and Storage bucket."), 500


@app.delete("/api/admin/products/<product_id>")
def admin_delete_product(product_id):
    user_id, error = admin_user_from_request()
    if error:
        return error
    # Permanent deletion is deliberately limited to the designated main admin.
    if not is_main_admin_user(user_id):
        return jsonify(error="Permanent product deletion is restricted to the main selection admin."), 403
    if not re.fullmatch(r"admin_[a-f0-9]{16}", product_id):
        return jsonify(error="This is a built-in catalogue product. Only admin-added products can currently be permanently deleted; built-in products are protected."), 400
    try:
        if supabase_enabled():
            rows = supabase_request("GET", f"/rest/v1/{quote(SUPABASE_PRODUCTS_TABLE, safe='')}",
                                    params={"select": "id,image_url,images", "id": f"eq.{product_id}", "limit": "1"}) or []
            if not rows:
                return jsonify(error="Product not found or already deleted."), 404
            # Hard delete the database row; do not merely mark it inactive.
            supabase_request("DELETE", f"/rest/v1/{quote(SUPABASE_PRODUCTS_TABLE, safe='')}",
                             params={"id": f"eq.{product_id}"})
            load_product_catalog()
            return jsonify(ok=True, permanently_deleted=True)

        catalog = load_product_catalog()
        item = catalog.get(product_id)
        if not item:
            return jsonify(error="Product not found or already deleted."), 404
        catalog.pop(product_id, None)
        save_product_catalog({k: v for k, v in catalog.items() if k.startswith("admin_")})
        image_sources = list(item.get("images", []) or [])
        if item.get("image_url"):
            image_sources.append(item.get("image_url"))
        for src in image_sources:
            name = Path(str(src)).name
            if name.startswith(product_id):
                try:
                    (PRODUCT_IMAGE_DIR / name).unlink(missing_ok=True)
                except OSError:
                    log.warning("Could not remove product image %s", name)
        return jsonify(ok=True, permanently_deleted=True)
    except Exception:
        log.exception("Could not permanently delete admin product")
        return jsonify(error="Could not permanently delete the product. Check Supabase configuration."), 500


@app.get("/products/<path:filename>")
def product_image(filename):
    # Prefer persistent uploads; fall back to the original bundled product images.
    candidate = PRODUCT_IMAGE_DIR / filename
    if candidate.is_file():
        return send_from_directory(PRODUCT_IMAGE_DIR, filename, max_age=3600)
    return send_from_directory(BASE_DIR / "products", filename, max_age=3600)


@app.get("/ambar-app-icon.png")
def app_icon():
    return send_from_directory(BASE_DIR, "ambar-app-icon.png", max_age=3600)


@app.get("/health")
def health():
    load_product_catalog()
    return jsonify({"status": "ok", "service": "ambar-furniture-miniapp"}), 200


@app.get("/api/auth/me")
def authenticated_telegram_user():
    load_product_catalog()
    init_data = request.headers.get("X-Telegram-Init-Data", "")
    valid, user_id = validate_telegram_init_data(init_data)
    if not valid or not user_id:
        write_security_event("failed_customer_auth", path=request.path, method=request.method,
                             status_code=401, details={"reason": "invalid_or_missing_telegram_auth"})
        return jsonify(authenticated=False, error="Telegram authentication failed. Open the Mini App from the AMBAR Telegram bot."), 401
    try:
        pairs = dict(parse_qsl(init_data, keep_blank_values=True, strict_parsing=True))
        user = json.loads(pairs.get("user", "{}"))
        if str(user.get("id", "")) != user_id:
            raise ValueError("User identity mismatch")
    except (ValueError, TypeError, json.JSONDecodeError):
        write_security_event("failed_customer_auth", path=request.path, method=request.method,
                             status_code=401, details={"reason": "invalid_signed_profile_data"})
        return jsonify(authenticated=False, error="Telegram profile data is invalid."), 401
    # Profile fields are read from Telegram's signed initData only after HMAC verification.
    safe_user = {
        "id": user_id,
        "first_name": clean_text(user.get("first_name", ""), 100, "First name"),
        "last_name": clean_text(user.get("last_name", ""), 100, "Last name"),
        "username": clean_text(user.get("username", ""), 100, "Username"),
        "language_code": clean_text(user.get("language_code", ""), 20, "Language"),
        "photo_url": clean_text(user.get("photo_url", ""), 2000, "Profile photo URL"),
    }
    # Show the admin entry point to the owner and any active staff account saved
    # in Supabase. Staff do not need to be added to the Render allowlist.
    is_owner = is_main_admin_user(user_id)
    role_data = None if is_owner else admin_permissions_for(user_id)
    is_admin = is_owner or bool(role_data and role_data.get("active", False) and role_data.get("role") != "disabled")
    permissions = ["*"] if is_owner else ((role_data or {}).get("permissions") or (["orders"] if (role_data or {}).get("role") == "orders" else []))
    write_security_event("customer_sign_in", actor_id=user_id, path=request.path, method=request.method,
                         status_code=200, details={"source": "telegram_mini_app",
                             "username": safe_user["username"], "first_name": safe_user["first_name"],
                             "last_name": safe_user["last_name"]})
    effective_permissions = normalize_admin_permissions(permissions) if is_admin else []
    non_workshop_permissions = [p for p in effective_permissions if p not in {"workshop_erp", "workshop_watch"}]
    # Section visibility is independent: the owner always sees both; staff see only
    # the sections explicitly assigned to them. A full-access '*' assignment grants both.
    has_main_admin_access = bool(is_admin and (is_owner or "*" in effective_permissions or non_workshop_permissions))
    has_workshop_access = bool(is_admin and (is_owner or "*" in effective_permissions or "workshop_erp" in effective_permissions))
    workshop_only_role = bool(has_workshop_access and not has_main_admin_access)
    return jsonify(authenticated=True, user=safe_user, is_admin=is_admin,
                   admin_permissions=permissions if is_admin else [],
                   has_main_admin_access=has_main_admin_access,
                   has_workshop_access=has_workshop_access,
                   workshop_only_role=workshop_only_role,
                   workshop_role_label=("Workshop Activity Observer" if "workshop_watch" in effective_permissions else "Workshop ERP Staff") if workshop_only_role else None), 200


@app.post("/api/cart-event")
def record_cart_event():
    load_product_catalog()
    """Record product additions for a daily service-team digest."""
    try:
        data = request.get_json(silent=True) or {}
        user_id = clean_text(data.get("telegram_user_id", ""), 40, "Telegram user ID", True)
        items = data.get("items", [])
        if not user_id.isdigit() or not isinstance(items, list) or not items:
            return jsonify(error="Invalid cart event."), 400
        safe_items = []
        for item in items[:20]:
            pid = str(item.get("product_id", "")) if isinstance(item, dict) else ""
            if pid in PRODUCTS:
                safe_items.append({"product_id": pid, "name": PRODUCTS[pid]["name"], "quantity": max(1, min(99, int(item.get("quantity", 1))))})
        if not safe_items:
            return jsonify(ok=True), 200
        with SUBSCRIBER_LOCK:
            try:
                events = json.loads(CART_EVENTS_FILE.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                events = []
            events.append({"timestamp": dt.datetime.now(ZoneInfo(NOTIFICATION_TIMEZONE)).isoformat(), "user_id": user_id, "items": safe_items})
            CART_EVENTS_FILE.parent.mkdir(parents=True, exist_ok=True)
            CART_EVENTS_FILE.write_text(json.dumps(events[-5000:], ensure_ascii=False, indent=2), encoding="utf-8")
        return jsonify(ok=True), 200
    except Exception:
        log.exception("Could not record cart event")
        return jsonify(error="Could not record cart event."), 500


async def send_daily_cart_digest(context: ContextTypes.DEFAULT_TYPE):
    if not SERVICE_CHAT_ID:
        log.info("Daily cart digest skipped: SERVICE_CHAT_ID is not configured.")
        return
    try:
        today = dt.datetime.now(ZoneInfo(NOTIFICATION_TIMEZONE)).date()
        with SUBSCRIBER_LOCK:
            try:
                events = json.loads(CART_EVENTS_FILE.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                events = []
            todays = [e for e in events if str(e.get("timestamp", "")).startswith(today.isoformat())]
        if not todays:
            message = f"🛒 AMBAR daily cart report — {today.isoformat()}\nNo products were added to carts today."
        else:
            users = {e.get("user_id") for e in todays}
            counts = {}
            for event in todays:
                for item in event.get("items", []):
                    counts[item.get("name", "Product")] = counts.get(item.get("name", "Product"), 0) + int(item.get("quantity", 1))
            lines = [f"🛒 AMBAR daily cart report — {today.isoformat()}", f"Cart additions: {len(todays)}", f"Customers: {len(users)}", "", "Products added:"]
            lines += [f"• {name}: {qty}" for name, qty in sorted(counts.items())]
            message = "\n".join(lines)
        await context.bot.send_message(chat_id=SERVICE_CHAT_ID, text=message[:4000])
    except Exception:
        log.exception("Daily cart digest failed")


@app.post("/api/order")
def create_order():
    load_product_catalog()
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error="Please send a valid order form."), 400
    init_data = request.headers.get("X-Telegram-Init-Data", "")
    valid, telegram_user_id = auth_result(init_data)
    telegram_username = telegram_username_from_init_data(init_data) if valid else "Not available"
    if not valid:
        return jsonify(error="Telegram authentication failed. Please close the Mini App and open it again from your Telegram bot."), 401
    try:
        customer, items, total, finish, material, notes = parse_standard_order(data)
    except ValueError as exc:
        return jsonify(error=str(exc)), 400

    reference = new_reference("AF")
    advance = total / 2
    lines = [
        f"STANDARD PRODUCT ORDER — {reference}",
        f"Customer: {customer['name']}",
        f"Telegram username: {telegram_username}",
        f"Telegram user ID: {telegram_user_id if telegram_user_id is not None else 'Not available'}",
        f"Telegram language: {telegram_language_from_init_data(init_data)}",
        f"Phone: {customer['phone']}",
        f"Delivery method: {'Customer pickup (free)' if delivery_method == 'pickup' else 'AMBAR team delivery'}",
        f"Location: {customer['location']}",
        f"Contact preference: {customer['contact_preference']}",
        "Products:",
    ]
    for item in items:
        lines.append(f"- {item['name']} — {item['measurement']} × {item['quantity']} @ {format(item['unit_price'], ',') + ' ETB' if item['unit_price'] > 0 else 'Price to be confirmed'} = {format(item['line_total'], ',') + ' ETB' if item['unit_price'] > 0 else 'Price to be confirmed'}")
    lines.extend([
        f"Product total: {total:,} ETB",
        f"Estimated 50% advance after confirmation: {advance:,.0f} ETB",
        "Measurement-specific pricing: AMBAR will confirm any unpriced size before requesting an advance.",
        f"Material preference: {material or 'Not specified'}",
        f"Customer notes: {notes or 'None'}",
        "PAYMENT STATUS: Not received or verified by this app.",
    ])
    # Save first so the order is immediately available in My Orders and tracking.
    if not supabase_enabled():
        return jsonify(error="Order tracking is not configured yet. Please contact AMBAR and try again later."), 503
    try:
        saved_rows = supabase_request("POST", "/rest/v1/customer_orders", payload={
            "reference": reference,
            "telegram_user_id": str(telegram_user_id),
            "telegram_username": telegram_username if telegram_username != "Not available" else "",
            "customer_name": customer.get("name", ""),
            "phone": customer.get("phone", ""),
            "delivery_location": customer.get("location", ""),
            "contact_preference": customer.get("contact_preference", "Phone call"),
            "items": items,
            "product_total_etb": total,
            "delivery_fee_etb": 0,
            "total_etb": total,
            "delivery_area": "To be confirmed",
            "status": "Pending",
            "payment_status": "Pending review",
            "notes": notes,
        })
        if not saved_rows:
            raise RuntimeError("Supabase did not return the saved order row")
    except Exception:
        log.exception("Could not save standard order %s for My Orders", reference)
        return jsonify(error="Your order could not be saved to tracking. Please try again; if it continues, contact AMBAR."), 503

    try:
        send_service_message("\n".join(lines))
    except Exception:
        log.exception("Service notification failed for %s; order is saved", reference)
        # Do not lose the saved order if staff notification is temporarily unavailable.
    maybe_send_customer_confirmation_with_photos(telegram_user_id,
        f"✓ AMBAR order received\nትዕዛዝዎ ደርሷል\nOrder ID / የትዕዛዝ ቁጥር: {reference}\nTotal / ጠቅላላ: {total:,} ETB\nWe’ll contact you to confirm details.\nዝርዝሩን ለማረጋገጥ እናገኝዎታለን።",
        product_photo_paths(items)[:1])
    return jsonify(ok=True, reference=reference, total=total, estimated_advance=advance), 200


@app.post("/api/payment-screenshot")
def submit_payment_screenshot():
    load_product_catalog()
    """Forward a customer's payment screenshot to service staff for manual review."""
    init_data = request.form.get("init_data", "")
    valid, telegram_user_id = auth_result(init_data)
    telegram_username = telegram_username_from_init_data(init_data) if valid else "Not available"
    if not valid:
        return jsonify(error="Telegram authentication failed. Please close the Mini App and reopen it from your Telegram bot."), 401
    reference = clean_text(request.form.get("reference"), 40, "Order reference", True)
    if not re.fullmatch(r"AF-[A-Z0-9]{6}", reference):
        return jsonify(error="The order reference format is invalid. Please submit your order again if needed."), 400
    screenshot = request.files.get("screenshot")
    if not screenshot or not screenshot.filename:
        return jsonify(error="Choose a payment screenshot first."), 400
    mime = (screenshot.mimetype or "").lower()
    extension = ALLOWED_MIME.get(mime)
    if not extension:
        return jsonify(error="Screenshot must be JPG, PNG, or WebP."), 400
    content = screenshot.stream.read(8 * 1024 * 1024 + 1)
    if len(content) >= 8 * 1024 * 1024:
        return jsonify(error="Screenshot must be smaller than 8 MB."), 400
    signatures = {
        "image/jpeg": content.startswith(b"\xff\xd8\xff"),
        "image/png": content.startswith(b"\x89PNG\r\n\x1a\n"),
        "image/webp": len(content) >= 12 and content[:4] == b"RIFF" and content[8:12] == b"WEBP",
    }
    if not signatures.get(mime, False):
        return jsonify(error="The screenshot does not match its declared image type."), 400
    temp_path = UPLOAD_DIR / secure_filename(f"payment_{secrets.token_hex(12)}{extension}")
    try:
        temp_path.write_bytes(content)
        caption = f"PAYMENT SCREENSHOT — {reference}\nCustomer Telegram username: {telegram_username}\nCustomer Telegram ID: {telegram_user_id or 'Unavailable'}\nSTATUS: Received for manual review; payment is NOT verified."
        send_service_photo(str(temp_path), caption)
    except Exception:
        log.exception("Payment screenshot forwarding failed for %s", reference)
        return jsonify(error="We could not send the screenshot to customer service. Please try again."), 502
    finally:
        try:
            temp_path.unlink(missing_ok=True)
        except OSError:
            pass
    return jsonify(ok=True, reference=reference, message="Screenshot forwarded for manual review."), 200


def chapa_api_request(method, path, *, payload=None, timeout=25):
    """Call Chapa only from the server; the secret key must never reach the browser."""
    if not CHAPA_SECRET_KEY:
        raise RuntimeError("Chapa is not configured. Add CHAPA_SECRET_KEY to the Render environment.")
    response = requests.request(
        method,
        f"{CHAPA_API_BASE}{path}",
        headers={"Authorization": f"Bearer {CHAPA_SECRET_KEY}", "Content-Type": "application/json"},
        json=payload,
        timeout=timeout,
    )
    try:
        body = response.json()
    except ValueError:
        body = {}
    if not response.ok:
        log.error("Chapa API error: HTTP %s; body=%s", response.status_code, str(body)[:700])
        raise RuntimeError("Chapa could not start or verify this payment. Please try again or choose Pay Later.")
    return body


def verify_chapa_order(reference):
    """Verify payment against Chapa and update the saved order only when amount/currency match."""
    rows = supabase_request("GET", "/rest/v1/customer_orders", params={"select":"*", "reference":f"eq.{reference}", "limit":"1"}) or []
    if not rows:
        raise LookupError("Order not found")
    order = rows[0]
    verify_reference = str(order.get("chapa_reference") or reference).strip()
    result = chapa_api_request("GET", f"/v2/payments/{quote(verify_reference, safe='')}/verify")
    details = result.get("data") if isinstance(result.get("data"), dict) else {}
    status = str(details.get("status") or result.get("status") or "").lower()
    try:
        paid_amount = float(details.get("amount"))
        expected_amount = round(float(order.get("amount_due_now_etb") or order.get("total_etb") or 0), 2)
    except (TypeError, ValueError):
        paid_amount = -1
        expected_amount = -2
    currency = str(details.get("currency") or "").upper()
    if status == "success" and currency == "ETB" and abs(paid_amount - expected_amount) < 0.01:
        percentage = int(order.get("payment_percentage") or 100)
        payment_label = "Paid in full via Chapa — verified" if percentage >= 100 else f"{percentage}% advance paid via Chapa — verified; balance remains due"
        supabase_request("PATCH", "/rest/v1/customer_orders", params={"reference":f"eq.{reference}"}, payload={"payment_status":payment_label, "updated_at":dt.datetime.now(dt.timezone.utc).isoformat()})
        return True, "Your advance payment was verified successfully. Thank you!" if percentage < 100 else "Payment verified successfully. Thank you!"
    if status in {"failed", "cancelled", "canceled", "blocked"}:
        supabase_request("PATCH", "/rest/v1/customer_orders", params={"reference":f"eq.{reference}"}, payload={"payment_status":f"Chapa payment {status}", "updated_at":dt.datetime.now(dt.timezone.utc).isoformat()})
        return False, f"Chapa reports that payment was {status}. You can retry or choose another payment method."
    return False, "Payment is not yet confirmed. If you completed payment, refresh order tracking shortly."


@app.get("/api/chapa/return")
def chapa_return():
    reference = clean_text(request.args.get("reference", ""), 40, "Order reference", True)
    if not re.fullmatch(r"AF-[A-Z0-9]{6}", reference):
        return "Invalid order reference.", 400
    try:
        paid, message = verify_chapa_order(reference)
    except LookupError:
        return "Order not found.", 404
    except Exception:
        log.exception("Chapa return verification failed for %s", reference)
        paid, message = False, "We could not verify the payment right now. Please return to AMBAR order tracking and refresh later."
    safe_message = message.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    status_color = "#237a43" if paid else "#b66a16"
    return (f"<!doctype html><html><head><meta name='viewport' content='width=device-width,initial-scale=1'><title>AMBAR payment status</title></head>"
            f"<body style='margin:0;background:#17181a;color:#f6f1eb;font-family:Arial,sans-serif;display:grid;place-items:center;min-height:100vh;padding:20px;box-sizing:border-box'>"
            f"<main style='max-width:440px;width:100%;background:#242528;border:1px solid #48413b;border-radius:20px;padding:28px;box-sizing:border-box'>"
            f"<div style='color:#ff9a45;font-weight:800;letter-spacing:2px'>AMBAR FURNITURE</div><h1 style='font-size:24px'>Payment {'confirmed' if paid else 'status'}</h1>"
            f"<p style='color:{status_color};font-weight:700'>{safe_message}</p><p>Order reference: <strong>{reference}</strong></p>"
            f"<a href='{WEBAPP_URL}' style='display:inline-block;margin-top:12px;padding:13px 18px;border-radius:12px;background:#f18a36;color:#17181a;text-decoration:none;font-weight:700'>Return to AMBAR</a>"
            f"</main></body></html>", 200)


@app.post("/api/chapa/webhook")
def chapa_webhook():
    """Optional Chapa v2 signed webhook receiver; payment is still verified server-side."""
    if not CHAPA_WEBHOOK_SECRET:
        return jsonify(error="Webhook secret is not configured."), 503
    raw = request.get_data(cache=True)
    signature = request.headers.get("x-chapa-signature", "")
    expected = hmac.new(CHAPA_WEBHOOK_SECRET.encode(), raw, hashlib.sha256).hexdigest()
    if not signature or not hmac.compare_digest(signature.lower(), expected.lower()):
        return jsonify(error="Invalid webhook signature."), 401
    event = request.get_json(silent=True) or {}
    reference = str(event.get("merchant_reference") or "").strip()
    if not re.fullmatch(r"AF-[A-Z0-9]{6}", reference):
        return jsonify(ok=True, ignored=True), 200
    try:
        verify_chapa_order(reference)
    except Exception:
        log.exception("Chapa webhook verification failed for %s", reference)
        return jsonify(error="Verification temporarily failed."), 503
    return jsonify(ok=True), 200


@app.post("/api/submit-order")
def submit_order_with_payment_choice():
    load_product_catalog()
    """Submit an order and send its product photos and any payment screenshot to staff."""
    init_data = request.form.get("init_data", "")
    valid, telegram_user_id = auth_result(init_data)
    telegram_username = telegram_username_from_init_data(init_data) if valid else "Not available"
    if not valid:
        return jsonify(error="Telegram authentication failed. Please close the Mini App and reopen it from your Telegram bot."), 401
    try:
        raw_order = json.loads(request.form.get("order_json", ""))
        customer, items, total, finish, material, notes = parse_standard_order(raw_order)
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        message = str(exc) if isinstance(exc, ValueError) else "Please send a valid order form."
        return jsonify(error=message), 400

    order_for = clean_text(raw_order.get("order_for", "myself"), 30, "Order recipient", True)
    if order_for not in {"myself", "someone_else"}:
        return jsonify(error="Choose whether the order is for yourself or someone else."), 400
    payer = clean_text(raw_order.get("payer", "buyer"), 30, "Payer", True)
    if payer not in {"buyer", "recipient"}:
        return jsonify(error="Choose who will pay for the order."), 400
    recipient = raw_order.get("recipient") if isinstance(raw_order.get("recipient"), dict) else {}
    if order_for == "someone_else":
        recipient_name = clean_text(recipient.get("name", ""), 100, "Recipient name", True)
        recipient_phone = clean_text(recipient.get("phone", ""), 20, "Recipient phone", True)
        recipient_instructions = clean_text(recipient.get("instructions", ""), 500, "Recipient delivery instructions")
        if not re.fullmatch(r"(?:\+251[79][0-9]{8}|0[79][0-9]{8}|\+[1-9][0-9]{7,14})", recipient_phone):
            return jsonify(error="Please enter a valid recipient phone number."), 400
        if payer == "recipient":
            # Recipient-paid orders are never charged to the buyer at checkout.
            request.form = request.form.copy()
            # Keep this rule server-side even if a client is modified.
            if request.form.get("payment_option") != "pay_later":
                return jsonify(error="Recipient pays on delivery requires the Pay Later option."), 400
    else:
        recipient_name = recipient_phone = recipient_instructions = ""
        payer = "buyer"

    payment_option = clean_text(request.form.get("payment_option"), 20, "Payment option", True)
    if payment_option not in {"pay_later", "chapa"}:
        return jsonify(error="Choose Chapa or Pay Later."), 400
    try:
        payment_percentage = int(request.form.get("payment_percentage", "50" if payment_option != "pay_later" else "0"))
    except (TypeError, ValueError):
        return jsonify(error="Choose a valid first-payment percentage."), 400
    if payment_option == "pay_later":
        payment_percentage = 0
    elif payment_percentage not in {20, 30, 40, 50}:
        return jsonify(error="Choose a first payment of 20%, 30%, 40%, or 50%, or choose Pay Later."), 400

    screenshot = request.files.get("screenshot") if payment_option == "pay_now" else None
    content = None
    extension = None
    if payment_option in {"pay_now", "chapa"} and any(float(item.get("unit_price", 0) or 0) <= 0 for item in items):
        return jsonify(error="One or more selected products have no confirmed price. Please choose Pay Later; AMBAR will confirm the measurement-specific price before any advance payment."), 400

    if payment_option == "pay_now":
        if not screenshot or not screenshot.filename:
            return jsonify(error="Choose a payment screenshot before submitting."), 400
        mime = (screenshot.mimetype or "").lower()
        extension = ALLOWED_MIME.get(mime)
        if not extension:
            return jsonify(error="Screenshot must be JPG, PNG, or WebP."), 400
        content = screenshot.stream.read(8 * 1024 * 1024 + 1)
        if len(content) >= 8 * 1024 * 1024:
            return jsonify(error="Screenshot must be smaller than 8 MB."), 400
        signatures = {
            "image/jpeg": content.startswith(b"\xff\xd8\xff"),
            "image/png": content.startswith(b"\x89PNG\r\n\x1a\n"),
            "image/webp": len(content) >= 12 and content[:4] == b"RIFF" and content[8:12] == b"WEBP",
        }
        if not signatures.get(mime, False):
            return jsonify(error="The screenshot does not match its declared image type."), 400

    # Resolve delivery pricing on the server; never trust a client-calculated fee.
    # Customer pickup is free. Team delivery uses the admin-configured base fee + per-kilometer rate.
    delivery_method = clean_text(raw_order.get("delivery_method", "pickup"), 30, "Delivery method", True)
    if delivery_method not in {"pickup", "team_delivery"}:
        return jsonify(error="Choose customer pickup or AMBAR team delivery."), 400
    delivery_fee = 0.0
    delivery_area = "Customer Pickup" if delivery_method == "pickup" else "AMBAR Team Delivery"
    delivery_distance_km = None
    delivery_fee_mode = "pickup" if delivery_method == "pickup" else "gps"
    gps_lat = gps_lon = None
    try:
        gps_data = raw_order.get("gps") if isinstance(raw_order, dict) else None
        if delivery_method == "team_delivery":
            if not isinstance(gps_data, dict):
                return jsonify(error="Choose your delivery location using GPS or the map."), 400
            gps_lat = float(gps_data.get("lat")); gps_lon = float(gps_data.get("lon"))
            if not (-90 <= gps_lat <= 90 and -180 <= gps_lon <= 180):
                raise ValueError("Invalid GPS coordinates")
            gps_settings = get_gps_delivery_settings() if supabase_enabled() else None
            if not gps_settings or not gps_settings.get("active") or gps_settings.get("origin_lat") is None or gps_settings.get("origin_lon") is None:
                return jsonify(error="AMBAR store GPS coordinates are not configured. Please contact AMBAR before choosing team delivery."), 503
            delivery_distance_km = round(haversine_km(gps_settings["origin_lat"], gps_settings["origin_lon"], gps_lat, gps_lon), 2)
            delivery_fee = round(float(gps_settings.get("price_per_km", 0) or 0) * delivery_distance_km, 2)
            delivery_area = "AMBAR Team Delivery (GPS)"
    except (ValueError, TypeError):
        return jsonify(error="Please refresh your GPS location or select a valid map pin and try again."), 400
    except Exception:
        log.exception("Could not resolve delivery fee for order")
        return jsonify(error="Could not calculate delivery fee. Please try again."), 503
    total_with_delivery = total + delivery_fee
    amount_due_now = round(total_with_delivery * payment_percentage / 100, 2) if payment_percentage else 0.0
    remaining_balance = round(max(0.0, total_with_delivery - amount_due_now), 2)
    reference = new_reference("AF")
    timestamp = ethiopian_datetime()
    product_summary = "\n".join(
        f"• {item['name']} × {item['quantity']} — {item['measurement']}"
        for item in items
    )
    lines = [
        "AMBAR FURNITURE | NEW ORDER",
        f"Order ID: {reference}",
        f"Date: {timestamp}",
        "",
        "CUSTOMER",
        f"Name: {customer['name']}",
        f"Telegram username: {telegram_username}",
        f"Telegram user ID: {telegram_user_id if telegram_user_id is not None else 'Not available'}",
        f"Telegram language: {telegram_language_from_init_data(init_data)}",
        f"Phone: {customer['phone']}",
        f"Location: {customer['location']}",
        f"Preferred contact: {customer['contact_preference']}",
        "",
        "ORDER DETAILS",
        product_summary,
        f"Material: {material or 'Not specified'}",
        f"Notes: {notes or 'None'}",
        (f"TOTAL: {total:,} ETB" if all(item["unit_price"] > 0 for item in items) else "TOTAL: Final price to be confirmed by AMBAR"),
    ]

    temp_path = None
    try:
        if payment_option == "pay_now":
            temp_path = UPLOAD_DIR / secure_filename(f"payment_{secrets.token_hex(12)}{extension}")
            temp_path.write_bytes(content)
            payment_line = f"Payment: {payment_percentage}% advance ({amount_due_now:,.2f} ETB) screenshot attached · awaiting verification; remaining balance {remaining_balance:,.2f} ETB"
            status_text = f"{payment_percentage}% advance screenshot received; verification pending."
        elif payment_option == "chapa":
            payment_line = f"Payment: Chapa hosted checkout · {payment_percentage}% advance ({amount_due_now:,.2f} ETB) pending verification; remaining balance {remaining_balance:,.2f} ETB"
            status_text = f"Chapa {payment_percentage}% advance payment pending."
        else:
            payment_line = "Payment: Pay Later · no payment collected now"
            status_text = "Pay Later selected; no payment collected."

        product_lines = [
            f"{item['name']} × {item['quantity']}" + (f" · {item['measurement']}" if item.get('measurement') else "")
            for item in items
        ]
        if payment_option == "pay_now":
            payment_method_label = f"Advance payment ({payment_percentage}%)"
            payment_status_label = "Advance payment screenshot received · awaiting verification"
        elif payment_option == "chapa":
            payment_method_label = f"Chapa ({payment_percentage}% advance)"
            payment_status_label = "Chapa payment pending verification"
        else:
            payment_method_label = "Pay Later"
            payment_status_label = "Pay Later · not paid yet"
        revenue_label = f"{total:,.2f} ETB" if all(item["unit_price"] > 0 for item in items) else "To be confirmed"
        total_label = f"{total_with_delivery:,.2f} ETB" if all(item["unit_price"] > 0 for item in items) else "Price to be confirmed"
        divider = "━━━━━━━━━━━━━━━━━━"
        lines = [
            "AMBAR FURNITURE",
            "NEW ORDER · CUSTOMER CHECKOUT",
            divider,
            f"ORDER REFERENCE: {reference}",
            f"Date & time: {timestamp}",
            "",
            "01 · CUSTOMER DETAILS",
            f"Customer name: {customer['name']}",
            f"Phone number: {customer['phone']}",
            f"Telegram: {telegram_username}" if telegram_username else "Telegram: Not provided",
            f"Customer ID: {telegram_user_id if telegram_user_id is not None else 'Not available'}",
            f"Preferred contact: {customer['contact_preference']}",
            f"Customer location: {customer['location'] or 'Not provided'}",
            f"Fulfilment location: GPS {gps_lat}, {gps_lon}" if delivery_method == 'team_delivery' else "Fulfilment: Customer pickup",
            divider,
            "02 · ORDER DETAILS",
            *product_lines,
            f"Material: {material or 'Not specified'}",
            f"Order notes: {notes or 'None'}",
            divider,
            "03 · PAYMENT SUMMARY",
            f"Product subtotal: {revenue_label}",
            f"Delivery fee: {delivery_fee:,.2f} ETB",
            f"TOTAL ORDER VALUE: {total_label}",
            f"Payment method: {payment_method_label}",
            f"Advance paid: {amount_due_now:,.2f} ETB" if payment_option != "pay_later" else "Advance paid: 0.00 ETB",
            f"BALANCE DUE: {remaining_balance:,.2f} ETB" if all(item["unit_price"] > 0 for item in items) else "BALANCE DUE: To be confirmed",
            divider,
            f"PAYMENT STATUS · {payment_status_label.upper()}",
        ]
        caption = "\n".join(lines)
        # Keep the complete order summary in Telegram's 1,024-character photo caption.
        # If customer notes make it too long, shorten only the notes field first.
        if len(caption) > 1024 and notes:
            note_line = f"Notes: {notes}"
            allowance = max(0, 1024 - (len(caption) - len(note_line)) - len("Notes: …"))
            shortened = notes[:allowance] + ("…" if allowance < len(notes) else "")
            lines = [f"Notes: {shortened}" if line == note_line else line for line in lines]
            caption = "\n".join(lines)
        if len(caption) > 1024:
            # Product quantities are limited, but retain all key details if a very large
            # multi-item order still exceeds Telegram's caption limit.
            caption = caption[:1023].rstrip() + "…"

        # Persist first so the order is visible immediately in My Orders and admin tracking.
        if not supabase_enabled():
            return jsonify(error="Order tracking is not configured yet. Please contact AMBAR before submitting again."), 503
        try:
            # Store the verified Telegram ID, not a development-mode None value.
            _, verified_order_user_id = validate_telegram_init_data(init_data)
            verified_order_user_id = verified_order_user_id or telegram_user_id
            if not verified_order_user_id:
                raise RuntimeError("Verified Telegram user ID is unavailable; cannot attach order to a customer account.")
            location_text = str(customer.get("location", ""))
            payment_label = (f"{payment_percentage}% advance screenshot submitted — review pending" if payment_option == "pay_now" else (f"Chapa {payment_percentage}% advance payment pending" if payment_option == "chapa" else ("Recipient pays on delivery — pending" if order_for == "someone_else" and payer == "recipient" else "Pay later — pending")))
            # Store recipient details inside the existing notes field for compatibility with deployed schemas.
            recipient_record = (f"ORDER FOR: Someone else\nRECIPIENT NAME: {recipient_name}\nRECIPIENT PHONE: {recipient_phone}\nPAYER: Recipient pays on delivery\nRECIPIENT INSTRUCTIONS: {recipient_instructions or 'None'}" if order_for == "someone_else" else "ORDER FOR: Buyer")
            saved_notes = (recipient_record + ("\nCUSTOMER NOTES: " + notes if notes else ""))[:1500]
            saved_order = supabase_request("POST", "/rest/v1/customer_orders", payload={"reference":reference,"telegram_user_id":str(verified_order_user_id),"telegram_username":telegram_username,"customer_name":customer.get("name", ""),"phone":customer.get("phone", ""),"delivery_location":location_text,"contact_preference":customer.get("contact_preference", "Phone call"),"items":items,"product_total_etb":total,"delivery_fee_etb":delivery_fee,"total_etb":total_with_delivery,"delivery_area":delivery_area,"delivery_distance_km":delivery_distance_km,"delivery_fee_mode":delivery_fee_mode,"gps_lat":gps_lat,"gps_lon":gps_lon,"payment_percentage":payment_percentage,"amount_due_now_etb":amount_due_now,"remaining_balance_etb":remaining_balance,"status":"Received","payment_status":payment_label,"notes":saved_notes})
            if not saved_order:
                raise RuntimeError("Supabase did not return the saved order row")
            chapa_checkout_url = None
            if payment_option == "chapa":
                if not CHAPA_SECRET_KEY:
                    return jsonify(error="Chapa is not configured yet. Please choose Pay Later or contact AMBAR."), 503
                if not all(item.get("unit_price", 0) > 0 for item in items):
                    return jsonify(error="Chapa checkout requires confirmed product prices."), 400
                first_name, _, last_name = (customer.get("name", "Customer").strip().partition(" "))
                phone = re.sub(r"[^0-9+]", "", str(customer.get("phone", "")))
                if phone.startswith("0") and len(phone) == 10:
                    phone = "+251" + phone[1:]
                return_url = f"{WEBAPP_URL.rstrip('/')}/api/chapa/return?reference={quote(reference, safe='')}"
                try:
                    chapa_result = chapa_api_request("POST", "/v2/payments/hosted", payload={
                        "amount": f"{amount_due_now:.2f}",
                        "currency": "ETB",
                        "merchant_reference": reference,
                        "return_url": return_url,
                        "customer": {"first_name": first_name or "Customer", "last_name": last_name or "AMBAR", "phone_number": phone},
                        "meta": {"order_id": reference, "business": "AMBAR Furniture", "payment_percentage": payment_percentage, "full_order_total_etb": f"{total_with_delivery:.2f}", "remaining_balance_etb": f"{remaining_balance:.2f}"},
                    })
                    chapa_data = chapa_result.get("data") if isinstance(chapa_result.get("data"), dict) else {}
                    chapa_checkout_url = str(chapa_data.get("checkout_url") or "").strip()
                    if not chapa_checkout_url.startswith("https://"):
                        raise RuntimeError("Chapa did not return a valid secure checkout URL.")
                    provider_reference = str(chapa_data.get("reference") or chapa_data.get("chapa_reference") or reference).strip()
                    supabase_request("PATCH", "/rest/v1/customer_orders", params={"reference":f"eq.{reference}"}, payload={"chapa_reference":provider_reference,"chapa_checkout_url":chapa_checkout_url,"payment_status":f"Chapa {payment_percentage}% advance payment pending","updated_at":dt.datetime.now(dt.timezone.utc).isoformat()})
                except Exception as chapa_exc:
                    log.exception("Could not initialize Chapa for order %s", reference)
                    return jsonify(error=str(chapa_exc) if "not configured" in str(chapa_exc).lower() else "Your order was saved, but Chapa checkout could not be opened. Please try again or choose Pay Later."), 502
        except Exception:
            log.exception("Could not persist order %s; order tracking is required", reference)
            return jsonify(error="Your order could not be saved to My Orders. Please check the connection and try again, or contact AMBAR."), 503

        # Staff notification is attempted only after the database has saved the order.
        try:
            send_order_album(caption, items, str(temp_path) if temp_path else None)
        except Exception:
            log.exception("Order %s is saved, but the staff Telegram notification failed", reference)
        stock_orderable_order = any(
            str(item.get("stock_status", "in_stock")).lower() == "out_of_stock"
            for item in items
        )
        # This exact confirmation is sent to the customer in Telegram and returned to
        # the Mini App, so both places show the same order details and status.
        customer_product_lines = "\n".join(
            f"• {item['name']} × {item['quantity']} — {item['measurement']} — {format(item['line_total'], ',') + ' ETB' if item['unit_price'] > 0 else 'Price to be confirmed'}"
            for item in items
        )
        payment_summary = (
            f"NOT VERIFIED — your {payment_percentage}% advance screenshot ({amount_due_now:,.2f} ETB) was received for review; payment is not confirmed. Remaining balance: {remaining_balance:,.2f} ETB."
            if payment_option == "pay_now"
            else (f"PENDING — Chapa checkout was created for your {payment_percentage}% advance ({amount_due_now:,.2f} ETB); server-side verification is required. Remaining balance: {remaining_balance:,.2f} ETB."
                  if payment_option == "chapa" else "NOT RECEIVED — Pay Later selected; your order was sent without collecting payment.")
        )
        recipient_summary = (
            f"\n\n✦ RECIPIENT  ·  GIFT OR FAMILY\n"
            f"Name: {recipient_name}\nPhone: {recipient_phone}\n"
            f"Payment: {'Recipient pays on delivery' if payer == 'recipient' else 'Buyer pays'}\n"
            f"Instructions: {recipient_instructions or 'None'}"
            if order_for == "someone_else" else ""
        )
        product_summary = "\n".join(
            f"{idx:02d}  {item['name']}  × {item['quantity']}  ·  {item['measurement']}  ·  "
            f"{format(item['line_total'], ',') + ' ETB' if item['unit_price'] > 0 else 'Price to be confirmed'}"
            for idx, item in enumerate(items, 1)
        )
        customer_name = str(customer.get('name', 'Customer')).strip() or 'Customer'
        total_label = f"{total_with_delivery:,.2f} ETB" if all(item["unit_price"] > 0 for item in items) and delivery_area != "To be confirmed" else "To be confirmed / ይረጋገጣል"
        advance_label = f"{amount_due_now:,.2f} ETB"
        remaining_label = f"{remaining_balance:,.2f} ETB"
        first_payment_selection = round(total_with_delivery * payment_percentage / 100, 2) if payment_percentage else 0.0
        first_payment_selection_label = f"{first_payment_selection:,.2f} ETB"
        if payment_option == "pay_later":
            payment_detail_en = f"First payment selection: {payment_percentage}% ({first_payment_selection_label})\nAdvance due now: 0.00 ETB\nRemaining balance: {remaining_label}\nPayment: Pay Later"
            payment_detail_am = f"የመጀመሪያ ክፍያ ምርጫ: {payment_percentage}% ({first_payment_selection_label})\nአሁን የሚከፈል ቅድሚያ: 0.00 ETB\nቀሪ ክፍያ: {remaining_label}\nክፍያ: በኋላ ይከፈላል"
        elif payment_option == "chapa":
            payment_detail_en = f"First payment selection: {payment_percentage}% ({first_payment_selection_label})\nAdvance payment: {advance_label} ({payment_percentage}%) · Pending verification\nRemaining balance: {remaining_label}"
            payment_detail_am = f"የመጀመሪያ ክፍያ ምርጫ: {payment_percentage}% ({first_payment_selection_label})\nየቅድሚያ ክፍያ: {advance_label} ({payment_percentage}%) · ማረጋገጫ በመጠባበቅ ላይ\nቀሪ ክፍያ: {remaining_label}"
        else:
            payment_detail_en = f"First payment selection: {payment_percentage}% ({first_payment_selection_label})\nAdvance payment: {advance_label} ({payment_percentage}%) · Awaiting verification\nRemaining balance: {remaining_label}"
            payment_detail_am = f"የመጀመሪያ ክፍያ ምርጫ: {payment_percentage}% ({first_payment_selection_label})\nየቅድሚያ ክፍያ: {advance_label} ({payment_percentage}%) · ማረጋገጫ በመጠባበቅ ላይ\nቀሪ ክፍያ: {remaining_label}"
        customer_message = (
            f"Hi {customer_name},\nyour order has been received.\n"
            f"AMBAR FURNITURE\n"
            f"Order ID: {reference}\n"
            f"Order total: {total_label}\n"
            f"{payment_detail_en}\n"
            "Thank you for choosing AMBAR. We’ll keep you updated.\n"
            "━━━━━━━━━━━━━━━━━━\n"
            f"ሰላም {customer_name}፣\nትዕዛዝዎ ደርሶናል።\n"
            f"የትዕዛዝ ቁጥር: {reference}\n"
            f"ጠቅላላ የትዕዛዝ ዋጋ: {total_label}\n"
            f"{payment_detail_am}\n"
            "እናመሰግናለን። ስለ ትዕዛዝዎ እናሳውቅዎታለን።"
        )
    except Exception:
        log.exception("Final order submission failed for %s", reference)
        return jsonify(error="We could not send your order to customer service. Please try again."), 502
    finally:
        if temp_path:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass

    customer_photo_paths = product_photo_paths(items)
    try:
        maybe_send_customer_confirmation_with_photos(telegram_user_id, customer_message, customer_photo_paths)
    finally:
        for photo_path in customer_photo_paths:
            if photo_path.name.startswith("order_product_"):
                try: photo_path.unlink(missing_ok=True)
                except OSError: pass
    return jsonify(ok=True, reference=reference, total=total, delivery_fee=delivery_fee, total_with_delivery=total_with_delivery, payment_status=status_text, timestamp=timestamp,
                   checkout_url=chapa_checkout_url if payment_option == "chapa" else None,
                   stock_orderable=stock_orderable_order, confirmation_message=customer_message), 200


@app.post("/api/custom-request")
def create_custom_request():
    load_product_catalog()
    # Multipart requests carry signed Telegram initData in a form field.
    init_data = request.form.get("init_data", "")
    valid, telegram_user_id = auth_result(init_data)
    telegram_username = telegram_username_from_init_data(init_data) if valid else "Not available"
    telegram_language = telegram_language_from_init_data(init_data) if valid else "Not available"
    if not valid:
        return jsonify(error="Telegram authentication failed. Please close the Mini App and open it again from your Telegram bot."), 401
    try:
        category = clean_text(request.form.get("category"), 140, "Furniture category", True)
        if category not in CATEGORIES and not (category.startswith("Other: ") and len(category[7:].strip()) > 0):
            raise ValueError("Choose one of the available furniture categories or specify Other.")
        description = clean_text(request.form.get("description"), 2000, "Design description", True)
        measurements = clean_text(request.form.get("measurements", ""), 1500, "Measurements")
        customer = validate_customer({
            "name": request.form.get("name"),
            "phone": request.form.get("phone"),
            "location": request.form.get("location"),
            "contact_preference": "Not specified",
        })
        images = request.files.getlist("images")
        voice = request.files.get("voice")
        voice_path = None
        if voice and voice.filename:
            voice_mime = (voice.mimetype or "").lower()
            if not (voice_mime.startswith("audio/") or voice.filename.lower().endswith((".webm", ".ogg", ".mp4", ".wav", ".m4a"))):
                raise ValueError("Voice recording must be an audio file.")
            voice_content = voice.stream.read(12 * 1024 * 1024 + 1)
            if len(voice_content) > 12 * 1024 * 1024:
                raise ValueError("Voice recording must be smaller than 12 MB.")
            voice_path = str(UPLOAD_DIR / secure_filename(f"{secrets.token_hex(12)}.webm"))
            with open(voice_path, "wb") as voice_handle:
                voice_handle.write(voice_content)
        if len(images) > 4:
            raise ValueError("Attach no more than four reference pictures.")
        if not any(image and image.filename for image in images):
            raise ValueError("Attach at least one reference photo of the product or design.")
        saved_paths = []
        for image in images:
            if not image or not image.filename:
                continue
            mime = (image.mimetype or "").lower()
            extension = ALLOWED_MIME.get(mime)
            if not extension:
                raise ValueError("Pictures must be JPG, PNG, or WebP.")
            # Read at most 8 MB + 1 byte to enforce the limit even if client metadata is wrong.
            content = image.stream.read(8 * 1024 * 1024 + 1)
            if len(content) >= 8 * 1024 * 1024:
                raise ValueError("Each picture must be smaller than 8 MB.")
            # Basic signature checks reduce reliance on browser-provided MIME types.
            signatures = {
                "image/jpeg": content.startswith(b"\xff\xd8\xff"),
                "image/png": content.startswith(b"\x89PNG\r\n\x1a\n"),
                "image/webp": len(content) >= 12 and content[:4] == b"RIFF" and content[8:12] == b"WEBP",
            }
            if not signatures.get(mime, False):
                raise ValueError("A selected picture does not match its declared image type.")
            filename = secure_filename(f"{secrets.token_hex(12)}{extension}")
            path = UPLOAD_DIR / filename
            path.write_bytes(content)
            saved_paths.append(str(path))
    except ValueError as exc:
        return jsonify(error=str(exc)), 400

    reference = new_reference("AC")
    timestamp = ethiopian_datetime()
    lines = [
        "🪑 AMBAR FURNITURE | CUSTOM REQUEST",
        "━━━━━━━━━━━━━━━━━━━━",
        f"🧾 Reference: {reference}",
        f"🕒 Submitted: {timestamp}",
        "",
        "📐 MATERIALS & DESIGN DESCRIPTION",
        f"Furniture type: {category}",
        f"Customer's design / materials description: {description or 'Not provided'}",
        f"Measurements / additional design details: {measurements or 'Not provided'}",
        "",
        "👤 CUSTOMER DETAILS",
        f"Name: {customer['name']}",
        f"Telegram username: {telegram_username}",
        f"Telegram user ID: {telegram_user_id or 'Not available'}",
        f"Telegram language: {telegram_language}",
        f"Phone: {customer['phone']}",
        f"Delivery location: {customer['location']}",
        "",
        "📎 SUBMITTED FILES",
        f"Reference photos: {len(saved_paths)} (attached below)",
        f"Voice recording: {'Attached as a reply below' if voice_path else 'Not provided'}",
        "",
        f"📍 AMBAR Furniture store location: {AMBAR_LOCATION_URL}",
        "Status: Received for review; price is not yet confirmed."
    ]
    request_text = "\n".join(lines)
    try:
        # Telegram cannot place photos, a voice recording, and long text in one literal message.
        # Send one complete, formatted master message, then attach the album and voice as replies
        # so all parts remain grouped under the same confirmation in the service channel.
        master_message = send_service_message(request_text)
        master_id = master_message.get("message_id") if isinstance(master_message, dict) else None
        if saved_paths:
            send_service_photo_album(
                saved_paths,
                f"📸 Reference photos for {reference} ({len(saved_paths)} photo(s)). See the confirmation message above for the design/materials description and AMBAR store location.",
                reply_to_message_id=master_id,
            )
            log.info("Sent %s custom-request photo(s) for %s to service chat", len(saved_paths), reference)
        if voice_path:
            send_service_voice(
                voice_path,
                f"🎙️ Customer voice instructions — {reference}. Attached to the same custom-request confirmation above.",
                reply_to_message_id=master_id,
            )
            log.info("Sent custom-request voice recording for %s to service chat", reference)
        maybe_send_customer_confirmation(
            telegram_user_id,
            "Estimated completion: 5–7 working days.\n"
            "Thank you! Your order details and final amount will be confirmed by our team.\n"
            "After the team confirms your custom request, our customer service team will contact you to discuss every detail.\n\n"
            f"Work location: {AMBAR_LOCATION_URL}"
        )
    except Exception:
        log.exception("Service notification failed for custom request %s", reference)
        for path in saved_paths + ([voice_path] if voice_path else []):
            try: os.remove(path)
            except OSError: pass
        return jsonify(error="We could not send the complete custom request and its attachments to customer service. Please try again."), 502
    finally:
        for path in saved_paths + ([voice_path] if voice_path else []):
            try: os.remove(path)
            except OSError: pass

    return jsonify(ok=True, reference=reference, image_count=len(saved_paths), voice_attached=bool(voice_path)), 200


def load_notification_subscribers():
    try:
        with SUBSCRIBER_LOCK:
            raw = json.loads(NOTIFICATION_SUBSCRIBERS_FILE.read_text(encoding="utf-8"))
        return {str(chat_id) for chat_id in raw if str(chat_id).lstrip("-").isdigit()}
    except (OSError, ValueError, TypeError):
        return set()


def save_notification_subscribers(subscribers):
    NOTIFICATION_SUBSCRIBERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with SUBSCRIBER_LOCK:
        temp_path = NOTIFICATION_SUBSCRIBERS_FILE.with_suffix(".tmp")
        temp_path.write_text(json.dumps(sorted(set(map(str, subscribers))), indent=2), encoding="utf-8")
        temp_path.replace(NOTIFICATION_SUBSCRIBERS_FILE)


async def subscribe_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat = update.effective_chat
    if not chat or chat.type != "private":
        await update.effective_message.reply_text("Please use /subscribe in a private chat with AMBAR Furniture.")
        return
    subscribers = load_notification_subscribers()
    subscribers.add(str(chat.id))
    save_notification_subscribers(subscribers)
    await update.effective_message.reply_text(
        "You’re subscribed to AMBAR product updates. We’ll send one featured product photo per day, rotating through the catalogue.\n\n"
        "To stop these messages any time, send /unsubscribe."
    )


async def unsubscribe_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat = update.effective_chat
    if not chat:
        return
    subscribers = load_notification_subscribers()
    subscribers.discard(str(chat.id))
    save_notification_subscribers(subscribers)
    await update.effective_message.reply_text("You’re unsubscribed from daily product updates. You can opt in again with /subscribe.")


async def send_daily_product_notifications(context: ContextTypes.DEFAULT_TYPE):
    subscribers = load_notification_subscribers()
    if not subscribers:
        log.info("Daily product notification skipped: no opted-in subscribers.")
        return
    try:
        today = dt.datetime.now(ZoneInfo(NOTIFICATION_TIMEZONE)).date()
    except Exception:
        log.exception("Invalid PRODUCT_NOTIFICATION_TIMEZONE; using UTC for product rotation.")
        today = dt.datetime.now(dt.timezone.utc).date()
    product_ids = list(PRODUCTS.keys())
    day_index = (today - PRODUCT_NOTIFICATION_START).days % len(product_ids)
    product_id = product_ids[day_index]
    product = PRODUCTS[product_id]
    image_path = BASE_DIR / "products" / f"{product_id.replace('_', '-')}.webp"
    if not image_path.is_file():
        log.error("Daily product image is missing: %s", image_path)
        return
    caption = (f"🪵 AMBAR Furniture — Daily Featured Product\n\n"
               f"{product['name']}\n"
               f"Category: {product['category']}\n"
               f"Price: {product['price']:,} ETB (120 cm)\n\n"
               f"Explore the catalogue and send an order: {WEBAPP_URL}\n\n"
               f"Daily product {day_index + 1} of {len(product_ids)} · Send /unsubscribe to stop.")
    for chat_id in sorted(subscribers):
        try:
            with image_path.open("rb") as photo:
                await context.bot.send_photo(chat_id=int(chat_id), photo=photo, caption=caption[:1024])
        except Exception as exc:
            log.warning("Daily product notification failed for chat %s: %s", chat_id, exc)


def build_luxury_share_card(product, photo_url=None):
    """Create a branded luxury product card image for Telegram sharing."""
    if Image is None:
        return None
    try:
        width, height = 1080, 1350
        bg = (20, 19, 18)
        gold = (224, 174, 105)
        cream = (247, 239, 224)
        muted = (194, 183, 166)
        canvas = Image.new("RGB", (width, height), bg)
        draw = ImageDraw.Draw(canvas)
        draw.rounded_rectangle((24, 24, width-24, height-24), radius=38, fill=(27, 25, 23), outline=(155, 107, 55), width=3)
        regular = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
        bold = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
        def ft(size, is_bold=False):
            path = bold if is_bold else regular
            try: return ImageFont.truetype(path, size)
            except Exception: return ImageFont.load_default()
        draw.text((68, 62), "AMBAR FURNITURE", font=ft(34, True), fill=gold)
        draw.text((68, 112), "PRODUCT COLLECTION  /  ETHIOPIA", font=ft(20, True), fill=muted)
        # Actual catalogue photo, cropped to a premium editorial frame.
        photo = None
        if photo_url and str(photo_url).startswith("https://"):
            try:
                r = requests.get(str(photo_url), timeout=8, headers={"User-Agent":"AMBAR-Furniture-Bot/1.0"})
                r.raise_for_status()
                photo = Image.open(BytesIO(r.content)).convert("RGB")
            except Exception:
                photo = None
        if photo is None:
            # If the catalogue image is unavailable, keep a clean, branded image area.
            photo = Image.new("RGB", (960, 650), (235, 226, 211))
            pd = ImageDraw.Draw(photo)
            pd.text((40, 280), "AMBAR FURNITURE", font=ft(36, True), fill=(120, 83, 47))
        photo = ImageOps.fit(photo, (950, 640), method=Image.Resampling.LANCZOS, centering=(0.5, 0.5))
        mask = Image.new("L", photo.size, 0)
        ImageDraw.Draw(mask).rounded_rectangle((0,0,photo.width-1,photo.height-1), radius=26, fill=255)
        canvas.paste(photo, (65, 170), mask)
        name = str(product.get("name") or "AMBAR Furniture Product")[:48]
        category = str(product.get("category") or "Furniture")[:36].upper()
        draw.text((68, 850), name, font=ft(56, True), fill=cream)
        draw.rounded_rectangle((68, 940, 390, 1000), radius=28, outline=gold, width=2)
        draw.text((91, 956), category, font=ft(21, True), fill=gold)
        try:
            price = float(product.get("price") or 0)
            price_text = f"{price:,.0f} ETB" if price > 0 else "PRICE ON REQUEST"
        except (TypeError, ValueError):
            price_text = "PRICE ON REQUEST"
        draw.text((68, 1030), price_text, font=ft(38, True), fill=(240, 198, 121))
        stock = "AVAILABLE TO ORDER" if product.get("stock_status") == "out_of_stock" and product.get("allow_order", True) else ("CURRENTLY OUT OF STOCK" if product.get("stock_status") == "out_of_stock" else "AVAILABLE IN STOCK")
        draw.text((68, 1090), "•  " + stock, font=ft(22, True), fill=muted)
        draw.line((68, 1150, 1012, 1150), fill=(83, 68, 53), width=2)
        draw.text((68, 1182), "VIEW DETAILS   •   CHECK COLORS   •   ORDER NOW", font=ft(20, True), fill=cream)
        draw.text((68, 1240), "Open the AMBAR bot for photos and ordering", font=ft(21), fill=gold)
        out = BytesIO()
        canvas.save(out, format="JPEG", quality=90, optimize=True)
        out.seek(0)
        out.name = "ambar-product-card.jpg"
        return out
    except Exception:
        log.exception("Could not render luxury Telegram product card")
        return None


async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat = update.effective_chat
    # Telegram bots can message a customer only after they have started the bot.
    # Automatically register private chats for daily product notifications on /start.
    if chat and chat.type == "private":
        subscribers = load_notification_subscribers()
        subscribers.add(str(chat.id))
        save_notification_subscribers(subscribers)
    app_url = WEBAPP_URL
    # Shared product links open a photo-led Telegram product card with real inline buttons.
    payload = context.args[0] if context.args else ""
    product = None
    if payload.startswith("product_"):
        product_id = payload[len("product_"):]
        if re.fullmatch(r"[A-Za-z0-9_-]{1,48}", product_id):
            try:
                load_product_catalog()
                product = PRODUCTS.get(product_id)
            except Exception:
                log.exception("Could not load product for Telegram share card")
            parsed = urlsplit(WEBAPP_URL)
            query = dict(parse_qsl(parsed.query, keep_blank_values=True))
            query["product"] = product_id
            app_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query), parsed.fragment))
    keyboard = [[InlineKeyboardButton("🪑 View product details", web_app=WebAppInfo(url=app_url)),
                 InlineKeyboardButton("🛍 Order now", web_app=WebAppInfo(url=app_url))]]
    markup = InlineKeyboardMarkup(keyboard)
    if product:
        price = product.get("price")
        try:
            price_text = f"{float(price):,.0f} ETB" if float(price or 0) > 0 else "Price to be confirmed"
        except (TypeError, ValueError):
            price_text = "Price to be confirmed"
        category = str(product.get("category") or "Furniture")[:100]
        name = str(product.get("name") or "AMBAR Furniture product")[:160]
        description = str(product.get("description") or "Discover the design, finish, and practical details of this AMBAR furniture piece.")
        stock = "Out of stock · Available to order" if product.get("stock_status") == "out_of_stock" and product.get("allow_order", True) else ("Currently out of stock" if product.get("stock_status") == "out_of_stock" else "Available in stock")
        caption = (f"🪑 AMBAR FURNITURE  •  PRODUCT COLLECTION\n\n"
                   f"✨ {name}\n"
                   f"📂 {category}\n"
                   f"💰 {price_text}\n"
                   f"🟡 {stock}\n\n"
                   f"{description[:500]}\n\n"
                   f"Tap a button below to view photos, colors, specifications, and order this product.")
        images = product.get("images") if isinstance(product.get("images"), list) else []
        # Check both catalogue image arrays and the single-image field.
        image_candidates = list(images)
        if product.get("image_url"):
            image_candidates.append(product.get("image_url"))
        photo = None
        for candidate in image_candidates:
            candidate = str(candidate or "").strip()
            if candidate.startswith("//"):
                candidate = "https:" + candidate
            if candidate.startswith(("https://", "http://")):
                photo = candidate
                break
        if photo:
            try:
                luxury_card = build_luxury_share_card(product, photo)
                if luxury_card:
                    await update.effective_message.reply_photo(photo=luxury_card, caption=caption[:1024], reply_markup=markup)
                    return
                await update.effective_message.reply_photo(photo=photo, caption=caption[:1024], reply_markup=markup)
                return
            except Exception:
                log.exception("Could not send luxury product share card for %s", product_id)
        await update.effective_message.reply_text(caption, reply_markup=markup)
        return
    message = "Welcome to AMBAR Furniture! You’ll receive one featured product photo each day. Use /unsubscribe any time to stop daily product updates. Browse the catalogue and place an order using the button below."
    await update.effective_message.reply_text(message, reply_markup=markup)


def start_telegram_polling():
    global telegram_app
    if not BOT_TOKEN:
        log.warning("BOT_TOKEN is missing. Website APIs will not be able to send Telegram notifications.")
        return
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        telegram_app = Application.builder().token(BOT_TOKEN).build()
        telegram_app.add_handler(CommandHandler("start", start_command))
        telegram_app.add_handler(CommandHandler("subscribe", subscribe_command))
        telegram_app.add_handler(CommandHandler("unsubscribe", unsubscribe_command))
        async def runner():
            await telegram_app.initialize()
            if telegram_app.job_queue is not None:
                try:
                    notification_tz = ZoneInfo(NOTIFICATION_TIMEZONE)
                except Exception:
                    log.exception("Invalid PRODUCT_NOTIFICATION_TIMEZONE; falling back to UTC.")
                    notification_tz = dt.timezone.utc
                telegram_app.job_queue.run_daily(
                    send_daily_product_notifications,
                    time=dt.time(hour=NOTIFICATION_HOUR, minute=0, tzinfo=notification_tz),
                    name="ambar-daily-product-notification",
                )
                telegram_app.job_queue.run_daily(
                    send_daily_cart_digest,
                    time=dt.time(hour=(NOTIFICATION_HOUR + 1) % 24, minute=0, tzinfo=notification_tz),
                    name="ambar-daily-cart-digest",
                )
                log.info("Daily product notifications scheduled for %02d:00 %s", NOTIFICATION_HOUR, NOTIFICATION_TIMEZONE)
            else:
                log.error("Daily product notifications are disabled: install python-telegram-bot with the job-queue extra.")
            await telegram_app.start()
            await telegram_app.updater.start_polling(drop_pending_updates=False)
        loop.run_until_complete(runner())
        log.info("Telegram polling started in the same process.")
        loop.run_forever()
    except Exception:
        log.exception("Telegram polling did not start. Check Render logs and ensure no second polling instance is running.")



# Customer order status is controlled by the admin. Automatic Received -> Confirmed
# transitions are intentionally disabled to keep customer tracking aligned with admin status.
_auto_confirm_thread_started = False


def auto_confirm_received_orders_once():
    """Legacy compatibility stub; automatic order status changes are disabled."""
    return
    # Historical implementation intentionally retained below for traceability.
    if not supabase_enabled():
        return
    now = dt.datetime.now(dt.timezone.utc)
    cutoff = (now - dt.timedelta(minutes=AUTO_CONFIRM_DELAY_MINUTES)).isoformat()
    rows = supabase_request(
        "GET", "/rest/v1/customer_orders",
        params={
            "select": "reference,status,created_at,telegram_user_id,customer_name,product_total_etb,delivery_fee_etb,total_etb,delivery_area",
            "status": "eq.Received",
            "created_at": f"lte.{cutoff}",
            "order": "created_at.asc",
            "limit": "100",
        },
    ) or []
    for order in rows:
        reference = str(order.get("reference") or "").strip()
        if not reference:
            continue
        # Compare-and-set prevents changing an order that staff already moved to another status.
        updated = supabase_request(
            "PATCH", "/rest/v1/customer_orders",
            params={"reference": f"eq.{reference}", "status": "eq.Received", "created_at": f"lte.{cutoff}"},
            payload={"status": "Confirmed", "updated_at": now.isoformat()},
        ) or []
        if not updated:
            continue
        saved = updated[0]
        user_id = str(saved.get("telegram_user_id") or order.get("telegram_user_id") or "").strip()
        if not user_id or not BOT_TOKEN:
            log.warning("Auto-confirmed order %s but cannot notify customer: missing Telegram ID or BOT_TOKEN", reference)
            continue
        customer = str(saved.get("customer_name") or order.get("customer_name") or "Valued Customer").strip()
        total = saved.get("total_etb", order.get("total_etb"))
        try:
            total_text = f"{float(total or 0):,.2f} ETB"
        except (TypeError, ValueError):
            total_text = "To be confirmed by AMBAR"
        message = (
            ""
            f"Hello {customer}! Your AMBAR order is confirmed.\n"
            f"Order ID: {reference} · Total: {total_text}\n"
            "Thank you! We’ll contact you if needed. Payment is handled separately.\n\n"
            ""
            f"ሰላም {customer}! ትዕዛዝዎ ተረጋግጧል።\n"
            f"የትዕዛዝ ቁጥር: {reference} · ጠቅላላ: {total_text}\n"
            "እናመሰግናለን! ካስፈለገ እናገኝዎታለን። ክፍያው በተለየ ይከናወናል።"
        )
        try:
            bot_api("sendMessage", {"chat_id": user_id, "text": message, "disable_web_page_preview": True})
        except Exception:
            log.exception("Order %s auto-confirmed, but customer notification failed", reference)


def auto_confirm_orders_loop():
    """Poll Supabase so auto-confirmation works even when no admin/customer is online."""
    while True:
        try:
            auto_confirm_received_orders_once()
        except Exception:
            log.exception("Automatic order confirmation sweep failed")
        time.sleep(AUTO_CONFIRM_POLL_SECONDS)


def main():
    global telegram_thread_started, _auto_confirm_thread_started
    if BOT_TOKEN and not telegram_thread_started:
        thread = threading.Thread(target=start_telegram_polling, name="telegram-polling", daemon=True)
        thread.start()
        telegram_thread_started = True
    # Render should run this file as a single process: python bot.py
    # Do not run a separate local polling copy while this service is active.
    port = int(os.getenv("PORT", "10000"))
    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False, threaded=True)


if __name__ == "__main__":
    main()
