"""Set the Telegram bot menu button to open the CHO SPOT Mini App.
Run after deploying: TELEGRAM_BOT_TOKEN=... PUBLIC_APP_URL=https://... python set_telegram_menu_button.py"""
import os, requests

token=os.environ.get('TELEGRAM_BOT_TOKEN','').strip()
url=os.environ.get('PUBLIC_APP_URL','').strip().rstrip('/')
if not token or not url.startswith('https://'):
    raise SystemExit('Set TELEGRAM_BOT_TOKEN and an HTTPS PUBLIC_APP_URL first.')
r=requests.post(f'https://api.telegram.org/bot{token}/setChatMenuButton',json={'menu_button':{'type':'web_app','text':'Order Food','web_app':{'url':url}}},timeout=20)
print(r.status_code, r.text)
r.raise_for_status()
