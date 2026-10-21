import os, json, hmac, hashlib, time, secrets, logging
from datetime import datetime, timezone, timedelta
from urllib.parse import urlencode
import requests
from flask import Flask, request, jsonify, send_from_directory, abort

app = Flask(__name__, static_folder='static')
app.config['MAX_CONTENT_LENGTH'] = 8 * 1024 * 1024
logging.basicConfig(level=logging.INFO)

SUPABASE_URL = os.getenv('SUPABASE_URL','').rstrip('/')
SUPABASE_KEY = os.getenv('SUPABASE_SERVICE_ROLE_KEY','') or os.getenv('SUPABASE_SECRET_KEY','')
BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN','')
ADMIN_IDS = {x.strip() for x in os.getenv('ADMIN_TELEGRAM_IDS','').split(',') if x.strip()}
CHAPA_SECRET = os.getenv('CHAPA_SECRET_KEY','')
PUBLIC_URL = os.getenv('PUBLIC_APP_URL','').rstrip('/')
RESTAURANT_NAME = os.getenv('RESTAURANT_NAME','CHO SPOT')
CURRENCY = 'ETB'

DEFAULT_MENU = [
 {'id':'food-burger','name':'CHO Special Burger','name_am':'የCHO ስፔሻል በርገር','category':'Burgers','price':450,'description':'Juicy burger, fresh greens & house sauce','description_am':'ጣፋጭ በርገር ከአትክልትና ልዩ ሶስ ጋር','image':'','available':True,'pinned':True,'prep_minutes':20},
 {'id':'food-pizza','name':'Classic Cheese Pizza','name_am':'ክላሲክ ቺዝ ፒዛ','category':'Pizza','price':650,'description':'Melted cheese, tomato & Italian herbs','description_am':'ቺዝ፣ ቲማቲም እና የጣሊያን ቅመሞች','image':'','available':True,'pinned':True,'prep_minutes':25},
 {'id':'food-chicken','name':'Grilled Chicken Plate','name_am':'የተጠበሰ ዶሮ','category':'Meals','price':580,'description':'Seasoned chicken with a hearty side','description_am':'በቅመም የተዘጋጀ ዶሮ ከጎን ምግብ ጋር','image':'','available':True,'pinned':True,'prep_minutes':25},
 {'id':'food-pasta','name':'Spicy Pasta','name_am':'ቅመም ያለው ፓስታ','category':'Meals','price':420,'description':'Rich tomato sauce with a gentle kick','description_am':'በቲማቲም ሶስ የተዘጋጀ ፓስታ','image':'','available':True,'pinned':False,'prep_minutes':18},
 {'id':'food-fries','name':'Crispy Fries','name_am':'ጥርት ያለ ቺፕስ','category':'Sides','price':180,'description':'Golden, crunchy and made to share','description_am':'ወርቃማና ጥርት ያለ ቺፕስ','image':'','available':True,'pinned':False,'prep_minutes':10},
 {'id':'food-juice','name':'Fresh Juice','name_am':'ትኩስ ጭማቂ','category':'Drinks','price':150,'description':'A refreshing fruit drink','description_am':'ትኩስ የፍራፍሬ ጭማቂ','image':'','available':True,'pinned':False,'prep_minutes':5},
 {'id':'food-double-burger','name':'Double Smash Burger','name_am':'ድርብ በርገር','category':'Burgers','price':590,'description':'Double patties, melted cheese & sauce','description_am':'ድርብ ስጋ፣ ቺዝ እና ሶስ','image':'','available':True,'pinned':False,'prep_minutes':22},
 {'id':'food-dessert','name':'Chocolate Dessert','name_am':'ቸኮሌት ጣፋጭ ምግብ','category':'Desserts','price':220,'description':'A sweet finish to your meal','description_am':'ለምግብዎ ጣፋጭ መደምደሚያ','image':'','available':True,'pinned':False,'prep_minutes':5},
]
DEFAULT_SETTINGS = {'restaurant_name':'CHO SPOT','phone':'','address':'','opening_hours':'','delivery_enabled':True,'pickup_enabled':True,'delivery_base_fee':50,'delivery_per_km':15,'delivery_max_km':20,'free_delivery_over':0,'service_fee':0,'currency':'ETB','about':'Good food. Good mood. Freshly prepared and served with love.','about_am':'ጣፋጭ ምግብ። ጥሩ ስሜት።','chapa_enabled':False,'advance_percentages':[100,50,40,30,20]}

class StoreError(Exception): pass

def db_headers(prefer=None):
    h={'apikey':SUPABASE_KEY,'Authorization':f'Bearer {SUPABASE_KEY}','Content-Type':'application/json'}
    if prefer: h['Prefer']=prefer
    return h

def db_get(table, params=None):
    if not SUPABASE_URL or not SUPABASE_KEY: raise StoreError('Database not configured. Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY, then run sql/schema.sql.')
    r=requests.get(f'{SUPABASE_URL}/rest/v1/{table}',headers=db_headers(),params=params or {},timeout=15)
    if not r.ok: raise StoreError(f'Database read failed for {table}: {r.text[:300]}')
    return r.json()

def db_insert(table, payload, upsert=False):
    if not SUPABASE_URL or not SUPABASE_KEY: raise StoreError('Database not configured. Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY, then run sql/schema.sql.')
    h=db_headers('resolution=merge-duplicates,return=representation' if upsert else 'return=representation')
    if upsert: h['Prefer']='resolution=merge-duplicates,return=representation'
    conflict_col = 'key' if table == 'restaurant_settings' else 'id'
    r=requests.post(f'{SUPABASE_URL}/rest/v1/{table}',headers=h,json=payload,params={'on_conflict':conflict_col} if upsert else {},timeout=15)
    if not r.ok: raise StoreError(f'Database write failed for {table}: {r.text[:300]}')
    return r.json()

def db_patch(table, params, payload):
    if not SUPABASE_URL or not SUPABASE_KEY: raise StoreError('Database not configured.')
    r=requests.patch(f'{SUPABASE_URL}/rest/v1/{table}',headers=db_headers('return=representation'),params=params,json=payload,timeout=15)
    if not r.ok: raise StoreError(f'Database update failed for {table}: {r.text[:300]}')
    return r.json()

def db_delete(table, params):
    if not SUPABASE_URL or not SUPABASE_KEY: raise StoreError('Database not configured.')
    r=requests.delete(f'{SUPABASE_URL}/rest/v1/{table}',headers=db_headers('return=representation'),params=params,timeout=15)
    if not r.ok: raise StoreError(f'Database delete failed for {table}: {r.text[:300]}')
    return r.json()

def db_ready(): return bool(SUPABASE_URL and SUPABASE_KEY)

def get_settings():
    if not db_ready(): return DEFAULT_SETTINGS
    rows=db_get('restaurant_settings',{'select':'key,value'})
    s=dict(DEFAULT_SETTINGS)
    for row in rows:
        try: s[row['key']]=row['value']
        except Exception: pass
    return s

def get_menu():
    if not db_ready(): return DEFAULT_MENU
    rows=db_get('menu_items',{'select':'*','order':'pinned.desc,category.asc,name.asc'})
    return rows or DEFAULT_MENU

def telegram_user():
    raw=request.headers.get('X-Telegram-Init-Data','')
    if not raw or not BOT_TOKEN: return None
    try:
        from urllib.parse import parse_qsl
        data=dict(parse_qsl(raw,keep_blank_values=True)); received=data.pop('hash',None)
        if not received: return None
        check='\n'.join(f'{k}={v}' for k,v in sorted(data.items()))
        secret=hmac.new(b'WebAppData',BOT_TOKEN.encode(),hashlib.sha256).digest()
        expected=hmac.new(secret,check.encode(),hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected,received): return None
        auth_date=int(data.get('auth_date','0'))
        if abs(time.time()-auth_date)>86400: return None
        user=json.loads(data.get('user','{}'))
        return user
    except Exception: return None

def require_admin():
    user=telegram_user()
    if not user or str(user.get('id')) not in ADMIN_IDS: abort(403,description='Admin access requires a verified Telegram account configured in ADMIN_TELEGRAM_IDS.')
    return user

def require_telegram_or_guest():
    return telegram_user()

def send_telegram(chat_id, text):
    if not BOT_TOKEN or not chat_id: return
    try: requests.post(f'https://api.telegram.org/bot{BOT_TOKEN}/sendMessage',json={'chat_id':chat_id,'text':text},timeout=8)
    except Exception: app.logger.exception('Telegram notification failed')

def money(n): return f'{float(n or 0):,.2f} ETB'.replace('.00','')

def error_response(e, code=400):
    app.logger.warning('%s',e)
    return jsonify({'error':str(e)}),code

@app.get('/')
def home(): return send_from_directory('static','index.html')
@app.get('/admin')
def admin_page(): return send_from_directory('static','admin.html')
@app.get('/health')
def health(): return jsonify({'ok':True,'database_configured':db_ready(),'chapa_configured':bool(CHAPA_SECRET)})

@app.get('/api/bootstrap')
def bootstrap():
    try:
        return jsonify({'restaurant':get_settings(),'menu':get_menu(),'categories':sorted(set(x.get('category','Meals') for x in get_menu())),'database_configured':db_ready(),'chapa_configured':bool(CHAPA_SECRET)})
    except Exception as e: return error_response(e,503)

@app.get('/api/menu')
def menu_list():
    try: return jsonify(get_menu())
    except Exception as e: return error_response(e,503)

@app.post('/api/orders')
def create_order():
    try:
        data=request.get_json(force=True) or {}; lines=data.get('items',[])
        if not lines or len(lines)>50: return jsonify({'error':'Add at least one menu item.'}),400
        menu={str(x['id']):x for x in get_menu()}; cleaned=[]; subtotal=0; prep=0
        for line in lines:
            item=menu.get(str(line.get('id'))); qty=int(line.get('quantity',0))
            if not item or not item.get('available',True) or qty<1 or qty>50: return jsonify({'error':'One or more menu items are unavailable or have invalid quantities.'}),400
            price=float(item['price']); subtotal+=price*qty; prep=max(prep,int(item.get('prep_minutes') or 15)); cleaned.append({'id':item['id'],'name':item['name'],'name_am':item.get('name_am',''),'price':price,'quantity':qty,'line_total':price*qty})
        name=str(data.get('customer_name','')).strip()[:120]; phone=str(data.get('phone','')).strip()[:40]; mode=data.get('order_type','Delivery')
        if not name or not phone: return jsonify({'error':'Customer name and phone are required.'}),400
        if mode not in ['Delivery','Pickup']: return jsonify({'error':'Invalid order type.'}),400
        address=str(data.get('address','')).strip()[:500]
        if mode=='Delivery' and not address: return jsonify({'error':'Delivery address is required.'}),400
        settings=get_settings(); km=max(0,min(float(data.get('distance_km') or 0),float(settings.get('delivery_max_km') or 20))) if mode=='Delivery' else 0
        fee=0 if mode=='Pickup' or (float(settings.get('free_delivery_over') or 0)>0 and subtotal>=float(settings['free_delivery_over'])) else (float(settings.get('delivery_base_fee') or 0)+km*float(settings.get('delivery_per_km') or 0) if mode=='Delivery' else 0)
        service_fee=float(settings.get('service_fee') or 0); total=round(subtotal+fee+service_fee,2)
        pct=int(data.get('advance_percent',100)); allowed=[int(x) for x in settings.get('advance_percentages',[100,50,40,30,20])]
        if pct not in allowed: pct=100
        advance=round(total*pct/100,2); order_ref='CS-'+datetime.now().strftime('%Y%m%d')+'-'+secrets.token_hex(3).upper()
        user=telegram_user(); payload={'id':order_ref,'customer_name':name,'phone':phone,'telegram_id':str(user.get('id')) if user else None,'order_type':mode,'address':address if mode=='Delivery' else '', 'notes':str(data.get('notes','')).strip()[:1000], 'items':cleaned,'subtotal':subtotal,'delivery_fee':round(fee,2),'distance_km':km,'service_fee':service_fee,'total':total,'advance_percent':pct,'advance_due':advance,'payment_method':str(data.get('payment_method','Cash')).strip()[:80],'payment_status':'Pending','status':'Received','created_at':datetime.now(timezone.utc).isoformat(),'updated_at':datetime.now(timezone.utc).isoformat(),'language':data.get('language','en')}
        db_insert('orders',payload)
        if user: send_telegram(user.get('id'),f'CHO SPOT order received: {order_ref}\nTotal: {money(total)}\nStatus: Received')
        for aid in ADMIN_IDS: send_telegram(aid,f'New CHO SPOT order {order_ref}\n{name} · {phone}\n{mode} · Total {money(total)}')
        return jsonify({'ok':True,'order':payload,'message':'Order submitted successfully.'}),201
    except StoreError as e: return error_response(e,503)
    except Exception as e: return error_response(e,400)

@app.get('/api/orders/<order_id>')
def get_order(order_id):
    try:
        user=telegram_user(); rows=db_get('orders',{'id':f'eq.{order_id}','select':'*','limit':'1'})
        if not rows: return jsonify({'error':'Order not found.'}),404
        o=rows[0]
        if not (user and (str(user.get('id'))==str(o.get('telegram_id')) or str(user.get('id')) in ADMIN_IDS)):
            # Order reference is intentionally not a bearer credential; require customer phone match.
            phone=request.args.get('phone','').strip()
            if not phone or phone!=o.get('phone'): return jsonify({'error':'Verify the phone number used for this order.'}),403
        return jsonify(o)
    except Exception as e: return error_response(e,503)

@app.post('/api/payments/chapa/initialize')
def chapa_initialize():
    if not CHAPA_SECRET: return jsonify({'error':'Chapa is not configured. Add CHAPA_SECRET_KEY in Render environment variables.'}),503
    try:
        d=request.get_json(force=True) or {}; ref=str(d.get('order_id','')); settings=get_settings()
        if not settings.get('chapa_enabled', False): return jsonify({'error':'Chapa payments are not enabled by the restaurant admin yet.'}),403
        rows=db_get('orders',{'id':f'eq.{ref}','select':'*','limit':'1'})
        if not rows: return jsonify({'error':'Order not found.'}),404
        o=rows[0]; user=telegram_user()
        if not (user and (str(user.get('id'))==str(o.get('telegram_id')) or str(user.get('id')) in ADMIN_IDS)):
            phone=str(d.get('phone','')).strip()
            if phone!=o.get('phone'): return jsonify({'error':'Phone verification required.'}),403
        tx_ref='CHO-'+ref+'-'+secrets.token_hex(3).upper(); amount=float(o.get('advance_due') or o['total'])
        body={'amount':str(amount),'currency':'ETB','email':str(d.get('email') or 'customer@chospot.example'),'first_name':o['customer_name'].split()[0],'last_name':' '.join(o['customer_name'].split()[1:]) or 'Customer','phone_number':o['phone'],'tx_ref':tx_ref,'callback_url':PUBLIC_URL+'/api/payments/chapa/callback','return_url':PUBLIC_URL+'/?payment='+tx_ref,'customization':{'title':'CHO SPOT','description':'Food order payment '+ref}}
        r=requests.post('https://api.chapa.co/v1/transaction/initialize',headers={'Authorization':'Bearer '+CHAPA_SECRET,'Content-Type':'application/json'},json=body,timeout=20); data=r.json()
        if not r.ok or data.get('status')!='success': return jsonify({'error':data.get('message','Chapa initialization failed.')}),502
        db_patch('orders',{'id':f'eq.{ref}'},{'payment_tx_ref':tx_ref,'payment_status':'Initiated','updated_at':datetime.now(timezone.utc).isoformat()})
        return jsonify({'checkout_url':data['data']['checkout_url'],'tx_ref':tx_ref})
    except Exception as e: return error_response(e,502)

@app.get('/api/payments/chapa/callback')
def chapa_callback(): return jsonify({'message':'Payment callback received. Verify status with Chapa before marking an order paid.'})

@app.post('/api/payments/chapa/verify')
def chapa_verify():
    if not CHAPA_SECRET: return jsonify({'error':'Chapa is not configured.'}),503
    try:
        d=request.get_json(force=True) or {}; tx=str(d.get('tx_ref','')); r=requests.get('https://api.chapa.co/v1/transaction/verify/'+tx,headers={'Authorization':'Bearer '+CHAPA_SECRET},timeout=20); result=r.json()
        if not r.ok or result.get('status')!='success' or result.get('data',{}).get('status')!='success': return jsonify({'error':'Payment is not confirmed by Chapa.'}),400
        rows=db_get('orders',{'payment_tx_ref':f'eq.{tx}','select':'*','limit':'1'})
        if not rows: return jsonify({'error':'Order not found for this transaction.'}),404
        o=rows[0]; amount=float(result.get('data',{}).get('amount') or 0)
        if abs(amount-float(o.get('advance_due') or o['total']))>0.01: return jsonify({'error':'Verified payment amount does not match order amount.'}),400
        db_patch('orders',{'id':f'eq.{o["id"]}'},{'payment_status':'Paid','updated_at':datetime.now(timezone.utc).isoformat()})
        return jsonify({'ok':True,'payment_status':'Paid','order_id':o['id']})
    except Exception as e: return error_response(e,502)

@app.get('/api/customer/orders')
def customer_orders():
    user=telegram_user()
    if not user: return jsonify({'error':'Open in Telegram to view your order history.'}),401
    try: return jsonify(db_get('orders',{'telegram_id':f'eq.{user["id"]}','select':'id,created_at,status,total,payment_status,order_type','order':'created_at.desc','limit':'100'}))
    except Exception as e: return error_response(e,503)

@app.get('/api/admin/summary')
def admin_summary():
    require_admin()
    try:
        orders=db_get('orders',{'select':'id,status,total,created_at,payment_status,items'})
        now=datetime.now(timezone.utc); start=now.replace(hour=0,minute=0,second=0,microsecond=0); week=now-timedelta(days=7); month=now-timedelta(days=30)
        def dt(o):
            try:return datetime.fromisoformat(o['created_at'].replace('Z','+00:00'))
            except:return now
        delivered=[o for o in orders if o.get('status')=='Delivered']
        return jsonify({'orders_today':sum(dt(o)>=start for o in orders),'orders_week':sum(dt(o)>=week for o in orders),'orders_month':sum(dt(o)>=month for o in orders),'revenue_today':sum(float(o['total']) for o in delivered if dt(o)>=start),'revenue_week':sum(float(o['total']) for o in delivered if dt(o)>=week),'revenue_month':sum(float(o['total']) for o in delivered if dt(o)>=month),'total_orders':len(orders),'pending_orders':sum(o.get('status') in ['Received','Confirmed','Preparing','Ready','Out for delivery'] for o in orders),'orders':sorted(orders,key=lambda o:o.get('created_at',''),reverse=True)[:500]})
    except Exception as e: return error_response(e,503)

@app.get('/api/admin/orders')
def admin_orders():
    require_admin()
    try: return jsonify(db_get('orders',{'select':'*','order':'created_at.desc','limit':'500'}))
    except Exception as e: return error_response(e,503)

@app.patch('/api/admin/orders/<order_id>')
def admin_update_order(order_id):
    require_admin()
    try:
        d=request.get_json(force=True) or {}; allowed=['Received','Confirmed','Preparing','Ready','Out for delivery','Delivered','Cancelled']; status=d.get('status')
        if status not in allowed: return jsonify({'error':'Invalid order status.'}),400
        rows=db_patch('orders',{'id':f'eq.{order_id}'},{'status':status,'admin_note':str(d.get('admin_note',''))[:500],'updated_at':datetime.now(timezone.utc).isoformat()})
        if not rows: return jsonify({'error':'Order not found.'}),404
        o=rows[0]
        if o.get('telegram_id'): send_telegram(o['telegram_id'],f'CHO SPOT order update {order_id}\nYour order status is now: {status}')
        return jsonify(o)
    except Exception as e: return error_response(e,503)

@app.get('/api/admin/menu')
def admin_menu():
    require_admin()
    try: return jsonify(get_menu())
    except Exception as e: return error_response(e,503)

@app.post('/api/admin/menu')
def admin_save_menu():
    require_admin()
    try:
        d=request.get_json(force=True) or {}; d['id']=str(d.get('id') or ('food-'+secrets.token_hex(6))); d['name']=str(d.get('name','')).strip()[:120]; d['category']=str(d.get('category','Meals')).strip()[:80]
        d['price']=float(d.get('price',0)); d['available']=bool(d.get('available',True)); d['pinned']=bool(d.get('pinned',False)); d['description']=str(d.get('description',''))[:500]; d['name_am']=str(d.get('name_am',''))[:120]; d['description_am']=str(d.get('description_am',''))[:500]; d['image']=str(d.get('image',''))[:1500]; d['prep_minutes']=max(0,min(240,int(d.get('prep_minutes',15))))
        if not d['name'] or d['price']<0: return jsonify({'error':'A name and non-negative price are required.'}),400
        rows=db_insert('menu_items',d,upsert=True); return jsonify(rows[0] if rows else d)
    except Exception as e: return error_response(e,400)

@app.delete('/api/admin/menu/<item_id>')
def admin_delete_menu(item_id):
    require_admin()
    try: return jsonify({'deleted':db_delete('menu_items',{'id':f'eq.{item_id}'})})
    except Exception as e: return error_response(e,503)

@app.get('/api/admin/settings')
def admin_settings():
    require_admin()
    try: return jsonify(get_settings())
    except Exception as e: return error_response(e,503)

@app.put('/api/admin/settings')
def admin_update_settings():
    require_admin()
    try:
        data=request.get_json(force=True) or {}
        allowed=set(DEFAULT_SETTINGS.keys())
        for key,val in data.items():
            if key in allowed: db_insert('restaurant_settings',{'key':key,'value':val},upsert=True)
        return jsonify(get_settings())
    except Exception as e: return error_response(e,503)

@app.get('/api/admin/reports')
def admin_reports():
    require_admin()
    try:
        period=request.args.get('period','daily'); orders=db_get('orders',{'select':'id,status,total,created_at,items,payment_status','order':'created_at.asc','limit':'5000'}); now=datetime.now(timezone.utc)
        buckets={}
        for o in orders:
            try: dt=datetime.fromisoformat(o['created_at'].replace('Z','+00:00'))
            except: continue
            if period=='weekly': key=dt.strftime('%G-W%V')
            elif period=='monthly': key=dt.strftime('%Y-%m')
            elif period=='yearly': key=dt.strftime('%Y')
            else: key=dt.strftime('%Y-%m-%d')
            b=buckets.setdefault(key,{'period':key,'orders':0,'delivered':0,'revenue':0,'paid':0}); b['orders']+=1
            if o.get('status')=='Delivered': b['delivered']+=1; b['revenue']+=float(o.get('total') or 0)
            if o.get('payment_status')=='Paid': b['paid']+=float(o.get('total') or 0)
        return jsonify({'period':period,'rows':list(buckets.values())[-365:]})
    except Exception as e: return error_response(e,503)

@app.get('/api/admin/whoami')
def admin_whoami():
    user=telegram_user()
    return jsonify({'authenticated':bool(user),'is_admin':bool(user and str(user.get('id')) in ADMIN_IDS),'user':user})

if __name__=='__main__':
    app.run(host='0.0.0.0',port=int(os.getenv('PORT','10000')))
