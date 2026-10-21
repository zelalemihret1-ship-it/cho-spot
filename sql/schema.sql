-- CHO SPOT initial Supabase schema. Run in Supabase SQL Editor before deployment.
-- The service-role key must only be stored on the server (Render), never in frontend code.
create extension if not exists pgcrypto;

create table if not exists public.menu_items (
  id text primary key,
  name text not null,
  name_am text not null default '',
  category text not null default 'Meals',
  price numeric(12,2) not null default 0 check (price >= 0),
  description text not null default '',
  description_am text not null default '',
  image text not null default '',
  available boolean not null default true,
  pinned boolean not null default false,
  prep_minutes integer not null default 15 check (prep_minutes between 0 and 240),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.orders (
  id text primary key,
  customer_name text not null,
  phone text not null,
  telegram_id text,
  order_type text not null check (order_type in ('Delivery','Pickup')),
  address text not null default '',
  notes text not null default '',
  items jsonb not null default '[]'::jsonb,
  subtotal numeric(12,2) not null default 0,
  delivery_fee numeric(12,2) not null default 0,
  distance_km numeric(8,2) not null default 0,
  service_fee numeric(12,2) not null default 0,
  total numeric(12,2) not null default 0,
  advance_percent integer not null default 100,
  advance_due numeric(12,2) not null default 0,
  payment_method text not null default 'Cash',
  payment_status text not null default 'Pending',
  payment_tx_ref text,
  status text not null default 'Received',
  admin_note text not null default '',
  language text not null default 'en',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists orders_created_at_idx on public.orders (created_at desc);
create index if not exists orders_telegram_id_idx on public.orders (telegram_id);
create index if not exists orders_status_idx on public.orders (status);
create unique index if not exists orders_payment_tx_ref_idx on public.orders (payment_tx_ref) where payment_tx_ref is not null;

create table if not exists public.restaurant_settings (
  key text primary key,
  value jsonb not null,
  updated_at timestamptz not null default now()
);

alter table public.menu_items enable row level security;
alter table public.orders enable row level security;
alter table public.restaurant_settings enable row level security;
-- Intentionally no anon/authenticated table policies: all access goes through the trusted Flask server.
-- Never expose SUPABASE_SERVICE_ROLE_KEY to browser code.

insert into public.menu_items (id,name,name_am,category,price,description,description_am,available,pinned,prep_minutes) values
('food-burger','CHO Special Burger','የCHO ስፔሻል በርገር','Burgers',450,'Juicy burger, fresh greens & house sauce','ጣፋጭ በርገር ከአትክልትና ልዩ ሶስ ጋር',true,true,20),
('food-pizza','Classic Cheese Pizza','ክላሲክ ቺዝ ፒዛ','Pizza',650,'Melted cheese, tomato & Italian herbs','ቺዝ፣ ቲማቲም እና የጣሊያን ቅመሞች',true,true,25),
('food-chicken','Grilled Chicken Plate','የተጠበሰ ዶሮ','Meals',580,'Seasoned chicken with a hearty side','በቅመም የተዘጋጀ ዶሮ ከጎን ምግብ ጋር',true,true,25),
('food-pasta','Spicy Pasta','ቅመም ያለው ፓስታ','Meals',420,'Rich tomato sauce with a gentle kick','በቲማቲም ሶስ የተዘጋጀ ፓስታ',true,false,18),
('food-fries','Crispy Fries','ጥርት ያለ ቺፕስ','Sides',180,'Golden, crunchy and made to share','ወርቃማና ጥርት ያለ ቺፕስ',true,false,10),
('food-juice','Fresh Juice','ትኩስ ጭማቂ','Drinks',150,'A refreshing fruit drink','ትኩስ የፍራፍሬ ጭማቂ',true,false,5),
('food-double-burger','Double Smash Burger','ድርብ በርገር','Burgers',590,'Double patties, melted cheese & sauce','ድርብ ስጋ፣ ቺዝ እና ሶስ',true,false,22),
('food-dessert','Chocolate Dessert','ቸኮሌት ጣፋጭ ምግብ','Desserts',220,'A sweet finish to your meal','ለምግብዎ ጣፋጭ መደምደሚያ',true,false,5)
on conflict (id) do nothing;

insert into public.restaurant_settings(key,value) values
('restaurant_name','"CHO SPOT"'::jsonb),('phone','""'::jsonb),('address','""'::jsonb),('opening_hours','""'::jsonb),
('delivery_enabled','true'::jsonb),('pickup_enabled','true'::jsonb),('delivery_base_fee','50'::jsonb),('delivery_per_km','15'::jsonb),('delivery_max_km','20'::jsonb),('free_delivery_over','0'::jsonb),('service_fee','0'::jsonb),('currency','"ETB"'::jsonb),('about','"Good food. Good mood. Freshly prepared and served with love."'::jsonb),('about_am','"ጣፋጭ ምግብ። ጥሩ ስሜት።"'::jsonb),('chapa_enabled','false'::jsonb),('advance_percentages','[100,50,40,30,20]'::jsonb)
on conflict (key) do nothing;
