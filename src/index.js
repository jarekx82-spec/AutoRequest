const json=(d,s=200,h={})=>new Response(JSON.stringify(d),{status:s,headers:{"content-type":"application/json; charset=UTF-8",...h}});
const clean=v=>v==null||String(v).trim()===""?null:String(v).trim();
const hex=a=>[...new Uint8Array(a)].map(b=>b.toString(16).padStart(2,"0")).join("");
async function hashPassword(p,salt){return hex(await crypto.subtle.digest("SHA-256",new TextEncoder().encode(salt+":"+p)))}
function cookie(req,n){return (req.headers.get("Cookie")||"").split(";").map(x=>x.trim()).find(x=>x.startsWith(n+"="))?.slice(n.length+1)||null}
async function auth(req,env){
 const t=cookie(req,"ar_session"); if(!t)return null;
 return await env.DB.prepare(`SELECT u.id,u.email,u.role,u.business_id,b.name,b.slug FROM sessions s
 JOIN business_users u ON u.id=s.user_id JOIN businesses b ON b.id=u.business_id
 WHERE s.token=? AND s.expires_at>datetime('now') AND u.active=1 AND b.active=1`).bind(t).first();
}
async function customerAuth(req,env){
  const t=cookie(req,"ar_customer_session");
  if(!t)return null;

  return await env.DB.prepare(`
    SELECT
      cu.id AS user_id,
      cu.customer_id,
      cu.email,
      cu.phone,
      c.name
    FROM customer_sessions cs
    JOIN customer_users cu ON cu.id=cs.user_id
    JOIN customers c ON c.id=cu.customer_id
    WHERE cs.token=?
      AND cs.expires_at>datetime('now')
      AND cu.active=1
  `).bind(t).first();
}
export default{async fetch(request,env){
 const url=new URL(request.url);
 try{
  if(url.pathname==="/api/health")return json({ok:true,version:"MVP v3"});
  if(url.pathname==="/api/setup-owner"&&request.method==="POST"){
   const count=await env.DB.prepare("SELECT COUNT(*) n FROM business_users").first();
   if(count.n>0)return json({ok:false,error:"Konto właściciela już istnieje."},403);
   const b=await request.json(); if(!clean(b.email)||!clean(b.password)||String(b.password).length<8)return json({ok:false,error:"Podaj e-mail i hasło min. 8 znaków."},400);
   const salt=crypto.randomUUID(), ph=await hashPassword(b.password,salt);
   await env.DB.prepare("INSERT INTO business_users(business_id,email,password_hash,role) VALUES(1,?,?,'OWNER')").bind(clean(b.email).toLowerCase(),salt+"$"+ph).run();
   return json({ok:true});
  }
  if(url.pathname==="/api/session"&&request.method==="POST"){
   const b=await request.json(),u=await env.DB.prepare("SELECT * FROM business_users WHERE email=? AND active=1").bind((clean(b.email)||"").toLowerCase()).first();
   if(!u)return json({ok:false,error:"Nieprawidłowy login lub hasło."},401);
   const [salt,stored]=u.password_hash.split("$"),calc=await hashPassword(b.password||"",salt);
   if(calc!==stored)return json({ok:false,error:"Nieprawidłowy login lub hasło."},401);
   const token=crypto.randomUUID()+crypto.randomUUID(),exp=new Date(Date.now()+7*864e5).toISOString();
   await env.DB.prepare("INSERT INTO sessions(token,user_id,expires_at) VALUES(?,?,?)").bind(token,u.id,exp).run();
   return json({ok:true},200,{"Set-Cookie":`ar_session=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800`});
  }
  if(url.pathname==="/api/customer/register" && request.method==="POST"){
  const b = await request.json();

  const name = clean(b.name);
  const phone = clean(b.phone);
  const email = clean(b.email).toLowerCase();
  const password = String(b.password || "");

  if(!name || !phone || !email || !password){
    return json({
      ok:false,
      error:"Uzupełnij wszystkie pola."
    },400);
  }

  if(password.length < 8){
    return json({
      ok:false,
      error:"Hasło musi mieć minimum 8 znaków."
    },400);
  }

  const existing = await env.DB.prepare(`
    SELECT id
    FROM customer_users
    WHERE LOWER(email)=? OR phone=?
    LIMIT 1
  `).bind(email,phone).first();

  if(existing){
    return json({
      ok:false,
      error:"Konto z tym e-mailem lub numerem telefonu już istnieje."
    },409);
  }

  let customer = await env.DB.prepare(`
    SELECT id
    FROM customers
    WHERE phone=? OR LOWER(email)=?
    ORDER BY id ASC
    LIMIT 1
  `).bind(phone,email).first();

  let customerId;

  if(customer){
    customerId = customer.id;

    await env.DB.prepare(`
      UPDATE customers
      SET name=?, phone=?, email=?
      WHERE id=?
    `).bind(name,phone,email,customerId).run();

  }else{
    const c = await env.DB.prepare(`
      INSERT INTO customers(name,phone,email)
      VALUES(?,?,?)
    `).bind(name,phone,email).run();

    customerId = c.meta.last_row_id;
  }

  const salt = crypto.randomUUID();
  const hash = await hashPassword(password,salt);
  const passwordHash = salt + "$" + hash;

  await env.DB.prepare(`
    INSERT INTO customer_users
      (customer_id,email,phone,password_hash,active)
    VALUES(?,?,?,?,1)
  `).bind(
    customerId,
    email,
    phone,
    passwordHash
  ).run();

  return json({
    ok:true,
    customer_id:customerId
  },201);
}
  if(url.pathname==="/api/customer/session" && request.method==="POST"){
  const b=await request.json();

  const login=clean(b.login).toLowerCase();
  const password=String(b.password||"");

  if(!login || !password){
    return json({ok:false,error:"Podaj telefon lub e-mail oraz hasło."},400);
  }

  const u=await env.DB.prepare(`
    SELECT *
    FROM customer_users
    WHERE active=1
      AND (LOWER(email)=? OR phone=?)
    LIMIT 1
  `).bind(login,login).first();

  if(!u){
    return json({ok:false,error:"Nieprawidłowy login lub hasło."},401);
  }

  const [salt,stored]=u.password_hash.split("$");
  const calc=await hashPassword(password,salt);

  if(calc!==stored){
    return json({ok:false,error:"Nieprawidłowy login lub hasło."},401);
  }

  const token=crypto.randomUUID()+crypto.randomUUID();
  const exp=new Date(Date.now()+7*864e5).toISOString();

  await env.DB.prepare(`
    INSERT INTO customer_sessions(token,user_id,expires_at)
    VALUES(?,?,?)
  `).bind(token,u.id,exp).run();

  return json(
    {ok:true},
    200,
    {"Set-Cookie":`ar_customer_session=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800`}
  );
}
  if(url.pathname==="/api/customer/me" && request.method==="GET"){
  const u=await customerAuth(request,env);

  if(!u){
    return json({
      ok:false,
      error:"Brak autoryzacji."
    },401);
  }

  return json({
    ok:true,
    user:{
      id:u.user_id,
      customer_id:u.customer_id,
      email:u.email,
      phone:u.phone,
      name:u.name
    }
  });
}
  if(url.pathname==="/api/logout"&&request.method==="POST"){
   const t=cookie(request,"ar_session"); if(t)await env.DB.prepare("DELETE FROM sessions WHERE token=?").bind(t).run();
   return json({ok:true},200,{"Set-Cookie":"ar_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"});
  }
  if(url.pathname==="/api/me"){const u=await auth(request,env);return u?json({ok:true,user:u}):json({ok:false},401)}
  if(url.pathname.startsWith("/api/public/business/")){
   const slug=url.pathname.split("/").pop(); const b=await env.DB.prepare("SELECT id,name,slug,type,city FROM businesses WHERE slug=? AND active=1").bind(slug).first();
   return b?json({ok:true,business:b}):json({ok:false,error:"Nie znaleziono firmy."},404);
  }
  if(url.pathname==="/api/public/requests"&&request.method==="POST"){
   const b=await request.json(),firm=await env.DB.prepare("SELECT id FROM businesses WHERE slug=? AND active=1").bind(clean(b.slug)).first();
   if(!firm)return json({ok:false,error:"Nie znaleziono firmy."},404);
   for(const f of ["name","phone","brand","model","description"])if(!clean(b[f]))return json({ok:false,error:"Brak pola: "+f},400);
  let customer=await env.DB.prepare(
  "SELECT id FROM customers WHERE phone=? ORDER BY id ASC LIMIT 1"
).bind(clean(b.phone)).first();

let customerId;

if(customer){
  customerId=customer.id;

  await env.DB.prepare(
    "UPDATE customers SET name=?,email=?,city=? WHERE id=?"
  ).bind(clean(b.name),clean(b.email),clean(b.city),customerId).run();
}else{
  const c=await env.DB.prepare(
    "INSERT INTO customers(name,phone,email,city) VALUES(?,?,?,?)"
  ).bind(clean(b.name),clean(b.phone),clean(b.email),clean(b.city)).run();

  customerId=c.meta.last_row_id;
}
   const v=await env.DB.prepare(`INSERT INTO vehicles(customer_id,brand,model,vin,production_year,engine_capacity,engine_code,fuel,power,mileage) VALUES(?,?,?,?,?,?,?,?,?,?)`).bind(customerId,clean(b.brand),clean(b.model),clean(b.vin),b.production_year?Number(b.production_year):null,clean(b.engine_capacity),clean(b.engine_code),clean(b.fuel),b.power?Number(b.power):null,b.mileage?Number(b.mileage):null).run();
   const num="AR-"+new Date().getFullYear()+"-"+crypto.randomUUID().slice(0,8).toUpperCase();
 const r=await env.DB.prepare(`INSERT INTO requests(request_number,business_id,customer_id,vehicle_id,request_type,category,description,part_number,status) VALUES(?,?,?,?,?,?,?,?,'NEW')`).bind(num,firm.id,customerId,v.meta.last_row_id,clean(b.request_type)||"PART",clean(b.category)||"OTHER",clean(b.description),clean(b.part_number)).run();
   return json({ok:true,request_number:num,request_id:r.meta.last_row_id},201);
  }
  if(/^\/api\/public\/requests\/\d+\/messages$/.test(url.pathname)&&request.method==="GET"){
 const id=Number(url.pathname.split("/")[4]);
 const r=await env.DB.prepare("SELECT id,sender_type,message,created_at FROM messages WHERE request_id=? ORDER BY id ASC").bind(id).all();
 return json({ok:true,messages:r.results});
}
  if(/^\/api\/public\/requests\/\d+\/messages$/.test(url.pathname)&&request.method==="POST"){
 const id=Number(url.pathname.split("/")[4]);
 const b=await request.json();
 if(!clean(b.message)) return json({ok:false,error:"Wiadomość jest pusta."},400);

 await env.DB.prepare(
  "INSERT INTO messages(request_id,sender_type,message) VALUES(?,'CUSTOMER',?)"
 ).bind(id,clean(b.message)).run();

 return json({ok:true},201);
}
  if(/^\/api\/public\/requests\/\d+\/messages$/.test(url.pathname) && request.method==="GET"){
  const id=Number(url.pathname.split("/")[4]);

  const r=await env.DB.prepare(
    "SELECT id,sender_type,message,created_at FROM messages WHERE request_id=? ORDER BY id ASC"
  ).bind(id).all();

  return json({ok:true,messages:r.results});
}
  if(/^\/api\/public\/requests\/\d+\/messages$/.test(url.pathname) && request.method==="GET"){
  const id=Number(url.pathname.split("/")[4]);

  const r=await env.DB.prepare(
    "SELECT id,sender_type,message,created_at FROM messages WHERE request_id=? ORDER BY id ASC"
  ).bind(id).all();

  return json({ok:true,messages:r.results});
}
  if(url.pathname==="/api/company/customers" && request.method==="GET"){
  const u=await auth(request,env);
  if(!u)return json({ok:false,error:"Brak autoryzacji."},401);

  const r=await env.DB.prepare(`
    SELECT DISTINCT
      c.id,
      c.name,
      c.phone,
      c.email,
      c.city
    FROM customers c
    JOIN requests r ON r.customer_id=c.id
    WHERE r.business_id=?
    ORDER BY c.id DESC
  `).bind(u.business_id).all();

  return json({ok:true,customers:r.results});
}
  if(/^\/api\/company\/customers\/\d+$/.test(url.pathname) && request.method==="GET"){
  const u=await auth(request,env);
  if(!u)return json({ok:false,error:"Brak autoryzacji."},401);

  const id=Number(url.pathname.split("/").pop());

  const customer=await env.DB.prepare(`
    SELECT c.id,c.name,c.phone,c.email,c.city
    FROM customers c
    JOIN requests r ON r.customer_id=c.id
    WHERE c.id=? AND r.business_id=?
    LIMIT 1
  `).bind(id,u.business_id).first();

  if(!customer)return json({ok:false,error:"Nie znaleziono klienta."},404);

  const vehicles=await env.DB.prepare(`
    SELECT DISTINCT v.id,v.brand,v.model,v.vin,v.production_year,
    v.engine_capacity,v.engine_code,v.fuel,v.power,v.mileage
    FROM vehicles v
    JOIN requests r ON r.vehicle_id=v.id
    WHERE v.customer_id=? AND r.business_id=?
    ORDER BY v.id DESC
  `).bind(id,u.business_id).all();

  const requests=await env.DB.prepare(`
    SELECT r.id,r.request_number,r.status,r.request_type,r.category,
    r.description,r.created_at,v.brand,v.model
    FROM requests r
    JOIN vehicles v ON v.id=r.vehicle_id
    WHERE r.customer_id=? AND r.business_id=?
    ORDER BY r.id DESC
  `).bind(id,u.business_id).all();

  return json({
    ok:true,
    customer,
    vehicles:vehicles.results,
    requests:requests.results
  });
}
  // Edycja klienta przez firmę
if(/^\/api\/company\/customers\/\d+$/.test(url.pathname) && request.method==="PUT"){
  const u=await auth(request,env); if(!u)return json({ok:false,error:"Brak autoryzacji."},401);
  const id=Number(url.pathname.split("/").pop());
  const own=await env.DB.prepare(`SELECT c.id FROM customers c JOIN requests r ON r.customer_id=c.id WHERE c.id=? AND r.business_id=? LIMIT 1`).bind(id,u.business_id).first();
  if(!own)return json({ok:false,error:"Nie znaleziono klienta."},404);
  const b=await request.json(),name=clean(b.name),phone=clean(b.phone),email=clean(b.email),city=clean(b.city);
  if(!name||!phone)return json({ok:false,error:"Imię/nazwa i telefon są wymagane."},400);
  const dup=await env.DB.prepare("SELECT id FROM customers WHERE id<>? AND phone=? LIMIT 1").bind(id,phone).first();
  if(dup)return json({ok:false,error:"Inny klient ma już ten numer telefonu."},409);
  const cu=await env.DB.prepare("SELECT id FROM customer_users WHERE customer_id=? ORDER BY id ASC LIMIT 1").bind(id).first();
  if(cu){
    const conflict=await env.DB.prepare(`SELECT id FROM customer_users WHERE id<>? AND (phone=? OR (? IS NOT NULL AND LOWER(email)=LOWER(?))) LIMIT 1`).bind(cu.id,phone,email,email).first();
    if(conflict)return json({ok:false,error:"Ten telefon lub e-mail jest już używany przez inne konto klienta."},409);
  }
  await env.DB.prepare("UPDATE customers SET name=?,phone=?,email=?,city=? WHERE id=?").bind(name,phone,email,city,id).run();
  if(cu)await env.DB.prepare("UPDATE customer_users SET phone=?,email=? WHERE customer_id=?").bind(phone,email,id).run();
  return json({ok:true});
}

// Trwałe usunięcie klienta testowego i jego danych
if(/^\/api\/company\/customers\/\d+$/.test(url.pathname) && request.method==="DELETE"){
  const u=await auth(request,env); if(!u)return json({ok:false,error:"Brak autoryzacji."},401);
  const id=Number(url.pathname.split("/").pop());
  const own=await env.DB.prepare(`SELECT c.id FROM customers c JOIN requests r ON r.customer_id=c.id WHERE c.id=? AND r.business_id=? LIMIT 1`).bind(id,u.business_id).first();
  if(!own)return json({ok:false,error:"Nie znaleziono klienta."},404);
  const other=await env.DB.prepare("SELECT id FROM requests WHERE customer_id=? AND business_id<>? LIMIT 1").bind(id,u.business_id).first();
  if(other)return json({ok:false,error:"Nie można trwale usunąć klienta, ponieważ ma historię także w innej firmie."},409);

  const reqs=await env.DB.prepare("SELECT id FROM requests WHERE customer_id=?").bind(id).all();
  for(const r of reqs.results){
    await env.DB.prepare("DELETE FROM messages WHERE request_id=?").bind(r.id).run();
    await env.DB.prepare("DELETE FROM responses WHERE request_id=?").bind(r.id).run();
    await env.DB.prepare("DELETE FROM vehicle_reminders WHERE request_id=?").bind(r.id).run();
    await env.DB.prepare("DELETE FROM request_items WHERE request_id=?").bind(r.id).run();
  }
  await env.DB.prepare("DELETE FROM vehicle_reminders WHERE customer_id=?").bind(id).run();
  await env.DB.prepare("DELETE FROM requests WHERE customer_id=?").bind(id).run();
  const users=await env.DB.prepare("SELECT id FROM customer_users WHERE customer_id=?").bind(id).all();
  for(const x of users.results)await env.DB.prepare("DELETE FROM customer_sessions WHERE user_id=?").bind(x.id).run();
  await env.DB.prepare("DELETE FROM customer_users WHERE customer_id=?").bind(id).run();
  await env.DB.prepare("DELETE FROM service_history WHERE vehicle_id IN (SELECT id FROM vehicles WHERE customer_id=?)").bind(id).run();
  await env.DB.prepare("DELETE FROM vehicles WHERE customer_id=?").bind(id).run();
  await env.DB.prepare("DELETE FROM customers WHERE id=?").bind(id).run();
  return json({ok:true});
}

if(/^\/api\/company\/vehicles\/\d+$/.test(url.pathname) && request.method==="GET"){
  const u=await auth(request,env);
  if(!u)return json({ok:false,error:"Brak autoryzacji."},401);

  const id=Number(url.pathname.split("/").pop());

  const vehicle=await env.DB.prepare(`
    SELECT DISTINCT
      v.id,v.customer_id,v.brand,v.model,v.vin,v.production_year,
      v.engine_capacity,v.engine_code,v.fuel,v.power,v.mileage
    FROM vehicles v
    JOIN requests r ON r.vehicle_id=v.id
    WHERE v.id=? AND r.business_id=?
    LIMIT 1
  `).bind(id,u.business_id).first();

  if(!vehicle)return json({ok:false,error:"Nie znaleziono samochodu."},404);

  const requests=await env.DB.prepare(`
    SELECT
      r.id,r.request_number,r.status,r.request_type,r.category,
      r.description,r.part_number,r.created_at,r.updated_at
    FROM requests r
    WHERE r.vehicle_id=? AND r.business_id=?
    ORDER BY r.id DESC
  `).bind(id,u.business_id).all();

   const serviceHistory=await env.DB.prepare(`
  SELECT
    id,service_date,mileage,service_type,description,parts,
    next_service_date,next_service_mileage,created_at
  FROM service_history
  WHERE vehicle_id=? AND business_id=?
  ORDER BY service_date DESC,id DESC
`).bind(id,u.business_id).all();

 return json({
  ok:true,
  vehicle,
  requests:requests.results,
  serviceHistory:serviceHistory.results
});
  }
  if(url.pathname==="/api/company/requests"&&request.method==="GET"){
   const u=await auth(request,env); if(!u)return json({ok:false,error:"Brak autoryzacji."},401);
   const r=await env.DB.prepare(`SELECT r.*,c.name customer_name,c.phone customer_phone,v.brand,v.model,v.vin,v.production_year,v.engine_capacity,v.engine_code,v.mileage FROM requests r JOIN customers c ON c.id=r.customer_id JOIN vehicles v ON v.id=r.vehicle_id WHERE r.business_id=? ORDER BY r.id DESC`).bind(u.business_id).all();
   return json({ok:true,requests:r.results});
  }
  if(/^\/api\/company\/requests\/\d+\/response$/.test(url.pathname)&&request.method==="POST"){
   const u=await auth(request,env); if(!u)return json({ok:false,error:"Brak autoryzacji."},401);
   const id=Number(url.pathname.split("/")[4]),own=await env.DB.prepare("SELECT id FROM requests WHERE id=? AND business_id=?").bind(id,u.business_id).first();
   if(!own)return json({ok:false,error:"Brak dostępu."},403);
   const b=await request.json();
   const items=Array.isArray(b.items)?b.items:[];
   await env.DB.prepare("INSERT INTO responses(request_id,price,availability,appointment_date,note) VALUES(?,?,?,?,?)").bind(id,b.price?Number(b.price):null,clean(b.availability),clean(b.appointment_date),clean(b.note)).run();

   // Pozycje części należą do aktualnej oferty dla tego zapytania.
   await env.DB.prepare("DELETE FROM request_items WHERE request_id=?").bind(id).run();
   for(const item of items){
     const partName=clean(item.part_name);
     if(!partName)continue;
     const qty=Math.max(1,Number.parseInt(item.quantity,10)||1);
     const unitPrice=item.unit_price===null||item.unit_price===undefined||String(item.unit_price).trim()==="" ? null : Number(item.unit_price);
     await env.DB.prepare(`
       INSERT INTO request_items(request_id,part_name,part_number,quantity,unit_price)
       VALUES(?,?,?,?,?)
     `).bind(id,partName,clean(item.part_number),qty,Number.isFinite(unitPrice)?unitPrice:null).run();
   }

   if(clean(b.note)){
     await env.DB.prepare("INSERT INTO messages(request_id,sender_type,sender_id,message) VALUES(?,?,?,?)").bind(id,"BUSINESS",u.id,clean(b.note)).run();
   }
   await env.DB.prepare("UPDATE requests SET status='ANSWERED',updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(id).run();
   return json({ok:true});
  }
  if(/^\/api\/company\/requests\/\d+$/.test(url.pathname)&&request.method==="GET"){
   const u=await auth(request,env); if(!u)return json({ok:false,error:"Brak autoryzacji."},401);
   const id=Number(url.pathname.split("/").pop()),x=await env.DB.prepare(`SELECT r.*,c.name customer_name,c.phone customer_phone,c.email customer_email,v.brand,v.model,v.vin,v.production_year,v.engine_capacity,v.engine_code,v.mileage FROM requests r JOIN customers c ON c.id=r.customer_id JOIN vehicles v ON v.id=r.vehicle_id WHERE r.id=? AND r.business_id=?`).bind(id,u.business_id).first();
   if(!x)return json({ok:false,error:"Brak dostępu."},403); const rr=await env.DB.prepare("SELECT * FROM responses WHERE request_id=? ORDER BY id DESC").bind(id).all(); return json({ok:true,request:x,responses:rr.results});
  }
  if(/^\/api\/company\/requests\/\d+\/messages$/.test(url.pathname) && request.method==="GET"){
  const u=await auth(request,env);
  if(!u)return json({ok:false,error:"Brak autoryzacji."},401);

  const id=Number(url.pathname.split("/")[4]);

  const own=await env.DB.prepare(
    "SELECT id FROM requests WHERE id=? AND business_id=?"
  ).bind(id,u.business_id).first();

  if(!own)return json({ok:false,error:"Brak dostępu."},403);

  const m=await env.DB.prepare(
    "SELECT * FROM messages WHERE request_id=? ORDER BY id ASC"
  ).bind(id).all();

  return json({ok:true,messages:m.results});
}
  if(/^\/api\/company\/requests\/\d+\/messages$/.test(url.pathname) && request.method==="POST"){
  const u=await auth(request,env);
  if(!u)return json({ok:false,error:"Brak autoryzacji."},401);

  const id=Number(url.pathname.split("/")[4]);

  const own=await env.DB.prepare(
    "SELECT id FROM requests WHERE id=? AND business_id=?"
  ).bind(id,u.business_id).first();

  if(!own)return json({ok:false,error:"Brak dostępu."},403);

  const b=await request.json();
  const message=clean(b.message);

  if(!message)
    return json({ok:false,error:"Wiadomość nie może być pusta."},400);

  await env.DB.prepare(
    "INSERT INTO messages(request_id,sender_type,sender_id,message) VALUES(?,?,?,?)"
  ).bind(id,"BUSINESS",u.id,message).run();

  return json({ok:true},201);
}

// Wylogowanie klienta
if(url.pathname==="/api/customer/logout" && request.method==="POST"){
  const t=cookie(request,"ar_customer_session");
  if(t){
    await env.DB.prepare(
      "DELETE FROM customer_sessions WHERE token=?"
    ).bind(t).run();
  }

  return json({ok:true},200,{
    "Set-Cookie":"ar_customer_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"
  });
}

// 1. Lista samochodów zalogowanego klienta
if(url.pathname==="/api/customer/vehicles" && request.method==="GET"){
  const u=await customerAuth(request,env);
  if(!u)return json({ok:false,error:"Brak autoryzacji."},401);

  const r=await env.DB.prepare(`
    SELECT id,brand,model,vin,production_year,engine_capacity,
           engine_code,fuel,power,mileage
    FROM vehicles
    WHERE customer_id=?
    ORDER BY id DESC
  `).bind(u.customer_id).all();

  return json({ok:true,vehicles:r.results});
}

// 2. Dodanie samochodu do konta klienta
if(url.pathname==="/api/customer/vehicles" && request.method==="POST"){
  const u=await customerAuth(request,env);
  if(!u)return json({ok:false,error:"Brak autoryzacji."},401);

  const b=await request.json();
  const brand=clean(b.brand);
  const model=clean(b.model);

  if(!brand || !model){
    return json({ok:false,error:"Marka i model są wymagane."},400);
  }

  const r=await env.DB.prepare(`
    INSERT INTO vehicles(
      customer_id,brand,model,vin,production_year,engine_capacity,
      engine_code,fuel,power,mileage
    )
    VALUES(?,?,?,?,?,?,?,?,?,?)
  `).bind(
    u.customer_id,
    brand,
    model,
    clean(b.vin),
    clean(b.production_year),
    clean(b.engine_capacity),
    clean(b.engine_code),
    clean(b.fuel),
    clean(b.power),
    clean(b.mileage)
  ).run();

  return json({ok:true,vehicle_id:r.meta.last_row_id},201);
}

// 2b. Edycja samochodu zalogowanego klienta
if(/^\/api\/customer\/vehicles\/\d+$/.test(url.pathname) && request.method==="PUT"){
  const u=await customerAuth(request,env);
  if(!u)return json({ok:false,error:"Brak autoryzacji."},401);
  const vehicleId=Number(url.pathname.split("/").pop());
  const owned=await env.DB.prepare("SELECT id FROM vehicles WHERE id=? AND customer_id=? LIMIT 1").bind(vehicleId,u.customer_id).first();
  if(!owned)return json({ok:false,error:"Nie znaleziono samochodu na Twoim koncie."},404);

  const b=await request.json(),brand=clean(b.brand),model=clean(b.model);
  if(!brand||!model)return json({ok:false,error:"Marka i model są wymagane."},400);

  const year=clean(b.production_year);
  if(year!==null){
    const y=Number(year),maxYear=new Date().getFullYear()+1;
    if(!Number.isInteger(y)||y<1886||y>maxYear)return json({ok:false,error:"Podaj prawidłowy rok produkcji."},400);
  }
  const mileage=clean(b.mileage);
  if(mileage!==null){
    const m=Number(mileage);
    if(!Number.isFinite(m)||m<0)return json({ok:false,error:"Przebieg nie może być ujemny."},400);
  }

  await env.DB.prepare(`UPDATE vehicles SET brand=?,model=?,vin=?,production_year=?,engine_capacity=?,engine_code=?,fuel=?,power=?,mileage=? WHERE id=? AND customer_id=?`).bind(
    brand,model,clean(b.vin),year===null?null:Number(year),clean(b.engine_capacity),clean(b.engine_code),clean(b.fuel),clean(b.power),mileage===null?null:Number(mileage),vehicleId,u.customer_id
  ).run();

  const vehicle=await env.DB.prepare(`SELECT id,brand,model,vin,production_year,engine_capacity,engine_code,fuel,power,mileage FROM vehicles WHERE id=? AND customer_id=?`).bind(vehicleId,u.customer_id).first();
  return json({ok:true,vehicle});
}

// 3. Zapytanie o część dla WYBRANEGO samochodu klienta
if(url.pathname==="/api/customer/requests" && request.method==="POST"){
  const u=await customerAuth(request,env);
  if(!u)return json({ok:false,error:"Brak autoryzacji."},401);

  const b=await request.json();
  const vehicleId=Number(b.vehicle_id);
  const description=clean(b.description);

  if(!vehicleId || !description){
    return json({ok:false,error:"Wybierz samochód i wpisz czego potrzebujesz."},400);
  }

  // Bardzo ważne: samochód musi należeć do zalogowanego klienta.
  const vehicle=await env.DB.prepare(`
    SELECT id FROM vehicles
    WHERE id=? AND customer_id=?
    LIMIT 1
  `).bind(vehicleId,u.customer_id).first();

  if(!vehicle){
    return json({ok:false,error:"Ten samochód nie należy do Twojego konta."},403);
  }

  const businessSlug=clean(b.business_slug)||"temot";
  const business=await env.DB.prepare(`
    SELECT id FROM businesses
    WHERE slug=? AND active=1
    LIMIT 1
  `).bind(businessSlug).first();

  if(!business){
    return json({ok:false,error:"Nie znaleziono firmy odbierającej zapytanie."},404);
  }

  const requestNumber="AR-"+new Date().getFullYear()+"-"+crypto.randomUUID().slice(0,8).toUpperCase();

  const r=await env.DB.prepare(`
    INSERT INTO requests(
      request_number,business_id,customer_id,vehicle_id,
      request_type,category,description,part_number,status
    )
    VALUES(?,?,?,?,?,?,?,?,?)
  `).bind(
    requestNumber,
    business.id,
    u.customer_id,
    vehicleId,
    clean(b.request_type)||"PART",
    clean(b.category)||"OTHER",
    description,
    clean(b.part_number),
    "NEW"
  ).run();

  return json({
    ok:true,
    request_id:r.meta.last_row_id,
    request_number:requestNumber
  },201);
}



// Lista zapytan zalogowanego klienta
if(url.pathname==="/api/customer/requests" && request.method==="GET"){
  const u=await customerAuth(request,env);
  if(!u)return json({ok:false,error:"Brak autoryzacji."},401);
  const r=await env.DB.prepare(`
    SELECT r.id,r.request_number,r.status,r.description,r.created_at,
           v.brand,v.model,b.name AS business_name
    FROM requests r
    JOIN vehicles v ON v.id=r.vehicle_id
    JOIN businesses b ON b.id=r.business_id
    WHERE r.customer_id=? ORDER BY r.id DESC
  `).bind(u.customer_id).all();
  return json({ok:true,requests:r.results});
}

// Wiadomosci klienta - tylko do jego wlasnego zapytania
if(/^\/api\/customer\/requests\/\d+\/messages$/.test(url.pathname)){
  const u=await customerAuth(request,env);
  if(!u)return json({ok:false,error:"Brak autoryzacji."},401);
  const requestId=Number(url.pathname.split("/")[4]);
  const owned=await env.DB.prepare("SELECT id FROM requests WHERE id=? AND customer_id=? LIMIT 1").bind(requestId,u.customer_id).first();
  if(!owned)return json({ok:false,error:"Nie znaleziono zapytania."},404);
  if(request.method==="GET"){
    const m=await env.DB.prepare("SELECT id,sender_type,message,created_at FROM messages WHERE request_id=? ORDER BY id ASC").bind(requestId).all();
    return json({ok:true,messages:m.results});
  }
  if(request.method==="POST"){
    const body=await request.json(),message=clean(body.message);
    if(!message)return json({ok:false,error:"Wiadomosc nie moze byc pusta."},400);
    await env.DB.prepare("INSERT INTO messages(request_id,sender_type,message) VALUES(?,'CUSTOMER',?)").bind(requestId,message).run();
    return json({ok:true},201);
  }
}


// Szczegoly oferty dla zalogowanego klienta
if(/^\/api\/customer\/requests\/\d+\/offer$/.test(url.pathname) && request.method==="GET"){
  const u=await customerAuth(request,env);
  if(!u)return json({ok:false,error:"Brak autoryzacji."},401);
  const id=Number(url.pathname.split("/")[4]);
  const req=await env.DB.prepare(`
    SELECT r.id,r.request_number,r.status,r.description,r.part_number,r.created_at,
           v.brand,v.model,v.vin,v.mileage,b.name AS business_name
    FROM requests r
    JOIN vehicles v ON v.id=r.vehicle_id
    JOIN businesses b ON b.id=r.business_id
    WHERE r.id=? AND r.customer_id=?
  `).bind(id,u.customer_id).first();
  if(!req)return json({ok:false,error:"Nie znaleziono zapytania."},404);
  const offer=await env.DB.prepare(`
    SELECT price,availability,appointment_date,note,created_at
    FROM responses WHERE request_id=? ORDER BY id DESC LIMIT 1
  `).bind(id).first();
  return json({ok:true,request:req,offer:offer||null});
}

// Pozycje części w ofercie - widok zalogowanego klienta
if(/^\/api\/customer\/requests\/\d+\/items$/.test(url.pathname) && request.method==="GET"){
  const u=await customerAuth(request,env);
  if(!u)return json({ok:false,error:"Brak autoryzacji."},401);
  const id=Number(url.pathname.split("/")[4]);
  const owned=await env.DB.prepare("SELECT id FROM requests WHERE id=? AND customer_id=? LIMIT 1").bind(id,u.customer_id).first();
  if(!owned)return json({ok:false,error:"Nie znaleziono zapytania."},404);
  const r=await env.DB.prepare(`
    SELECT id,part_name,part_number,quantity,unit_price,created_at
    FROM request_items WHERE request_id=? ORDER BY id ASC
  `).bind(id).all();
  return json({ok:true,items:r.results});
}

// Klient potwierdza albo rezygnuje z zakupu
if(/^\/api\/customer\/requests\/\d+\/decision$/.test(url.pathname) && request.method==="POST"){
  const u=await customerAuth(request,env);
  if(!u)return json({ok:false,error:"Brak autoryzacji."},401);
  const id=Number(url.pathname.split("/")[4]);
  const body=await request.json();
  const decision=clean(body.decision).toUpperCase();
  const req=await env.DB.prepare("SELECT id,status FROM requests WHERE id=? AND customer_id=?").bind(id,u.customer_id).first();
  if(!req)return json({ok:false,error:"Nie znaleziono zapytania."},404);
  if(req.status!=="ANSWERED")return json({ok:false,error:"Ta oferta nie oczekuje już na decyzję."},400);
  if(decision!=="CONFIRMED" && decision!=="CANCELLED")return json({ok:false,error:"Nieprawidłowa decyzja."},400);
  await env.DB.prepare("UPDATE requests SET status=?,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(decision,id).run();
  const txt=decision==="CONFIRMED" ? "Klient potwierdził zakup." : "Klient zrezygnował z zakupu.";
  await env.DB.prepare("INSERT INTO messages(request_id,sender_type,message) VALUES(?,'CUSTOMER',?)").bind(id,txt).run();
  return json({ok:true,status:decision});
}

// Historia zakupow klienta - tylko zrealizowane
if(url.pathname==="/api/customer/order-history" && request.method==="GET"){
  const u=await customerAuth(request,env);
  if(!u)return json({ok:false,error:"Brak autoryzacji."},401);
  const r=await env.DB.prepare(`
    SELECT r.id,r.request_number,r.vehicle_id,r.description,r.part_number,r.updated_at,
           v.brand,v.model,v.vin,v.production_year,v.engine_capacity,v.engine_code,v.mileage,b.name AS business_name,
           (SELECT price FROM responses rr WHERE rr.request_id=r.id ORDER BY rr.id DESC LIMIT 1) AS price
    FROM requests r
    JOIN vehicles v ON v.id=r.vehicle_id
    JOIN businesses b ON b.id=r.business_id
    WHERE r.customer_id=? AND r.status='COMPLETED'
    ORDER BY r.updated_at DESC,r.id DESC
  `).bind(u.customer_id).all();
  return json({ok:true,orders:r.results});
}



// Powiadomienia / przypomnienia zalogowanego klienta
if(url.pathname==="/api/customer/reminders" && request.method==="GET"){
  const u=await customerAuth(request,env);
  if(!u)return json({ok:false,error:"Brak autoryzacji."},401);

  const showAll=url.searchParams.get("all")==="1";
  const dateFilter=showAll ? "" : "AND date(vr.reminder_date)<=date(\'now\',\'+30 days\')";

  const r=await env.DB.prepare(`
    SELECT
      vr.id,
      vr.vehicle_id,
      vr.request_id,
      vr.request_item_id,
      vr.reminder_type,
      vr.title,
      vr.reminder_date,
      vr.active,
      v.brand,
      v.model,
      v.vin,
      ri.part_name,
      ri.part_number,
      CAST(julianday(vr.reminder_date)-julianday(date('now')) AS INTEGER) AS days_left
    FROM vehicle_reminders vr
    JOIN vehicles v ON v.id=vr.vehicle_id
    LEFT JOIN request_items ri ON ri.id=vr.request_item_id
    WHERE vr.customer_id=?
      AND v.customer_id=?
      AND vr.active=1
      ${dateFilter}
    ORDER BY date(vr.reminder_date) ASC,vr.id DESC
  `).bind(u.customer_id,u.customer_id).all();

  return json({ok:true,reminders:r.results});
}
// Zmiana terminu przypomnienia
if(/^\/api\/customer\/reminders\/\d+$/.test(url.pathname) && request.method==="PUT"){
  const u=await customerAuth(request,env);
  if(!u)return json({ok:false,error:"Brak autoryzacji."},401);

  const id=Number(url.pathname.split("/").pop());
  const b=await request.json();
  const d=clean(b.reminder_date);

  if(!d || !/^\d{4}-\d{2}-\d{2}$/.test(d)){
    return json({ok:false,error:"Podaj prawidłową datę RRRR-MM-DD."},400);
  }

  const p=d.split("-").map(Number);
  const dt=new Date(Date.UTC(p[0],p[1]-1,p[2]));

  if(
    dt.getUTCFullYear()!==p[0] ||
    dt.getUTCMonth()!==p[1]-1 ||
    dt.getUTCDate()!==p[2]
  ){
    return json({ok:false,error:"Podana data nie istnieje."},400);
  }

  const own=await env.DB.prepare(
    "SELECT id FROM vehicle_reminders WHERE id=? AND customer_id=? AND active=1"
  ).bind(id,u.customer_id).first();

  if(!own){
    return json({ok:false,error:"Nie znaleziono aktywnego przypomnienia."},404);
  }

  await env.DB.prepare(
    "UPDATE vehicle_reminders SET reminder_date=? WHERE id=? AND customer_id=? AND active=1"
  ).bind(d,id,u.customer_id).run();

  return json({
    ok:true,
    reminder_id:id,
    reminder_date:d
  });
}


// Usunięcie przypomnienia
if(/^\/api\/customer\/reminders\/\d+$/.test(url.pathname) && request.method==="DELETE"){
  const u=await customerAuth(request,env);
  if(!u)return json({ok:false,error:"Brak autoryzacji."},401);

  const id=Number(url.pathname.split("/").pop());

  const own=await env.DB.prepare(
    "SELECT id FROM vehicle_reminders WHERE id=? AND customer_id=? AND active=1"
  ).bind(id,u.customer_id).first();

  if(!own){
    return json({ok:false,error:"Nie znaleziono aktywnego przypomnienia."},404);
  }

  await env.DB.prepare(
    "UPDATE vehicle_reminders SET active=0 WHERE id=? AND customer_id=? AND active=1"
  ).bind(id,u.customer_id).run();

  return json({
    ok:true,
    reminder_id:id
  });
}
// Historia zakupow WYBRANEGO samochodu zalogowanego klienta
if(/^\/api\/customer\/vehicles\/\d+\/purchase-history$/.test(url.pathname) && request.method==="GET"){
  const u=await customerAuth(request,env);
  if(!u)return json({ok:false,error:"Brak autoryzacji."},401);

  const vehicleId=Number(url.pathname.split("/")[4]);

  const vehicle=await env.DB.prepare(`
    SELECT id,brand,model,vin,production_year,engine_capacity,engine_code,fuel,power,mileage
    FROM vehicles
    WHERE id=? AND customer_id=?
    LIMIT 1
  `).bind(vehicleId,u.customer_id).first();

  if(!vehicle)return json({ok:false,error:"Nie znaleziono samochodu."},404);

  const items=await env.DB.prepare(`
    SELECT
      ri.id AS request_item_id,ri.request_id,ri.part_name,ri.part_number,
      ri.quantity,ri.unit_price,r.request_number,r.updated_at AS purchase_date,
      b.name AS business_name,vr.id AS reminder_id,vr.reminder_type,
      vr.reminder_date,vr.active AS reminder_active
    FROM requests r
    JOIN request_items ri ON ri.request_id=r.id
    JOIN businesses b ON b.id=r.business_id
    LEFT JOIN vehicle_reminders vr
      ON vr.request_item_id=ri.id
     AND vr.customer_id=?
     AND vr.vehicle_id=?
     AND vr.active=1
    WHERE r.customer_id=?
      AND r.vehicle_id=?
      AND r.status='COMPLETED'
    ORDER BY r.updated_at DESC,ri.id DESC
  `).bind(u.customer_id,vehicleId,u.customer_id,vehicleId).all();

  return json({ok:true,vehicle,items:items.results});
}

// Dodanie / odnowienie przypomnienia za rok dla pozycji z historii pojazdu
if(/^\/api\/customer\/vehicles\/\d+\/reminders$/.test(url.pathname) && request.method==="POST"){
  const u=await customerAuth(request,env);
  if(!u)return json({ok:false,error:"Brak autoryzacji."},401);

  const vehicleId=Number(url.pathname.split("/")[4]);
  const body=await request.json();
  const requestItemId=Number(body.request_item_id);

  if(!requestItemId)return json({ok:false,error:"Brak pozycji części."},400);

  const item=await env.DB.prepare(`
    SELECT ri.id,ri.request_id,ri.part_name,ri.part_number,r.updated_at AS purchase_date
    FROM request_items ri
    JOIN requests r ON r.id=ri.request_id
    WHERE ri.id=? AND r.customer_id=? AND r.vehicle_id=? AND r.status='COMPLETED'
    LIMIT 1
  `).bind(requestItemId,u.customer_id,vehicleId).first();

  if(!item)return json({ok:false,error:"Nie znaleziono tej części w historii samochodu."},404);

  const reminderType=clean(body.reminder_type)||"YEARLY";
  const baseDate=new Date(item.purchase_date || Date.now());
  if(Number.isNaN(baseDate.getTime()))return json({ok:false,error:"Nie udało się ustalić daty zakupu."},400);

  baseDate.setFullYear(baseDate.getFullYear()+1);
  const reminderDate=baseDate.toISOString().slice(0,10);

  await env.DB.prepare(`
    UPDATE vehicle_reminders
    SET active=0
    WHERE customer_id=? AND vehicle_id=? AND request_item_id=? AND active=1
  `).bind(u.customer_id,vehicleId,requestItemId).run();

  const rr=await env.DB.prepare(`
    INSERT INTO vehicle_reminders(
      customer_id,vehicle_id,request_id,request_item_id,
      reminder_type,title,reminder_date,active
    ) VALUES(?,?,?,?,?,?,?,1)
  `).bind(
    u.customer_id,vehicleId,item.request_id,requestItemId,
    reminderType,"Wymiana: "+item.part_name,reminderDate
  ).run();

  return json({ok:true,reminder_id:rr.meta.last_row_id,reminder_date:reminderDate},201);
}

// Lista aktywnych przypomnien dla wybranego samochodu
if(/^\/api\/customer\/vehicles\/\d+\/reminders$/.test(url.pathname) && request.method==="GET"){
  const u=await customerAuth(request,env);
  if(!u)return json({ok:false,error:"Brak autoryzacji."},401);

  const vehicleId=Number(url.pathname.split("/")[4]);

  const vehicle=await env.DB.prepare(`
    SELECT id FROM vehicles WHERE id=? AND customer_id=? LIMIT 1
  `).bind(vehicleId,u.customer_id).first();

  if(!vehicle)return json({ok:false,error:"Nie znaleziono samochodu."},404);

  const r=await env.DB.prepare(`
    SELECT id,request_id,request_item_id,reminder_type,title,reminder_date,active,created_at
    FROM vehicle_reminders
    WHERE customer_id=? AND vehicle_id=? AND active=1
    ORDER BY reminder_date ASC,id DESC
  `).bind(u.customer_id,vehicleId).all();

  return json({ok:true,reminders:r.results});
}

// Zamowienia firmy: potwierdzone i zrealizowane
if(url.pathname==="/api/company/orders" && request.method==="GET"){
  const u=await auth(request,env);
  if(!u)return json({ok:false,error:"Brak autoryzacji."},401);
  const r=await env.DB.prepare(`
    SELECT r.id,r.request_number,r.status,r.description,r.part_number,r.updated_at,
           c.name AS customer_name,c.phone AS customer_phone,
           v.brand,v.model,v.vin,v.mileage,
           (SELECT price FROM responses rr WHERE rr.request_id=r.id ORDER BY rr.id DESC LIMIT 1) AS price
    FROM requests r
    JOIN customers c ON c.id=r.customer_id
    JOIN vehicles v ON v.id=r.vehicle_id
    WHERE r.business_id=? AND r.status IN ('CONFIRMED','COMPLETED','CANCELLED')
    ORDER BY r.updated_at DESC,r.id DESC
  `).bind(u.business_id).all();
  return json({ok:true,orders:r.results});
}

// Pozycje części w zamówieniu - widok firmy
if(/^\/api\/company\/orders\/\d+\/items$/.test(url.pathname) && request.method==="GET"){
  const u=await auth(request,env);
  if(!u)return json({ok:false,error:"Brak autoryzacji."},401);
  const id=Number(url.pathname.split("/")[4]);
  const own=await env.DB.prepare("SELECT id FROM requests WHERE id=? AND business_id=? LIMIT 1").bind(id,u.business_id).first();
  if(!own)return json({ok:false,error:"Brak dostępu."},403);
  const r=await env.DB.prepare(`SELECT id,part_name,part_number,quantity,unit_price,created_at FROM request_items WHERE request_id=? ORDER BY id ASC`).bind(id).all();
  return json({ok:true,items:r.results});
}

// Pozycje części w historii klienta - tylko zrealizowane zamówienia
if(/^\/api\/customer\/order-history\/\d+\/items$/.test(url.pathname) && request.method==="GET"){
  const u=await customerAuth(request,env);
  if(!u)return json({ok:false,error:"Brak autoryzacji."},401);
  const id=Number(url.pathname.split("/")[4]);
  const owned=await env.DB.prepare("SELECT id FROM requests WHERE id=? AND customer_id=? AND status='COMPLETED' LIMIT 1").bind(id,u.customer_id).first();
  if(!owned)return json({ok:false,error:"Nie znaleziono zrealizowanego zamówienia."},404);
  const r=await env.DB.prepare(`SELECT id,part_name,part_number,quantity,unit_price,created_at FROM request_items WHERE request_id=? ORDER BY id ASC`).bind(id).all();
  return json({ok:true,items:r.results});
}

// Firma oznacza potwierdzone zamowienie jako zrealizowane
if(/^\/api\/company\/requests\/\d+\/complete$/.test(url.pathname) && request.method==="POST"){
  const u=await auth(request,env);
  if(!u)return json({ok:false,error:"Brak autoryzacji."},401);
  const id=Number(url.pathname.split("/")[4]);
  const req=await env.DB.prepare("SELECT id,status FROM requests WHERE id=? AND business_id=?").bind(id,u.business_id).first();
  if(!req)return json({ok:false,error:"Brak dostępu."},403);
  if(req.status!=="CONFIRMED")return json({ok:false,error:"Najpierw klient musi potwierdzić zakup."},400);
  await env.DB.prepare("UPDATE requests SET status='COMPLETED',updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(id).run();
  await env.DB.prepare("INSERT INTO messages(request_id,sender_type,sender_id,message) VALUES(?,?,?,?)").bind(id,"BUSINESS",u.id,"Zamówienie zostało zrealizowane.").run();
  return json({ok:true,status:"COMPLETED"});
}

    return env.ASSETS.fetch(new Request(new URL("/index.html", request.url), request));
 }catch(e){
  return json({ok:false,error:e.message},500);
 }
}};
