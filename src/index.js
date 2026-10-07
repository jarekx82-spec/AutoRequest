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
   const c=await env.DB.prepare("INSERT INTO customers(name,phone,email,city) VALUES(?,?,?,?)").bind(clean(b.name),clean(b.phone),clean(b.email),clean(b.city)).run();
   const v=await env.DB.prepare(`INSERT INTO vehicles(customer_id,brand,model,vin,production_year,engine_capacity,engine_code,fuel,power,mileage) VALUES(?,?,?,?,?,?,?,?,?,?)`).bind(c.meta.last_row_id,clean(b.brand),clean(b.model),clean(b.vin),b.production_year?Number(b.production_year):null,clean(b.engine_capacity),clean(b.engine_code),clean(b.fuel),b.power?Number(b.power):null,b.mileage?Number(b.mileage):null).run();
   const num="AR-"+new Date().getFullYear()+"-"+crypto.randomUUID().slice(0,8).toUpperCase();
   await env.DB.prepare(`INSERT INTO requests(request_number,business_id,customer_id,vehicle_id,request_type,category,description,part_number,status) VALUES(?,?,?,?,?,?,?,?,'NEW')`).bind(num,firm.id,c.meta.last_row_id,v.meta.last_row_id,clean(b.request_type)||"PART",clean(b.category)||"OTHER",clean(b.description),clean(b.part_number)).run();
   return json({ok:true,request_number:num},201);
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
   const b=await request.json(); await env.DB.prepare("INSERT INTO responses(request_id,price,availability,appointment_date,note) VALUES(?,?,?,?,?)").bind(id,b.price?Number(b.price):null,clean(b.availability),clean(b.appointment_date),clean(b.note)).run();
   await env.DB.prepare("UPDATE requests SET status='ANSWERED',updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(id).run(); return json({ok:true});
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
  return env.ASSETS.fetch(new Request(new URL("/", request.url), request));
 }catch(e){return json({ok:false,error:e.message},500)}
}};
