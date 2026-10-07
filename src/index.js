
const json=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:{"content-type":"application/json; charset=UTF-8"}});
const clean=v=>v==null||String(v).trim()===""?null:String(v).trim();

export default {
 async fetch(request,env){
  const url=new URL(request.url);
  try{
   if(url.pathname==="/api/health") return json({ok:true,app:"AutoRequest",version:"MVP v2"});

   if(url.pathname==="/api/businesses"&&request.method==="GET"){
    const r=await env.DB.prepare("SELECT id,name,type,city FROM businesses WHERE active=1 ORDER BY name").all();
    return json({ok:true,businesses:r.results});
   }

   if(url.pathname==="/api/requests"&&request.method==="POST"){
    const b=await request.json();
    for(const f of ["name","phone","brand","model","description"])
     if(!clean(b[f])) return json({ok:false,error:"Brak pola: "+f},400);

    const businessId=Number(b.business_id||1);
    const company=await env.DB.prepare("SELECT id FROM businesses WHERE id=? AND active=1").bind(businessId).first();
    if(!company) return json({ok:false,error:"Firma nie istnieje."},400);

    const c=await env.DB.prepare("INSERT INTO customers(name,phone,email,city) VALUES(?,?,?,?)")
     .bind(clean(b.name),clean(b.phone),clean(b.email),clean(b.city)).run();

    const v=await env.DB.prepare(`INSERT INTO vehicles
     (customer_id,brand,model,vin,production_year,engine_capacity,engine_code,fuel,power,mileage)
     VALUES(?,?,?,?,?,?,?,?,?,?)`).bind(
      c.meta.last_row_id,clean(b.brand),clean(b.model),clean(b.vin),
      b.production_year?Number(b.production_year):null,clean(b.engine_capacity),
      clean(b.engine_code),clean(b.fuel),b.power?Number(b.power):null,
      b.mileage?Number(b.mileage):null).run();

    const num="AR-"+new Date().getFullYear()+"-"+String(Date.now()).slice(-6);
    const r=await env.DB.prepare(`INSERT INTO requests
     (request_number,business_id,customer_id,vehicle_id,request_type,category,description,part_number,status)
     VALUES(?,?,?,?,?,?,?,?,'NEW')`).bind(
      num,businessId,c.meta.last_row_id,v.meta.last_row_id,
      clean(b.request_type)||"PART",clean(b.category)||"OTHER",
      clean(b.description),clean(b.part_number)).run();

    return json({ok:true,request_id:r.meta.last_row_id,request_number:num},201);
   }

   if(url.pathname==="/api/requests"&&request.method==="GET"){
    const id=Number(url.searchParams.get("business_id")||1);
    const r=await env.DB.prepare(`SELECT r.*,c.name customer_name,c.phone customer_phone,
     v.brand,v.model,v.vin,v.production_year,v.engine_capacity,v.engine_code,v.fuel,v.power,v.mileage
     FROM requests r JOIN customers c ON c.id=r.customer_id JOIN vehicles v ON v.id=r.vehicle_id
     WHERE r.business_id=? ORDER BY r.id DESC`).bind(id).all();
    return json({ok:true,requests:r.results});
   }

   if(/^\/api\/requests\/\d+\/response$/.test(url.pathname)&&request.method==="POST"){
    const id=Number(url.pathname.split("/")[3]),b=await request.json();
    await env.DB.prepare("INSERT INTO responses(request_id,price,availability,appointment_date,note) VALUES(?,?,?,?,?)")
     .bind(id,b.price?Number(b.price):null,clean(b.availability),clean(b.appointment_date),clean(b.note)).run();
    await env.DB.prepare("UPDATE requests SET status='ANSWERED',updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(id).run();
    return json({ok:true});
   }

   if(/^\/api\/requests\/\d+$/.test(url.pathname)&&request.method==="GET"){
    const id=Number(url.pathname.split("/").pop());
    const item=await env.DB.prepare(`SELECT r.*,c.name customer_name,c.phone customer_phone,c.email customer_email,
     v.brand,v.model,v.vin,v.production_year,v.engine_capacity,v.engine_code,v.fuel,v.power,v.mileage
     FROM requests r JOIN customers c ON c.id=r.customer_id JOIN vehicles v ON v.id=r.vehicle_id WHERE r.id=?`).bind(id).first();
    const responses=await env.DB.prepare("SELECT * FROM responses WHERE request_id=? ORDER BY id DESC").bind(id).all();
    return json({ok:true,request:item,responses:responses.results});
   }

   return env.ASSETS.fetch(request);
  }catch(e){return json({ok:false,error:e.message},500)}
 }
};
