// AUTOREQUEST — DODATEK DO src/index.js
// Wklej TEN BLOK wewnątrz export default { async fetch(request, env) { ... } }
// po endpointach /api/customer/me, a przed końcowym return env.ASSETS.fetch(...).

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
