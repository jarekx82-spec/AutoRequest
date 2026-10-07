PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS businesses (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 type TEXT NOT NULL DEFAULT 'SHOP',
 email TEXT, phone TEXT, city TEXT,
 active INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS customers (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL, phone TEXT NOT NULL,
 email TEXT, city TEXT,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS vehicles (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 customer_id INTEGER NOT NULL,
 brand TEXT NOT NULL, model TEXT NOT NULL, vin TEXT,
 production_year INTEGER, engine_capacity TEXT, engine_code TEXT,
 fuel TEXT, power INTEGER, mileage INTEGER,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(customer_id) REFERENCES customers(id)
);

CREATE TABLE IF NOT EXISTS requests (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 request_number TEXT UNIQUE NOT NULL,
 business_id INTEGER NOT NULL, customer_id INTEGER NOT NULL, vehicle_id INTEGER NOT NULL,
 request_type TEXT NOT NULL DEFAULT 'PART',
 category TEXT NOT NULL DEFAULT 'OTHER',
 description TEXT NOT NULL, part_number TEXT,
 status TEXT NOT NULL DEFAULT 'NEW',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(business_id) REFERENCES businesses(id),
 FOREIGN KEY(customer_id) REFERENCES customers(id),
 FOREIGN KEY(vehicle_id) REFERENCES vehicles(id)
);

CREATE TABLE IF NOT EXISTS responses (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 request_id INTEGER NOT NULL,
 price REAL, availability TEXT, appointment_date TEXT, note TEXT,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(request_id) REFERENCES requests(id)
);

CREATE TABLE IF NOT EXISTS service_history (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 vehicle_id INTEGER NOT NULL,
 service_type TEXT NOT NULL, service_date TEXT NOT NULL,
 mileage INTEGER, part_number TEXT, description TEXT,
 next_due_date TEXT, next_due_mileage INTEGER,
 business_id INTEGER,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(vehicle_id) REFERENCES vehicles(id),
 FOREIGN KEY(business_id) REFERENCES businesses(id)
);

CREATE TABLE IF NOT EXISTS reminders (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 vehicle_id INTEGER NOT NULL,
 service_history_id INTEGER,
 reminder_type TEXT NOT NULL,
 due_date TEXT, due_mileage INTEGER,
 sent INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(vehicle_id) REFERENCES vehicles(id),
 FOREIGN KEY(service_history_id) REFERENCES service_history(id)
);

INSERT OR IGNORE INTO businesses
(id,name,type,email,city)
VALUES (1,'TEMOT AUTO CZĘŚCI','SHOP','demo@example.com','Ruda Śląska');
