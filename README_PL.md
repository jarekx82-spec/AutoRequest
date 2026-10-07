# AutoRequest MVP v2

Panel zleceń motoryzacyjnych — nie sklep internetowy.

## Funkcje MVP
- klient wpisuje dane samochodu,
- wysyła zapytanie do zarejestrowanej firmy,
- sklep/warsztat widzi zapytanie,
- firma odpowiada ceną, dostępnością lub terminem,
- struktura bazy obsługuje historię serwisową i przyszłe przypomnienia.

## Pliki
- `public/index.html` — interfejs klienta i demonstracyjny panel firmy
- `src/index.js` — API Cloudflare Worker
- `schema.sql` — struktura bazy Cloudflare D1
- `wrangler.toml` — konfiguracja wdrożenia

## Ważne
Po utworzeniu bazy D1 zamień `TU_WKLEJ_DATABASE_ID` w `wrangler.toml` na Database ID z Cloudflare.
