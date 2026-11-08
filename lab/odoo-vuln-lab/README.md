# odoo-vuln-lab  (~/odoo-vuln-lab in WSL) — INTENTIONALLY VULNERABLE, localhost only
Start: `cd ~/odoo-vuln-lab && docker compose up -d`   Stop: `docker compose down` (add -v to wipe)

| | A "acme" | B "globex" |
|---|---|---|
| URL | http://localhost:8081 | http://localhost:8082 |
| admin | admin / admin | admin / Winter2026! |
| master pw | admin | Summer2026 |
| DB | 127.0.0.1:5441 odoo/odoo | 127.0.0.1:5442 odoo/odoo |
| signup | open (b2c, uninvited) | default |
| log level | debug | info |

Both: list_db on, DB manager reachable (backup/dump w/ master pw), users sales/accountant/buyer/intern/portal1 with
weak/reused passwords (A: login==password; B: Welcome1), `intern` holds Settings (group_system), fake PII/card strings in
partner comments, demo + 50 seeded partners, sale orders. No HTTPS, no proxy hardening.
Reseed: `docker compose exec -T -e LAB_PROFILE=a odoo-a odoo shell -d acme --no-http < seed/seed.py`
