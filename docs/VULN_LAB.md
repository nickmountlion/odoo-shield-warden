# Vulnerable Odoo lab: what we learned (2026-11-05)

Two intentionally vulnerable Odoo 18 instances for testing Shield and Warden detections. Files: `lab/odoo-vuln-lab/` (compose, configs, seed, README with credentials). Localhost only. Never expose these ports or reuse these credentials.

## Design
- Two independent stacks in one compose project (`odoo-vuln-lab`): own Postgres, config and volumes each. Separate from the `~/odoo` stack on port 8069.
- Instance A "acme" `:8081`: admin/admin, master password `admin`, open uninvited signup, debug logging, users whose password equals the login.
- Instance B "globex" `:8082`: admin `Winter2026!`, master password `Summer2026` (seasonal, guessable), reused password `Welcome1`.
- Both: DB list and DB manager reachable, Postgres published on 127.0.0.1 (5441/5442) with odoo/odoo, `intern` user holds Settings (group_system), portal user with weak password, fake SSN/card strings in partner comments, Odoo demo data plus 50 seeded partners and sale orders, no HTTPS.
- Every published port is bound to 127.0.0.1.

## Method
- Init each DB with `odoo -d <db> -i base,sale_management,purchase,account,crm --stop-after-init --no-http` (about 5 minutes, both in parallel).
- Seed with `docker compose exec -T -e LAB_PROFILE=a odoo-a odoo shell -d acme --no-http < seed/seed.py`. The script must call `env.cr.commit()`.
- Verify through XML-RPC (login, counts, db list, db dump), not the UI.
- Iterated five passes per the repo rule (4-5 passes on every new Odoo instance): init and seed; logins and counts; master password, signup, log errors; restart persistence; restart-race fix.

## Lessons
1. A `&` background job inside `wsl -e bash -c` dies when the wsl call returns, so the first DB init never ran and left empty logs. Run the command blocking in one wsl call and use `run_in_background` on the tool.
2. `list_db = False` makes Odoo block all DB-manager functions, including dump, even with the correct master password. A weak master password is only exploitable with `list_db = True`. This matters for detection rules: check both settings together.
3. Odoo containers exit with code 1 when they start before Postgres is ready. Use `restart: on-failure`.
4. WSL idling stops containers. Connection refused on 8081/8082 means run `docker compose up -d`.
5. Odoo demo data adds customers and orders (92 partners and 35 orders after seeding), so counts exceed what the seed creates.
6. `seed.py` is idempotent for users only; a re-run duplicates partners and orders.
7. A monitor must watch a marker written by the command that actually runs, otherwise it expires silently.
8. Git Bash needs `MSYS_NO_PATHCONV=1` for wsl calls, and `docker compose` needs `</dev/null` so it does not swallow stdin.

## Ideas for Shield and Warden
- Each misconfiguration above is a candidate control: weak or default master password, `list_db` on, DB port published, open signup, non-admin users holding Settings, default or login-equal passwords, debug log level, no HTTPS.
- Use the lab as a positive fixture: run the Shield checks against A and B and expect a finding per weakness. Use `~/odoo` odoo_shield_warden_showcase as the clean negative.

## Repository roles (proposal)
- `odoo-shield-warden` (private): development, labs, fixtures, strategy, kaizen cycles. This lab belongs here.
- `warden-odoo` (private): commercial packages (`warden_security`, `warden_pro`, `warden_money`). Ship only vetted, generalized code. Never copy lab credentials, seed data or vulnerable configs into it.
- Flow: build and test in odoo-shield-warden, then promote to warden-odoo by reviewed pull request.
