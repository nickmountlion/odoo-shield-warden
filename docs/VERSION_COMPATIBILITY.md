# Odoo version compatibility (2026-11-05)

Source of truth is the Odoo 18 code in `addons/`. The 19 and 17 ports are **patches**, not branches, and are not merged.
Apply with `patch -p1 -d <copy of the repo> < docs/ports/odooNN.patch` (paths in the files are relative to the repo
parent; check with `--dry-run`). The patches also carry line-ending noise from the scripted edits.

| Odoo | Install | Tests (`/odoo_shield_warden,/odoo_shield_warden_finance`) | Argentina tests (`l10n_ar_withholding`) | Status |
|---|---|---|---|---|
| 18.0 | clean | **60/60** | **4/4** | Supported. Kaizen loop PASS: 22/22 scenarios, 2 prevention checks |
| 19.0 | clean | **60/60** | **4/4** | Ported by patch. **Kaizen loop PASS** on 19: 22/22 scenarios, 2 prevention checks, 5 cases from 15 alerts, 54,800.00 at risk (same as 18) |
| 17.0 | installs after the view backports | **46/60** | not run | **Not supported**: 14 finance tests fail |

All runs used the official `odoo:NN.0` images with `--without-demo=all`, a fresh database each time.
The Argentina tests were also confirmed to fail when the payment hold is switched off (3 of 4 fail), so they check something.

## Odoo 19 changes (`docs/ports/odoo19.patch`)
- Manifest version `19.0.x`.
- `res.groups.category_id` is replaced by a `res.groups.privilege` record (`privilege_id`).
- `res.groups.users` became `user_ids`, and `res.users.groups_id` became `group_ids`.
- `<group expand="0">` is no longer valid in search views.
- `res.users._login(credential, user_agent_env)` is now an instance method without `db`. **The 18 override broke every login on 19**; the unit tests did not catch it, the attack lab did.
- The lab fixture `lab_vuln_portal` needs a `19.0` manifest version and a place on the addons path (the lab copies it to `~/odoo/addons` for the 18 stack only).
- One 19 loop run reported 2 failed unit tests; two direct reruns and a second full loop passed 60/60. Cause unknown (not reproduced).
- Not yet needed, but deprecated: `_sql_constraints` (replaced by `models.Constraint`). It still works in 19.0.

## Odoo 17 changes (`docs/ports/odoo17.patch`)
- Manifest version `17.0.x`; `<list>` to `<tree>`; `view_mode` list to tree; `<chatter/>` to the `oe_chatter` div.
- `aggregator=` to `group_operator=`; `env._()` to `_()`.
- A field used in a modifier must be present in the view (`has_fix`).
- `ir.cron.failure_count` does not exist: the cron-failure check returns "n/a".
- **Still failing (14 tests, all in `TestMoneyAtRisk`)**: e.g. `test_self_paid_bill` returns `pass` instead of `fail`.
  Likely cause (not verified): Odoo 17 links payments to bills differently, so the transaction rules find nothing. This
  needs real work, not a backport. 17 is therefore not offered until someone does it.

## What this does not cover
Enterprise, Odoo.sh builds, and Odoo Online (no custom modules there; use `scanner/`).
