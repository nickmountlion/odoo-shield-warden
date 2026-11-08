# Kaizen cycle 4: login attacks, self-integrity and a repeatable gate (2026-10-30)

Cycle 3 ([KAIZEN_CYCLE_3.md](KAIZEN_CYCLE_3.md)) added prevention (payment hold) and cases. Cycle 4 widens detection to
attacks on the front door and on Shield itself, and makes the whole claim re-checkable with one command.

## Headline results (fresh database, `python lab/kaizen_loop.py`, last run 2026-10-31: PASS)

| | Cycle 3 | Cycle 4 |
|---|---|---|
| Lab scenarios detected | 18/18 | **21/21** (A16 brute force to takeover, A17 password spraying, A18 insider disables Shield) |
| Attacks prevented | 2/2 | **2/2** |
| Tests | 41 | **46**, all passing, 0 errors on a clean install |
| Cases / alerts / money at risk (lab) | 5 / 15 | **5 cases from 15 alerts, 54,800 at risk** |

## What changed
1. **Login-attack log and detection**: failed-login bursts, password spraying and "brute force ending in a successful login".
2. **Shield self-integrity**: detects an insider who disables or tampers with Shield, and the evidence-seal chain
   stays verifiable (new payload keys are optional so older seals still verify).
3. **Record-rule-aware segregation of duties**: effective permissions now account for record rules, not only model access.
4. **`lab/kaizen_loop.py`**: the gate. Runs unit tests on a fresh install, builds a fresh lab database, replays attack
   waves 1-4, grades against `lab/results/best.json` and exits 1 on any regression. `--keep-db` is faster but less strict.

## Still open
Maintained CVE/advisory feed (currently curated `data/advisories.json`), Odoo 19 port, Enterprise/Odoo.sh validation,
multi-company scoping, app icon, CI workflow (`postgres:16` + `odoo:18.0`).
