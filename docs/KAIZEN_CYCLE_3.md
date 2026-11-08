# Kaizen cycle 3: from detecting fraud to stopping it (2026-10-30)

Cycle 2 ([REAL_WORLD_ASSESSMENT.md](REAL_WORLD_ASSESSMENT.md)) ended with 14/14 lab scenarios detected and a list of
open gaps. Cycle 3 closes most of them and adds the one thing no Odoo competitor does: **stopping the payment.**

## Headline results

| | Cycle 2 | Cycle 3 |
|---|---|---|
| Lab scenarios detected | 14/14 | **18/18** (4 new scenarios) |
| Attacks *prevented* | 0 | **2/2** (payment to swapped IBAN blocked; fraudster can't self-verify) |
| What the reviewer sees | 15 alerts | **5 cases**, one per real incident |
| Money at risk accuracy | counted per alert | each payment counted once per incident; blocked payments excluded |
| Controls | 45 | **52** (40 base + 12 finance) |
| Tests | 27 | **41**, all passing |

## What changed

### 1. Payment hold (prevention) *(roadmap item 2)*
- When `shield.payment_hold = enforce`, Odoo **refuses to post** an outbound payment to a bank account whose number
  was set or changed within `shield.payment_hold_days` (default 30), or that Shield flagged (hidden change,
  shared IBAN, lookalike vendor).
- The hold lifts only when someone **other than the person who set the number** clicks **Verify with Shield** on the
  bank account. The verification is written to the bank account's and the vendor's chatter.
- It ships **off by default**, so installing it never blocks a customer's payment run by surprise. The `payment_hold` control fails until it is
  enabled, and its one-click fix turns it on.
- Odoo's own "trusted account" switch can be flipped by the same person who changed the IBAN. This one can't.

### 2. Cases, not alerts *(K9)*
- Alerts that share a bank account, a payment or a bill are grouped into one **case** (connected components via union-find).
  One attacker IBAN used against two vendors is one case. If a later alert links two existing cases, they merge.
- Reviewing a case reviews all its alerts. A second-person rule still applies: you can't clear a case about your own actions.
- The scorecard now leads with **Cases to review**: incident, who did it, why, money.

### 3. Patch level *(K10)*
- `patch_level` reads the build date from the Odoo version string (e.g. `18.0-20261015`) and checks
  `data/advisories.json` (series, module, publication date). It flags builds older than 60 days (warning) or 180 days (fail).
- Keep `advisories.json` updated. It is data, not code.

### 4. Evidence outside Odoo *(K11)*
- After every seal, an email with the seal and the previous seal goes to `shield.seal_recipients`. Once that
  mailbox holds the receipts, even a full rewrite of the history can be proven. The `seal_offbox` control checks this.

### 5. Cover-ups and leaks *(G4, G5)*
- **Deleted messages:** every chatter message deleted from partners, bank accounts, invoices, payments,
  employees and users is logged. Deletions from records that still exist are flagged as cover-ups (`message_deletions`).
- **Public attachments:** business documents downloadable without login are flagged (`public_attachments`).

### 6. Vendor-master fraud *(roadmap item 8)*
- `ccm_lookalike_vendor`: "N0rthwind Logistics Ltd" vs "Northwind Logistics". Names are normalized (digit-for-letter
  swaps, legal suffixes) and fuzzy-matched.
- `ccm_new_vendor_fast_payment`: the vendor is paid within 7 days by the person who created it (critical if they
  also created its bank account).

### 7. One-click fixes *(K13)*
Login throttling, template editors and the payment hold can now be fixed in one click. That makes 7 fixes in total.

## What the lab taught us this time (Check → Act)

| # | Finding | Fix |
|---|---|---|
| K14 | **Changing the number again erased the evidence.** After a second IBAN change, a past $18,400 payment to the employee's IBAN no longer matched any shared account | The shared-IBAN rule judges each payment by the number the bank record held **when it was paid** (number timeline from old/new tracking values). Regression test added |
| K15 | One incident still split across two cases (the shared IBAN alert pointed at a different bank record) | Union-find grouping on every bank account, payment and bill an alert touches; cases merge automatically |
| K16 | The verifier couldn't write the verification note (no rights on contacts) | Note posted with elevated rights, the verifier kept as author, so the trail is always written |
| K17 | Tests can't order events inside one transaction (records use the transaction start, chatter the wall clock) | Tests place events on a realistic timeline with SQL; number attribution uses a 5-second tolerance |

## Still open
- Record-rule-aware toxic-rights detection (K12) and multi-company scoping.
- A maintained, authoritative advisory feed (today: a curated JSON file).
- Brute-force and session anomalies need server logs (failed logins aren't stored in Odoo's database).
- Odoo 19 port and validation on Enterprise / Odoo.sh.

## Try it
```bash
python lab/attack_lab.py --wave 3 --label mine     # lookalike vendor, erased trail, public PDF, payment hold
```
Then open **Shield > Money at Risk** (cases) and any vendor bank account (**Verify with Shield**).
