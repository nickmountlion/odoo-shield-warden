# Stakeholder demo (about 10 min): ROSI first

**Setup (done):** clean database `odoo_shield_warden_showcase`, one fraud story, nothing else. Do **not** use `odoo-shield-warden` (polluted by
attack-lab runs) or `odoo_shield_warden_demo` (carries one false "audit trail erased" alert from a test cleanup).

- Start stack: `wsl -d Ubuntu -- bash -lc "cd ~/odoo && docker compose up -d"` (WSL idles out; re-run if the page is dead)
- URL: http://localhost:8069/web/login?db=odoo_shield_warden_showcase, login `admin` / `admin`
- Backup if the live demo breaks: `docs/demo-scorecard.pdf` (includes the ROSI table); interactive what-if: `docs/rosi_dashboard.html`
- The seed script is not idempotent: re-seed only on a fresh database.

## The story
Ana (Accounts Payable) can edit vendor bank details, mark them trusted *and* pay. She swapped Acme's IBAN/CBU for her own,
re-trusted it and paid **18,400**. She also entered a Northwind bill, paid it herself, then entered it again.
Odoo's own bank-account control did not stop her. Money at risk in the database: **27,900**.

## Click path
1. **Shield > Run Assessment**: grade D, 8 critical. The headline is the **money at risk** (27,900) with the cases behind it.
2. **ROSI block** (same screen, and on the PDF scorecard): net benefit, ROSI and **break-even chance** for conservative / base /
   aggressive scenarios. Default licence price is an illustrative price; change it with the system parameter
   `shield.rosi_annual_price` to show another price point.
3. **Shield > Money at Risk**: open the Acme case: who changed the IBAN/CBU, when, and the payment that followed.
4. **Prevention**: apply the one-click fix on *Payments to new bank details are held* (sets `shield.payment_hold=enforce`). As
   `ana.ap` / `demo-Passw0rd!`, a payment to a freshly changed IBAN/CBU is now refused until a second person clicks
   *Verify with Shield* (refusal verified on 2026-10-31 on the earlier demo database `odoo_shield_warden_demo`, same code; not re-run on `odoo_shield_warden_showcase`, so try it once beforehand). Off by default on purpose.
5. **Evidence**: SHA-256 seal chain on the assessment and the PDF scorecard.

## Talk track (ROSI, not a scare number)
- "27,900 is what one incident like this touches. ROSI asks the question you actually decide on: does the control earn its cost?"
- **Be upfront that it is modest.** At this loss size the base case is negative (about -44% ROSI at the Essential price); it turns
  positive in the aggressive case (+140%) and for any incident above roughly EUR 50k. We lead with **break-even** ("pays for itself
  if it stops one incident of this size every ~5 years") and with a **back-test on your own payments**, not a flattering percentage.
- Where the numbers come from: loss sizes are sourced (FBI IC3 about $123k per BEC complaint; UK Finance about 17.9k GBP per invoice scam);
  the control effect is anchored on ACFE 2026 (proactive monitoring = 53% lower median loss) but the yearly chance, recovery share,
  hold effectiveness and review labour are **our estimates**, labelled as such.
- Why Shield and not what exists: config checkers and group-pair SoD apps cost $0-250 and detect; we use users' **real effective
  permissions**, tie them to **actual payments**, and can **stop** the payment.
- Proof: replayable attack lab, 21/21 scenarios detected, 2/2 prevented, 52 tests green (`python lab/kaizen_loop.py`).

## Likely CFO objections
- "Your frequency is made up." Correct: 74% of US firms were *targeted* by BEC (AFP 2026) but no source gives a loss probability for a
  company like yours. That is why the pilot back-tests your own history and the table shows a range plus break-even.
- "Why would it be off by default?" We never block a customer's payment run on install; turning it on is one click.

## Be upfront about
- Odoo Online cannot install custom modules; those get the external `scanner/` only.
- Odoo 18 only; Odoo 19 port, Enterprise/Odoo.sh validation, multi-company scoping and a maintained CVE feed are open.
- Cycles 3-4 and the ROSI view are on local branches, not pushed. Licence enforcement for paid tiers is not implemented.
- Demo data is synthetic; 27,900 is the seeded scenario, not a customer. Insurance and audit-fee savings are not claimed.
