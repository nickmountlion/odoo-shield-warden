# Real-world assessment and Kaizen review (cycle 2, 2026-10-30)

**Goal:** attack our own tool with the most common and the most creative Odoo breach and fraud scenarios,
measure what Odoo Shield Warden catches, improve it, and say plainly where it still falls short.

**Result:** the attack lab went from **3/14 scenarios detected (v1) to 14/14 (v1.1)**. Ten new detections and
six bug fixes in our own logic came out of it. Six known gaps remain open (section 6).

---

## 1. Scope and ground rules

- All attacks ran against the **local lab instance only** (`lab/attack_lab.py` refuses any non-localhost URL),
  on synthetic data.
- Scenarios use **legitimate Odoo features** that an insider or someone holding stolen credentials can use:
  RPC calls, context flags, record rules, scheduled actions, exports. No software vulnerability was exploited,
  and no exploit code for published CVEs was written. CVEs are analysed from their advisories only.
- We first tried to build a fixture module with a *live* vulnerable endpoint (public route, SQL injection,
  `eval`). Our own safety review **blocked it, rightly**: a running exploitable endpoint isn't needed to
  test a static scanner. The scanner is tested against source snippets in unit tests instead, and the
  installable fixture (`lab/vulnerable_addons/lab_vuln_portal`) has **no routes**. It holds only an unsafe access rule and an
  unsanitized field, and must never be installed outside the lab.

## 2. Threat catalogue

### 2a. The common, repetitive ones (what actually hits Odoo customers)

| # | Scenario | Real-world basis | Odoo mechanics | Shield control(s) | Status |
|---|---|---|---|---|---|
| C1 | **Vendor bank-detail swap (BEC)** | Payments fraud hit 79% of organisations in 2024; business email compromise was the top route (AFP 2025) | Edit `res.partner.bank`, re-trust, pay | `ccm_bank_change_payment`, `ccm_self_trusted_bank`, `sod_redirect_and_pay` | Detected (v1) |
| C2 | **Exposed database manager** (download or drop every DB) | CVE-2026-25137 (CVSS 9.1): unauthenticated DB manager on NixOS Odoo; generic risk on every self-host | `/web/database/*`, `list_db`, weak `admin_passwd` | `dbmanager_exposed`, `master_password`, external scanner | Detected (v1) |
| C3 | **Default/weak admin credentials, no 2FA** | Most common finding in Odoo audits | `admin`/`admin`, optional TOTP | `admin_default_login`, `mfa_coverage`, `mfa_enforced` | Detected (v1) |
| C4 | **Password guessing through the API** | XML-RPC/JSON-RPC accept login attempts without a UI | `base.login_cooldown_after = 0` disables throttling | `login_throttling` | **New in v1.1** |
| C5 | **Over-privileged staff / admin creep** | Billing schemes are 20–38% of occupational fraud cases (ACFE, secondary sources) | Billing role can both bill and pay; admins accumulate | `sod_*`, `admin_count`, `privilege_drift` | Partly v1; drift **new** |
| C6 | **Duplicate / self-approved bills** | Classic AP fraud and error | Same bill entered twice; clerk pays own bill | `ccm_duplicate_bill`, `ccm_self_paid_bill` | Detected (v1, normalisation fixed) |
| C7 | **Insecure third-party modules** | Most Odoo vulns in the wild live in custom code (SQL strings, `sudo()` in public routes) | App Store / in-house modules | `custom_module_acl`, `custom_code_risks`, `third_party_modules` | Static scan **new** |
| C8 | **Departing employee exports the customer base** | Common insider data theft; Odoo keeps **no export log** | `export_data` from any list view | `mass_export` + export log | **New in v1.1** |
| C9 | **Unpatched Odoo** | CVE-2024-12368 (OAuth token takeover, 15.0), CVE-2024-36259 (mail info leak, 17.0) | Patch level within a major version | `version_support` (major only) | **Gap G2** |
| C10 | **Weak database credentials** | Docker defaults `odoo`/`odoo` are public knowledge | Direct PostgreSQL bypasses every Odoo rule | `db_credentials` | **New in v1.1** |

### 2b. The craziest (advanced, low-noise, anti-forensic)

| # | Scenario | Why it's nasty | Shield control(s) | Status |
|---|---|---|---|---|
| X1 | **Silent IBAN swap with `tracking_disable`**: the API caller switches off chatter tracking, swaps the IBAN, re-trusts and pays | Bank-account audit trail stays empty; v1 relied on it | `ccm_untracked_bank_change` (3 layers: owner-chatter vs bank-tracking mismatch, untracked `write_date`, Shield's own fingerprint) | **New; was MISSED in v1** |
| X2 | **Direct SQL rewrite of an IBAN** (stolen DB creds or a rogue module) | No ORM, no chatter, no `write_date` | Fingerprint layer of `ccm_untracked_bank_change` (next assessment) | **New** (detected at the next run, not prevented) |
| X3 | **Ghost beneficiary**: the vendor's "new" IBAN is the employee's own account, stored on a private contact | Payroll/refund diversion and fake vendors, hidden in plain sight | `ccm_shared_bank_account` (critical when one holder is staff-created) | **New** |
| X4 | **Backdoor scheduled action** (inactive until needed) with `sudo()` code touching bank data | Survives module reinstalls; never code-reviewed | `db_code_objects` (flags DB-stored code and dangerous tokens) | **New** |
| X5 | **Record rule that hides fraud from the auditor**: `create_uid != fraudster` for the read-only role | The controller literally cannot see the payments | `custom_record_rules` | **New** |
| X6 | **Quiet admin account** ("IT Support") with Settings rights | Odoo doesn't log group changes | `privilege_drift` (sealed baseline diff + recent privileged accounts) | **New** |
| X7 | **Server-side template injection** via a non-admin Mail Template Editor | Same bug class gave RCE in ERPNext (CVE-2026-38431) | `template_editors` | **New** |
| X8 | **Tampering with Shield's own history** (editing past results) | Destroys the evidence | SHA-256 chain, `action_verify_chain` (tested) | Detected (v1) |
| X9 | **Deleting chatter messages** to erase the trail | Admins can unlink `mail.message` | Fingerprint still catches the number change; deletion itself undetected | **Gap G4** |
| X10 | **Public attachments / portal token leakage** (invoices with `access_token`, `ir.attachment` with `public=True`) | Data leak without any login | none yet | **Gap G5** |

## 3. Lab results (Check)

`python lab/attack_lab.py` → `lab/results/coverage-*.json`

| Scenario | v1 (before) | v1.1 | Detected by |
|---|---|---|---|
| A1 Silent IBAN swap (tracking disabled) + payment | MISSED | DETECTED | `ccm_untracked_bank_change`, `ccm_bank_change_payment` |
| A1b Silent IBAN swap after a baseline (wave 2) | MISSED | DETECTED | `ccm_untracked_bank_change` |
| A2 Vendor IBAN = employee's own account | MISSED | DETECTED | `ccm_shared_bank_account` |
| A3 Backdoor scheduled action | MISSED | DETECTED | `db_code_objects` |
| A4 Record rule hiding fraud from auditors | MISSED | DETECTED | `custom_record_rules` |
| A5 New account with admin rights | MISSED | DETECTED | `privilege_drift` |
| A6 Brute-force protection disabled | MISSED | DETECTED | `login_throttling` |
| A7 Mass export of customer data | MISSED | DETECTED* | `mass_export` |
| A8 Template editor granted to non-admin | MISSED | DETECTED | `template_editors` |
| A9 Weak database credentials | MISSED | DETECTED | `db_credentials` |
| A10 Misconfigured third-party module | MISSED** | DETECTED | `custom_module_acl`, `custom_code_risks` |
| R1 Tracked IBAN swap + self-trust | DETECTED | DETECTED | finance rules |
| R2 Bill entered and paid by the same user | DETECTED | DETECTED | `ccm_self_paid_bill` |
| R3 Duplicate vendor bill | DETECTED | DETECTED | `ccm_duplicate_bill` |
| **Total** | **3/14** | **14/14** | |

\* Only exports made **after** Shield is installed: Odoo keeps no export history, so the first export (before
the log existed) is invisible. That is an inherent limit; recommend installing Shield at onboarding.
\** The control failed but only named the module in the evidence field; the detail text now names the models.

Money-at-risk in the final run: **$47,500**, exactly the sum of the fraudulent payments and bills in the lab
(18,400 + 9,800 + 9,800 + 4,750 + 4,750), after fixing K4 below. Evidence chain intact across 8 sealed assessments.
Test suite: **27 tests, all passing** (was 14).

## 4. Kaizen findings in our own tool (Act)

| # | Problem found | Root cause | Fix | Status |
|---|---|---|---|---|
| K1 | Silent IBAN swap invisible | Read only the bank account's tracking, which `tracking_disable` turns off | Read the owner-chatter copy too; flag mismatch; untracked `write_date`; own fingerprint | Fixed |
| K2 | A10 "missed" although the control failed | Offending models only in evidence | Detail names the models; lab scorer reads detail and evidence | Fixed |
| K3 | Worst events could be cut from the summary | Events listed in DB order, truncated to 3 | Rank by severity then amount; all events in evidence | Fixed |
| K4 | Money at risk inflated by a genuine old payment | Payments link to the bank *record*, not the number it held | Count only payments after the record got its current number (+test) | Fixed |
| K5 | `admin (by __system__)` flagged as new admin | Installer-created accounts counted as drift | Exclude accounts created by the superuser | Fixed |
| K6 | Same-second change and payment mis-ordered | Record dates use transaction start, chatter uses wall clock | 60 s tolerance in time comparisons | Fixed |
| K7 | Tests passed while tracking was off | Odoo's test base disables tracking globally | Tests re-enable it where it matters | Fixed |
| K8 | Exports before install are invisible | Odoo has no export history | Documented; onboarding advice | Inherent |
| K9 | **12 alerts for 5 incidents** | One fraudulent payment trips 2–3 rules | Group events into *cases* per payment/bank account | **Open (next)** |
| K10 | Patch-level CVEs not checked | Only major version compared | Ship a CVE-by-version feed | **Done (cve_feed, offline advisories.json, manual refresh)** |
| K11 | Shield's own logs deletable by an admin (sudo) | Logs live in the monitored DB | Periodic off-box export of seals (email/S3) so deletion shows | **Open** |
| K12 | SoD ignores record rules / multi-company | Only model-level ACLs evaluated | Evaluate `ir.rule` domains per user | Open (from cycle 1) |
| K13 | New checks have no one-click fix | Time | Add fixes for throttling, template editors, export rights | Open (quick win) |

## 5. Pain points we address that competitors don't

| Pain point (buyer's words) | What competitors offer | Our answer | Built? |
|---|---|---|---|
| "We don't know if fraud is *happening*, only who *could* do it" | Group-pair SoD reports (Pokutsoft, ~$80) | Rights read from real permissions, transaction rules, money at risk per event | Yes |
| "Fraudsters cover their tracks" | Nobody in the Odoo market | Anti-forensics: suppressed tracking, untracked writes, fingerprints, hidden record rules, DB-stored code | Yes (v1.1) |
| "Our auditor wants evidence, not screenshots" | Manual evidence upload (ISO 27001 Evidence) | Machine-generated, SHA-256-chained assessments; one-click chain verification | Yes |
| "Alerts get ignored" | Email alerts (FraudGuard) | Amount, actor, a second-person review with notes; you can't clear your own alert | Yes; **case grouping next (K9)** |
| "IT tools don't speak finance" | Free config checkers (Odevmo, Webkul) | CFO headline: "$47,500 at risk"; money issues rank first | Yes |
| "A leaver walked off with our customer list" | Audit-trail apps log edits, not exports | Export log on every model + bulk-export detection | Yes (from install) |
| "We can't review third-party modules" | AI code review that sends your code to an external LLM | Local static scan; no code leaves the server | Yes (pattern level) |
| "Admin rights creep and nobody notices" | Nothing; Odoo doesn't log group changes | Privilege drift against the sealed baseline | Yes |
| "One-off audits are expensive and stale" | Consultants ($8k per audit, Upwork), Octura tiers | Weekly automated, sealed history, plus our review service | Yes |
| "Finding is easy, fixing is hard" | Checkers don't fix | 4 one-click hardening fixes, logged in the chatter | Partly (K13) |
| "We're on Odoo Online and can't install apps" | Not served | External scanner in `scanner/` | Partly |

## 6. Open gaps and planned solutions (next cycle, by value/effort)

> **Update (cycle 3):** items 1, 2, 3, 4, 5, 6 and 8 and K13 are done. See [KAIZEN_CYCLE_3.md](KAIZEN_CYCLE_3.md).

1. **Case grouping (K9).** Collapse events that share a payment or bank account into one case with all
   matched rules as reasons. *Impact: high (alert fatigue); effort: S.*
2. **Payment hold.** Block posting payments to bank accounts changed in the last N days, or flagged by
   `ccm_untracked_bank_change`, until a second person approves. Moves us from detection to prevention.
   *Impact: very high; effort: M.*
3. **CVE feed by version (K10).** Map `release.version` to published Odoo advisories (e.g. CVE-2024-12368,
   CVE-2024-36259). *Impact: high; effort: M (needs a maintained data file).*
4. **Off-box seal export (K11).** Push each assessment's hash to an external store (email or S3), so a
   deleted or rewritten history is provable. *Impact: high for audits; effort: S.*
5. **Public data exposure (G5).** Flag `ir.attachment` with `public=True` on sensitive models and documents
   whose portal `access_token` links are shared widely. *Effort: S.*
6. **Chatter deletion (G4).** Count `mail.message` deletions on financial records (override `unlink` to log).
   *Effort: S.*
7. **Record-rule-aware SoD (K12)** and **one-click fixes for the new checks (K13).**
8. **Lookalike vendors.** Detect near-duplicate vendor names ("N0rthwind") and vendors created and paid within
   7 days by the same user. *Effort: S.*

## 7. How to reproduce

```bash
python tools/seed_fraud_demo.py              # baseline fraud data (R1–R3)
python lab/attack_lab.py --wave 1 --label v1 # attacks A1–A10 + coverage
python lab/attack_lab.py --wave 2 --label v2 # time-sensitive replays after a baseline
python lab/attack_lab.py --score-only --label check
```

## Sources

- CVE-2026-25137, Odoo database manager exposure on NixOS: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-25137) · [CCB Belgium advisory](https://ccb.belgium.be/advisories/warning-critical-unauthenticated-database-manager-exposure-odoo-nixos-patch-immediately) · [NixOS advisory](https://discourse.nixos.org/t/security-advisory-database-and-filestore-publicly-accessible-with-default-odoo-configuration-cve-2026-25137/74894)
- CVE-2024-12368 / CVE-2024-36259, Odoo access-control issues: [CCB Belgium advisory](https://ccb.belgium.be/advisories/warning-two-high-improper-access-control-vulnerabilities-odoo-community-enterprise-patch) · [cvefeed CVE-2024-36259](https://cvefeed.io/vuln/detail/CVE-2024-36259)
- Server-side template injection in comparable ERPs: [CVE-2026-38431 (ERPNext)](https://www.sentinelone.com/vulnerability-database/cve-2026-38431/) · [PortSwigger SSTI](https://portswigger.net/web-security/server-side-template-injection)
- Payments fraud and business email compromise: [AFP Payments Fraud survey](https://financialprofessionals.org/training-resources/resources/survey-research-economic-data/details/payments-fraud) · [U.S. Bank summary of the 2026 survey](https://www.usbank.com/corporate-and-commercial-banking/insights/risk/mitigation/battling-payments-fraud.html)
- Occupational fraud and billing schemes (secondary summaries of ACFE data): [NYSSCPA on the 2024 report](https://nysscpa.org/news/1052118-report-worldwide-organizations-lose-billions-to-fraud-2024-03-21) · [Weaver on manufacturing](https://www.weaver.com/blog/spotlight-fraud-manufacturing-industry)
- Odoo pentest tooling: [OdooMap](https://korben.info/en/odoomap-pentest-tool-odoo-security.html)
