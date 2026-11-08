"""Odoo Shield Warden attack lab: replay real-world Odoo breach and fraud scenarios against the LOCAL lab
instance, then measure which ones Odoo Shield Warden detects.

Every scenario uses only normal Odoo API calls that an insider or someone holding stolen credentials
could make. Nothing here exploits a software vulnerability. The script refuses to run against
anything but localhost.

    python lab/attack_lab.py --wave 1 --label v1     # perform attacks, assess, score coverage
    python lab/attack_lab.py --score-only --label v2 # re-assess and score (after improving Shield)
    python lab/attack_lab.py --wave 2 --label v2     # repeat time-sensitive attacks after a baseline
"""

import argparse
import json
import os
import subprocess
import sys
import xmlrpc.client
from pathlib import Path
from urllib.parse import urlparse

URL, DB = os.environ.get("ODOO_SHIELD_WARDEN_URL", "http://localhost:8069"), os.environ.get("ODOO_SHIELD_WARDEN_DB", "odoo-shield-warden")
COMPOSE_DIR = os.environ.get("ODOO_COMPOSE_DIR", "~/odoo")  # stack that holds the lab database
ATTACKER_IBAN = "GB29NWBK60161331926819"     # the IBAN Ana swapped into Acme's account (seed_fraud_demo.py)
ATTACKER_IBAN_2 = "DE44500105175407324931"
RESULTS = Path(__file__).parent / "results"

if urlparse(URL).hostname not in ("localhost", "127.0.0.1"):
    sys.exit("The attack lab only runs against a local lab instance.")

common = xmlrpc.client.ServerProxy(f"{URL}/xmlrpc/2/common")
models = xmlrpc.client.ServerProxy(f"{URL}/xmlrpc/2/object", allow_none=True)


def session(login, password):
    uid = common.authenticate(DB, login, password, {})
    if not uid:
        sys.exit(f"Login failed for {login}; run tools/seed_fraud_demo.py first.")

    def call(model, method, *args, **kw):
        try:
            return models.execute_kw(DB, uid, password, model, method, list(args), kw)
        except xmlrpc.client.Fault as e:
            if "cannot marshal None" in e.faultString:  # method returned None after committing
                return None
            raise
    call.uid = uid
    return call


def sql(statement):
    subprocess.run(["wsl.exe", "-d", "Ubuntu", "--", "bash", "-lc",
                    f'cd {COMPOSE_DIR} && docker compose exec -T db psql -U odoo -d {DB} -c "{statement}" < /dev/null'],
                   check=True, capture_output=True)


admin = session("admin", "admin")
GROUPS_FIELD = "group_ids" if admin("ir.model.fields", "search_count", [("model", "=", "res.users"), ("name", "=", "group_ids")]) else "groups_id"  # renamed in Odoo 19
ana = session("ana.ap", "demo-Passw0rd!")


def xmlid(full):
    module, name = full.split(".")
    rec = admin("ir.model.data", "search_read", [("module", "=", module), ("name", "=", name)], fields=["res_id"])
    return rec[0]["res_id"]


def model_id(model):
    return admin("ir.model", "search", [("model", "=", model)])[0]


def find_or_create(model, domain, vals, who=admin):
    found = who(model, "search", domain, limit=1)
    return found[0] if found else who(model, "create", vals)


def pay(who, partner, amount, bank):
    journal = admin("account.journal", "search", [("type", "=", "bank")], limit=1)[0]
    payment = who("account.payment", "create", {"payment_type": "outbound", "partner_type": "supplier",
                                                 "partner_id": partner, "amount": amount, "journal_id": journal,
                                                 "partner_bank_id": bank})
    who("account.payment", "action_post", [payment])
    return payment


# -- scenarios ------------------------------------------------------------------------------------
# Each returns a short description of what was done. EXPECTATIONS maps it to (control code, needle in detail).

def a1_silent_iban_swap(suffix=""):
    """BEC with anti-forensics: swap a vendor IBAN through the API with tracking switched off, then pay."""
    vendor_name = "Globex Freight" if suffix else "Northwind Logistics"
    vendor = find_or_create("res.partner", [("name", "=", vendor_name)],
                            {"name": vendor_name, "supplier_rank": 1, "is_company": True})
    genuine = "BE71096123456769" if suffix else "NL91ABNA0417164300"
    bank = find_or_create("res.partner.bank", [("partner_id", "=", vendor), ("acc_number", "in", [genuine, ATTACKER_IBAN_2])],
                          {"partner_id": vendor, "acc_number": genuine, "allow_out_payment": True})
    sql(f"UPDATE res_partner_bank SET create_date = now() - interval '300 days', "
        f"write_date = now() - interval '300 days' WHERE id = {bank}")
    quiet = {"tracking_disable": True, "mail_notrack": True}
    ana("res.partner.bank", "write", [bank], {"allow_out_payment": False, "acc_number": ATTACKER_IBAN_2}, context=quiet)
    ana("res.partner.bank", "write", [bank], {"allow_out_payment": True}, context=quiet)
    pay(ana, vendor, 9800, bank)
    return f"ana.ap swapped {vendor_name}'s IBAN to {ATTACKER_IBAN_2} with tracking disabled and paid 9,800"


def a2_shared_bank_account():
    """Ghost beneficiary: the 'vendor' IBAN is also the employee's own account."""
    me = find_or_create("res.partner", [("name", "=", "Ana Pereira (private)")],
                        {"name": "Ana Pereira (private)", "type": "contact"}, who=ana)
    find_or_create("res.partner.bank", [("partner_id", "=", me), ("acc_number", "=", ATTACKER_IBAN)],
                   {"partner_id": me, "acc_number": ATTACKER_IBAN}, who=ana)
    return f"Ana's private contact holds {ATTACKER_IBAN}, the same IBAN now on Acme's vendor record"


def a3_backdoor_scheduled_action():
    """Persistence: a code-based scheduled action created in the database (inactive, harmless body)."""
    find_or_create("ir.cron", [("cron_name", "=", "System cleanup")], {
        "name": "System cleanup", "model_id": model_id("res.partner.bank"), "state": "code",
        "code": "# LAB: simulated backdoor body; a real one would rewrite IBANs before each payment run\n"
                "records = env['res.partner.bank'].sudo().search([])",
        "interval_number": 1, "interval_type": "days", "active": False})
    return "Inactive scheduled action 'System cleanup' with sudo() code created via the UI/API"


def a4_hiding_record_rule():
    """Anti-forensics: a record rule that hides Ana's payments from the read-only auditor role."""
    find_or_create("ir.rule", [("name", "=", "Payment visibility")], {
        "name": "Payment visibility", "model_id": model_id("account.payment"),
        "groups": [(6, 0, [xmlid("account.group_account_readonly")])],
        "domain_force": f"[('create_uid', '!=', {ana.uid})]",
        "perm_read": True, "perm_write": False, "perm_create": False, "perm_unlink": False})
    return "Record rule 'Payment visibility' hides ana.ap's payments from Accounting/Read-only users"


def a5_privilege_escalation(suffix=""):
    """A new account quietly granted Settings/Administration."""
    login = f"it.support{suffix}"
    find_or_create("res.users", [("login", "=", login)], {
        "login": login, "name": f"IT Support{suffix}", "password": "demo-Passw0rd!",
        GROUPS_FIELD: [(6, 0, [xmlid("base.group_user"), xmlid("base.group_system")])]})
    return f"New user {login} created with Settings rights"


def a6_disable_brute_force_protection():
    admin("ir.config_parameter", "set_param", "base.login_cooldown_after", "0")
    return "Login cooldown disabled (base.login_cooldown_after = 0): unlimited password guessing"


def a7_mass_export():
    """Insider exfiltration: export the whole customer base."""
    existing = admin("res.partner", "search_count", [("name", "=like", "Customer %")])
    if existing < 600:
        admin("res.partner", "create", [{"name": f"Customer {i:04d}", "email": f"c{i}@example.com",
                                         "phone": f"+1 555 {i:04d}"} for i in range(existing, 600)])
    admin("res.users", "write", [ana.uid], {GROUPS_FIELD: [(4, xmlid("base.group_allow_export"))]})
    ids = ana("res.partner", "search", [("name", "=like", "Customer %")])
    ana("res.partner", "export_data", ids, ["name", "email", "phone"])
    return f"ana.ap exported {len(ids)} customer records (name, email, phone)"


def a8_template_editor():
    admin("res.users", "write", [ana.uid], {GROUPS_FIELD: [(4, xmlid("mail.group_mail_template_editor"))]})
    return "ana.ap granted Mail Template Editor (can write dynamic template expressions)"


def a10_misconfigured_module():
    subprocess.run(["wsl.exe", "-d", "Ubuntu", "--", "bash", "-lc",
                    "mkdir -p ~/odoo/addons && cp -r ./lab/vulnerable_addons/lab_vuln_portal ~/odoo/addons/"],
                   check=True, capture_output=True)
    admin("ir.module.module", "update_list")
    mod = admin("ir.module.module", "search_read", [("name", "=", "lab_vuln_portal")], fields=["state"])[0]
    if mod["state"] != "installed":
        try:
            admin("ir.module.module", "button_immediate_install", [mod["id"]])
        except xmlrpc.client.Fault as e:
            if "cannot marshal" not in e.faultString and "reload" not in e.faultString.lower():
                raise
    return "Third-party module installed whose access rule gives every user write/delete"


def a11_lookalike_vendor():
    """Fake vendor imitating a real one, created with its own bank account and paid at once."""
    fake = find_or_create("res.partner", [("name", "=", "N0rthwind Logistics Ltd")],
                          {"name": "N0rthwind Logistics Ltd", "supplier_rank": 1, "is_company": True}, who=ana)
    bank = find_or_create("res.partner.bank", [("partner_id", "=", fake)],
                          {"partner_id": fake, "acc_number": "DE89370400440532013000", "allow_out_payment": True}, who=ana)
    pay(ana, fake, 7300, bank)
    return "ana.ap created 'N0rthwind Logistics Ltd' with a bank account and paid it 7,300 the same day"


def a12_erase_audit_trail():
    """Cover-up: change a vendor IBAN normally, then delete the chatter messages that recorded it."""
    vendor = find_or_create("res.partner", [("name", "=", "Initech Supplies")],
                            {"name": "Initech Supplies", "supplier_rank": 1, "is_company": True})
    bank = find_or_create("res.partner.bank", [("partner_id", "=", vendor)],
                          {"partner_id": vendor, "acc_number": "FR7630006000011234567890189", "allow_out_payment": True})
    ana("res.partner.bank", "write", [bank], {"allow_out_payment": False, "acc_number": "IT60X0542811101000000123456"})
    msgs = admin("mail.message", "search", [("model", "=", "res.partner"), ("res_id", "=", vendor),
                                            ("body", "ilike", "Bank Account")])
    admin("mail.message", "unlink", msgs)
    return f"Initech's IBAN changed, then {len(msgs)} chatter message(s) recording it deleted by admin"


def a13_public_invoice():
    """Data leak: a vendor bill's PDF made public, downloadable without login."""
    bill = admin("account.move", "search", [("move_type", "=", "in_invoice")], limit=1)[0]
    find_or_create("ir.attachment", [("name", "=", "invoice_scan.pdf")], {
        "name": "invoice_scan.pdf", "res_model": "account.move", "res_id": bill, "public": True,
        "datas": "JVBERi0xLjQK"})
    return "A vendor bill's PDF attachment marked public"


PREVENTION = {}


def a14_payment_hold():
    """Prevention: with the payment hold on, the IBAN-swap-and-pay attack must be stopped."""
    control = admin("shield.control", "search", [("code", "=", "payment_hold")])[0]
    finding = admin("shield.finding", "search", [("control_id", "=", control)])
    if finding:
        admin("shield.finding", "action_apply_fix", finding)  # the one-click fix, as a customer would apply it
    else:
        admin("ir.config_parameter", "set_param", "shield.payment_hold", "enforce")
    acme = admin("res.partner", "search", [("name", "=", "Acme Industrial Supplies")])[0]
    bank = admin("res.partner.bank", "search", [("partner_id", "=", acme)], limit=1)[0]
    ana("res.partner.bank", "write", [bank], {"allow_out_payment": False, "acc_number": "ES9121000418450200051332"})
    ana("res.partner.bank", "write", [bank], {"allow_out_payment": True})
    try:
        pay(ana, acme, 25000, bank)
        PREVENTION["Payment to swapped IBAN blocked"] = False
    except xmlrpc.client.Fault as e:
        PREVENTION["Payment to swapped IBAN blocked"] = "held by Odoo Shield Warden" in e.faultString
    try:
        ana("res.partner.bank", "action_shield_verify", [bank])
        PREVENTION["Fraudster cannot verify own change"] = False
    except xmlrpc.client.Fault as e:
        PREVENTION["Fraudster cannot verify own change"] = "second person" in e.faultString
    return "Payment hold enabled via one-click fix; ana.ap swapped Acme's IBAN again and tried to pay 25,000"


def a16_brute_force_takeover():
    """Password guessing through the XML-RPC API until the right password is found."""
    for i in range(15):
        common.authenticate(DB, "carlos.controller", f"Winter2026!{i}", {})
    ok = common.authenticate(DB, "carlos.controller", "demo-Passw0rd!", {})
    return f"15 wrong passwords for carlos.controller over XML-RPC, then a successful login (uid {ok})"


def a17_password_spraying():
    """One common password tried against many accounts from one address."""
    for login in ("admin", "ana.ap", "it.support", "accounting", "finance", "ceo"):
        common.authenticate(DB, login, "Welcome2026!", {})
    return "Password 'Welcome2026!' sprayed across 6 accounts from one IP"


def a18_sabotage_shield():
    """Insider switches the monitor off piece by piece: payment hold, a control, the weekly schedule."""
    admin("ir.config_parameter", "set_param", "shield.payment_hold", "off")
    dormant = admin("shield.control", "search", [("code", "=", "dormant_users")])
    admin("shield.control", "write", dormant, {"active": False})
    cron = xmlid("odoo_shield_warden.cron_weekly_assessment")
    admin("ir.cron", "write", [cron], {"active": False})
    return "Payment hold switched off, a control archived and the weekly assessment disabled"


def a19_unpatched_build_advisory():
    """A newly published advisory for the running series arrives offline; the build predates its fix."""
    serie = common.version()["server_serie"]
    entry = [{"id": "LAB-ADVISORY-1", "series": [serie], "module": "base", "published": "2026-01-01",
              "fixed_build": "2999-01-01", "severity": "high", "summary": "Synthetic lab advisory, not a real CVE.",
              "url": "https://example.invalid/lab-advisory"}]
    admin("ir.config_parameter", "set_param", "shield.advisory_extra", json.dumps(entry))
    return f"Offline advisory LAB-ADVISORY-1 added for series {serie}; the running build predates its fix"


WAVE1 = [a1_silent_iban_swap, a2_shared_bank_account, a3_backdoor_scheduled_action, a4_hiding_record_rule,
         a5_privilege_escalation, a6_disable_brute_force_protection, a7_mass_export, a8_template_editor,
         a10_misconfigured_module]
# Time-sensitive replays: detections that need a baseline, or logging that only exists from install onwards.
WAVE2 = [lambda: a1_silent_iban_swap("_2"), lambda: a5_privilege_escalation("2"), a7_mass_export]
WAVE3 = [a11_lookalike_vendor, a12_erase_audit_trail, a13_public_invoice, a14_payment_hold]
WAVE4 = [a16_brute_force_takeover, a17_password_spraying, a18_sabotage_shield, a19_unpatched_build_advisory]

EXPECTATIONS = {
    "A1 Silent IBAN swap (tracking disabled) + payment": [("ccm_untracked_bank_change", "Northwind"),
                                                          ("ccm_bank_change_payment", "Northwind")],
    "A1b Silent IBAN swap after baseline (wave 2)": [("ccm_untracked_bank_change", "Globex")],
    "A2 Vendor IBAN = employee's own account": [("ccm_shared_bank_account", ATTACKER_IBAN)],
    "A3 Backdoor scheduled action (code in DB)": [("db_code_objects", "System cleanup")],
    "A4 Record rule hiding fraud from auditors": [("custom_record_rules", "Payment visibility")],
    "A5 New account with admin rights": [("privilege_drift", "it.support")],
    "A6 Brute-force protection disabled": [("login_throttling", "")],
    "A7 Mass export of customer data": [("mass_export", "ana.ap")],
    "A8 Template editor granted to non-admin": [("template_editors", "ana.ap")],
    "A9 Weak database credentials": [("db_credentials", "")],
    "A10 Misconfigured third-party module": [("custom_module_acl", "lab.portal.note")],
    "A11 Lookalike vendor paid the same day": [("ccm_lookalike_vendor", "N0rthwind"),
                                               ("ccm_new_vendor_fast_payment", "N0rthwind")],
    "A12 Audit trail erased (chatter deleted)": [("message_deletions", "Bank Account")],
    "A13 Invoice PDF made public": [("public_attachments", "invoice_scan.pdf")],
    "A15 Seals only stored inside Odoo": [("seal_offbox", "")],
    "A16 Brute force ending in account takeover": [("login_attacks", "account takeover")],
    "A17 Password spraying": [("login_attacks", "spraying")],
    "A18 Insider disables Shield": [("shield_integrity", "switched off")],
    "A19 Build predates a published advisory fix (offline feed)": [("cve_feed", "LAB-ADVISORY-1")],
    "R1 Tracked IBAN swap + self-trust (seeded)": [("ccm_bank_change_payment", "Acme"),
                                                   ("ccm_self_trusted_bank", "Acme")],
    "R2 Bill entered and paid by same user (seeded)": [("ccm_self_paid_bill", "BILL/")],
    "R3 Duplicate vendor bill (seeded)": [("ccm_duplicate_bill", "duplicates")],
}


def assess_and_score(label):
    action = admin("shield.assessment", "action_run_assessment")
    aid = action["res_id"]
    head = admin("shield.assessment", "read", [aid], fields=["security_score", "grc_score", "grade",
                                                             "case_count", "risk_event_count", "transaction_exposure"])[0]
    results = admin("shield.assessment.result", "search_read", [("assessment_id", "=", aid)],
                    fields=["control_id", "status", "detail", "evidence"])
    codes = {c["id"]: c["code"] for c in admin("shield.control", "search_read", [], fields=["code"])}
    by_code = {codes[r["control_id"][0]]: r for r in results}
    rows = []
    for scenario, expects in EXPECTATIONS.items():
        hits = []
        for code, needle in expects:
            r = by_code.get(code)
            text = f"{r['detail'] or ''}\n{r['evidence'] or ''}".lower() if r else ""
            ok = bool(r and r["status"] in ("fail", "warn") and needle.lower() in text)
            hits.append({"control": code, "exists": bool(r), "detected": ok,
                         "status": r["status"] if r else "no control"})
        rows.append({"scenario": scenario, "detected": any(h["detected"] for h in hits), "checks": hits})
    detected = sum(r["detected"] for r in rows)
    summary = {"label": label, "assessment_id": aid, "security_score": head["security_score"],
               "grc_score": head["grc_score"], "detected": detected, "total": len(rows), "scenarios": rows,
               "cases": head["case_count"], "alerts": head["risk_event_count"],
               "money_at_risk": head["transaction_exposure"], "prevention": PREVENTION}
    RESULTS.mkdir(exist_ok=True)
    (RESULTS / f"coverage-{label}.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"\nCoverage {label}: {detected}/{len(rows)} scenarios detected "
          f"(security {head['security_score']}, GRC {head['grc_score']}%)")
    print(f"  money at risk {head['transaction_exposure']:,.2f} in {head['case_count']} case(s) "
          f"from {head['risk_event_count']} alert(s)")
    for name, ok in PREVENTION.items():
        print(f"  {'PREVENTED' if ok else 'NOT PREVENTED'} {name}")
    for r in rows:
        mark = "DETECTED" if r["detected"] else "MISSED  "
        print(f"  {mark} {r['scenario']:<52} " + ", ".join(f"{h['control']}={h['status']}" for h in r["checks"]))
    return summary


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--wave", type=int, choices=(1, 2, 3, 4))
    p.add_argument("--score-only", action="store_true")
    p.add_argument("--label", required=True)
    args = p.parse_args()
    if not args.score_only and args.wave:
        for attack in {1: WAVE1, 2: WAVE2, 3: WAVE3, 4: WAVE4}[args.wave]:
            name = getattr(attack, "__name__", "attack")
            try:
                print("attack:", attack())
            except xmlrpc.client.Fault as e:
                # Once the payment hold is on (e.g. on a re-run), an attack's payment is refused: that's a win.
                if "held by Odoo Shield Warden" not in e.faultString:
                    raise
                PREVENTION[f"{name}: payment blocked by the payment hold"] = True
                print(f"attack: {name} -> PREVENTED: {e.faultString.splitlines()[0]}")
    assess_and_score(args.label)


if __name__ == "__main__":
    main()
