"""Seed a realistic vendor-fraud scenario into the local odoo-shield-warden test database, then run an assessment.

Story: Ana (accounts payable) can edit vendor bank accounts, trust them and pay. She swaps Acme's IBAN
for her own, re-trusts it and pays. She also enters and pays a Northwind bill, then enters it again.
Only for the local test instance.
"""

import os
import subprocess
import xmlrpc.client

URL, DB = os.environ.get("ODOO_SHIELD_WARDEN_URL", "http://localhost:8069"), os.environ.get("ODOO_SHIELD_WARDEN_DB", "odoo-shield-warden")
COMPOSE_DIR = os.environ.get("ODOO_COMPOSE_DIR", "~/odoo")  # stack that holds the lab database
common = xmlrpc.client.ServerProxy(f"{URL}/xmlrpc/2/common")
models = xmlrpc.client.ServerProxy(f"{URL}/xmlrpc/2/object", allow_none=True)


def session(login, password):
    uid = common.authenticate(DB, login, password, {})
    assert uid, f"login failed for {login}"

    def call(model, method, *a, **k):
        try:
            return models.execute_kw(DB, uid, password, model, method, list(a), k)
        except xmlrpc.client.Fault as e:
            # Methods returning None (e.g. action_post) succeed but cannot be marshalled back.
            if "cannot marshal None" in e.faultString:
                return None
            raise
    return call


def sql(statement):
    subprocess.run(["wsl.exe", "-d", "Ubuntu", "--", "bash", "-lc",
                    f'cd {COMPOSE_DIR} && docker compose exec -T db psql -U odoo -d {DB} -c "{statement}"'],
                   check=True, capture_output=True)


admin = session("admin", "admin")
GROUPS_FIELD = "group_ids" if admin("ir.model.fields", "search_count", [("model", "=", "res.users"), ("name", "=", "group_ids")]) else "groups_id"  # renamed in Odoo 19
ref = lambda xmlid: admin("ir.model.data", "search_read", [("module", "=", xmlid.split(".")[0]),
                                                            ("name", "=", xmlid.split(".")[1])],
                          fields=["res_id"])[0]["res_id"]


def user(login, name, groups):
    found = admin("res.users", "search", [("login", "=", login)])
    if found:
        return found[0]
    return admin("res.users", "create", {"login": login, "name": name, "password": "demo-Passw0rd!",
                                          GROUPS_FIELD: [(6, 0, [ref(g) for g in groups])]})


user("ana.ap", "Ana Pereira (Accounts Payable)",
     ["base.group_user", "base.group_partner_manager", "account.group_account_invoice",
      "account.group_validate_bank_account"])
user("carlos.controller", "Carlos Ruiz (Controller)",
     ["base.group_user", "account.group_account_readonly", "odoo_shield_warden.group_shield_manager"])
ana = session("ana.ap", "demo-Passw0rd!")

bank_journal = admin("account.journal", "search", [("type", "=", "bank")], limit=1)[0]
def vendor(name):
    found = admin("res.partner", "search", [("name", "=", name)], limit=1)
    return found[0] if found else admin("res.partner", "create", {"name": name, "supplier_rank": 1, "is_company": True})


acme, northwind = vendor("Acme Industrial Supplies"), vendor("Northwind Logistics")

# Months ago: admin sets up Acme's genuine account and pays it once (legitimate history).
found = admin("res.partner.bank", "search", [("partner_id", "=", acme)], limit=1)
bank = found[0] if found else admin("res.partner.bank", "create", {
    "partner_id": acme, "acc_number": "BE68539007547034", "allow_out_payment": True})
found = admin("account.payment", "search", [("partner_id", "=", acme), ("amount", "=", 3200)], limit=1)
old_pay = found[0] if found else admin("account.payment", "create", {
    "payment_type": "outbound", "partner_type": "supplier", "partner_id": acme, "amount": 3200,
    "journal_id": bank_journal, "partner_bank_id": bank})
admin("account.payment", "action_post", [old_pay])
sql(f"UPDATE res_partner_bank SET create_date = now() - interval '200 days' WHERE id = {bank}")
sql(f"UPDATE account_payment SET create_date = now() - interval '150 days' WHERE id = {old_pay}")
sql(f"UPDATE account_move SET date = current_date - 150 WHERE id = (SELECT move_id FROM account_payment WHERE id = {old_pay})")

# Today: Ana un-trusts the account, swaps the IBAN, re-trusts it and pays 18,400.
ana("res.partner.bank", "write", [bank], {"allow_out_payment": False, "acc_number": "GB29NWBK60161331926819"})
ana("res.partner.bank", "write", [bank], {"allow_out_payment": True})
pay = ana("account.payment", "create", {"payment_type": "outbound", "partner_type": "supplier", "partner_id": acme,
                                         "amount": 18400, "journal_id": bank_journal, "partner_bank_id": bank})
ana("account.payment", "action_post", [pay])

# Ana enters a Northwind bill, pays it herself, then enters the same bill again.
def bill(ref_):
    move = ana("account.move", "create", {"move_type": "in_invoice", "partner_id": northwind, "ref": ref_,
                                           "invoice_date": "2026-10-28",
                                           "invoice_line_ids": [(0, 0, {"name": "Freight October", "quantity": 1,
                                                                        "price_unit": 4750, "tax_ids": [(6, 0, [])]})]})
    ana("account.move", "action_post", [move])
    return move


first = bill("NW-2291")
wizard = ana("account.payment.register", "create", {"journal_id": bank_journal},
             context={"active_model": "account.move", "active_ids": [first]})
ana("account.payment.register", "action_create_payments", [wizard],
    context={"active_model": "account.move", "active_ids": [first]})
bill("NW 2291")

tracked = admin("mail.tracking.value", "search_count", [("mail_message_id.model", "=", "res.partner.bank"),
                                                        ("mail_message_id.res_id", "=", bank)])
print(f"Seeded. Tracking values recorded on the bank account: {tracked}")
