# Run via: odoo shell -d <db> < seed.py   (env provided). Weak creds + dummy data. LAB ONLY.
import os
P = os.environ.get("LAB_PROFILE", "a")
Users, Groups = env["res.users"], env["res.groups"]
g = lambda x: env.ref(x)
def mk(login, name, pw, groups):
    u = Users.search([("login", "=", login)]) or Users.with_context(no_reset_password=True).create(
        {"login": login, "name": name, "email": login + "@lab.test"})
    u.write({"password": pw, "groups_id": [(6, 0, [g(x).id for x in groups])]})
    return u
base = ["base.group_user"]
env.ref("base.user_admin").password = "admin" if P == "a" else "Winter2026!"
mk("sales", "Sally Sales", "sales" if P == "a" else "Welcome1", base + ["sales_team.group_sale_manager"])
mk("accountant", "Adam Accountant", "accountant" if P == "a" else "Welcome1", base + ["account.group_account_manager"])
mk("buyer", "Bob Buyer", "password" if P == "a" else "Welcome1", base + ["purchase.group_purchase_manager"])
# vuln: low-priv-looking user holding Settings (group_system)
mk("intern", "Ian Intern", "intern", base + ["base.group_system"])
# vuln: portal user with weak pw
mk("portal1", "Portia Portal", "portal1", ["base.group_portal"])
ICP = env["ir.config_parameter"].sudo()
if P == "a":
    ICP.set_param("auth_signup.invitation_scope", "b2c")      # open signup
    ICP.set_param("auth_signup.allow_uninvited", "True")
    ICP.set_param("web.base.url", "http://localhost:8081")
else:
    ICP.set_param("web.base.url", "http://localhost:8082")
# dummy data
Partner = env["res.partner"]
for i in range(1, 41):
    Partner.create({"name": f"Dummy Customer {i:02d}", "email": f"cust{i}@dummy.test",
                    "phone": f"+1-555-01{i:02d}", "street": f"{i} Test Street", "city": "Testville",
                    "comment": f"SSN-like fake: 000-00-{1000+i}  card: 4111 1111 1111 1111"})
for i in range(1, 11):
    Partner.create({"name": f"Dummy Vendor {i:02d}", "email": f"vendor{i}@dummy.test", "supplier_rank": 1})
prods = [env["product.product"].create({"name": f"Widget {i}", "list_price": 10 * i, "standard_price": 6 * i}) for i in range(1, 11)]
cust = Partner.search([("name", "like", "Dummy Customer")], limit=15)
for c in cust:
    so = env["sale.order"].create({"partner_id": c.id, "order_line": [(0, 0, {"product_id": p.id, "product_uom_qty": 2}) for p in prods[:3]]})
    so.action_confirm()
env.cr.commit()
print("SEED DONE", P)
