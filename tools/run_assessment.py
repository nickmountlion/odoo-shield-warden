import sys, xmlrpc.client
url, db, user, pw = "http://localhost:8069", "odoo-shield-warden", "admin", "admin"
uid = xmlrpc.client.ServerProxy(f"{url}/xmlrpc/2/common").authenticate(db, user, pw, {})
m = xmlrpc.client.ServerProxy(f"{url}/xmlrpc/2/object", allow_none=True)
x = lambda model, method, *a, **k: m.execute_kw(db, uid, pw, model, method, list(a), k)
action = x("shield.assessment", "action_run_assessment")
a = x("shield.assessment", "read", [action["res_id"]], fields=["name", "grade", "security_score", "grc_score", "critical_count", "fail_count", "warn_count", "pass_count", "na_count", "error_count", "framework_score_ids"])[0]
print(f"{a['name']}: grade {a['grade']}, security {a['security_score']}/100, GRC {a['grc_score']}%  "
      f"(fail {a['fail_count']}, warn {a['warn_count']}, pass {a['pass_count']}, n/a {a['na_count']}, error {a['error_count']}, critical {a['critical_count']})")
for f in x("shield.framework.score", "read", a["framework_score_ids"], fields=["framework_id", "satisfied", "applicable", "percent"]):
    print(f"  {f['framework_id'][1]:<34} {f['satisfied']}/{f['applicable']}  {f['percent']}%")
res = x("shield.assessment.result", "search_read", [("assessment_id", "=", a["id"])], fields=["status", "severity", "name", "detail"])
for r in res:
    print(f"  [{r['status']:>5}] {r['severity']:<8} {r['name']}: {r['detail'][:110]}")

# Money at risk (only when the finance pack is installed)
if x("ir.module.module", "search_count", [("name", "=", "odoo_shield_warden_finance"), ("state", "=", "installed")]):
    money = x("shield.assessment", "read", [a["id"]], fields=["transaction_exposure", "access_exposure", "risk_event_count", "content_hash"])[0]
    print(f"\nMONEY AT RISK: {money['transaction_exposure']:,.2f}  |  paid by users with toxic rights: {money['access_exposure']:,.2f}  |  events: {money['risk_event_count']}")
    for e in x("shield.risk.event", "search_read", [("state", "in", ("open", "escalated"))], fields=["severity", "rule", "amount", "detail"]):
        print(f"  [{e['severity']:>8}] {e['amount']:>10,.2f}  {e['detail']}")
    for c in x("shield.access.conflict", "search_read", [("assessment_id", "=", a["id"])], fields=["user_id", "combo", "payment_count", "exposure"]):
        print(f"  conflict: {c['user_id'][1]:<34} {c['combo']:<17} {c['payment_count']} payments, {c['exposure']:,.2f}")
    print(f"  seal: {money['content_hash']}")
