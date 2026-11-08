import http.cookiejar, json, sys, urllib.request, xmlrpc.client
url, db = "http://localhost:8069", "odoo-shield-warden"
jar = http.cookiejar.CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
body = json.dumps({"jsonrpc": "2.0", "params": {"db": db, "login": "admin", "password": "admin"}}).encode()
op.open(urllib.request.Request(f"{url}/web/session/authenticate", body, {"Content-Type": "application/json"}))
uid = xmlrpc.client.ServerProxy(f"{url}/xmlrpc/2/common").authenticate(db, "admin", "admin", {})
ids = xmlrpc.client.ServerProxy(f"{url}/xmlrpc/2/object").execute_kw(db, uid, "admin", "shield.assessment", "search", [[]], {"limit": 1})
pdf = op.open(f"{url}/report/pdf/odoo_shield_warden.report_scorecard/{ids[0]}", timeout=120).read()
open(sys.argv[1], "wb").write(pdf)
print(len(pdf), "bytes, starts with", pdf[:5])
