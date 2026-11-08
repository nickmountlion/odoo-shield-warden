"""Odoo Shield - baseline audit (read-only).

Runs external HTTP checks plus read-only XML-RPC checks against one Odoo
instance, writes findings to JSON and renders a one-page HTML scorecard.
Only run it against instances you are authorized to assess.

Usage:
    python shield_audit.py --url http://localhost:8069 --db odoo-shield-warden \
        --user admin --password admin --out report
"""

import argparse
import datetime as dt
import html
import json
import ssl
import urllib.error
import urllib.request
import xmlrpc.client
from pathlib import Path

SEVERITY_WEIGHT = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}
DORMANT_DAYS = 90
MAX_ADMINS = 2


class Audit:
    def __init__(self, url, db, user, password, timeout=15):
        self.url = url.rstrip("/")
        self.db = db
        self.user = user
        self.password = password
        self.timeout = timeout
        self.findings = []
        self.facts = {}
        self.uid = None
        self.models = None

    # -- helpers -----------------------------------------------------------

    def add(self, check_id, severity, title, detail, fix, category):
        self.findings.append({
            "id": check_id, "severity": severity, "category": category,
            "title": title, "detail": detail, "fix": fix,
        })

    def http(self, path, data=None, headers=None):
        req = urllib.request.Request(self.url + path, data=data, headers=headers or {})
        ctx = ssl.create_default_context()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                return resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read()

    def jsonrpc(self, path, params=None):
        body = json.dumps({"jsonrpc": "2.0", "method": "call", "params": params or {}}).encode()
        status, _, raw = self.http(path, body, {"Content-Type": "application/json"})
        try:
            return status, json.loads(raw)
        except ValueError:
            return status, None

    def call(self, model, method, *args, **kw):
        return self.models.execute_kw(self.db, self.uid, self.password, model, method, list(args), kw)

    def safe(self, fn, label):
        try:
            fn()
        except Exception as e:  # one failing check must not stop the audit
            self.add(f"error.{label}", "info", f"Check '{label}' could not run",
                     f"{type(e).__name__}: {str(e)[:200]}", "Verify the audit user's access rights.", "audit")

    # -- external checks (unauthenticated) ---------------------------------

    def check_transport(self):
        if self.url.startswith("http://"):
            host = self.url.split("//", 1)[1].split("/")[0].split(":")[0]
            local = host in ("localhost", "127.0.0.1")
            self.add("ext.no_tls", "low" if local else "critical", "Odoo served over plain HTTP",
                     f"{self.url} does not use TLS; logins and session cookies travel unencrypted."
                     + (" (Local test instance.)" if local else ""),
                     "Put Odoo behind a reverse proxy (nginx/Caddy) with TLS and set proxy_mode = True.",
                     "external")

    def check_headers(self):
        status, headers, _ = self.http("/web/login")
        h = {k.lower(): v for k, v in headers.items()}
        self.facts["login_page_status"] = status
        missing = []
        if self.url.startswith("https://") and "strict-transport-security" not in h:
            missing.append("Strict-Transport-Security")
        if "x-frame-options" not in h and "frame-ancestors" not in h.get("content-security-policy", ""):
            missing.append("X-Frame-Options / CSP frame-ancestors")
        if h.get("x-content-type-options", "").lower() != "nosniff":
            missing.append("X-Content-Type-Options: nosniff")
        if "content-security-policy" not in h:
            missing.append("Content-Security-Policy")
        if missing:
            self.add("ext.headers", "medium", "Missing HTTP security headers",
                     "Not set on /web/login: " + ", ".join(missing) + ".",
                     "Add the headers at the reverse proxy.", "external")
        server = h.get("server")
        if server and any(c.isdigit() for c in server):
            self.add("ext.server_banner", "low", "Server banner discloses version",
                     f"Server: {server}", "Strip or genericize the Server header at the proxy.", "external")

    def check_db_manager(self):
        status, _, body = self.http("/web/database/manager")
        if status == 200 and b"database" in body.lower():
            self.add("ext.db_manager", "high", "Database manager is publicly reachable",
                     "/web/database/manager responds. Anyone who obtains or guesses the master "
                     "password can back up, drop or restore every database.",
                     "Set list_db = False, a strong admin_passwd, and block /web/database/* at the proxy.",
                     "external")
        status, data = self.jsonrpc("/web/database/list")
        dbs = (data or {}).get("result")
        if isinstance(dbs, list):
            self.facts["databases_listed"] = dbs
            self.add("ext.list_db", "medium", "Database list is exposed (list_db enabled)",
                     f"/web/database/list returns {len(dbs)} database(s): {', '.join(dbs)}.",
                     "Set list_db = False and a dbfilter in odoo.conf.", "external")

    def check_version(self):
        status, data = self.jsonrpc("/web/webclient/version_info")
        info = (data or {}).get("result") or {}
        version = info.get("server_version")
        if version:
            self.facts["server_version"] = version
            self.facts["server_serie"] = info.get("server_serie")
            self.add("ext.version_info", "info", "Odoo version is discoverable",
                     f"Unauthenticated version_info reports {version}.",
                     "Expected Odoo behaviour; track the version against the support window.", "external")

    # -- authenticated checks (read-only XML-RPC) --------------------------

    def login(self):
        common = xmlrpc.client.ServerProxy(f"{self.url}/xmlrpc/2/common", allow_none=True)
        self.uid = common.authenticate(self.db, self.user, self.password, {})
        if not self.uid:
            raise SystemExit("Authentication failed; check --db/--user/--password.")
        self.models = xmlrpc.client.ServerProxy(f"{self.url}/xmlrpc/2/object", allow_none=True)
        if self.user == "admin" and self.password == "admin":
            self.add("cfg.default_admin", "critical", "Default admin credentials work",
                     "Login 'admin' with password 'admin' authenticated successfully.",
                     "Rename the admin login, set a strong unique password and enable 2FA.", "config")

    def installed(self, name):
        return bool(self.call("ir.module.module", "search_count",
                              [("name", "=", name), ("state", "=", "installed")]))

    def group_users(self, xmlid):
        module, name = xmlid.split(".")
        ref = self.call("ir.model.data", "search_read",
                        [("module", "=", module), ("name", "=", name)], fields=["res_id"], limit=1)
        if not ref:
            return []
        return self.call("res.users", "search_read",
                         [("groups_id", "in", [ref[0]["res_id"]]), ("share", "=", False)],
                         fields=["login", "name", "login_date"])

    def check_admins(self):
        admins = self.group_users("base.group_system")
        self.facts["settings_admins"] = [u["login"] for u in admins]
        if len(admins) > MAX_ADMINS:
            self.add("acl.admin_sprawl", "high", "Too many Settings administrators",
                     f"{len(admins)} users hold Administration/Settings: "
                     + ", ".join(self.facts["settings_admins"]) + ".",
                     f"Keep Settings access to at most {MAX_ADMINS} named people.", "access")

    def check_dormant(self):
        users = self.call("res.users", "search_read", [("share", "=", False)],
                          fields=["login", "login_date", "create_date"])
        cutoff = dt.datetime.now() - dt.timedelta(days=DORMANT_DAYS)
        dormant = []
        for u in users:
            last = u.get("login_date")
            if last and dt.datetime.fromisoformat(str(last)) < cutoff:
                dormant.append(f"{u['login']} (last login {str(last)[:10]})")
            elif not last and dt.datetime.fromisoformat(str(u["create_date"])) < cutoff:
                dormant.append(f"{u['login']} (never logged in)")
        self.facts["internal_users"] = len(users)
        if dormant:
            self.add("acl.dormant", "medium", "Dormant internal accounts",
                     f"{len(dormant)} active internal user(s) idle > {DORMANT_DAYS} days: "
                     + ", ".join(dormant[:10]) + ".",
                     "Archive accounts that are no longer needed.", "access")

    def check_portal(self):
        count = self.call("res.users", "search_count", [("share", "=", True)])
        self.facts["portal_users"] = count
        if count:
            self.add("acl.portal", "info", "Portal/public users present",
                     f"{count} share (portal/public) user(s) exist.",
                     "Review record rules for any custom model exposed to portal users.", "access")

    def check_2fa(self):
        if not self.installed("auth_totp"):
            self.add("cfg.no_2fa_module", "high", "Two-factor authentication not available",
                     "Module auth_totp is not installed.", "Install auth_totp and require it for internal users.",
                     "config")
            return
        users = self.call("res.users", "search_read", [("share", "=", False)],
                          fields=["login", "totp_enabled"])
        without = [u["login"] for u in users if not u.get("totp_enabled")]
        self.facts["users_without_2fa"] = without
        enforced = self.installed("auth_totp_mail_enforce")
        if without:
            self.add("cfg.2fa_not_enforced", "high" if not enforced else "medium",
                     "Internal users without 2FA",
                     f"{len(without)} of {len(users)} internal users have no TOTP: " + ", ".join(without[:10])
                     + (". Enforcement module is installed." if enforced else ". 2FA is not enforced."),
                     "Install auth_totp_mail_enforce, or have every admin enable TOTP, starting with Settings admins.",
                     "config")

    def check_api_keys(self):
        keys = self.call("res.users.apikeys", "search_read", [], fields=["name", "user_id", "create_date"])
        self.facts["api_keys"] = len(keys)
        if keys:
            self.add("cfg.api_keys", "info", "API keys inventory",
                     f"{len(keys)} API key(s): "
                     + ", ".join(f"{k['name']} ({k['user_id'][1]})" for k in keys[:10]) + ".",
                     "Confirm each key has an owner and a purpose; revoke unused keys.", "config")

    def check_crons(self):
        crons = self.call("ir.cron", "search_read", [("active", "=", True)],
                          fields=["name", "failure_count", "first_failure_date"])
        failing = [c for c in crons if c.get("failure_count")]
        self.facts["active_crons"] = len(crons)
        if failing:
            self.add("health.cron_failures", "medium", "Scheduled actions are failing",
                     ", ".join(f"{c['name']} ({c['failure_count']} failures)" for c in failing[:10]) + ".",
                     "Read the server log for each cron and fix or disable it.", "health")

    def check_mail_queue(self):
        if not self.installed("mail"):
            return
        stuck = self.call("mail.mail", "search_count", [("state", "=", "exception")])
        if stuck:
            self.add("health.mail_exceptions", "medium", "Outgoing emails failing",
                     f"{stuck} email(s) in exception state.", "Check the outgoing mail server configuration.",
                     "health")

    def check_modules(self):
        mods = self.call("ir.module.module", "search_read", [("state", "=", "installed")],
                         fields=["name", "author"])
        custom = [m["name"] for m in mods if "Odoo S.A." not in (m.get("author") or "")]
        self.facts["installed_modules"] = len(mods)
        self.facts["third_party_modules"] = custom
        if custom:
            self.add("upg.custom_modules", "info", "Third-party / custom modules installed",
                     f"{len(custom)} non-Odoo S.A. module(s): " + ", ".join(custom[:15]) + ".",
                     "Include these in the Upgrade Runway compatibility scan.", "upgrade")

    def check_sod(self):
        if not self.installed("account"):
            return
        accountants = {u["login"] for u in self.group_users("account.group_account_manager")}
        approvers = {u["login"] for u in self.group_users("account.group_account_invoice")}
        both = sorted(accountants & approvers - {"__system__"})
        if len(both) > 1:
            self.add("acl.sod", "medium", "Segregation-of-duties review needed",
                     "Users can both create and validate accounting entries: " + ", ".join(both[:10]) + ".",
                     "Split vendor bill creation and payment approval between different people.", "access")

    # -- run ----------------------------------------------------------------

    def run(self):
        for name in ("transport", "headers", "db_manager", "version"):
            self.safe(getattr(self, f"check_{name}"), name)
        self.login()
        for name in ("admins", "dormant", "portal", "2fa", "api_keys", "crons",
                     "mail_queue", "modules", "sod"):
            self.safe(getattr(self, f"check_{name}"), name)
        order = list(SEVERITY_WEIGHT)
        self.findings.sort(key=lambda f: order.index(f["severity"]))
        score = max(0, 100 - sum(SEVERITY_WEIGHT[f["severity"]] for f in self.findings))
        return {
            "target": self.url, "database": self.db,
            "generated_at": dt.datetime.now().isoformat(timespec="seconds"),
            "score": score, "grade": grade(score),
            "top_fixes": [f for f in self.findings if f["severity"] != "info"][:3],
            "facts": self.facts, "findings": self.findings,
        }


def grade(score):
    return next(g for limit, g in ((90, "A"), (75, "B"), (60, "C"), (40, "D"), (0, "F")) if score >= limit)


COLORS = {"critical": "#b3261e", "high": "#d9480f", "medium": "#c08b00", "low": "#3b6ea8", "info": "#6b7280"}


def render_html(report):
    e = html.escape
    rows = "".join(
        f"<tr><td><span class='sev' style='background:{COLORS[f['severity']]}'>{f['severity']}</span></td>"
        f"<td>{e(f['category'])}</td><td><b>{e(f['title'])}</b><br><small>{e(f['detail'])}</small></td>"
        f"<td>{e(f['fix'])}</td></tr>"
        for f in report["findings"])
    fixes = "".join(f"<li><b>{e(f['title'])}</b> — {e(f['fix'])}</li>" for f in report["top_fixes"])
    facts = "".join(f"<li>{e(k)}: {e(str(v))}</li>" for k, v in report["facts"].items())
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>Odoo Shield scorecard</title>
<style>body{{font-family:system-ui,sans-serif;max-width:960px;margin:2rem auto;color:#1f2937}}
.score{{font-size:3rem;font-weight:700}}table{{border-collapse:collapse;width:100%}}
td,th{{border-bottom:1px solid #e5e7eb;padding:.5rem;vertical-align:top;text-align:left}}
.sev{{color:#fff;border-radius:4px;padding:2px 6px;font-size:.8rem}}small{{color:#4b5563}}</style></head><body>
<h1>Odoo Shield — Baseline Scorecard</h1>
<p>{e(report['target'])} · database <b>{e(report['database'])}</b> · {e(report['generated_at'])}</p>
<div class="score">{report['score']}/100 · grade {report['grade']}</div>
<h2>Top 3 fixes</h2><ol>{fixes}</ol>
<h2>Findings</h2><table><tr><th>Severity</th><th>Area</th><th>Finding</th><th>Fix</th></tr>{rows}</table>
<h2>Inventory</h2><ul>{facts}</ul>
<p><small>Read-only assessment. "Measured and improving", not a guarantee of security.</small></p>
</body></html>"""


def main():
    p = argparse.ArgumentParser(description="Odoo Shield baseline audit (read-only)")
    p.add_argument("--url", required=True)
    p.add_argument("--db", required=True)
    p.add_argument("--user", required=True)
    p.add_argument("--password", required=True)
    p.add_argument("--out", default="report", help="output path prefix (writes .json and .html)")
    args = p.parse_args()

    report = Audit(args.url, args.db, args.user, args.password).run()
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.with_suffix(".json").write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    out.with_suffix(".html").write_text(render_html(report), encoding="utf-8")

    print(f"Score {report['score']}/100 (grade {report['grade']}) - {len(report['findings'])} findings")
    for f in report["findings"]:
        print(f"  [{f['severity']:>8}] {f['title']}")
    print(f"Wrote {out.with_suffix('.json')} and {out.with_suffix('.html')}")


if __name__ == "__main__":
    main()
