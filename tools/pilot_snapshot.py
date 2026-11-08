"""Fraud Exposure Snapshot: one read-only assessment on a COPY of a client's Odoo database.

Run it only against a restored backup in an isolated Odoo (see docs/PILOT_SNAPSHOT.md), never against production.
It installs nothing; Shield must already be installed in that copy. It refuses a non-local URL unless you pass
--copy-confirmed, and writes a summary plus the PDF scorecard to ./snapshot-<db>/.

    python tools/pilot_snapshot.py --db client_copy [--url http://localhost:8069] --login admin --password admin
"""

import argparse
import http.cookiejar
import json
import sys
import urllib.request
import xmlrpc.client
from pathlib import Path
from urllib.parse import urlparse


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--db", required=True)
    p.add_argument("--url", default="http://localhost:8069")
    p.add_argument("--login", default="admin")
    p.add_argument("--password", required=True)
    p.add_argument("--copy-confirmed", action="store_true",
                   help="required for a non-local URL: I confirm this is a restored copy and the client consented")
    a = p.parse_args()
    if urlparse(a.url).hostname not in ("localhost", "127.0.0.1") and not a.copy_confirmed:
        sys.exit("Refusing: the URL is not local. Use a restored copy, and pass --copy-confirmed only with consent.")

    uid = xmlrpc.client.ServerProxy(f"{a.url}/xmlrpc/2/common").authenticate(a.db, a.login, a.password, {})
    if not uid:
        sys.exit("Login failed.")
    m = xmlrpc.client.ServerProxy(f"{a.url}/xmlrpc/2/object", allow_none=True)

    def x(model, method, *args, **kw):
        return m.execute_kw(a.db, uid, a.password, model, method, list(args), kw)

    if not x("ir.module.module", "search_count", [("name", "=", "odoo_shield_warden_finance"), ("state", "=", "installed")]):
        sys.exit("odoo_shield_warden_finance is not installed in this copy.")
    out = Path(f"snapshot-{a.db}")
    out.mkdir(exist_ok=True)
    action = x("shield.assessment", "action_run_assessment")
    rid = action["res_id"]
    f = ["name", "grade", "security_score", "grc_score", "transaction_exposure", "access_exposure", "risk_event_count",
         "content_hash"]
    summary = x("shield.assessment", "read", [rid], fields=f)[0]
    cases = x("shield.risk.case", "search_read", [], fields=["name", "state", "amount"]) \
        if x("ir.model", "search_count", [("model", "=", "shield.risk.case")]) else []
    (out / "summary.json").write_text(json.dumps({"summary": summary, "cases": cases}, indent=2, default=str),
                                      encoding="utf-8")
    print(f"MONEY AT RISK: {summary['transaction_exposure']:,.2f} | events: {summary['risk_event_count']} | "
          f"cases: {len(cases)} | grade {summary['grade']}")
    try:  # the scorecard PDF is best-effort (same route as tools/fetch_scorecard.py)
        jar = http.cookiejar.CookieJar()
        op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
        body = json.dumps({"jsonrpc": "2.0", "params": {"db": a.db, "login": a.login, "password": a.password}}).encode()
        op.open(urllib.request.Request(f"{a.url}/web/session/authenticate", body, {"Content-Type": "application/json"}))
        pdf = op.open(f"{a.url}/report/pdf/odoo_shield_warden.report_scorecard/{rid}", timeout=120).read()
        (out / "scorecard.pdf").write_bytes(pdf)
    except Exception as exc:  # noqa: BLE001
        print(f"(scorecard PDF skipped: {type(exc).__name__})")
    print(f"Wrote {out}/summary.json. Delete the restored copy when the readout is done.")


if __name__ == "__main__":
    main()
