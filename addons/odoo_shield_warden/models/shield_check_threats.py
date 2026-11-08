"""Threat-driven checks added after the real-world attack lab (docs/REAL_WORLD_ASSESSMENT.md).

Each check targets something an insider or an attacker with stolen credentials did in the lab,
using only legitimate Odoo features.
"""

import json
import os
import re
from collections import defaultdict
from datetime import timedelta

from odoo import SUPERUSER_ID, _, fields, models, release
from odoo.modules.module import get_module_path
from odoo.tools import config

from .shield_check import SELF_MODULE, WEAK_PASSWORDS, listing, result

# Tokens that make database-stored code dangerous: privilege bypass, raw SQL, network, OS, money data.
DANGEROUS_CODE = {
    "sudo()": r"\.sudo\(", "raw SQL": r"\bcr\.execute\(", "eval/exec": r"\b(eval|exec)\(",
    "network call": r"\b(requests|urllib|http\.client|socket)\b", "OS access": r"\b(os\.|subprocess)",
    "bank data": r"res\.partner\.bank|acc_number|allow_out_payment", "user rights": r"groups_id|res\.users",
    "mass delete": r"\.unlink\(",
}
SENSITIVE_RULE_MODELS = ("account.", "res.partner.bank", "res.users", "res.groups", "hr.", "ir.", "shield.",
                         "payment.", "mail.message")
# Static patterns for third-party module source (file suffix, label, regex, severity).
CODE_PATTERNS = [
    (".py", "SQL built from strings", r"\.execute\(\s*(f[\"']|[\"'][^\"']*[\"']\s*%|.*\.format\()", "high"),
    (".py", "eval/exec on dynamic input", r"(?<![\w.])(eval|exec)\(", "high"),
    (".py", "OS command execution", r"\bsubprocess\.|\bos\.system\(", "high"),
    (".py", "unsafe deserialization", r"\bpickle\.loads?\(|\byaml\.load\((?!.*SafeLoader)", "high"),
    (".py", "TLS verification disabled", r"verify\s*=\s*False", "medium"),
    (".py", "CSRF protection disabled", r"csrf\s*=\s*False", "medium"),
    (".py", "HTML field without sanitizing", r"fields\.Html\([^)]*sanitize\s*=\s*False", "medium"),
    (".xml", "raw HTML output (t-raw)", r"\bt-raw=", "medium"),
]
PUBLIC_ROUTE = re.compile(r"auth\s*=\s*[\"'](public|none)[\"']")
SUDO = re.compile(r"\.sudo\(")
MAX_SCAN_FILES = 4000


class ShieldCheck(models.AbstractModel):
    _inherit = "shield.check"

    # -- helpers -------------------------------------------------------------------

    def _module_xmlids(self, model, ids):
        """Record ids of ``model`` that were created by an installed module's data files."""
        installed = set(self.env["ir.module.module"].sudo().search([("state", "=", "installed")]).mapped("name"))
        data = self.env["ir.model.data"].sudo().search([("model", "=", model), ("res_id", "in", list(ids))])
        return {d.res_id for d in data if d.module in installed and d.module != "__export__"}

    def _code_tokens(self, code):
        return [label for label, rx in DANGEROUS_CODE.items() if re.search(rx, code or "")]

    # -- persistence: code stored in the database ---------------------------------------

    def _check_db_code_objects(self):
        actions = self.env["ir.actions.server"].sudo().with_context(active_test=False).search([("state", "=", "code")])
        crons = self.env["ir.cron"].sudo().with_context(active_test=False).search(
            [("ir_actions_server_id", "in", actions.ids)])
        from_modules = self._module_xmlids("ir.actions.server", actions.ids)
        module_crons = self._module_xmlids("ir.cron", crons.ids)
        from_modules |= set(crons.filtered(lambda c: c.id in module_crons).mapped("ir_actions_server_id").ids)
        cron_by_action = {c.ir_actions_server_id.id: c for c in crons}
        custom = actions.filtered(lambda a: a.id not in from_modules)
        if not custom:
            return result("pass", _("All server-side code comes from installed modules."))
        rows, worst = [], "medium"
        for action in custom:
            tokens = self._code_tokens(action.code)
            cron = cron_by_action.get(action.id)
            kind = _("scheduled action") if cron else _("server action")
            if tokens:
                worst = "high"
            rows.append(_("%(name)s (%(kind)s%(state)s, by %(user)s on %(date)s%(tok)s)",
                          name=action.name, kind=kind,
                          state="" if not cron or cron.active else _(", inactive"),
                          user=action.create_uid.login, date=fields.Date.to_string(action.create_date.date()),
                          tok=(": " + ", ".join(tokens)) if tokens else ""))
        return result("fail" if worst == "high" else "warn",
                      _("%(n)s piece(s) of Python code were added through the database rather than a reviewed module: "
                        "%(rows)s. Code here runs with full server access and survives module reinstalls.",
                        n=len(custom), rows=listing(rows, limit=5)), severity=worst)

    # -- anti-forensics: record rules created outside modules ------------------------------

    def _check_custom_record_rules(self):
        rules = self.env["ir.rule"].sudo().with_context(active_test=False).search([])
        from_modules = self._module_xmlids("ir.rule", rules.ids)
        custom = rules.filtered(lambda r: r.id not in from_modules)
        if not custom:
            return result("pass", _("All record rules come from installed modules."))
        sensitive = custom.filtered(lambda r: r.model_id.model.startswith(SENSITIVE_RULE_MODELS) or r["global"])
        rows = [_("%(name)s on %(model)s for %(groups)s by %(user)s: %(domain)s",
                  name=r.name, model=r.model_id.model,
                  groups=", ".join(r.groups.mapped("full_name")) or _("everyone"),
                  user=r.create_uid.login, domain=r.domain_force) for r in (sensitive or custom)]
        if sensitive:
            return result("fail", _("%(n)s record rule(s) on financial/security data were created by hand. Rules "
                                    "decide who can SEE records, so they can hide transactions from reviewers: %(rows)s",
                                    n=len(sensitive), rows=listing(rows, limit=4)))
        return result("warn", _("%(n)s hand-made record rule(s): %(rows)s", n=len(custom), rows=listing(rows, limit=4)))

    # -- privilege drift (needs the previous assessment's snapshot) --------------------------

    def _privileged_snapshot(self):
        groups = {"settings": "base.group_system", "access_rights": "base.group_erp_manager",
                  "template_editor": "mail.group_mail_template_editor", "export": "base.group_allow_export"}
        snap = {}
        for key, xmlid in groups.items():
            group = self.env.ref(xmlid, raise_if_not_found=False)
            snap[key] = sorted(group.sudo().users.filtered(
                lambda u: u.active and u.id != SUPERUSER_ID).mapped("login")) if group else []
        return snap

    def _check_privilege_drift(self):
        now = self._privileged_snapshot()
        previous = self.env["shield.assessment"].sudo().search([("privileged_snapshot", "!=", False)], limit=1)
        lines = []
        if previous:
            before = json.loads(previous.privileged_snapshot)
            for key in ("settings", "access_rights"):
                added = sorted(set(now[key]) - set(before.get(key, [])))
                if added:
                    lines.append(_("gained %(right)s since %(date)s: %(who)s", right=key.replace("_", " "),
                                   date=fields.Date.to_string(previous.date.date()), who=", ".join(added)))
        # Accounts created by the installer (create_uid = superuser) are not drift.
        recent = self.env["res.users"].sudo().search([
            ("login", "in", now["settings"] + now["access_rights"]),
            ("create_date", ">=", fields.Datetime.now() - timedelta(days=30)),
            ("create_uid", "!=", SUPERUSER_ID)])
        if recent:
            lines.append(_("privileged accounts created in the last 30 days: %s",
                           ", ".join(f"{u.login} (by {u.create_uid.login})" for u in recent)))
        if lines:
            return result("fail", _("Privileged access changed: %s.", "; ".join(lines)))
        if not previous:
            return result("pass", _("Baseline of privileged users recorded (%s with Settings).", len(now["settings"])))
        return result("pass", _("No new administrators since the last assessment."))

    # -- authentication hardening ----------------------------------------------------------------

    def _check_login_throttling(self):
        after = int(self._param("base.login_cooldown_after", 5) or 0)
        duration = int(self._param("base.login_cooldown_duration", 60) or 0)
        if after == 0:
            return result("fail", _("Login throttling is disabled (base.login_cooldown_after = 0): passwords can "
                                    "be guessed without limit, including through the XML-RPC/JSON-RPC API."))
        if after > 10 or duration < 30:
            return result("warn", _("Weak login throttling: cooldown after %(a)s failures for %(d)s seconds.",
                                    a=after, d=duration))
        return result("pass", _("Login cooldown after %(a)s failures for %(d)s seconds.", a=after, d=duration))

    def _check_template_editors(self):
        group = self.env.ref("mail.group_mail_template_editor", raise_if_not_found=False)
        if not group:
            return result("na", _("Mail not installed."))
        editors = group.sudo().users.filtered(
            lambda u: u.active and not u.share and u.id != SUPERUSER_ID and not u.has_group("base.group_system"))
        if editors:
            return result("fail", _("%(n)s non-administrator(s) can write dynamic email templates: %(who)s. Template "
                                    "expressions are evaluated on the server; the same class of bug gave remote code "
                                    "execution in other ERPs (e.g. CVE-2026-38431 in ERPNext).",
                                    n=len(editors), who=listing(editors.mapped("login"))))
        return result("pass", _("Only administrators can write dynamic templates."))

    def _check_db_credentials(self):
        db_user = config.get("db_user") or ""
        db_password = config.get("db_password") or ""
        db_host = config.get("db_host")
        problems = []
        if db_password and db_password.lower() in WEAK_PASSWORDS + ("odoo", "postgres"):
            problems.append(_("the database password is a common default ('%s')", db_password[:2] + "***"))
        if db_user == "postgres":
            problems.append(_("Odoo connects as the PostgreSQL superuser 'postgres'"))
        if problems:
            where = _("over the network to host '%s'", db_host) if db_host and db_host not in ("localhost", "127.0.0.1") \
                else _("locally")
            return result("fail", _("Database credentials are weak: %(p)s. Odoo connects %(where)s; anyone who reaches "
                                    "PostgreSQL bypasses every Odoo access rule and audit trail.",
                                    p="; ".join(problems), where=where))
        if not db_password and not db_host:
            return result("pass", _("Database accessed over a local socket with peer authentication."))
        return result("pass", _("Database credentials are not a known default."))

    # -- data exfiltration ---------------------------------------------------------------------

    def _check_mass_export(self):
        days = 30
        limit = int(self._param("shield.mass_export_rows", 500) or 500)
        sensitive = (self._param("shield.sensitive_export_models", "") or
                     "res.partner,res.partner.bank,account.move,account.move.line,account.payment,hr.employee,"
                     "res.users,sale.order,crm.lead,purchase.order").split(",")
        logs = self.env["shield.export.log"].sudo().search([
            ("create_date", ">=", fields.Datetime.now() - timedelta(days=days)), ("model", "in", sensitive)])
        per_user = defaultdict(lambda: defaultdict(int))
        for log in logs:
            per_user[log.user_id][log.model] += log.record_count
        heavy = {u: m for u, m in per_user.items() if sum(m.values()) >= limit}
        exporters = self._group_users("base.group_allow_export")
        rights = _("%s user(s) hold export rights.", len(exporters))
        if heavy:
            rows = [f"{u.login}: " + ", ".join(f"{n} {model}" for model, n in sorted(m.items())) for u, m in heavy.items()]
            return result("fail", _("Bulk exports of sensitive data in the last %(d)s days: %(rows)s. %(rights)s",
                                    d=days, rows=listing(rows), rights=rights), severity="high")
        return result("pass", _("No bulk export of sensitive data in the last %(d)s days. %(rights)s", d=days, rights=rights))

    # -- third-party code review -----------------------------------------------------------------

    def _scan_source(self, text, filename):
        """Findings for one file: [(label, severity, line_no)]."""
        out = []
        suffix = os.path.splitext(filename)[1]
        for line_no, line in enumerate(text.splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            for ext, label, rx, severity in CODE_PATTERNS:
                if ext == suffix and re.search(rx, line):
                    out.append((label, severity, line_no))
        if suffix == ".py" and PUBLIC_ROUTE.search(text) and SUDO.search(text):
            out.append((_("public route combined with sudo()"), "high", 0))
        return out

    def _check_custom_code_risks(self):
        modules = self._third_party_modules()
        if not modules:
            return result("na", _("No third-party modules installed."))
        findings, scanned = [], 0
        for module in modules:
            path = get_module_path(module.name, display_warning=False)
            if not path:
                continue
            for root, _dirs, files in os.walk(path):
                for name in files:
                    if not name.endswith((".py", ".xml")) or scanned >= MAX_SCAN_FILES:
                        continue
                    scanned += 1
                    full = os.path.join(root, name)
                    try:
                        with open(full, encoding="utf-8", errors="ignore") as fh:
                            hits = self._scan_source(fh.read(), name)
                    except OSError:
                        continue
                    rel = os.path.relpath(full, os.path.dirname(path))
                    findings += [(module.name, f"{rel}:{ln}" if ln else rel, label, sev) for label, sev, ln in hits]
        if not findings:
            return result("pass", _("%(f)s files in %(m)s third-party module(s) scanned; no risky patterns.",
                                    f=scanned, m=len(modules)))
        high = [f for f in findings if f[3] == "high"]
        rows = [f"{label} ({where})" for _mod, where, label, _sev in (high or findings)]
        return result("fail" if high else "warn",
                      _("%(n)s risky pattern(s) in third-party code (%(h)s high): %(rows)s",
                        n=len(findings), h=len(high), rows=listing(rows, limit=6)),
                      "\n".join(f"{m} {w}: {label} [{s}]" for m, w, label, s in findings),
                      severity="high" if high else "medium")

    # -- cycle 3: patching, data exposure, cover-ups, off-box evidence ----------------------------

    def _advisories(self):
        path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "advisories.json")
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)["advisories"]

    def _build_date(self):
        """Odoo builds carry their date in the version string, e.g. '18.0-20261015' or '18.0+e-20261015'."""
        match = re.search(r"(20\d{6})", release.version)
        return fields.Date.to_date(f"{match.group(1)[:4]}-{match.group(1)[4:6]}-{match.group(1)[6:]}") if match else None

    def _check_patch_level(self):
        if "saas" in release.serie:
            return result("pass", _("Odoo Online is patched by Odoo."))
        build = self._build_date()
        lines, worst = [], None
        for adv in self._advisories():
            if release.serie in adv["series"] and self._installed(adv["module"]) and (
                    not build or build < fields.Date.to_date(adv["published"])):
                lines.append(f"{adv['id']} ({adv['module']}): {adv['summary']}")
                worst = "critical" if adv["severity"] == "critical" else worst or "high"
        if lines:
            return result("fail", _("Build %(v)s is likely affected by %(n)s published advisory(ies): %(items)s. "
                                    "Update to the latest %(s)s build.", v=release.version, n=len(lines),
                                    items="; ".join(lines), s=release.serie), severity=worst)
        if not build:
            return result("warn", _("Build date of %s is unknown; patch level cannot be verified.", release.version),
                          severity="low")
        age = (fields.Date.context_today(self) - build).days
        if age > 180:
            return result("fail", _("This Odoo build is %(d)s days old (%(v)s). Odoo ships security fixes in its "
                                    "regular builds; a build this old misses them.", d=age, v=release.version))
        if age > 60:
            return result("warn", _("This Odoo build is %(d)s days old (%(v)s); update monthly.", d=age, v=release.version),
                          severity="medium")
        return result("pass", _("Build %(v)s is %(d)s days old; no known advisory applies.", v=release.version, d=age))

    def _check_public_attachments(self):
        sensitive = ("account.move", "account.payment", "res.partner", "res.partner.bank", "hr.employee",
                     "hr.contract", "sale.order", "purchase.order", "res.users")
        public = self.env["ir.attachment"].sudo().search([("public", "=", True), ("res_model", "in", sensitive)])
        if public:
            by_model = defaultdict(int)
            for att in public:
                by_model[att.res_model] += 1
            return result("fail", _("%(n)s attachment(s) on business documents are public: anyone with the URL can "
                                    "download them without logging in (%(models)s).", n=len(public),
                                    models=", ".join(f"{n} on {m}" for m, n in sorted(by_model.items()))),
                          listing((f"{a.name} ({a.res_model},{a.res_id})" for a in public), limit=50))
        return result("pass", _("No public attachments on business documents."))

    def _check_message_deletions(self):
        logs = self.env["shield.deletion.log"].sudo().search([
            ("create_date", ">=", fields.Datetime.now() - timedelta(days=30))])
        cover_ups = logs.filtered("record_still_exists")
        if cover_ups:
            rows = [f"{log.deleted_by.login} deleted '{log.summary}' on {log.res_model},{log.res_id}" for log in cover_ups]
            return result("fail", _("%(n)s chatter message(s) were deleted from records that still exist, which is how "
                                    "an audit trail gets erased: %(rows)s.", n=len(cover_ups), rows=listing(rows, limit=4)))
        return result("pass", _("No audit-trail messages deleted from existing records in the last 30 days."))

    def _check_seal_offbox(self):
        recipients = self._param("shield.seal_recipients", "")
        if not recipients:
            return result("fail", _("Assessment seals only live inside this database: an administrator could delete or "
                                    "rewrite the whole history. Set the system parameter shield.seal_recipients to an "
                                    "external mailbox (e.g. your auditor or board) to receive each seal."))
        last = self.env["mail.mail"].sudo().search([("subject", "=like", "[Shield seal]%")], limit=1, order="id desc")
        if last and last.state == "exception":
            return result("warn", _("Seal receipts go to %s, but the last one failed to send.", recipients))
        return result("pass", _("Each seal is sent to %s outside this database.", recipients))

    # -- cycle 3: one-click fixes ------------------------------------------------------------------

    def _fix_login_throttling(self):
        self._set_param("base.login_cooldown_after", 5, False)
        self._set_param("base.login_cooldown_duration", 60, False)
        return _("Login throttling restored: cooldown after 5 failures for 60 seconds."), False

    def _fix_template_editors(self):
        group = self.env.ref("mail.group_mail_template_editor")
        editors = group.sudo().users.filtered(
            lambda u: not u.share and u.id != SUPERUSER_ID and not u.has_group("base.group_system"))
        logins = listing(editors.mapped("login"))
        group.sudo().write({"users": [(3, u.id) for u in editors]})
        return _("Mail Template Editor removed from: %s.", logins), False

    # -- cycle 4: login attacks and Shield's own integrity --------------------------------------

    def _check_login_attacks(self):
        since = fields.Datetime.now() - timedelta(hours=24)
        logs = self.env["shield.login.log"].sudo().search([("create_date", ">=", since)], order="create_date")
        fails_by_login, logins_by_ip, takeovers = defaultdict(int), defaultdict(set), []
        for log in logs:
            if log.success:
                if fails_by_login[log.login] >= 5:
                    takeovers.append(_("%(login)s logged in from %(ip)s after %(n)s failed attempts",
                                       login=log.login, ip=log.ip, n=fails_by_login[log.login]))
                continue
            fails_by_login[log.login] += 1
            logins_by_ip[log.ip].add(log.login)
        brute = {login: n for login, n in fails_by_login.items() if n >= 10}
        spray = {ip: sorted(logins) for ip, logins in logins_by_ip.items() if len(logins) >= 5}
        lines = []
        if takeovers:
            lines.append(_("possible account takeover: %s", "; ".join(takeovers)))
        if brute:
            lines.append(_("password guessing against %s",
                           ", ".join(f"{login} ({n} failures)" for login, n in sorted(brute.items()))))
        if spray:
            lines.append(_("password spraying from %s",
                           ", ".join(f"{ip} ({len(logins)} accounts)" for ip, logins in spray.items())))
        if lines:
            return result("fail", _("Login attacks in the last 24 hours: %s.", "; ".join(lines)),
                          severity="critical" if takeovers else "high")
        return result("pass", _("%s failed login(s) in the last 24 hours; no attack pattern.", len(logs.filtered(
            lambda log: not log.success))))

    # Protections whose silent removal is itself an attack signal.
    _guarded_controls = ("payment_hold", "seal_offbox", "login_throttling", "mfa_enforced", "dbmanager_exposed",
                        "signup_open", "template_editors", "password_policy")

    def _check_shield_integrity(self):
        """Who watches the watchmen: catch Shield itself being switched off, piece by piece."""
        problems = []
        archived = self.env["shield.control"].sudo().with_context(active_test=False).search([("active", "=", False)])
        if archived:
            problems.append(_("controls disabled: %s", listing(archived.mapped("name"))))
        cron = self.env.ref("odoo_shield_warden.cron_weekly_assessment", raise_if_not_found=False)
        if not cron or not cron.sudo().active:
            problems.append(_("the weekly assessment schedule is switched off"))
        previous = self.env["shield.assessment"].sudo().search([("content_hash", "!=", False)], limit=1)
        if previous:
            gap = (fields.Datetime.now() - previous.date).days
            if gap > 14:
                problems.append(_("no assessment for %s days", gap))
            was_ok = previous.result_ids.filtered(
                lambda r: r.control_id.code in self._guarded_controls and r.status == "pass")
            regressed = []
            for res in was_ok:
                method = getattr(self, f"_check_{res.control_id.code}", None)
                if method and method()["status"] in ("fail", "warn"):
                    regressed.append(res.control_id.name)
            if regressed:
                problems.append(_("protections switched off since %(date)s: %(what)s",
                                  date=fields.Date.to_string(previous.date.date()), what=", ".join(regressed)))
        if problems:
            return result("fail", _("Shield is being weakened: %s. Disabling the monitor is a typical step before "
                                    "or after fraud.", "; ".join(problems)))
        return result("pass", _("All Shield controls, the schedule and previously passing protections are intact."))
