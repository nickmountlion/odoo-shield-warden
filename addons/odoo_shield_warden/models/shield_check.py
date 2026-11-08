"""Check and fix implementations.

Every automated control with code X is evaluated by ``_check_X`` and may offer a
one-click hardening via ``_fix_X``. Checks are read-only and return a dict:
``{"status": pass|warn|fail|na, "detail": str, "evidence": str, "severity": optional}``.
Fixes return ``(message, needs_reload)``.
"""

import os
from datetime import timedelta

from odoo import SUPERUSER_ID, _, api, fields, models, release
from odoo.exceptions import AccessDenied, UserError
from odoo.modules.registry import Registry
from odoo.tools import config

WEAK_PASSWORDS = ("admin", "odoo", "password", "123456", "changeme", "demo")
DORMANT_DAYS = 90
API_KEY_MAX_AGE_DAYS = 180
MAX_ADMINS = 3
MAX_ACCOUNTING_ADMINS = 2
MIN_PASSWORD_LENGTH = 12
SELF_MODULE = "odoo_shield_warden"
# Controls that Odoo.sh operates on the customer's behalf.
ODOO_SH_MANAGED = {"backup_offsite": "Odoo.sh takes daily off-site backups of production.",
                   "staging_env": "Odoo.sh provides staging branches built from production."}


def result(status, detail, evidence="", severity=None):
    res = {"status": status, "detail": detail, "evidence": evidence}
    if severity:
        res["severity"] = severity
    return res


def listing(items, limit=15):
    items = list(items)
    more = f" (+{len(items) - limit} more)" if len(items) > limit else ""
    return ", ".join(items[:limit]) + more


class ShieldCheck(models.AbstractModel):
    _name = "shield.check"
    _description = "Security Check Engine"

    # -- helpers ---------------------------------------------------------------

    def _param(self, key, default=False):
        return self.env["ir.config_parameter"].sudo().get_param(key, default)

    def _installed(self, name):
        return bool(self.env["ir.module.module"].sudo().search_count(
            [("name", "=", name), ("state", "=", "installed")]))

    def _internal_users(self):
        return self.env["res.users"].sudo().search([("share", "=", False)])

    def _group_users(self, xmlid):
        group = self.env.ref(xmlid, raise_if_not_found=False)
        if not group:
            return self.env["res.users"]
        return group.sudo().users.filtered(lambda u: u.active and not u.share and u.id != SUPERUSER_ID)

    def _third_party_modules(self):
        mods = self.env["ir.module.module"].sudo().search([("state", "=", "installed")])
        return mods.filtered(lambda m: "Odoo S.A." not in (m.author or "") and not m.name.startswith(SELF_MODULE))

    def _is_odoo_sh(self):
        return bool(os.environ.get("ODOO_STAGE"))

    def _is_local(self, url):
        return any(h in (url or "") for h in ("://localhost", "://127.0.0.1"))

    def _ensure_module(self, name):
        """Install ``name`` if needed. Returns True when an install happened (registry reloaded)."""
        module = self.env["ir.module.module"].sudo().search([("name", "=", name)], limit=1)
        if not module:
            raise UserError(_("Module %s is not available on this server.", name))
        if module.state == "installed":
            return False
        module.button_immediate_install()
        return True

    def _set_param(self, key, value, after_install):
        if after_install:
            # The install reloaded the registry; write through a fresh cursor on the new one.
            with Registry(self.env.cr.dbname).cursor() as cr:
                api.Environment(cr, SUPERUSER_ID, {})["ir.config_parameter"].set_param(key, value)
        else:
            self.env["ir.config_parameter"].sudo().set_param(key, value)

    # -- manual controls ---------------------------------------------------------

    def _attestation_result(self, control):
        if control.code in ODOO_SH_MANAGED and self._is_odoo_sh():
            return result("pass", ODOO_SH_MANAGED[control.code], "ODOO_STAGE environment detected")
        att = self.env["shield.attestation"].sudo().search([("control_id", "=", control.id)], limit=1)
        if not att:
            return result("fail", _("No attestation recorded. Record evidence under Shield > Attestations."))
        if att.result != "compliant":
            return result("fail", _("Attested NOT compliant on %(date)s by %(user)s.",
                                    date=att.date, user=att.attested_by.name))
        if att.valid_until < fields.Date.context_today(self):
            return result("fail", _("Last attestation expired on %s.", att.valid_until))
        return result("pass", _("Attested by %(user)s on %(date)s, valid until %(until)s.",
                                user=att.attested_by.name, date=att.date, until=att.valid_until),
                      f"shield.attestation,{att.id}")

    # -- identity & authentication ------------------------------------------------

    def _check_admin_default_login(self):
        user = self.env["res.users"].sudo().search([("login", "=", "admin")], limit=1)
        if not user:
            return result("pass", _("No active account uses the default login 'admin'."))
        try:
            user.with_user(user)._check_credentials(
                {"type": "password", "password": "admin", "login": "admin"}, {"interactive": False})
            return result("fail", _("The 'admin' account still has the default password 'admin'."),
                          f"res.users,{user.id}", severity="critical")
        except AccessDenied:
            pass
        except Exception:  # credential API differs between versions; fall back to login-only finding
            pass
        return result("fail", _("An active account uses the predictable login 'admin'."), f"res.users,{user.id}")

    def _check_admin_count(self):
        admins = self._group_users("base.group_system")
        evidence = listing(admins.mapped("login"))
        if len(admins) > MAX_ADMINS:
            return result("fail", _("%(n)s users hold Settings/Administration rights (target <= %(max)s): %(who)s",
                                    n=len(admins), max=MAX_ADMINS, who=evidence), evidence)
        return result("pass", _("%s Settings administrator(s).", len(admins)), evidence)

    def _check_mfa_coverage(self):
        if not self._installed("auth_totp"):
            return result("fail", _("Two-factor authentication (auth_totp) is not installed."))
        users = self._internal_users()
        missing = users.filtered(lambda u: not u.totp_enabled)
        admins_missing = missing & self._group_users("base.group_system")
        if admins_missing:
            return result("fail", _("%(n)s administrator(s) without 2FA: %(who)s",
                                    n=len(admins_missing), who=listing(admins_missing.mapped("login"))),
                          listing(missing.mapped("login")))
        if missing:
            return result("warn", _("%(n)s of %(t)s internal users without 2FA: %(who)s",
                                    n=len(missing), t=len(users), who=listing(missing.mapped("login"))))
        return result("pass", _("All %s internal users use 2FA.", len(users)))

    def _check_mfa_enforced(self):
        policy = self._param("auth_totp.policy")
        if self._installed("auth_totp_mail_enforce") and policy in ("employee_required", "all_required"):
            return result("pass", _("2FA is enforced (policy: %s).", policy))
        return result("fail", _("2FA is optional; users can log in with a password only."))

    def _fix_mfa_enforced(self):
        has_mail = self.env["ir.mail_server"].sudo().search_count([]) or self._is_odoo_sh() or "saas" in release.serie
        if not has_mail:
            raise UserError(_("Configure an outgoing mail server first. Enforced 2FA emails a login code to users "
                              "without an authenticator app; without mail they would be locked out."))
        installed_now = self._ensure_module("auth_totp_mail_enforce")
        self._set_param("auth_totp.policy", "employee_required", installed_now)
        return _("2FA is now required for all internal users."), installed_now

    def _check_password_policy(self):
        if not self._installed("auth_password_policy"):
            return result("fail", _("No password policy module installed."))
        length = int(self._param("auth_password_policy.minlength", 0) or 0)
        if length < MIN_PASSWORD_LENGTH:
            return result("warn", _("Minimum password length is %(n)s (target %(t)s).",
                                    n=length, t=MIN_PASSWORD_LENGTH))
        return result("pass", _("Minimum password length is %s.", length))

    def _fix_password_policy(self):
        installed_now = self._ensure_module("auth_password_policy")
        self._set_param("auth_password_policy.minlength", MIN_PASSWORD_LENGTH, installed_now)
        return _("Minimum password length set to %s characters.", MIN_PASSWORD_LENGTH), installed_now

    def _dormant_users(self):
        cutoff = fields.Datetime.now() - timedelta(days=DORMANT_DAYS)
        return self._internal_users().filtered(
            lambda u: u.id != SUPERUSER_ID and ((u.login_date or u.create_date) < cutoff))

    def _check_dormant_users(self):
        dormant = self._dormant_users()
        if dormant:
            return result("fail", _("%(n)s internal account(s) idle for more than %(d)s days: %(who)s",
                                    n=len(dormant), d=DORMANT_DAYS, who=listing(dormant.mapped("login"))))
        return result("pass", _("No internal account idle for more than %s days.", DORMANT_DAYS))

    def _fix_dormant_users(self):
        dormant = self._dormant_users() - self.env.user
        logins = listing(dormant.mapped("login"))
        dormant.sudo().write({"active": False})
        return _("Archived %(n)s dormant account(s): %(who)s. Unarchive from Settings > Users if needed.",
                 n=len(dormant), who=logins), False

    def _check_signup_open(self):
        if not self._installed("auth_signup"):
            return result("na", _("Self sign-up module not installed."))
        if self._param("auth_signup.invitation_scope") == "b2c":
            return result("fail", _("Anyone can create a portal account (free sign-up)."))
        return result("pass", _("Sign-up is by invitation only."))

    def _fix_signup_open(self):
        self._set_param("auth_signup.invitation_scope", "b2b", False)
        return _("Customer account sign-up switched to invitation only."), False

    def _check_api_keys(self):
        keys = self.env["res.users.apikeys"].sudo().search([])
        if not keys:
            return result("pass", _("No API keys issued."))
        cutoff = fields.Datetime.now() - timedelta(days=API_KEY_MAX_AGE_DAYS)
        inventory = listing(f"{k.name} ({k.user_id.login})" for k in keys)
        orphaned = keys.filtered(lambda k: not k.user_id.active)
        old = keys.filtered(lambda k: k.create_date < cutoff)
        if orphaned:
            return result("fail", _("%s API key(s) belong to archived users.", len(orphaned)), inventory)
        if old:
            return result("warn", _("%(n)s API key(s) older than %(d)s days; rotate them.",
                                    n=len(old), d=API_KEY_MAX_AGE_DAYS), inventory)
        return result("pass", _("%s API key(s), all recent and owned by active users.", len(keys)), inventory)

    # -- access control ------------------------------------------------------------

    def _check_custom_module_acl(self):
        custom = self._third_party_modules()
        if not custom:
            return result("na", _("No third-party modules installed."))
        xmlids = self.env["ir.model.data"].sudo().search(
            [("model", "=", "ir.model.access"), ("module", "in", custom.mapped("name"))])
        risky = self.env["ir.model.access"].sudo().browse(xmlids.mapped("res_id")).exists().filtered(
            lambda a: not a.group_id and (a.perm_write or a.perm_create or a.perm_unlink))
        if risky:
            return result("fail", _("%(n)s access rule(s) from custom modules grant write/delete to every user, "
                                    "portal and public included (no group): %(models)s.",
                                    n=len(risky), models=listing(risky.mapped("model_id.model"))),
                          listing(risky.mapped("model_id.model"), limit=100))
        return result("pass", _("Custom modules (%s) restrict write access to groups.", len(custom)))

    def _check_accounting_admins(self):
        if not self._installed("account"):
            return result("na", _("Accounting is not installed."))
        admins = self._group_users("account.group_account_manager")
        if len(admins) > MAX_ACCOUNTING_ADMINS:
            return result("warn", _("%(n)s accounting administrators (target <= %(m)s): %(who)s. Review that bill "
                                    "creation and payment approval are split between people.",
                                    n=len(admins), m=MAX_ACCOUNTING_ADMINS, who=listing(admins.mapped("login"))))
        return result("pass", _("%s accounting administrator(s).", len(admins)))

    # -- platform configuration --------------------------------------------------

    def _check_dbmanager_exposed(self):
        if config.get("list_db"):
            return result("fail", _("The database manager and database list are enabled (list_db = True). "
                                    "Anyone holding the master password can download or drop databases."))
        return result("pass", _("Database manager disabled (list_db = False)."))

    def _check_master_password(self):
        stored = config.get("admin_passwd") or ""
        if not stored:
            return result("pass", _("No master password set; database management is disabled."))
        weak = any(config.verify_admin_password(p) for p in WEAK_PASSWORDS)
        if weak:
            return result("fail", _("The master password is a common default."), severity="critical")
        if not stored.startswith("$"):
            return result("fail", _("The master password is stored in plain text in the config file."),
                          severity="high")
        return result("pass", _("Master password is hashed and not a known default."))

    def _check_dev_mode(self):
        if config.get("dev_mode"):
            return result("fail", _("Server runs with dev_mode = %s (auto-reload, detailed tracebacks).",
                                    ",".join(config["dev_mode"])))
        return result("pass", _("Developer mode is off server-wide."))

    def _check_workers(self):
        if self._is_odoo_sh():
            return result("na", _("Worker configuration is managed by Odoo.sh."))
        if not config.get("workers"):
            return result("warn", _("workers = 0: single process without memory/time limits; one heavy request "
                                    "can stall every user."))
        return result("pass", _("%s worker processes with limits.", config["workers"]))

    def _check_dbfilter(self):
        if self._is_odoo_sh() or config.get("dbfilter") or config.get("db_name"):
            return result("pass", _("Database selection is restricted."))
        return result("warn", _("No dbfilter: any database on the server can be selected by URL."))

    # -- encryption in transit -----------------------------------------------------

    def _check_https_base_url(self):
        url = self._param("web.base.url", "")
        if url.startswith("https://"):
            return result("pass", _("Base URL uses HTTPS: %s", url))
        if self._is_local(url):
            return result("warn", _("Base URL is local plain HTTP (%s); fine for testing only.", url),
                          severity="low")
        return result("fail", _("Base URL uses plain HTTP (%s); logins travel unencrypted.", url))

    def _check_mail_server_tls(self):
        servers = self.env["ir.mail_server"].sudo().search([])
        if not servers:
            return result("na", _("No custom outgoing mail server configured."))
        insecure = servers.filtered(lambda s: s.smtp_encryption == "none" and not self._is_local(f"://{s.smtp_host}"))
        if insecure:
            return result("fail", _("Mail server(s) without TLS: %s", listing(insecure.mapped("name"))))
        return result("pass", _("All %s outgoing mail server(s) use TLS.", len(servers)))

    # -- monitoring & operations ---------------------------------------------------

    def _check_cron_failures(self):
        failing = self.env["ir.cron"].sudo().search([("active", "=", True), ("failure_count", ">", 0)])
        if failing:
            return result("fail", _("%s scheduled action(s) failing: %s", len(failing),
                                    listing(f"{c.name} ({c.failure_count}x)" for c in failing)))
        return result("pass", _("No failing scheduled actions."))

    def _check_mail_queue(self):
        if "mail.mail" not in self.env:
            return result("na", _("Mail not installed."))
        stuck = self.env["mail.mail"].sudo().search_count([("state", "=", "exception")])
        if stuck:
            return result("warn", _("%s outgoing email(s) failed to send.", stuck))
        return result("pass", _("No failed outgoing emails."))

    # -- vulnerability management --------------------------------------------------

    def _check_version_support(self):
        serie = release.serie
        if "saas" in serie:
            return result("pass", _("Odoo Online (%s) is upgraded by Odoo.", serie))
        latest = int(self._param("shield.latest_odoo_major", 19))
        major = int(serie.split(".")[0])
        if major >= latest:
            return result("pass", _("Odoo %s is the latest major version.", serie))
        if major >= latest - 2:
            return result("warn", _("Odoo %(s)s is supported but %(n)s major version(s) behind %(l)s.0.",
                                    s=serie, n=latest - major, l=latest), severity="low")
        return result("fail", _("Odoo %s no longer receives security fixes.", serie), severity="critical")

    def _check_pending_module_upgrades(self):
        mods = self.env["ir.module.module"].sudo().search([("state", "in", ("installed", "to upgrade"))])
        stale = mods.filtered(lambda m: m.state == "to upgrade" or (
            m.installed_version and m.latest_version and m.installed_version != m.latest_version))
        if stale:
            return result("fail", _("%s module(s) have new code on disk that was never upgraded in the database: %s",
                                    len(stale), listing(stale.mapped("name"))))
        return result("pass", _("All module code matches the database (%s modules).", len(mods)))

    def _check_third_party_modules(self):
        custom = self._third_party_modules()
        if not custom:
            return result("pass", _("Only official Odoo modules installed."))
        return result("warn", _("%s third-party module(s) need security review and upgrade testing: %s",
                                len(custom), listing(custom.mapped("name"))))
