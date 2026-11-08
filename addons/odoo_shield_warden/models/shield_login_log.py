"""Login attempts, kept in the database.

Odoo only writes failed logins to the server log and keeps its cooldown counters in memory, so brute force,
password spraying and the one success that follows them leave no queryable trace. Shield records every
failure and the successes that follow recent failures (not every success: API integrations authenticate
on each call).
"""

import logging
from datetime import timedelta

from odoo import SUPERUSER_ID, api, fields, models
from odoo.exceptions import AccessDenied
from odoo.http import request

_logger = logging.getLogger(__name__)
SUCCESS_AFTER_FAILURES_WINDOW = timedelta(hours=24)


class ShieldLoginLog(models.Model):
    _name = "shield.login.log"
    _description = "Login Attempt"
    _order = "create_date desc"

    login = fields.Char(required=True, readonly=True, index=True)
    ip = fields.Char(string="IP address", readonly=True, index=True)
    success = fields.Boolean(readonly=True)

    @api.model
    def _record(self, login, ip, success):
        """Store one attempt. Successes are kept only when they follow recent failures for that login."""
        if success and not self.search_count([
                ("login", "=", login), ("success", "=", False),
                ("create_date", ">=", fields.Datetime.now() - SUCCESS_AFTER_FAILURES_WINDOW)]):
            return self.browse()
        return self.create({"login": (login or "")[:200], "ip": ip, "success": success})


class ResUsers(models.Model):
    _inherit = "res.users"

    @classmethod
    def _login(cls, db, credential, user_agent_env):
        login = credential.get("login") if isinstance(credential, dict) else None
        ip = request.httprequest.environ.get("REMOTE_ADDR") if request else "n/a"
        try:
            result = super()._login(db, credential, user_agent_env)
        except AccessDenied:
            cls._shield_log_login(login, ip, False)
            raise
        cls._shield_log_login(login, ip, True)
        return result

    @classmethod
    def _shield_log_login(cls, login, ip, success):
        if not login:
            return
        try:
            # Own cursor: the failed login's transaction is rolled back, the evidence must not be.
            with cls.pool.cursor() as cr:
                env = api.Environment(cr, SUPERUSER_ID, {})
                if "shield.login.log" in env:
                    env["shield.login.log"]._record(login, ip, success)
        except Exception:  # logging must never break authentication
            _logger.exception("Shield could not record a login attempt")
