"""Payment hold: from detecting vendor-bank fraud to preventing it.

With ``shield.payment_hold`` = ``enforce``, an outbound payment cannot be posted to a bank account whose
current number was set or changed in the last ``shield.payment_hold_days`` days (default 30), or that
Shield flagged, until someone OTHER than the person who set the number verifies it. Odoo's own
"trusted account" switch can be flipped by the same person who changed the IBAN; this cannot.
"""

from datetime import timedelta

from odoo import SUPERUSER_ID, _, fields, models
from odoo.exceptions import AccessError, UserError

from .shield_risk_event import ACTIVE_STATES

FLAGGING_RULES = ("untracked_bank_change", "shared_bank_account", "lookalike_vendor")


class ResPartnerBank(models.Model):
    _inherit = "res.partner.bank"

    shield_verified_hash = fields.Char(copy=False, readonly=True)
    shield_verified_by = fields.Many2one("res.users", string="Verified by (Shield)", copy=False, readonly=True)
    shield_verified_on = fields.Datetime(string="Verified on (Shield)", copy=False, readonly=True)
    shield_hold_reason = fields.Char(string="Shield payment hold", compute="_compute_shield_hold_reason")

    def _compute_shield_hold_reason(self):
        for bank in self:
            bank.shield_hold_reason = bank._shield_hold_reason() or False

    def _shield_last_setter(self):
        """(date, user) of the most recent creation or number change, from both audit-trail sources."""
        rows = self.env["shield.check"]._account_changes(self.sudo()).get(self.id, [])
        if not rows:
            return self.create_date, self.create_uid
        date, user, _kind = max(rows, key=lambda r: r[0])
        return date, user

    def _shield_hold_reason(self):
        self.ensure_one()
        params = self.env["ir.config_parameter"].sudo()
        if params.get_param("shield.payment_hold", "off") != "enforce":
            return None
        check = self.env["shield.check"]
        if self.shield_verified_hash and self.shield_verified_hash == check._acc_digest(self.sudo()):
            return None
        flagged = self.env["shield.risk.event"].sudo().search_count([
            ("bank_id", "=", self.id), ("rule", "in", FLAGGING_RULES), ("state", "in", ACTIVE_STATES)])
        if flagged:
            return _("Shield flagged this bank account (%s open alert(s))", flagged)
        days = int(params.get_param("shield.payment_hold_days", 30) or 30)
        date, user = self._shield_last_setter()
        if date and fields.Datetime.now() - date <= timedelta(days=days):
            return _("the account number was set by %(who)s on %(date)s and has not been verified by a second person",
                     who=user.login, date=fields.Date.to_string(date.date()))
        return None

    def action_shield_verify(self):
        """Second-person verification of the current account number."""
        for bank in self:
            if not (self.env.user.has_group("account.group_validate_bank_account")
                    or self.env.user.has_group("odoo_shield_warden.group_shield_manager")):
                raise AccessError(_("You need the 'Validate bank account' right to verify bank accounts."))
            _date, setter = bank._shield_last_setter()
            if setter == self.env.user and self.env.uid != SUPERUSER_ID:
                raise AccessError(_("You set this account number yourself; a second person must verify it."))
            bank.sudo().write({"shield_verified_hash": self.env["shield.check"]._acc_digest(bank.sudo()),
                               "shield_verified_by": self.env.uid, "shield_verified_on": fields.Datetime.now()})
            note = _("Account %(acc)s verified by %(who)s (second person) for Shield's payment hold.",
                     acc=bank.acc_number, who=self.env.user.name)
            # Always leave the trail, even if the verifier has no rights on contacts; keep them as author.
            author = self.env.user.partner_id.id
            bank.sudo().message_post(body=note, author_id=author)
            bank.partner_id.sudo().message_post(body=note, author_id=author)
        return True


class AccountPayment(models.Model):
    _inherit = "account.payment"

    def action_post(self):
        for payment in self:
            if payment.payment_type == "outbound" and payment.partner_bank_id:
                reason = payment.partner_bank_id._shield_hold_reason()
                if reason:
                    raise UserError(_(
                        "Payment %(pay)s to %(vendor)s is held by Odoo Shield Warden: %(reason)s.\n\nAsk a colleague "
                        "to call the vendor on a number you already had, then click 'Verify with Shield' on the "
                        "bank account.", pay=payment.name or _("(draft)"), vendor=payment.partner_id.display_name,
                        reason=reason))
        return super().action_post()
