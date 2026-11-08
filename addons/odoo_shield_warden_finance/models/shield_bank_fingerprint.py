from odoo import fields, models


class ShieldBankFingerprint(models.Model):
    """Shield's own record of each bank account number, independent of Odoo's chatter.

    If an account number changes without any log entry (direct SQL, a module bypassing write(), deleted
    chatter), the next assessment sees that it no longer matches the fingerprint.
    """

    _name = "shield.bank.fingerprint"
    _description = "Bank Account Fingerprint"

    bank_id = fields.Many2one("res.partner.bank", required=True, ondelete="cascade", index=True)
    acc_hash = fields.Char(required=True, help="SHA-256 of the normalized account number.")
    last_seen = fields.Datetime(required=True)

    _sql_constraints = [("bank_uniq", "unique(bank_id)", "One fingerprint per bank account.")]
