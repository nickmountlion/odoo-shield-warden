from odoo import fields, models

from odoo.addons.odoo_shield_warden.models.shield_control import SEVERITIES

COMBOS = [
    ("redirect_and_pay", "Redirect & Pay"),
    ("escalate_and_pay", "Escalate & Pay"),
    ("bill_and_pay", "Bill & Pay"),
]


class ShieldAccessConflict(models.Model):
    """Snapshot, per assessment, of a user holding a toxic combination of effective rights."""

    _name = "shield.access.conflict"
    _description = "Access Conflict"
    _order = "severity_rank, exposure desc"

    assessment_id = fields.Many2one("shield.assessment", required=True, ondelete="cascade", index=True)
    user_id = fields.Many2one("res.users", required=True, ondelete="cascade")
    combo = fields.Selection(COMBOS, required=True)
    severity = fields.Selection(SEVERITIES, required=True)
    severity_rank = fields.Integer()
    capabilities = fields.Char(help="The effective rights that combine into this conflict.")
    payment_count = fields.Integer(string="Payments (12 months)")
    company_id = fields.Many2one("res.company", default=lambda self: self.env.company)
    currency_id = fields.Many2one(related="company_id.currency_id")
    exposure = fields.Monetary(string="Paid by this user (12 months)",
                               help="Outbound payments this user created in the last 12 months: "
                                    "the money that passed through the conflict.")
