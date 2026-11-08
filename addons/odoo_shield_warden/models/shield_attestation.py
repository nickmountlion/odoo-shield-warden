from datetime import timedelta

from odoo import api, fields, models


class ShieldAttestation(models.Model):
    _name = "shield.attestation"
    _description = "Control Attestation"
    _inherit = ["mail.thread"]
    _order = "date desc, id desc"

    control_id = fields.Many2one(
        "shield.control", required=True, ondelete="cascade", domain=[("kind", "=", "manual")], tracking=True)
    result = fields.Selection(
        [("compliant", "Compliant"), ("non_compliant", "Not compliant")],
        required=True, default="compliant", tracking=True)
    date = fields.Date(required=True, default=fields.Date.context_today, tracking=True)
    valid_until = fields.Date(compute="_compute_valid_until", store=True, readonly=False, tracking=True)
    attested_by = fields.Many2one("res.users", required=True, default=lambda self: self.env.user, tracking=True)
    evidence = fields.Html(help="What was checked, how, and where the evidence lives.")
    attachment_ids = fields.Many2many("ir.attachment", string="Evidence files")
    is_valid = fields.Boolean(compute="_compute_is_valid")

    @api.depends("date", "control_id.attestation_validity_days")
    def _compute_valid_until(self):
        for att in self:
            if att.date:
                att.valid_until = att.date + timedelta(days=att.control_id.attestation_validity_days or 90)

    def _compute_is_valid(self):
        today = fields.Date.context_today(self)
        for att in self:
            att.is_valid = att.result == "compliant" and bool(att.valid_until) and att.valid_until >= today

    @api.depends("control_id", "date")
    def _compute_display_name(self):
        for att in self:
            att.display_name = f"{att.control_id.name} ({att.date})"
