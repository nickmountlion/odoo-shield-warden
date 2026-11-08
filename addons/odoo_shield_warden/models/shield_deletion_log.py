from odoo import api, fields, models
from odoo.tools import html2plaintext

# Chatter on these models is audit trail: bank details, money, people and rights.
WATCHED_MODELS = ("res.partner", "res.partner.bank", "account.move", "account.payment", "hr.employee",
                  "res.users", "purchase.order", "sale.order")


class ShieldDeletionLog(models.Model):
    """Every deleted chatter message on audit-relevant records. Odoo keeps no trace of deletions."""

    _name = "shield.deletion.log"
    _description = "Deleted Audit-Trail Message"
    _order = "create_date desc"

    deleted_by = fields.Many2one("res.users", required=True, readonly=True)
    res_model = fields.Char(required=True, readonly=True, index=True)
    res_id = fields.Integer(readonly=True)
    message_date = fields.Datetime(readonly=True)
    message_author = fields.Char(readonly=True)
    summary = fields.Char(readonly=True, help="First characters of the deleted message.")
    had_tracking = fields.Boolean(readonly=True, help="The message recorded field changes (e.g. an IBAN/CBU change).")
    record_still_exists = fields.Boolean(compute="_compute_record_still_exists", store=True,
                                         help="The message was removed from a live record: a cover-up, not cleanup.")

    @api.depends("res_model", "res_id")
    def _compute_record_still_exists(self):
        for log in self:
            model = self.env.get(log.res_model)
            log.record_still_exists = bool(model is not None and model.sudo().browse(log.res_id).exists())


class MailMessage(models.Model):
    _inherit = "mail.message"

    def unlink(self):
        watched = self.filtered(lambda m: m.model in WATCHED_MODELS and m.res_id)
        if watched:
            self.env["shield.deletion.log"].sudo().create([{
                "deleted_by": self.env.uid, "res_model": m.model, "res_id": m.res_id, "message_date": m.date,
                "message_author": m.author_id.display_name or "",
                "summary": (html2plaintext(m.body or "") or m.subject or "")[:180],
                "had_tracking": bool(m.sudo().tracking_value_ids),
            } for m in watched])
        return super().unlink()
