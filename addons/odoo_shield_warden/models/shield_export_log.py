from odoo import fields, models


class ShieldExportLog(models.Model):
    """Who exported how many records of which model. Odoo keeps no record of exports by default."""

    _name = "shield.export.log"
    _description = "Data Export Log"
    _order = "create_date desc"
    _log_access = True

    user_id = fields.Many2one("res.users", required=True, default=lambda self: self.env.user, readonly=True)
    model = fields.Char(required=True, readonly=True, index=True)
    record_count = fields.Integer(readonly=True)
    exported_fields = fields.Char(readonly=True)


class Base(models.AbstractModel):
    _inherit = "base"

    def export_data(self, fields_to_export):
        res = super().export_data(fields_to_export)
        if self and self._name != "shield.export.log":
            self.env["shield.export.log"].sudo().create({
                "user_id": self.env.uid, "model": self._name, "record_count": len(self),
                "exported_fields": ", ".join(fields_to_export)[:500],
            })
        return res
