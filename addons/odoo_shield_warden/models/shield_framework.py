from odoo import api, fields, models


class ShieldFramework(models.Model):
    _name = "shield.framework"
    _description = "Compliance Framework"
    _order = "sequence, id"

    name = fields.Char(required=True)
    code = fields.Char(required=True)
    version = fields.Char()
    sequence = fields.Integer(default=10)
    requirement_ids = fields.One2many("shield.requirement", "framework_id", string="Requirements")

    _sql_constraints = [("code_uniq", "unique(code)", "Framework code must be unique.")]


class ShieldRequirement(models.Model):
    _name = "shield.requirement"
    _description = "Framework Requirement"
    _order = "framework_id, ref"
    _rec_names_search = ["ref", "name"]

    framework_id = fields.Many2one("shield.framework", required=True, ondelete="cascade")
    ref = fields.Char(string="Reference", required=True)
    name = fields.Char(required=True)
    control_ids = fields.Many2many(
        "shield.control", "shield_control_requirement_rel", "requirement_id", "control_id", string="Controls")

    @api.depends("ref", "name", "framework_id.code")
    def _compute_display_name(self):
        for req in self:
            req.display_name = f"{req.framework_id.code} {req.ref} {req.name}"
