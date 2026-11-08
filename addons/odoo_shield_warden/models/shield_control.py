from odoo import api, fields, models

DOMAINS = [
    ("identity", "Identity & Authentication"),
    ("access", "Access Control"),
    ("platform", "Platform Configuration"),
    ("crypto", "Encryption in Transit"),
    ("operations", "Monitoring & Operations"),
    ("vulnerability", "Vulnerability Management"),
    ("resilience", "Backup & Resilience"),
    ("governance", "Governance"),
    ("finance", "Financial Controls"),
]
SEVERITIES = [("critical", "Critical"), ("high", "High"), ("medium", "Medium"), ("low", "Low")]
SEVERITY_WEIGHT = {"critical": 10, "high": 6, "medium": 3, "low": 1}
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


class ShieldControl(models.Model):
    _name = "shield.control"
    _description = "Security Control"
    _order = "sequence, code"

    code = fields.Char(required=True, help="Technical code; maps to _check_<code> and _fix_<code>.")
    name = fields.Char(required=True)
    sequence = fields.Integer(default=10)
    active = fields.Boolean(default=True)
    domain = fields.Selection(DOMAINS, required=True)
    severity = fields.Selection(SEVERITIES, required=True, default="medium")
    kind = fields.Selection(
        [("automated", "Automated check"), ("manual", "Manual attestation")], required=True, default="automated")
    description = fields.Text()
    remediation = fields.Text()
    attestation_validity_days = fields.Integer(default=90, help="How long a manual attestation stays valid.")
    requirement_ids = fields.Many2many(
        "shield.requirement", "shield_control_requirement_rel", "control_id", "requirement_id",
        string="Framework requirements")
    framework_refs = fields.Char(compute="_compute_framework_refs")
    has_fix = fields.Boolean(compute="_compute_has_fix", string="One-click fix")
    attestation_ids = fields.One2many("shield.attestation", "control_id")
    finding_ids = fields.One2many("shield.finding", "control_id")

    _sql_constraints = [("code_uniq", "unique(code)", "Control code must be unique.")]

    @api.depends("requirement_ids")
    def _compute_framework_refs(self):
        for control in self:
            control.framework_refs = ", ".join(
                f"{r.framework_id.code} {r.ref}" for r in control.requirement_ids.sorted("framework_id"))

    def _compute_has_fix(self):
        check = self.env["shield.check"]
        for control in self:
            control.has_fix = hasattr(check, f"_fix_{control.code}")

    def _evaluate(self):
        """Run this control and return {status, detail, evidence[, severity]}."""
        self.ensure_one()
        check = self.env["shield.check"]
        if self.kind == "manual":
            return check._attestation_result(self)
        method = getattr(check, f"_check_{self.code}", None)
        if not method:
            return {"status": "error", "detail": f"No check implemented for '{self.code}'."}
        return method()
