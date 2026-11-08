from datetime import timedelta

from odoo import _, api, fields, models
from odoo.exceptions import AccessError, UserError

from .shield_control import SEVERITIES, SEVERITY_RANK

MAX_ACCEPTANCE_DAYS = 365


class ShieldFinding(models.Model):
    """One persistent finding per control: the risk register entry."""

    _name = "shield.finding"
    _description = "Security Finding"
    _inherit = ["mail.thread", "mail.activity.mixin"]
    _order = "state_rank, severity_rank, id"

    control_id = fields.Many2one("shield.control", required=True, ondelete="cascade", index=True)
    name = fields.Char(related="control_id.name", store=True)
    domain = fields.Selection(related="control_id.domain", store=True)
    framework_refs = fields.Char(related="control_id.framework_refs")
    remediation = fields.Text(related="control_id.remediation")
    has_fix = fields.Boolean(related="control_id.has_fix")
    severity = fields.Selection(SEVERITIES, required=True, tracking=True)
    severity_rank = fields.Integer(compute="_compute_ranks", store=True)
    status = fields.Selection([("fail", "Failed"), ("warn", "Warning")], required=True)
    state = fields.Selection(
        [("open", "Open"), ("in_progress", "In progress"), ("accepted", "Risk accepted"), ("resolved", "Resolved")],
        default="open", required=True, tracking=True)
    state_rank = fields.Integer(compute="_compute_ranks", store=True)
    detail = fields.Text()
    evidence = fields.Text()
    user_id = fields.Many2one("res.users", string="Owner", tracking=True)
    due_date = fields.Date(tracking=True)
    acceptance_reason = fields.Text(tracking=True)
    acceptance_expiry = fields.Date(tracking=True)
    accepted_by = fields.Many2one("res.users", readonly=True)
    first_seen = fields.Datetime(readonly=True)
    last_seen = fields.Datetime(readonly=True)
    resolved_date = fields.Datetime(readonly=True)
    last_assessment_id = fields.Many2one("shield.assessment", readonly=True)

    _sql_constraints = [("control_uniq", "unique(control_id)", "There is one finding per control.")]

    @api.depends("severity", "state")
    def _compute_ranks(self):
        order = {"open": 0, "in_progress": 1, "accepted": 2, "resolved": 3}
        for finding in self:
            finding.severity_rank = SEVERITY_RANK.get(finding.severity, 9)
            finding.state_rank = order.get(finding.state, 9)

    def _is_accepted(self):
        self.ensure_one()
        return self.state == "accepted" and (
            not self.acceptance_expiry or self.acceptance_expiry >= fields.Date.context_today(self))

    def _check_manager(self):
        if not self.env.user.has_group("odoo_shield_warden.group_shield_manager"):
            raise AccessError(_("Only Shield managers can change the risk register."))

    def action_start(self):
        self._check_manager()
        self.filtered(lambda f: f.state == "open").write({"state": "in_progress"})

    def action_accept_risk(self):
        self._check_manager()
        today = fields.Date.context_today(self)
        for finding in self:
            if not finding.acceptance_reason or not finding.acceptance_expiry:
                raise UserError(_("Give a justification and an expiry date before accepting a risk."))
            if finding.acceptance_expiry > today + timedelta(days=MAX_ACCEPTANCE_DAYS):
                raise UserError(_("A risk can be accepted for at most %s days.", MAX_ACCEPTANCE_DAYS))
            if finding.severity == "critical" and not self.env.user.has_group("base.group_system"):
                raise AccessError(_("Only an administrator can accept a critical risk."))
        self.write({"state": "accepted", "accepted_by": self.env.user.id})

    def action_reopen(self):
        self._check_manager()
        self.write({"state": "open", "accepted_by": False})

    def action_apply_fix(self):
        self.ensure_one()
        if not self.env.user.has_group("base.group_system"):
            raise AccessError(_("Only administrators can apply hardening changes."))
        method = getattr(self.env["shield.check"], f"_fix_{self.control_id.code}", None)
        if not method:
            raise UserError(_("No automatic fix exists for this control."))
        message, needs_reload = method()
        self.message_post(body=_("Hardening applied by %(user)s: %(msg)s", user=self.env.user.name, msg=message))
        if needs_reload:
            return {"type": "ir.actions.client", "tag": "reload"}
        self._recheck()
        return True

    def action_recheck(self):
        for finding in self:
            finding._recheck()

    def _recheck(self):
        self.ensure_one()
        res = self.control_id._evaluate()
        if res["status"] in ("pass", "na"):
            self.write({"state": "resolved", "resolved_date": fields.Datetime.now(), "detail": res["detail"]})
        elif res["status"] in ("fail", "warn"):
            self.write({"status": res["status"], "detail": res["detail"], "evidence": res.get("evidence", ""),
                        "last_seen": fields.Datetime.now()})

    @api.model
    def _cron_expire_acceptances(self):
        today = fields.Date.context_today(self)
        for finding in self.search([("state", "=", "accepted"), ("acceptance_expiry", "<", today)]):
            finding.write({"state": "open", "accepted_by": False})
            finding.message_post(body=_("Risk acceptance expired on %s; finding reopened.", finding.acceptance_expiry))
