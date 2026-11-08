import hashlib
import json
import logging

from markupsafe import Markup

from odoo import _, api, fields, models, release
from odoo.exceptions import AccessError, UserError
from odoo.addons.base.models.ir_model import MODULE_UNINSTALL_FLAG

from .shield_control import SEVERITIES, SEVERITY_WEIGHT

_logger = logging.getLogger(__name__)

STATUSES = [("pass", "Pass"), ("warn", "Warning"), ("fail", "Fail"), ("na", "Not applicable"), ("error", "Error")]
GRADES = ((90, "A"), (75, "B"), (60, "C"), (40, "D"), (0, "F"))
GENESIS_HASH = "0" * 64
# Fields Odoo's mail mixin writes on a record without changing its evidence.
MAIL_FIELDS = {"message_ids", "message_follower_ids", "message_partner_ids", "message_main_attachment_id"}


def _sealed_error(env):
    return UserError(env._("Sealed assessments are evidence and cannot be changed or deleted."))


def _is_uninstall(env):
    # The flag is a context key, which RPC callers control; module uninstall always runs it as sudo.
    return env.su and bool(env.context.get(MODULE_UNINSTALL_FLAG))


def grade_for(score):
    return next(g for limit, g in GRADES if score >= limit)


class ShieldAssessment(models.Model):
    _name = "shield.assessment"
    _description = "Security Assessment"
    _inherit = ["mail.thread"]
    _order = "date desc, id desc"

    name = fields.Char(required=True, default=lambda self: self._default_name())
    date = fields.Datetime(default=fields.Datetime.now, readonly=True)
    user_id = fields.Many2one("res.users", string="Run by", default=lambda self: self.env.user, readonly=True)
    odoo_version = fields.Char(readonly=True)
    edition = fields.Char(readonly=True)
    result_ids = fields.One2many("shield.assessment.result", "assessment_id", string="Results")
    framework_score_ids = fields.One2many("shield.framework.score", "assessment_id", string="Framework compliance")
    security_score = fields.Float(readonly=True, aggregator="avg",
                                  help="Severity-weighted share of passing controls. Accepted risks count as failing.")
    grc_score = fields.Float(string="GRC compliance", readonly=True, aggregator="avg",
                             help="Average share of satisfied framework requirements. Valid risk acceptances count.")
    grade = fields.Char(readonly=True)
    pass_count = fields.Integer(readonly=True)
    warn_count = fields.Integer(readonly=True)
    fail_count = fields.Integer(readonly=True)
    na_count = fields.Integer(readonly=True)
    error_count = fields.Integer(readonly=True)
    critical_count = fields.Integer(string="Critical issues", readonly=True)
    content_hash = fields.Char(string="Seal (SHA-256)", readonly=True, copy=False)
    previous_hash = fields.Char(string="Previous seal", readonly=True, copy=False)
    control_snapshot = fields.Text(readonly=True, copy=False,
                                   help="Every control (archived too) with its severity at assessment time (JSON), "
                                        "so archiving or downgrading a control shows up in the sealed record.")
    privileged_snapshot = fields.Text(readonly=True, copy=False,
                                      help="Logins holding privileged groups at assessment time (JSON); "
                                           "the baseline for privilege-drift detection.")

    score_delta = fields.Float(compute="_compute_score_delta", digits=(5, 1),
                               help="Security score minus the previous assessment's. Empty for the first one.")
    has_previous = fields.Boolean(compute="_compute_score_delta")

    @api.model
    def _default_name(self):
        # A running number, not a time: the card already shows the exact date and time in the viewer's zone.
        return _("Assessment #%s", self.sudo().search_count([]) + 1)

    @api.depends("security_score")
    def _compute_score_delta(self):
        for rec in self:
            prev = self.search([("id", "<", rec.id)], order="id desc", limit=1) if rec.id else self.browse()
            rec.has_previous = bool(prev)
            rec.score_delta = rec.security_score - prev.security_score if prev else 0.0

    @api.model
    def action_run_assessment(self, *_ids):
        # The form button passes the current record id; the menu and RPC callers pass nothing.
        if not self.env.user.has_group("odoo_shield_warden.group_shield_manager"):
            raise AccessError(_("Only Shield managers can run assessments."))
        assessment = self._run()
        return {
            "type": "ir.actions.act_window", "res_model": self._name, "res_id": assessment.id,
            "view_mode": "form", "target": "current",
        }

    @api.model
    def _cron_run_assessment(self):
        self._run()

    @api.model
    def _run(self):
        lines = []
        for control in self.env["shield.control"].search([]):
            try:
                with self.env.cr.savepoint():
                    res = control._evaluate()
            except Exception as e:  # a broken check must not abort the assessment
                _logger.exception("Shield check %s failed", control.code)
                res = {"status": "error", "detail": f"{type(e).__name__}: {e}"}
            lines.append((0, 0, {
                "control_id": control.id, "status": res["status"],
                "severity": res.get("severity") or control.severity,
                "detail": res.get("detail", ""), "evidence": res.get("evidence", ""),
            }))
        edition = "Enterprise" if self.env["shield.check"]._installed("web_enterprise") else "Community"
        assessment = self.create({"result_ids": lines, "odoo_version": release.version, "edition": edition})
        assessment.result_ids._sync_findings()
        assessment._compute_scores()
        assessment._on_assessed()
        assessment._seal()
        return assessment

    def _on_assessed(self):
        """Attach data before the assessment is sealed. Extensions call super() and add theirs."""
        snapshot = json.dumps(self.env["shield.check"]._privileged_snapshot(), sort_keys=True)
        controls = sorted([c.code, c.active, c.severity, c.kind]
                          for c in self.env["shield.control"].with_context(active_test=False).search([]))
        previous = self.search([("control_snapshot", "!=", False), ("id", "!=", self.id)], order="id desc", limit=1)
        self.write({"privileged_snapshot": snapshot, "control_snapshot": json.dumps(controls)})
        if previous:
            before = {c[0]: c for c in json.loads(previous.control_snapshot)}
            now = {c[0]: c for c in controls}
            changed = [f"{code} ({before[code][1:]} -> {now[code][1:]})"
                       for code in now.keys() & before.keys() if now[code] != before[code]]
            changed += [f"{code} (added)" for code in now.keys() - before.keys()]
            changed += [f"{code} (removed)" for code in before.keys() - now.keys()]
            if changed:
                self.message_post(body=_("Control configuration changed since the last assessment: %s",
                                         "; ".join(sorted(changed))))

    # -- tamper-evident evidence chain --------------------------------------------

    def write(self, vals):
        if set(vals) - MAIL_FIELDS and self.filtered("content_hash"):
            raise _sealed_error(self.env)
        return super().write(vals)

    def unlink(self):
        if self.filtered("content_hash") and not _is_uninstall(self.env):
            raise _sealed_error(self.env)
        return super().unlink()

    def _hash_payload(self):
        """Canonical content covered by the seal. Extensions may add keys."""
        self.ensure_one()
        return {
            "name": self.name, "date": fields.Datetime.to_string(self.date),
            "odoo_version": self.odoo_version, "edition": self.edition,
            "security_score": self.security_score, "grc_score": self.grc_score,
            "results": sorted([r.control_id.code, r.status, r.severity, r.detail or "", r.evidence or ""]
                              for r in self.result_ids),
            "frameworks": sorted([f.framework_id.code, f.satisfied, f.applicable, f.percent]
                                 for f in self.framework_score_ids),
            # Only present from the version that introduced it, so older seals still verify.
            **({"privileged": self.privileged_snapshot} if self.privileged_snapshot else {}),
            **({"controls": self.control_snapshot} if self.control_snapshot else {}),
        }

    def _compute_hash(self, previous_hash):
        payload = json.dumps(self._hash_payload(), sort_keys=True, default=str, separators=(",", ":"))
        return hashlib.sha256(f"{previous_hash}|{payload}".encode()).hexdigest()

    def _seal(self):
        for assessment in self:
            previous = self.search([("content_hash", "!=", False), ("id", "!=", assessment.id)],
                                   order="id desc", limit=1)
            prev_hash = previous.content_hash or GENESIS_HASH
            assessment.write({"previous_hash": prev_hash, "content_hash": assessment._compute_hash(prev_hash)})
            assessment._send_seal_receipt()

    def _send_seal_receipt(self):
        """Email the seal outside the database, so a rewritten or deleted history can be proven."""
        recipients = self.env["ir.config_parameter"].sudo().get_param("shield.seal_recipients")
        if not recipients:
            return
        for assessment in self:
            body = Markup(
                "<p>Odoo Shield Warden sealed assessment <b>%s</b> (id %s) on %s.</p>"
                "<p>Seal: <code>%s</code><br/>Previous seal: <code>%s</code><br/>"
                "Security score %s, GRC compliance %s%%.</p>"
                "<p>Keep this email. To check the history later, run <i>Verify evidence chain</i> in Shield and compare "
                "this seal with the one shown for the same assessment id.</p>") % (
                assessment.name, assessment.id, fields.Datetime.to_string(assessment.date),
                assessment.content_hash, assessment.previous_hash, assessment.security_score, assessment.grc_score)
            self.env["mail.mail"].sudo().create({
                "subject": f"[Shield seal] {self.env.cr.dbname} #{assessment.id} {assessment.content_hash[:16]}",
                "email_to": recipients, "body_html": body, "auto_delete": False,
            })

    def action_verify_chain(self):
        """Recompute every seal up to this assessment; report the first break."""
        self.ensure_one()
        chain = self.search([("content_hash", "!=", False), ("id", "<=", self.id)], order="id asc")
        expected_prev = GENESIS_HASH
        for link in chain:
            if link.previous_hash != expected_prev or link._compute_hash(link.previous_hash) != link.content_hash:
                message = _("Evidence chain BROKEN at %(name)s (id %(id)s): its content or order was altered "
                            "after sealing.", name=link.name, id=link.id)
                self.message_post(body=message)
                return self._notify(message, "danger")
            expected_prev = link.content_hash
        message = _("Evidence chain intact: %(n)s sealed assessment(s) verified up to %(hash)s.",
                    n=len(chain), hash=self.content_hash[:16])
        self.message_post(body=message)
        return self._notify(message, "success")

    def _notify(self, message, kind):
        return {"type": "ir.actions.client", "tag": "display_notification",
                "params": {"message": message, "type": kind, "sticky": kind == "danger"}}

    def _compute_scores(self):
        frameworks = self.env["shield.framework"].search([])
        for assessment in self:
            results = assessment.result_ids
            scored = results.filtered(lambda r: r.status in ("pass", "warn", "fail"))
            total = sum(SEVERITY_WEIGHT[r.severity] for r in scored)
            earned = sum(SEVERITY_WEIGHT[r.severity] * {"pass": 1, "warn": 0.5}.get(r.status, 0) for r in scored)
            security = round(100.0 * earned / total, 1) if total else 100.0

            by_control = {r.control_id.id: r for r in results}
            fw_lines = []
            for fw in frameworks:
                applicable = satisfied = 0
                for req in fw.requirement_ids:
                    rs = [by_control[c.id] for c in req.control_ids if c.id in by_control]
                    rs = [r for r in rs if r.status != "na"]
                    if not rs:
                        continue
                    applicable += 1
                    if all(r.status == "pass" or (r.finding_id and r.finding_id._is_accepted()) for r in rs):
                        satisfied += 1
                pct = round(100.0 * satisfied / applicable, 1) if applicable else 100.0
                fw_lines.append((0, 0, {"framework_id": fw.id, "applicable": applicable,
                                        "satisfied": satisfied, "percent": pct}))
            grc = round(sum(line[2]["percent"] for line in fw_lines) / len(fw_lines), 1) if fw_lines else 100.0

            counts = {s: len(results.filtered(lambda r, s=s: r.status == s)) for s, _label in STATUSES}
            assessment.write({
                "security_score": security, "grc_score": grc, "grade": grade_for(security),
                "framework_score_ids": [(5, 0, 0)] + fw_lines,
                "pass_count": counts["pass"], "warn_count": counts["warn"], "fail_count": counts["fail"],
                "na_count": counts["na"], "error_count": counts["error"],
                "critical_count": len(results.filtered(lambda r: r.status == "fail" and r.severity == "critical")),
            })
            assessment.message_post(body=_("Security score %(s)s (%(g)s), GRC compliance %(c)s%%.",
                                           s=security, g=grade_for(security), c=grc))

    def top_fixes(self, limit=3):
        """Highest-impact open issues, for the scorecard."""
        self.ensure_one()
        failing = self.result_ids.filtered(lambda r: r.status in ("fail", "warn"))
        return failing.sorted(lambda r: (-SEVERITY_WEIGHT[r.severity] * (1 if r.status == "fail" else 0.5),
                                         r.control_id.sequence))[:limit]

    def action_print_scorecard(self):
        return self.env.ref("odoo_shield_warden.action_report_scorecard").report_action(self)


class ShieldAssessmentResult(models.Model):
    _name = "shield.assessment.result"
    _description = "Assessment Result"
    _order = "status_rank, severity_rank, id"

    assessment_id = fields.Many2one("shield.assessment", required=True, ondelete="cascade", index=True)
    control_id = fields.Many2one("shield.control", required=True, ondelete="cascade")
    name = fields.Char(related="control_id.name")
    domain = fields.Selection(related="control_id.domain", store=True)
    kind = fields.Selection(related="control_id.kind")
    framework_refs = fields.Char(related="control_id.framework_refs")
    status = fields.Selection(STATUSES, required=True)
    severity = fields.Selection(SEVERITIES, required=True)
    status_rank = fields.Integer(compute="_compute_ranks", store=True)
    severity_rank = fields.Integer(compute="_compute_ranks", store=True)
    detail = fields.Text()
    evidence = fields.Text()
    finding_id = fields.Many2one("shield.finding")

    def _check_unsealed(self):
        if self.assessment_id.filtered("content_hash") and not _is_uninstall(self.env):
            raise _sealed_error(self.env)

    @api.model_create_multi
    def create(self, vals_list):
        sealed = self.env["shield.assessment"].browse([v["assessment_id"] for v in vals_list if v.get("assessment_id")])
        if sealed.filtered("content_hash"):
            raise _sealed_error(self.env)
        return super().create(vals_list)

    def write(self, vals):
        self._check_unsealed()
        return super().write(vals)

    def unlink(self):
        self._check_unsealed()
        return super().unlink()

    @api.depends("status", "severity")
    def _compute_ranks(self):
        status_order = {"fail": 0, "error": 1, "warn": 2, "pass": 3, "na": 4}
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        for r in self:
            r.status_rank = status_order.get(r.status, 9)
            r.severity_rank = sev_order.get(r.severity, 9)

    def _sync_findings(self):
        Finding = self.env["shield.finding"].sudo()
        now = fields.Datetime.now()
        for r in self:
            finding = Finding.search([("control_id", "=", r.control_id.id)], limit=1)
            if r.status in ("fail", "warn"):
                vals = {"status": r.status, "severity": r.severity, "detail": r.detail, "evidence": r.evidence,
                        "last_seen": now, "last_assessment_id": r.assessment_id.id}
                if not finding:
                    finding = Finding.create({**vals, "control_id": r.control_id.id, "first_seen": now})
                else:
                    if finding.state == "resolved":
                        vals.update(state="open", resolved_date=False)
                        finding.message_post(body=_("Regression: control failed again in %s.", r.assessment_id.name))
                    finding.write(vals)
            elif r.status in ("pass", "na") and finding and finding.state != "resolved":
                finding.write({"state": "resolved", "resolved_date": now, "detail": r.detail,
                               "last_assessment_id": r.assessment_id.id})
                finding.message_post(body=_("Resolved automatically: control passed in %s.", r.assessment_id.name))
            r.finding_id = finding


class ShieldFrameworkScore(models.Model):
    _name = "shield.framework.score"
    _description = "Framework Compliance Score"
    _order = "framework_id"

    assessment_id = fields.Many2one("shield.assessment", required=True, ondelete="cascade")
    framework_id = fields.Many2one("shield.framework", required=True, ondelete="cascade")
    applicable = fields.Integer(string="Applicable requirements")
    satisfied = fields.Integer(string="Satisfied")
    percent = fields.Float(string="Compliance %")

    def _check_unsealed(self):
        if self.assessment_id.filtered("content_hash") and not _is_uninstall(self.env):
            raise _sealed_error(self.env)

    @api.model_create_multi
    def create(self, vals_list):
        sealed = self.env["shield.assessment"].browse([v["assessment_id"] for v in vals_list if v.get("assessment_id")])
        if sealed.filtered("content_hash"):
            raise _sealed_error(self.env)
        return super().create(vals_list)

    def write(self, vals):
        self._check_unsealed()
        return super().write(vals)

    def unlink(self):
        self._check_unsealed()
        return super().unlink()


class ShieldRunWizard(models.TransientModel):
    """Confirm step for the Run Assessment menu: opening a menu must not write to the evidence chain."""
    _name = "shield.run.wizard"
    _description = "Run assessment (confirmation)"

    last_run = fields.Char(readonly=True, default=lambda self: self._default_last_run())

    @api.model
    def _default_last_run(self):
        last = self.env["shield.assessment"].search([], order="create_date desc, id desc", limit=1)
        return _("Last assessment: %s.", last.name) if last else _("No assessment has run yet.")

    def action_confirm(self):
        return self.env["shield.assessment"].action_run_assessment()
