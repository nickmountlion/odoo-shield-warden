from odoo import api, fields, models

from odoo.addons.odoo_shield_warden.models.shield_control import SEVERITY_WEIGHT

from markupsafe import Markup, escape

from .shield_risk_event import ACTIVE_STATES
from .shield_rosi import DEFAULT_ANNUAL_PRICE, ROSI_SCENARIOS, rosi_calc


class ShieldAssessment(models.Model):
    _inherit = "shield.assessment"

    conflict_ids = fields.One2many("shield.access.conflict", "assessment_id", string="Access conflicts")
    company_id = fields.Many2one("res.company", default=lambda self: self.env.company, readonly=True)
    currency_id = fields.Many2one(related="company_id.currency_id")
    access_exposure = fields.Monetary(
        string="Paid through conflicted users", readonly=True,
        help="Outbound payments (12 months) created by users who hold a toxic combination of rights.")
    transaction_exposure = fields.Monetary(
        string="Money at risk", readonly=True,
        help="Distinct payments and bills behind unresolved money-at-risk events.")
    risk_event_count = fields.Integer(string="Alerts to review", readonly=True)
    case_count = fields.Integer(string="Cases to review", readonly=True,
                                help="Alerts grouped per bank account, payment or bill.")

    def _on_assessed(self):
        super()._on_assessed()
        check = self.env["shield.check"]
        self.env["shield.risk.case"]._rebuild()
        events = self.env["shield.risk.event"].sudo().search([("state", "in", ACTIVE_STATES)])
        cases = self.env["shield.risk.case"].sudo().search_count([("state", "in", ACTIVE_STATES)])
        # Several rules can flag the same money: count each payment once, then unpaid bills.
        per_document = {}
        for event in events:
            if event.payment_ids:
                for pay in event.payment_ids:
                    per_document[("pay", pay.id)] = abs(pay.amount_company_currency_signed)
            elif event.move_id:
                per_document.setdefault(("move", event.move_id.id), event.amount)
            else:
                per_document[("event", event.id)] = event.amount
        for assessment in self:
            conflicts = check._sod_conflicts()
            per_user = {c["user_id"]: c["exposure"] for c in conflicts}
            assessment.write({
                "conflict_ids": [(5, 0, 0)] + [(0, 0, c) for c in conflicts],
                "access_exposure": sum(per_user.values()),
                "transaction_exposure": sum(per_document.values()),
                "risk_event_count": len(events),
                "case_count": cases,
            })

    rosi_html = fields.Html(string="Return on security investment", compute="_compute_rosi_html", sanitize=False)

    def rosi_scenarios(self):
        """ROSI per scenario, treating the money at risk as the loss that could recur once a year.

        Not part of the evidence seal: it depends on a price and on estimates that the customer may change.
        """
        self.ensure_one()
        price = float(self.env["ir.config_parameter"].sudo().get_param("shield.rosi_annual_price", DEFAULT_ANNUAL_PRICE)
                      or DEFAULT_ANNUAL_PRICE)
        rows = []
        for key, label, prob, recovered, effectiveness, labour in ROSI_SCENARIOS:
            row = rosi_calc(self.transaction_exposure, prob, recovered, effectiveness, price + labour)
            rows.append(dict(
                row, key=key, label=label, probability=prob, cost=price + labour, price=price,
                rosi_text="n/a" if row["rosi"] is None else "{:.0f}%".format(row["rosi"] * 100),
                breakeven_text=("n/a" if row["breakeven_probability"] is None
                                else "{:.0f}%".format(row["breakeven_probability"] * 100))))
        return rows

    @api.depends("transaction_exposure")
    def _compute_rosi_html(self):
        for rec in self:
            if not rec.transaction_exposure:
                rec.rosi_html = False
                continue
            fmt = rec.currency_id.format
            scenarios = rec.rosi_scenarios()
            cells = []
            for r in scenarios:
                cells.append(Markup("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>") % (
                    r["label"], fmt(r["cost"]), fmt(r["net"]), r["rosi_text"], r["breakeven_text"]))
            rec.rosi_html = Markup(
                "<table class='table table-sm'><thead><tr><th>Scenario</th><th>Annual cost</th><th>Net benefit / yr</th>"
                "<th>ROSI</th><th>Break-even annual chance</th></tr></thead><tbody>%s</tbody></table>"
                "<p class='text-muted small'>If a loss of %s recurs once a year. Cost = Shield licence (%s) + alert-review "
                "labour. Probability, recovery, hold effectiveness and labour are estimates, not benchmarks.</p>"
            ) % (Markup("").join(cells), escape(fmt(rec.transaction_exposure)), escape(fmt(scenarios[0]["price"])))

    def open_cases(self, limit=8):
        """Largest open cases, for the scorecard."""
        return self.env["shield.risk.case"].sudo().search([("state", "in", ACTIVE_STATES)],
                                                          order="severity_rank, amount desc", limit=limit)

    def top_fixes(self, limit=3):
        """Within the same severity, money already moving beats configuration gaps."""
        self.ensure_one()
        failing = self.result_ids.filtered(lambda r: r.status in ("fail", "warn"))
        if self.case_count:
            # Transaction alerts are already shown as cases; the fixes list is for things to change.
            failing = failing.filtered(lambda r: not r.control_id.code.startswith("ccm_"))
        return failing.sorted(lambda r: (
            -SEVERITY_WEIGHT[r.severity] * (1 if r.status == "fail" else 0.5),
            0 if r.control_id.code.startswith("ccm_") else 1 if r.domain == "finance" else 2,
            r.control_id.sequence))[:limit]

    def _hash_payload(self):
        payload = super()._hash_payload()
        payload["money"] = {
            "access_exposure": self.access_exposure, "transaction_exposure": self.transaction_exposure,
            "currency": self.currency_id.name, "risk_event_count": self.risk_event_count,
            "conflicts": sorted([c.user_id.login, c.combo, c.payment_count, c.exposure] for c in self.conflict_ids),
        }
        if self.case_count:  # added in 1.2; absent from older seals
            payload["money"]["case_count"] = self.case_count
        return payload
