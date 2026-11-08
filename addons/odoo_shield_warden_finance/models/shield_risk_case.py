from markupsafe import Markup

from odoo import _, api, fields, models
from odoo.exceptions import AccessError, UserError
from odoo.tools.misc import format_datetime

from odoo.addons.odoo_shield_warden.models.shield_control import SEVERITIES, SEVERITY_RANK

from .shield_risk_event import ACTIVE_STATES


class ShieldRiskCase(models.Model):
    """One incident: every alert about the same bank account, payment or bill, reviewed once.

    The attack lab showed one fraudulent payment tripping two or three rules (12 alerts for 5 incidents).
    Cases fix that alert fatigue: the reviewer sees one card with all the reasons and the money counted once.
    """

    _name = "shield.risk.case"
    _description = "Money-at-Risk Case"
    _inherit = ["mail.thread", "mail.activity.mixin", "shield.review.mixin"]
    _order = "state_rank, severity_rank, amount desc, id desc"

    @api.model
    def get_empty_list_help(self, help_message):
        """Honest empty state: cases only exist after an assessment, so "No money at risk" is only true
        if one ran after the latest payments, bills and bank-account edits."""
        last = self.env["shield.assessment"].sudo().search([], order="create_date desc, id desc", limit=1)
        # sudo: counts and a date only, and the action loads this help on every open, whatever the reader's rights.
        if not last:
            title, body = _("Not assessed yet"), _("Run an assessment from the Shield menu to look for money at risk.")
            icon = ""
        else:
            since = [("write_date", ">", last.create_date)]
            changed = (self.env["account.payment"].sudo().search_count(since)
                       + self.env["account.move"].sudo().search_count(since + [("move_type", "in", ("in_invoice", "in_refund"))])
                       + self.env["res.partner.bank"].sudo().search_count(since))
            when = format_datetime(self.env, last.create_date)
            if changed:
                title = _("Not assessed since %s", when)
                body = _("%s payment, bill or bank account record(s) changed since the last assessment. "
                         "Run a new assessment before relying on this list.", changed)
                icon = ""
            else:
                title, body = _("No money at risk"), _("As of the last assessment (%s). Each case groups every alert about one bank account, payment or bill, with the money counted once.", when)
                icon = "o_view_nocontent_smiling_face"
        return Markup('<p class="%s">%s</p><p>%s</p>') % (icon, title, body)

    key = fields.Char(required=True, index=True, readonly=True)
    name = fields.Char(required=True, readonly=True)
    state = fields.Selection(
        [("open", "To review"), ("escalated", "Escalated"), ("legitimate", "Verified legitimate"),
         ("closed", "No longer detected")], default="open", required=True, tracking=True)
    state_rank = fields.Integer(compute="_compute_ranks", store=True)
    severity = fields.Selection(SEVERITIES, required=True, default="medium", tracking=True)
    severity_rank = fields.Integer(compute="_compute_ranks", store=True)
    event_ids = fields.One2many("shield.risk.event", "case_id", string="Alerts")
    alert_count = fields.Integer(compute="_compute_summary", store=True)
    reasons = fields.Text(compute="_compute_summary", store=True)
    actor_ids = fields.Many2many("res.users", string="Done by", compute="_compute_summary", store=True)
    partner_id = fields.Many2one("res.partner", string="Counterparty", readonly=True)
    bank_id = fields.Many2one("res.partner.bank", string="Bank account", readonly=True)
    company_id = fields.Many2one("res.company", readonly=True, default=lambda self: self.env.company)
    currency_id = fields.Many2one(related="company_id.currency_id")
    amount = fields.Monetary(string="Money at risk", readonly=True,
                             help="Distinct payments (then unpaid bills) behind the case's active alerts.")
    reviewer_id = fields.Many2one("res.users", readonly=True, tracking=True)
    review_note = fields.Text(tracking=True)

    _sql_constraints = [("key_uniq", "unique(key)", "One case per incident key.")]

    @api.depends("state", "severity")
    def _compute_ranks(self):
        order = {"open": 0, "escalated": 1, "legitimate": 2, "closed": 3}
        for case in self:
            case.state_rank = order.get(case.state, 9)
            case.severity_rank = SEVERITY_RANK.get(case.severity, 9)

    @api.depends("event_ids.detail", "event_ids.state", "event_ids.actor_id", "event_ids.rule")
    def _compute_summary(self):
        labels = dict(self.env["shield.risk.event"]._fields["rule"].selection)
        for case in self:
            events = case.event_ids.sorted(lambda e: SEVERITY_RANK[e.severity])
            case.alert_count = len(events)
            case.reasons = "\n".join(f"- {labels[e.rule]}: {e.detail}" for e in events)
            case.actor_ids = events.actor_id

    # -- review -------------------------------------------------------------------------------

    def _involved_users(self):
        self.ensure_one()
        return self.event_ids._involved_users() | self.actor_ids

    def action_mark_legitimate(self):
        self._check_reviewer()
        if self.filtered(lambda c: not c.review_note):
            raise UserError(_("Explain how you verified it (e.g. 'called the vendor on the number in our 2024 contract') "
                              "in the review note."))
        for case in self:
            active = case.event_ids.filtered(lambda e: e.state in ACTIVE_STATES)
            active.write({"review_note": case.review_note})
            active.action_mark_legitimate()
        self._review_write({"state": "legitimate", "reviewer_id": self.env.user.id})

    def action_escalate(self):
        self._check_reviewer()
        self.event_ids.filtered(lambda e: e.state == "open").action_escalate()
        self._review_write({"state": "escalated", "reviewer_id": self.env.user.id})

    def action_reopen(self):
        self._check_reviewer()
        self._review_write({"state": "open"})

    # -- grouping -------------------------------------------------------------------------------

    @api.model
    def _case_key(self, event, flagged_banks):
        if event.bank_id:
            return f"bank:{event.bank_id.id}", event.bank_id
        if event.payment_id and event.payment_id.partner_bank_id.id in flagged_banks:
            return f"bank:{event.payment_id.partner_bank_id.id}", event.payment_id.partner_bank_id
        if event.payment_id:
            return f"payment:{event.payment_id.id}", event.payment_id.partner_bank_id
        if event.move_id:
            return f"bill:{event.move_id.id}", self.env["res.partner.bank"]
        return f"event:{event.id}", self.env["res.partner.bank"]

    @api.model
    def _incident_groups(self, events):
        """Connected components of alerts that share a bank account, a payment or a bill (union-find).

        One IBAN used against two vendors, or one payment flagged under two bank records, is one incident.
        """
        parent = {e.id: e.id for e in events}

        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        owner = {}
        for event in events:
            links = [f"bank:{event.bank_id.id}"] if event.bank_id else []
            links += [f"payment:{p.id}" for p in event.payment_ids | event.payment_id]
            links += [f"bank:{p.partner_bank_id.id}" for p in event.payment_ids | event.payment_id if p.partner_bank_id]
            links += [f"bill:{event.move_id.id}"] if event.move_id else []
            for link in links:
                if link in owner:
                    parent[find(event.id)] = find(owner[link])
                else:
                    owner[link] = event.id
        groups = {}
        for event in events:
            groups.setdefault(find(event.id), self.env["shield.risk.event"].sudo())
            groups[find(event.id)] |= event
        return list(groups.values())

    @api.model
    def _rebuild(self):
        """Attach every alert to its incident case, merge cases that turn out to be one incident, refresh money."""
        events = self.env["shield.risk.event"].sudo().search([])
        flagged_banks = set(events.bank_id.ids)
        Case = self.sudo()
        touched = Case.browse()
        for group in self._incident_groups(events):
            cases = group.case_id
            if not cases:
                if not group.filtered(lambda e: e.state in ACTIVE_STATES):
                    continue
                first = group.sorted(lambda e: (SEVERITY_RANK[e.severity], -e.amount))[0]
                key, bank = self._case_key(first, flagged_banks)
                while Case.search_count([("key", "=", key)]):
                    key = f"{key}+{first.id}"
                label = bank.acc_number if bank else (first.payment_id.name or first.move_id.name or first.rule)
                cases = Case.create({
                    "key": key, "name": f"{first.partner_id.display_name or ''} · {label}".strip(" ·"),
                    "partner_id": first.partner_id.id, "bank_id": bank.id, "company_id": first.company_id.id})
            keeper = cases.sorted("id")[0]
            for merged in cases - keeper:
                merged.message_post(body=_("Merged into case %s: same incident.", keeper.name))
                merged.event_ids.write({"case_id": keeper.id})
                merged.write({"state": "closed", "amount": 0})
            group.filtered(lambda e, k=keeper: e.case_id != k).write({"case_id": keeper.id})
            touched |= keeper
        touched._refresh()

    def _refresh(self):
        for case in self:
            active = case.event_ids.filtered(lambda e: e.state in ACTIVE_STATES)
            money = {}
            for event in active:
                if event.payment_ids:
                    for pay in event.payment_ids:
                        money[("pay", pay.id)] = abs(pay.amount_company_currency_signed)
                elif event.move_id:
                    money.setdefault(("bill", event.move_id.id), event.amount)
                else:
                    money[("event", event.id)] = event.amount
            vals = {"amount": sum(money.values())}
            if active:
                vals["severity"] = min(active.mapped("severity"), key=lambda s: SEVERITY_RANK[s])
                if case.state in ("legitimate", "closed"):
                    vals["state"] = "open"
                    case.message_post(body=_("Reopened: new alert(s) on a case that was %s.", case.state))
            elif case.state == "open":
                vals["state"] = "legitimate" if "legitimate" in case.event_ids.mapped("state") else "closed"
            case.write(vals)
