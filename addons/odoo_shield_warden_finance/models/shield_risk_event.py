from odoo import _, api, fields, models
from odoo.exceptions import AccessError, UserError

from odoo.addons.odoo_shield_warden.models.shield_control import SEVERITIES

RULES = [
    ("bank_change_payment", "Bank account changed before payment"),
    ("self_trusted_bank", "Bank account trusted by the person who changed it"),
    ("self_paid_bill", "Bill paid by the person who entered it"),
    ("duplicate_bill", "Duplicate vendor bill"),
    ("untracked_bank_change", "Bank account changed without an audit trail"),
    ("shared_bank_account", "Bank account shared between unrelated contacts"),
    ("lookalike_vendor", "Vendor name imitates an existing vendor"),
    ("new_vendor_fast_payment", "New vendor paid within days by the person who created it"),
]
ACTIVE_STATES = ("open", "escalated")
NOTE_VANISHED = "The flagged record was deleted, cancelled or reset to draft; review needed."


class ShieldRiskEvent(models.Model):
    """A real transaction that matched a fraud-risk pattern, with the money involved."""

    _name = "shield.risk.event"
    _description = "Money-at-Risk Event"
    _inherit = ["mail.thread", "mail.activity.mixin", "shield.review.mixin"]
    _order = "state_rank, event_date desc, id desc"

    key = fields.Char(required=True, index=True, readonly=True, help="Deduplication key: rule + record.")
    rule = fields.Selection(RULES, required=True, readonly=True)
    severity = fields.Selection(SEVERITIES, required=True, tracking=True)
    state = fields.Selection(
        [("open", "To review"), ("escalated", "Escalated"), ("legitimate", "Verified legitimate"),
         ("closed", "No longer detected")],
        default="open", required=True, tracking=True)
    state_rank = fields.Integer(compute="_compute_state_rank", store=True)
    detail = fields.Text(readonly=True)
    event_date = fields.Datetime(readonly=True)
    actor_id = fields.Many2one("res.users", string="Done by", readonly=True)
    partner_id = fields.Many2one("res.partner", string="Vendor", readonly=True)
    payment_id = fields.Many2one("account.payment", readonly=True)
    payment_ids = fields.Many2many("account.payment", string="Payments involved", readonly=True,
                                   help="Every payment whose money this event covers; used to count exposure once.")
    move_id = fields.Many2one("account.move", string="Bill", readonly=True)
    bank_id = fields.Many2one("res.partner.bank", string="Bank account", readonly=True)
    company_id = fields.Many2one("res.company", readonly=True, default=lambda self: self.env.company)
    currency_id = fields.Many2one(related="company_id.currency_id")
    amount = fields.Monetary(string="Amount at risk", readonly=True)
    reviewer_id = fields.Many2one("res.users", readonly=True, tracking=True)
    review_note = fields.Text(tracking=True)
    case_id = fields.Many2one("shield.risk.case", string="Case", readonly=True, index=True, ondelete="set null")

    _sql_constraints = [("key_uniq", "unique(key)", "One event per rule and record.")]

    @api.depends("state")
    def _compute_state_rank(self):
        order = {"open": 0, "escalated": 1, "legitimate": 2, "closed": 3}
        for event in self:
            event.state_rank = order.get(event.state, 9)

    def _involved_users(self):
        """Everyone who did something the event is about: they must not review it."""
        # sudo: a reviewer without accounting rights must still be checked against who touched the records.
        rec = self.sudo()
        return rec.actor_id | rec.payment_ids.create_uid | rec.move_id.create_uid | rec.bank_id.create_uid

    def action_mark_legitimate(self):
        self._check_reviewer()
        if self.filtered(lambda e: not e.review_note):
            raise UserError(_("Explain how you verified it (e.g. 'called vendor on known number') in the review note."))
        self._review_write({"state": "legitimate", "reviewer_id": self.env.user.id})

    def action_escalate(self):
        self._check_reviewer()
        self._review_write({"state": "escalated", "reviewer_id": self.env.user.id})

    def action_reopen(self):
        self._check_reviewer()
        self._review_write({"state": "open"})

    def _source_vanished(self):
        """True if the payment or bill this event is keyed on no longer exists or is no longer posted."""
        self.ensure_one()
        rule, _sep, rest = self.key.partition(":")
        rec_id = rest.split(":")[0]
        if not rec_id.isdigit():
            return False
        if rule in ("bank_change_payment", "self_paid_bill", "new_vendor_fast_payment"):
            pay = self.env["account.payment"].sudo().browse(int(rec_id)).exists()
            return not pay or pay.state in ("draft", "canceled", "rejected")
        if rule == "duplicate_bill":
            move = self.env["account.move"].sudo().browse(int(rec_id)).exists()
            return not move or move.state != "posted"
        return False

    def _upsert(self, rule, found):
        """Create or refresh events for ``rule``; close events of that rule no longer detected."""
        existing = self.sudo().search([("rule", "=", rule)])
        by_key = {e.key: e for e in existing}
        seen = set()
        for vals in found:
            seen.add(vals["key"])
            event = by_key.get(vals["key"])
            if event:
                update = {k: v for k, v in vals.items() if k not in ("key", "rule")}
                if event.state == "closed":
                    update["state"] = "open"
                event.write(update)
            else:
                self.sudo().create({**vals, "rule": rule})
        stale = existing.filtered(lambda e: e.key not in seen and e.state == "open")
        vanished = stale.filtered(lambda e: e._source_vanished())
        for event in vanished:  # a deleted or reset record must not quietly remove its money from the total
            event.write({"state": "escalated",
                         "detail": "%s\n%s" % (event.detail or "", NOTE_VANISHED)})
            event.message_post(body=_("The flagged record disappeared. Escalated for review instead of closing."))
        (stale - vanished).write({"state": "closed"})
        return self.sudo().search([("rule", "=", rule), ("state", "in", ACTIVE_STATES)])
