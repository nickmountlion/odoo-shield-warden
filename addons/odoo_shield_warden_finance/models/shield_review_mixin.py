from contextlib import contextmanager

from odoo import _, models
from odoo.exceptions import AccessError, UserError

REVIEW_STATES = ("legitimate", "escalated")


class ShieldReviewMixin(models.AbstractModel):
    """Review rules enforced in write(), so a direct write cannot skip them.

    The bypass is a flag on the database cursor, never a context key: RPC callers control the context
    but cannot reach the cursor. Server-side code that is not a human review (sudo) is not checked.
    """

    _name = "shield.review.mixin"
    _description = "Money-at-Risk review rules"

    def _involved_users(self):
        raise NotImplementedError

    @contextmanager
    def _review_checked(self):
        cr = self.env.cr
        previous = getattr(cr, "_shield_review_checked", False)
        cr._shield_review_checked = True
        try:
            yield
        finally:
            cr._shield_review_checked = previous

    def _check_reviewer(self):
        if not self.env.user.has_group("odoo_shield_warden.group_shield_manager"):
            raise AccessError(_("Only Shield managers can review money-at-risk items."))
        if self.filtered(lambda r: self.env.user in r._involved_users()):
            raise AccessError(_("You cannot review something you were involved in."))

    def write(self, vals):
        if (not self.env.su and not getattr(self.env.cr, "_shield_review_checked", False)
                and (vals.get("state") in REVIEW_STATES or "reviewer_id" in vals)):
            self._check_reviewer()
            if vals.get("state") == "legitimate" and self.filtered(lambda r: not (vals.get("review_note") or r.review_note)):
                raise UserError(_("Explain how you verified it in the review note."))
        return super().write(vals)

    def _review_write(self, vals):
        with self._review_checked():
            return self.write(vals)
