"""Money-at-risk checks: effective-permission conflicts and transaction monitoring."""

import hashlib
import re
from collections import defaultdict, namedtuple
from difflib import SequenceMatcher
from datetime import timedelta

from odoo import SUPERUSER_ID, _, fields, models
from odoo.tools import format_amount, html2plaintext

from odoo.addons.odoo_shield_warden.models.shield_check import listing, result
from odoo.addons.odoo_shield_warden.models.shield_control import SEVERITY_RANK

LOOKBACK_DAYS = 365
BANK_CHANGE_WINDOW_DAYS = 30
PAID_STATES = ("in_process", "paid")
UNTRACKED_WRITE_TOLERANCE = timedelta(seconds=60)
NUMBER_ATTRIBUTION_TOLERANCE = timedelta(seconds=5)
HistoryRow = namedtuple("HistoryRow", "date user field old_char new_char new_int source")

CAPABILITIES = {
    "bank_edit": "edit vendor bank accounts",
    "bank_trust": "mark bank accounts as trusted",
    "bill": "enter vendor bills",
    "pay": "create payments",
    "user_admin": "create users and assign rights",
}
# Model and access mode behind each ACL-based capability (bank_trust is a group, not an ACL).
CAPABILITY_ACCESS = {
    "bank_edit": ("res.partner.bank", "write"), "bill": ("account.move", "create"),
    "pay": ("account.payment", "create"), "user_admin": ("res.users", "create"),
}
# (code, required capabilities, severity, why it matters)
TOXIC_COMBOS = [
    ("redirect_and_pay", ("bank_edit", "bank_trust", "pay"), "critical",
     "can change a vendor's bank account, mark it trusted and pay it alone, which defeats Odoo's "
     "bank-account validation safeguard"),
    ("escalate_and_pay", ("user_admin", "pay"), "critical",
     "can grant themselves any right, then pay"),
    ("bill_and_pay", ("bill", "pay"), "high",
     "can enter a vendor bill and pay it without a second person"),
]


class ShieldCheck(models.AbstractModel):
    _inherit = "shield.check"

    # -- helpers -------------------------------------------------------------------

    def _since(self):
        return fields.Datetime.now() - timedelta(days=LOOKBACK_DAYS)

    def _money(self, amount):
        return format_amount(self.env, amount, self.env.company.currency_id)

    def _outbound_payments(self):
        return self.env["account.payment"].sudo().search([
            ("payment_type", "=", "outbound"), ("state", "in", PAID_STATES),
            ("date", ">=", self._since().date()), ("company_id", "in", self.env.companies.ids)])

    def _effective_capabilities(self, user):
        access = self.env["ir.model.access"].with_user(user)
        caps = set()
        if access.check("res.partner.bank", "write", raise_exception=False):
            caps.add("bank_edit")
        if user.has_group("account.group_validate_bank_account") or user.has_group("base.group_system"):
            caps.add("bank_trust")
        if access.check("account.move", "create", raise_exception=False):
            caps.add("bill")
        if access.check("account.payment", "create", raise_exception=False):
            caps.add("pay")
        if access.check("res.users", "create", raise_exception=False):
            caps.add("user_admin")
        return caps

    def _restricted_capabilities(self, user, caps):
        """{capability: rule names} for capabilities narrowed by group-specific record rules (K12).

        Global rules (usually multi-company isolation) apply to everyone and are not a segregation control;
        a rule attached to one of the user's groups is, e.g. "clerks may only pay from journal X".
        """
        out = {}
        for cap in caps:
            model, mode = CAPABILITY_ACCESS.get(cap, (None, None))
            if not model:
                continue
            rules = self.env["ir.rule"].sudo().search([
                ("model_id.model", "=", model), (f"perm_{mode}", "=", True), ("groups", "in", user.groups_id.ids)])
            if rules:
                out[cap] = rules.mapped("name")
        return out

    def _sod_conflicts(self):
        """Every internal user holding a toxic combination, with the payments they actually made."""
        users = self.env["res.users"].sudo().search([("share", "=", False), ("id", "!=", SUPERUSER_ID)])
        payments = self._outbound_payments()
        paid_by = defaultdict(lambda: [0, 0.0])
        for pay in payments:
            paid_by[pay.create_uid.id][0] += 1
            paid_by[pay.create_uid.id][1] += abs(pay.amount_company_currency_signed)
        conflicts = []
        for user in users:
            caps = self._effective_capabilities(user)
            restricted = self._restricted_capabilities(user, caps)
            for code, needed, severity, _why in TOXIC_COMBOS:
                if set(needed) <= caps:
                    count, amount = paid_by[user.id]
                    limits = sorted({name for c in needed for name in restricted.get(c, [])})
                    text = ", ".join(CAPABILITIES[c] for c in needed)
                    if limits:
                        # Record rules narrow the conflict to some records: still a gap, one level lower.
                        severity = {"critical": "high", "high": "medium"}.get(severity, severity)
                        text += _(" (limited by record rules: %s)", ", ".join(limits))
                    conflicts.append({
                        "user_id": user.id, "combo": code, "severity": severity,
                        "severity_rank": SEVERITY_RANK[severity], "capabilities": text,
                        "payment_count": count, "exposure": amount,
                    })
        return conflicts

    def _sod_result(self, code):
        combo = next(c for c in TOXIC_COMBOS if c[0] == code)
        hits = [c for c in self._sod_conflicts() if c["combo"] == code]
        if not hits:
            return result("pass", _("No internal user holds this combination of rights."))
        users = self.env["res.users"].browse([h["user_id"] for h in hits])
        exercised = [h for h in hits if h["payment_count"]]
        total = sum(h["exposure"] for h in hits)
        who = listing(f"{u.login} ({self._money(h['exposure'])})" for u, h in zip(users, hits))
        detail = _("%(n)s user(s) %(why)s: %(who)s.", n=len(hits), why=combo[3], who=who)
        if exercised:
            detail += " " + _("%(k)s of them created %(amt)s of payments in the last 12 months.",
                              k=len(exercised), amt=self._money(total))
            return result("fail", detail, severity=combo[2])
        # Possible but never exercised: still a gap, one level lower.
        lower = {"critical": "high", "high": "medium"}.get(combo[2], combo[2])
        return result("fail", detail + " " + _("No payments made by them yet."), severity=lower)

    def _check_sod_redirect_and_pay(self):
        return self._sod_result("redirect_and_pay")

    def _check_sod_escalate_and_pay(self):
        return self._sod_result("escalate_and_pay")

    def _check_sod_bill_and_pay(self):
        return self._sod_result("bill_and_pay")

    # -- transaction monitoring -------------------------------------------------------

    def _bank_history(self, banks):
        """{bank_id: [HistoryRow]} for account-number and trust changes.

        Odoo records them twice: as tracking on the bank account itself, and as a "Bank Account #id updated"
        message on the owner's chatter. API callers can suppress the first with ``tracking_disable``;
        the second is written by res.partner.bank.write() regardless. Reading both, and noting which
        source each row came from, catches the suppression.
        """
        banks = banks.sudo()
        field_ids = {self.env["ir.model.fields"]._get("res.partner.bank", f).id: f
                     for f in ("acc_number", "allow_out_payment")}
        values = self.env["mail.tracking.value"].sudo().search([
            ("field_id", "in", list(field_ids)), "|",
            "&", ("mail_message_id.model", "=", "res.partner.bank"), ("mail_message_id.res_id", "in", banks.ids),
            "&", ("mail_message_id.model", "=", "res.partner"), ("mail_message_id.res_id", "in", banks.partner_id.ids)])
        by_partner = defaultdict(list)
        for bank in banks:
            by_partner[bank.partner_id.id].append(bank.id)
        history = defaultdict(list)
        for tv in values:
            msg = tv.mail_message_id
            if msg.model == "res.partner.bank":
                bank_id, source = msg.res_id, "bank"
            else:
                ref = re.search(r"#(\d+)", html2plaintext(msg.body or ""))
                candidates = by_partner[msg.res_id]
                bank_id = int(ref.group(1)) if ref and int(ref.group(1)) in candidates else \
                    (candidates[0] if len(candidates) == 1 else None)
                source = "owner"
            if bank_id:
                history[bank_id].append(HistoryRow(msg.date, msg.create_uid, field_ids[tv.field_id.id],
                                                   tv.old_value_char, tv.new_value_char, tv.new_value_integer, source))
        return history

    def _tracking(self, banks, field_name):
        """{bank_id: [(date, user, new_value_integer)]} for one field, de-duplicated across both sources."""
        out = defaultdict(list)
        for bank_id, rows in self._bank_history(banks).items():
            seen = set()
            for row in sorted(rows, key=lambda r: r.date):
                key = (row.date.replace(microsecond=0), row.new_char, row.new_int)
                if row.field == field_name and key not in seen:
                    seen.add(key)
                    out[bank_id].append((row.date, row.user, row.new_int))
        return out

    def _account_changes(self, banks):
        """{bank_id: [(date, user, kind)]} where kind is 'created' or 'changed'."""
        changes = defaultdict(list)
        for bank in banks:
            changes[bank.id].append((bank.create_date, bank.create_uid, "created"))
        for bank_id, rows in self._tracking(banks, "acc_number").items():
            changes[bank_id] += [(date, user, "changed") for date, user, _v in rows]
        return changes

    def _events_result(self, events, label):
        if not events:
            return result("pass", _("No %s in the last 12 months.", label))
        total = sum(events.mapped("amount"))
        worst = min(events.mapped("severity"), key=lambda s: SEVERITY_RANK[s])
        ranked = events.sorted(lambda e: (SEVERITY_RANK[e.severity], -e.amount))
        return result("fail", _("%(n)s %(label)s to review, touching %(amt)s: %(items)s",
                                n=len(events), label=label, amt=self._money(total),
                                items=listing(ranked.mapped("detail"), limit=3)),
                      "\n".join(f"[event {e.id}] {e.detail}" for e in ranked), severity=worst)

    def _check_ccm_bank_change_payment(self):
        payments = self._outbound_payments().filtered("partner_bank_id")
        changes = self._account_changes(payments.partner_bank_id)
        window = timedelta(days=BANK_CHANGE_WINDOW_DAYS)
        found = []
        for pay in payments:
            # Chatter dates use the wall clock, record dates the transaction start: allow for the gap.
            recent = [c for c in changes[pay.partner_bank_id.id]
                      if c[0] <= pay.create_date + UNTRACKED_WRITE_TOLERANCE and pay.create_date - c[0] <= window]
            if not recent:
                continue
            date, changer, kind = max(recent, key=lambda c: c[0])
            same = changer == pay.create_uid
            days = max((pay.create_date - date).days, 0)
            severity = ("critical" if same else "high") if kind == "changed" else ("high" if same else "medium")
            what = _("account number changed") if kind == "changed" else _("new bank account")
            found.append({
                "key": f"bank_change_payment:{pay.id}", "severity": severity,
                "detail": _("%(pay)s to %(vendor)s: %(what)s by %(who)s %(d)s day(s) before payment by %(payer)s",
                            pay=pay.name, vendor=pay.partner_id.display_name, what=what, who=changer.login,
                            d=days, payer=pay.create_uid.login),
                "event_date": pay.create_date, "actor_id": pay.create_uid.id, "partner_id": pay.partner_id.id,
                "payment_id": pay.id, "payment_ids": [(6, 0, pay.ids)], "bank_id": pay.partner_bank_id.id,
                "company_id": pay.company_id.id,
                "amount": abs(pay.amount_company_currency_signed),
            })
        events = self.env["shield.risk.event"]._upsert("bank_change_payment", found)
        return self._events_result(events, _("payment(s) to recently changed bank accounts"))

    def _check_ccm_self_trusted_bank(self):
        banks = self.env["res.partner.bank"].sudo().search([("allow_out_payment", "=", True)])
        changes = self._account_changes(banks)
        trusts = self._tracking(banks, "allow_out_payment")
        payments = self._outbound_payments()
        found = []
        for bank in banks:
            trust_rows = [(d, u) for d, u, v in trusts.get(bank.id, []) if v]
            if not trust_rows:
                # Trusted at creation: the creator trusted their own entry.
                trust_rows = [(bank.create_date, bank.create_uid)]
            trust_date, truster = max(trust_rows, key=lambda r: r[0])
            prior = [c for c in changes[bank.id] if c[0] <= trust_date]
            if truster.id == SUPERUSER_ID or not prior:
                continue
            _date, changer, kind = max(prior, key=lambda c: c[0])
            if changer != truster:
                continue
            paid = payments.filtered(lambda p, b=bank, t=trust_date: p.partner_bank_id == b and p.create_date >= t)
            amount = sum(abs(p.amount_company_currency_signed) for p in paid)
            found.append({
                "key": f"self_trusted_bank:{bank.id}:{fields.Datetime.to_string(trust_date)}",
                "severity": "critical" if amount else "high",
                "detail": _("%(acc)s of %(vendor)s %(kind)s and trusted by the same person (%(who)s); %(n)s payment(s) since",
                            acc=bank.acc_number, vendor=bank.partner_id.display_name,
                            kind=_("created") if kind == "created" else _("changed"), who=truster.login, n=len(paid)),
                "event_date": trust_date, "actor_id": truster.id, "partner_id": bank.partner_id.id,
                "bank_id": bank.id, "payment_ids": [(6, 0, paid.ids)], "amount": amount,
            })
        events = self.env["shield.risk.event"]._upsert("self_trusted_bank", found)
        return self._events_result(events, _("self-verified bank account(s)"))

    def _check_ccm_self_paid_bill(self):
        found = []
        for pay in self._outbound_payments():
            bills = pay.reconciled_bill_ids.filtered(lambda b, p=pay: b.create_uid == p.create_uid)
            if not bills:
                continue
            found.append({
                "key": f"self_paid_bill:{pay.id}", "severity": "high",
                "detail": _("%(user)s entered %(bills)s and paid it with %(pay)s",
                            user=pay.create_uid.login, bills=", ".join(bills.mapped("name")), pay=pay.name),
                "event_date": pay.create_date, "actor_id": pay.create_uid.id, "partner_id": pay.partner_id.id,
                "payment_id": pay.id, "payment_ids": [(6, 0, pay.ids)], "move_id": bills[:1].id,
                "company_id": pay.company_id.id,
                "amount": abs(pay.amount_company_currency_signed),
            })
        events = self.env["shield.risk.event"]._upsert("self_paid_bill", found)
        return self._events_result(events, _("bill(s) paid by the person who entered them"))

    def _check_ccm_duplicate_bill(self):
        bills = self.env["account.move"].sudo().search([
            ("move_type", "=", "in_invoice"), ("state", "=", "posted"),
            ("payment_state", "!=", "reversed"), ("invoice_date", ">=", self._since().date()),
            ("company_id", "in", self.env.companies.ids)], order="id")
        buckets = defaultdict(list)
        for bill in bills:
            # "NW-2291", "nw 2291" and "NW/2291" are the same reference typed differently.
            ref = re.sub(r"[^0-9a-z]", "", (bill.ref or "").lower())
            buckets[(bill.partner_id.commercial_partner_id.id, bill.currency_id.id,
                     round(bill.amount_total, 2), ref or str(bill.invoice_date))].append(bill)
        found = []
        for group in buckets.values():
            original = group[0]
            for dup in group[1:]:
                found.append({
                    "key": f"duplicate_bill:{dup.id}", "severity": "medium",
                    "detail": _("%(dup)s duplicates %(orig)s (%(vendor)s, %(amt)s)", dup=dup.name, orig=original.name,
                                vendor=dup.partner_id.display_name, amt=self._money(abs(dup.amount_total_signed))),
                    "event_date": dup.create_date, "actor_id": dup.create_uid.id, "partner_id": dup.partner_id.id,
                    "move_id": dup.id, "company_id": dup.company_id.id, "amount": abs(dup.amount_total_signed),
                })
        events = self.env["shield.risk.event"]._upsert("duplicate_bill", found)
        return self._events_result(events, _("possible duplicate bill(s)"))

    # -- anti-forensics and ghost beneficiaries (added after the attack lab) --------------------

    def _acc_digest(self, bank):
        return hashlib.sha256((bank.sanitized_acc_number or bank.acc_number or "").encode()).hexdigest()

    def _check_ccm_untracked_bank_change(self):
        """Bank details changed while hiding it: suppressed tracking, no trace at all, or a silent rewrite."""
        banks = self.env["res.partner.bank"].sudo().with_context(active_test=False).search([])
        history = self._bank_history(banks)
        Fingerprint = self.env["shield.bank.fingerprint"].sudo()
        prints = {fp.bank_id.id: fp for fp in Fingerprint.search([("bank_id", "in", banks.ids)])}
        payments = self._outbound_payments()
        now = fields.Datetime.now()
        found = []
        for bank in banks:
            rows = history.get(bank.id, [])
            acc_rows = [r for r in rows if r.field == "acc_number"]
            logged_on_bank = {r.new_char or "" for r in acc_rows if r.source == "bank"}
            suppressed = [r for r in acc_rows if r.source == "owner" and (r.new_char or "") not in logged_on_bank]
            last_trace = max([bank.create_date] + [r.date for r in rows])
            digest = self._acc_digest(bank)
            fp = prints.get(bank.id)
            reasons, actor, since = [], bank.write_uid, bank.write_date
            if suppressed:
                row = max(suppressed, key=lambda r: r.date)
                actor, since = row.user, row.date
                reasons.append(_("account number changed to %(new)s by %(who)s on %(date)s with the bank account's "
                                 "own audit trail switched off (tracking_disable)",
                                 new=row.new_char, who=row.user.login, date=fields.Datetime.to_string(row.date)))
            elif bank.write_date and bank.write_date - last_trace > UNTRACKED_WRITE_TOLERANCE:
                reasons.append(_("modified by %(who)s on %(date)s without any audit-trail entry",
                                 who=bank.write_uid.login, date=fields.Datetime.to_string(bank.write_date)))
            if fp and fp.acc_hash != digest and not any((r.new_char or "") == bank.acc_number for r in acc_rows):
                reasons.append(_("its number no longer matches the one Shield fingerprinted on %s, and no change "
                                 "was logged anywhere", fields.Datetime.to_string(fp.last_seen)))
            if fp:
                fp.write({"acc_hash": digest, "last_seen": now})
            else:
                Fingerprint.create({"bank_id": bank.id, "acc_hash": digest, "last_seen": now})
            if not reasons:
                continue
            # Record timestamps use the transaction start, chatter uses the wall clock: allow for the gap.
            paid = payments.filtered(lambda p, b=bank, s=since: p.partner_bank_id == b
                                     and p.create_date >= s - UNTRACKED_WRITE_TOLERANCE)
            found.append({
                "key": f"untracked_bank_change:{bank.id}:{digest[:16]}", "severity": "critical",
                "detail": _("%(acc)s of %(owner)s: %(why)s; %(n)s payment(s) since",
                            acc=bank.acc_number, owner=bank.partner_id.display_name, why="; ".join(reasons),
                            n=len(paid)),
                "event_date": since, "actor_id": actor.id, "partner_id": bank.partner_id.id, "bank_id": bank.id,
                "payment_ids": [(6, 0, paid.ids)], "amount": sum(abs(p.amount_company_currency_signed) for p in paid),
            })
        events = self.env["shield.risk.event"]._upsert("untracked_bank_change", found)
        return self._events_result(events, _("bank account change(s) hidden from the audit trail"))

    @staticmethod
    def _norm_acc(number):
        return re.sub(r"[^0-9A-Za-z]", "", number or "").upper()

    def _number_timeline(self, banks):
        """{bank_id: [(from_date, normalized number, as typed)]}: every number each bank record has held.

        Payments point at the bank *record*, whose number can change later. Judging a payment by the
        number the record held when it was paid stops a fraudster from erasing the trail by changing
        the number again.
        """
        history = self._bank_history(banks)
        timeline = {}
        for bank in banks:
            rows, seen = [], set()
            for row in sorted((r for r in history.get(bank.id, []) if r.field == "acc_number"), key=lambda r: r.date):
                key = (row.date.replace(microsecond=0), row.new_char)
                if key not in seen:
                    seen.add(key)
                    rows.append(row)
            steps = []
            if rows and rows[0].old_char:
                steps.append((bank.create_date, self._norm_acc(rows[0].old_char), rows[0].old_char))
            steps += [(r.date, self._norm_acc(r.new_char), r.new_char) for r in rows]
            if not steps:
                steps = [(bank.create_date, self._norm_acc(bank.acc_number), bank.acc_number)]
            if steps[-1][1] != self._norm_acc(bank.acc_number):  # changed without any trace
                steps.append((bank.write_date, self._norm_acc(bank.acc_number), bank.acc_number))
            timeline[bank.id] = steps
        return timeline

    def _number_at(self, steps, when):
        # Small tolerance: record time is the transaction start, chatter time the wall clock.
        held = [s for s in steps if s[0] <= when + NUMBER_ATTRIBUTION_TOLERANCE]
        return (held[-1] if held else steps[0])[1]

    def _check_ccm_shared_bank_account(self):
        """One IBAN on several unrelated contacts, now or in the past: ghost vendors and payroll diversion."""
        banks = self.env["res.partner.bank"].sudo().with_context(active_test=False).search([])
        timeline = self._number_timeline(banks)
        holders, typed, banks_by_number = defaultdict(set), {}, defaultdict(set)
        for bank in banks:
            for _date, number, as_typed in timeline[bank.id]:
                if number:
                    holders[number].add(bank.partner_id.commercial_partner_id.id)
                    banks_by_number[number].add(bank.id)
                    typed.setdefault(number, as_typed)
        staff = self.env["res.users"].sudo().search([("share", "=", False)])
        paid_by_number = defaultdict(lambda: self.env["account.payment"].sudo())
        for pay in self._outbound_payments().filtered("partner_bank_id"):
            steps = timeline.get(pay.partner_bank_id.id)
            if steps:
                paid_by_number[self._number_at(steps, pay.create_date)] |= pay
        found = []
        for number, partner_ids in holders.items():
            if len(partner_ids) < 2:
                continue
            partners = self.env["res.partner"].sudo().browse(sorted(partner_ids))
            personal = partners.filtered(lambda p: p in staff.partner_id or (
                not p.is_company and p.create_uid in staff and p.create_uid.id != SUPERUSER_ID))
            current = banks.filtered(lambda b, n=number: self._norm_acc(b.acc_number) == n)
            paid = paid_by_number[number]
            names = ", ".join(p.display_name + (_(" (created by %s)", p.create_uid.login) if p in personal else "")
                              for p in partners)
            history_note = "" if len(current.partner_id.commercial_partner_id) == len(partners) else                 _(" (some no longer hold it: the number was changed afterwards)")
            holder_banks = self.env["res.partner.bank"].sudo().browse(sorted(banks_by_number[number]))
            found.append({
                "key": f"shared_bank_account:{number}", "severity": "critical" if personal else "high",
                "detail": _("%(acc)s is or was registered on %(n)s different contacts: %(who)s%(note)s; "
                            "%(p)s payment(s) made to it", acc=typed[number], n=len(partners), who=names,
                            note=history_note, p=len(paid)),
                "event_date": max(holder_banks.mapped("create_date")),
                "actor_id": holder_banks.sorted("create_date")[-1].create_uid.id,
                "partner_id": partners[0].id, "bank_id": (current or holder_banks)[:1].id,
                "payment_ids": [(6, 0, paid.ids)], "amount": sum(abs(p.amount_company_currency_signed) for p in paid),
            })
        events = self.env["shield.risk.event"]._upsert("shared_bank_account", found)
        return self._events_result(events, _("bank account(s) shared between unrelated contacts"))

    # -- cycle 3: prevention and vendor-master fraud ----------------------------------------------

    def _check_payment_hold(self):
        mode = self._param("shield.payment_hold", "off")
        days = int(self._param("shield.payment_hold_days", 30) or 30)
        if mode != "enforce":
            return result("fail", _("Payments to freshly changed bank accounts are only detected, not stopped. "
                                    "Turn on Shield's payment hold (one-click fix) to require a second person to "
                                    "verify any account number set in the last %s days before money leaves.", days))
        held = self.env["res.partner.bank"].sudo().search([]).filtered(lambda b: b._shield_hold_reason())
        return result("pass", _("Payment hold enforced (%(d)s days); %(n)s bank account(s) currently held for "
                                "verification.", d=days, n=len(held)),
                      listing(f"{b.acc_number} ({b.partner_id.display_name})" for b in held))

    def _fix_payment_hold(self):
        self._set_param("shield.payment_hold", "enforce", False)
        days = self._param("shield.payment_hold_days", 30)
        return _("Payment hold enforced: payments to bank accounts set or changed in the last %s days now need "
                 "second-person verification ('Verify with Shield' on the bank account).", days), False

    @staticmethod
    def _vendor_key(name):
        """Normalize a vendor name so 'N0rthwind Logistics Ltd.' and 'Northwind Logistics' compare equal."""
        text = (name or "").lower().translate(str.maketrans("0134578@$", "oleastbas"))
        text = re.sub(r"\b(ltd|llc|inc|gmbh|sarl|srl|sas|sa|bv|nv|co|corp|company|limited|plc|ag|spa)\b", " ", text)
        return re.sub(r"[^a-z]", "", text)

    def _vendors(self):
        return self.env["res.partner"].sudo().search([("supplier_rank", ">", 0), ("parent_id", "=", False)])

    def _check_ccm_lookalike_vendor(self):
        vendors = self._vendors()
        recent = vendors.filtered(lambda v: v.create_date >= self._since())
        payments = self._outbound_payments()
        found = []
        for new in recent:
            key = self._vendor_key(new.name)
            if len(key) < 5:
                continue
            for old in vendors:
                if old == new or old.create_date > new.create_date:
                    continue
                other = self._vendor_key(old.name)
                matcher = SequenceMatcher(None, key, other)
                if matcher.real_quick_ratio() < 0.88 or matcher.ratio() < 0.88:
                    continue
                paid = payments.filtered(lambda p, n=new: p.partner_id.commercial_partner_id == n)
                found.append({
                    "key": f"lookalike_vendor:{new.id}:{old.id}",
                    "severity": "critical" if paid else "high",
                    "detail": _("'%(new)s' (created by %(who)s on %(date)s) imitates existing vendor '%(old)s'; "
                                "%(n)s payment(s) to it", new=new.name, who=new.create_uid.login,
                                date=fields.Date.to_string(new.create_date.date()), old=old.name, n=len(paid)),
                    "event_date": new.create_date, "actor_id": new.create_uid.id, "partner_id": new.id,
                    "bank_id": new.bank_ids[:1].id, "payment_ids": [(6, 0, paid.ids)],
                    "amount": sum(abs(p.amount_company_currency_signed) for p in paid),
                })
                break
        events = self.env["shield.risk.event"]._upsert("lookalike_vendor", found)
        return self._events_result(events, _("lookalike vendor(s)"))

    def _check_ccm_new_vendor_fast_payment(self):
        window = timedelta(days=7)
        found = []
        for pay in self._outbound_payments():
            vendor = pay.partner_id.commercial_partner_id
            if not vendor.create_date or not (timedelta(0) <= pay.create_date - vendor.create_date
                                              + UNTRACKED_WRITE_TOLERANCE <= window):
                continue
            creators = vendor.create_uid | pay.partner_bank_id.create_uid
            if pay.create_uid not in creators or pay.create_uid.id == SUPERUSER_ID:
                continue
            same_bank = pay.partner_bank_id.create_uid == pay.create_uid
            found.append({
                "key": f"new_vendor_fast_payment:{pay.id}", "severity": "critical" if same_bank else "high",
                "detail": _("%(who)s created %(vendor)s%(bank)s and paid it %(d)s day(s) later (%(pay)s)",
                            who=pay.create_uid.login, vendor=vendor.display_name,
                            bank=_(" and its bank account") if same_bank else "",
                            d=max((pay.create_date - vendor.create_date).days, 0), pay=pay.name),
                "event_date": pay.create_date, "actor_id": pay.create_uid.id, "partner_id": vendor.id,
                "payment_id": pay.id, "payment_ids": [(6, 0, pay.ids)], "company_id": pay.company_id.id,
                "amount": abs(pay.amount_company_currency_signed),
            })
        events = self.env["shield.risk.event"]._upsert("new_vendor_fast_payment", found)
        return self._events_result(events, _("new vendor(s) paid within a week by their creator"))
