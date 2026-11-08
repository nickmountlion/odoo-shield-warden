from odoo import fields
from odoo.exceptions import AccessError, UserError
from odoo.tests import new_test_user, tagged

from odoo.addons.account.tests.common import AccountTestInvoicingCommon


@tagged("post_install", "-at_install")
class TestMoneyAtRisk(AccountTestInvoicingCommon):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        company = cls.company_data["company"]
        cls.bank_journal = cls.company_data["default_journal_bank"]
        cls.clerk = new_test_user(
            cls.env, login="shield_clerk", company_id=company.id, company_ids=[(6, 0, company.ids)],
            groups="base.group_user,base.group_partner_manager,account.group_account_invoice,"
                   "account.group_validate_bank_account")
        cls.viewer = new_test_user(cls.env, login="shield_viewer", company_id=company.id,
                                   company_ids=[(6, 0, company.ids)], groups="base.group_user")
        cls.controller = new_test_user(
            cls.env, login="shield_controller", company_id=company.id, company_ids=[(6, 0, company.ids)],
            groups="base.group_user,odoo_shield_warden.group_shield_manager")
        # The accounting test user runs the assessments, as a Shield manager would.
        cls.env.user.groups_id |= cls.env.ref("odoo_shield_warden.group_shield_manager")
        cls.check = cls.env["shield.check"]

    def _pay(self, user, amount, bank=False, partner=None):
        payment = self.env["account.payment"].with_user(user).create({
            "payment_type": "outbound", "partner_type": "supplier",
            "partner_id": (partner or self.partner_a).id, "amount": amount,
            "journal_id": self.bank_journal.id, "partner_bank_id": bank and bank.id,
        })
        payment.action_post()
        return payment

    def _bill(self, user, amount, ref="INV-001"):
        bill = self.env["account.move"].with_user(user).create({
            "move_type": "in_invoice", "partner_id": self.partner_a.id, "ref": ref,
            "invoice_date": fields.Date.today(),
            "invoice_line_ids": [(0, 0, {"name": "Consulting", "quantity": 1, "price_unit": amount,
                                         "tax_ids": [(6, 0, [])]})],
        })
        bill.action_post()
        return bill

    def test_effective_permission_conflicts(self):
        conflicts = self.check._sod_conflicts()
        clerk = {c["combo"] for c in conflicts if c["user_id"] == self.clerk.id}
        self.assertEqual(clerk, {"redirect_and_pay", "bill_and_pay"})
        self.assertFalse([c for c in conflicts if c["user_id"] == self.viewer.id])

    def test_record_rules_soften_a_conflict(self):
        """K12: a group-specific record rule on payments narrows the conflict; it stays visible, one level lower."""
        group = self.env["res.groups"].create({"name": "Clerks limited to small payments"})
        self.clerk.groups_id |= group
        self.env["ir.rule"].create({
            "name": "Clerks pay only below 1,000", "model_id": self.env.ref("account.model_account_payment").id,
            "groups": [(6, 0, group.ids)], "domain_force": "[('amount', '<', 1000)]",
            "perm_read": False, "perm_write": False, "perm_create": True, "perm_unlink": False})
        conflict = next(c for c in self.check._sod_conflicts()
                        if c["user_id"] == self.clerk.id and c["combo"] == "redirect_and_pay")
        self.assertEqual(conflict["severity"], "high")  # was critical
        self.assertIn("Clerks pay only below 1,000", conflict["capabilities"])

    def test_conflict_exposure_counts_real_payments(self):
        self._pay(self.clerk, 700)
        self._pay(self.clerk, 300)
        conflict = next(c for c in self.check._sod_conflicts()
                        if c["user_id"] == self.clerk.id and c["combo"] == "bill_and_pay")
        self.assertEqual(conflict["payment_count"], 2)
        self.assertAlmostEqual(conflict["exposure"], 1000)
        res = self.check._check_sod_bill_and_pay()
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["severity"], "high")

    def test_payment_to_new_bank_account_by_same_user(self):
        bank = self.env["res.partner.bank"].with_user(self.clerk).create({
            "partner_id": self.partner_a.id, "acc_number": "NL91ABNA0417164300", "allow_out_payment": True})
        self._pay(self.clerk, 2500, bank=bank)
        res = self.check._check_ccm_bank_change_payment()
        self.assertEqual(res["status"], "fail")
        event = self.env["shield.risk.event"].search([("rule", "=", "bank_change_payment")])
        self.assertEqual(len(event), 1)
        self.assertEqual(event.actor_id, self.clerk)
        self.assertAlmostEqual(event.amount, 2500)
        self.assertEqual(event.severity, "high")  # new account, same person
        # Self-trust is flagged too: the clerk created the account and enabled "Send Money".
        self.assertEqual(self.check._check_ccm_self_trusted_bank()["status"], "fail")

        # Re-running does not duplicate events.
        self.check._check_ccm_bank_change_payment()
        self.assertEqual(self.env["shield.risk.event"].search_count([("rule", "=", "bank_change_payment")]), 1)

    def test_self_paid_bill(self):
        bill = self._bill(self.clerk, 1200)
        self.env["account.payment.register"].with_user(self.clerk).with_context(
            active_model="account.move", active_ids=bill.ids).create(
            {"journal_id": self.bank_journal.id})._create_payments()
        res = self.check._check_ccm_self_paid_bill()
        self.assertEqual(res["status"], "fail")
        event = self.env["shield.risk.event"].search([("rule", "=", "self_paid_bill")])
        self.assertEqual(event.move_id, bill)
        self.assertAlmostEqual(event.amount, 1200)

    def test_duplicate_bill(self):
        self._bill(self.clerk, 990, ref="ACME 4411")
        dup = self._bill(self.clerk, 990, ref="ACME-4411")
        self._bill(self.clerk, 990, ref="ACME 4412")  # different reference: not a duplicate
        res = self.check._check_ccm_duplicate_bill()
        self.assertEqual(res["status"], "fail")
        events = self.env["shield.risk.event"].search([("rule", "=", "duplicate_bill")])
        self.assertEqual(events.move_id, dup)

    def test_review_workflow(self):
        bank = self.env["res.partner.bank"].with_user(self.clerk).create({
            "partner_id": self.partner_a.id, "acc_number": "DE89370400440532013000", "allow_out_payment": True})
        self._pay(self.clerk, 400, bank=bank)
        self.check._check_ccm_bank_change_payment()
        event = self.env["shield.risk.event"].search([("rule", "=", "bank_change_payment")])
        with self.assertRaises(AccessError):
            event.with_user(self.clerk).action_mark_legitimate()  # not a reviewer
        with self.assertRaises(UserError):
            event.with_user(self.controller).action_mark_legitimate()  # no note
        event.review_note = "Called vendor on number from signed contract."
        event.with_user(self.controller).action_mark_legitimate()
        self.assertEqual(event.state, "legitimate")
        # A legitimate event does not count as money at risk.
        assessment = self.env["shield.assessment"]._run()
        self.assertNotIn(event, self.env["shield.risk.event"].search([("state", "in", ("open", "escalated"))]))
        self.assertTrue(assessment.content_hash)

    def test_direct_write_cannot_skip_review_rules(self):
        bank = self.env["res.partner.bank"].with_user(self.clerk).create({
            "partner_id": self.partner_a.id, "acc_number": "DE89370400440532013000", "allow_out_payment": True})
        self._pay(self.clerk, 400, bank=bank)
        self.check._check_ccm_bank_change_payment()
        event = self.env["shield.risk.event"].search([("rule", "=", "bank_change_payment")])
        with self.assertRaises(AccessError):  # the payer, writing the state directly
            event.with_user(self.clerk).write({"state": "legitimate"})
        with self.assertRaises(UserError):  # a reviewer, but no note
            event.with_user(self.controller).write({"state": "legitimate"})
        # Whoever changed the bank account is involved too, even if they did not pay.
        other = new_test_user(
            self.env, login="shield_bank_editor", company_id=self.company_data["company"].id,
            groups="base.group_user,odoo_shield_warden.group_shield_manager")
        self.env.cr.execute("UPDATE res_partner_bank SET create_uid=%s WHERE id=%s", (other.id, event.bank_id.id))
        self.env.invalidate_all()
        event.review_note = "Called vendor."
        with self.assertRaises(AccessError):
            event.with_user(other).action_mark_legitimate()

    def test_context_flag_cannot_skip_review(self):
        bank = self.env["res.partner.bank"].with_user(self.clerk).create({
            "partner_id": self.partner_a.id, "acc_number": "DE89370400440532013000", "allow_out_payment": True})
        self._pay(self.clerk, 400, bank=bank)
        self.check._check_ccm_bank_change_payment()
        event = self.env["shield.risk.event"].search([("rule", "=", "bank_change_payment")])
        with self.assertRaises(AccessError):
            event.with_user(self.clerk).with_context(shield_review_checked=True).write({"state": "legitimate"})

    def test_involved_manager_can_still_run_assessment_after_payment_reset(self):
        bank = self.env["res.partner.bank"].create({
            "partner_id": self.partner_a.id, "acc_number": "DE89370400440532013000", "allow_out_payment": True})
        payment = self._pay(self.env.user, 400, bank=bank)  # the manager running the assessment is the payer
        self.env["shield.assessment"]._run()
        payment.action_draft()
        assessment = self.env["shield.assessment"]._run()
        self.assertTrue(assessment.content_hash)
        self.assertEqual(self.env["shield.risk.event"].search([("rule", "=", "bank_change_payment")]).state, "escalated")

    def test_sealed_assessment_is_immutable(self):
        assessment = self.env["shield.assessment"]._run()
        result = assessment.result_ids[:1]
        with self.assertRaises(UserError):
            result.write({"status": "pass"})
        with self.assertRaises(UserError):
            assessment.write({"security_score": 100})
        with self.assertRaises(UserError):
            assessment.unlink()
        with self.assertRaises(UserError):  # an RPC caller can put anything in the context
            assessment.with_context(module="x", _force_unlink=True).unlink()
        with self.assertRaises(UserError):
            result.unlink()
        assessment.message_post(body="still allowed")
        self.assertIn("intact", assessment.action_verify_chain()["params"]["message"])

    def test_archived_control_is_sealed_and_reported(self):
        self.env["shield.assessment"]._run()
        control = self.env["shield.control"].search([("kind", "=", "automated")], limit=1)
        control.active = False
        second = self.env["shield.assessment"]._run()
        self.assertIn(control.code, second.control_snapshot)
        self.assertIn("configuration changed", " ".join(second.message_ids.mapped("body")))
        self.assertEqual(second.action_verify_chain()["params"]["type"], "success")
        # A deleted control is reported too.
        gone = self.env["shield.control"].with_context(active_test=False).search([("code", "!=", control.code)], limit=1)
        code = gone.code
        gone.sudo().unlink()
        third = self.env["shield.assessment"]._run()
        self.assertIn(f"{code} (removed)", " ".join(third.message_ids.mapped("body")))

    def test_deleted_flagged_payment_escalates_instead_of_closing(self):
        bank = self.env["res.partner.bank"].with_user(self.clerk).create({
            "partner_id": self.partner_a.id, "acc_number": "DE89370400440532013000", "allow_out_payment": True})
        payment = self._pay(self.clerk, 400, bank=bank)
        self.check._check_ccm_bank_change_payment()
        event = self.env["shield.risk.event"].search([("rule", "=", "bank_change_payment")])
        payment.sudo().action_draft()
        self.check._check_ccm_bank_change_payment()
        self.assertEqual(event.state, "escalated")

    # -- scenarios from the real-world attack lab ------------------------------------------------

    def _trusted_vendor_bank(self, number):
        bank = self.env["res.partner.bank"].create({
            "partner_id": self.partner_a.id, "acc_number": number, "allow_out_payment": True})
        self.env.flush_all()
        self.env.cr.precommit.run()
        return bank

    def test_iban_swap_with_tracking_disabled(self):
        bank = self._trusted_vendor_bank("BE68539007547034")
        quiet = bank.with_user(self.clerk).with_context(tracking_disable=True, mail_notrack=True)
        quiet.write({"allow_out_payment": False, "acc_number": "DE44500105175407324931"})
        quiet.write({"allow_out_payment": True})
        self._pay(self.clerk, 9800, bank=bank)
        res = self.check._check_ccm_untracked_bank_change()
        self.assertEqual(res["status"], "fail")
        self.assertIn("switched off", res["detail"])
        event = self.env["shield.risk.event"].search([("rule", "=", "untracked_bank_change")])
        self.assertEqual(event.actor_id, self.clerk)
        self.assertAlmostEqual(event.amount, 9800)
        # The vendor-side trail also feeds the payment rule: the clerk changed and paid.
        self.check._check_ccm_bank_change_payment()
        pay_event = self.env["shield.risk.event"].search([("rule", "=", "bank_change_payment")])
        self.assertEqual(pay_event.severity, "critical")

    def test_normal_change_is_not_flagged_as_hidden(self):
        bank = self._trusted_vendor_bank("BE68539007547034")
        # Odoo's test base disables tracking globally (DISABLED_MAIL_CONTEXT); a real user has it on.
        tracked = bank.with_user(self.clerk).with_context(tracking_disable=False, mail_notrack=False)
        tracked.write({"allow_out_payment": False, "acc_number": "NL91ABNA0417164300"})
        self.env.flush_all()
        self.env.cr.precommit.run()
        self.check._check_ccm_untracked_bank_change()
        hidden = self.env["shield.risk.event"].search([("rule", "=", "untracked_bank_change")])
        self.assertFalse(hidden, hidden.mapped("detail"))

    def test_fingerprint_catches_silent_database_rewrite(self):
        bank = self._trusted_vendor_bank("BE68539007547034")
        self.check._check_ccm_untracked_bank_change()  # fingerprint taken
        self.env.cr.execute("UPDATE res_partner_bank SET acc_number = %s, sanitized_acc_number = %s WHERE id = %s",
                            ("FR7630006000011234567890189", "FR7630006000011234567890189", bank.id))
        self.env.invalidate_all()
        res = self.check._check_ccm_untracked_bank_change()
        self.assertEqual(res["status"], "fail")
        self.assertIn("fingerprinted", res["detail"])

    def test_vendor_iban_on_employee_contact(self):
        self._trusted_vendor_bank("GB29NWBK60161331926819")
        private = self.env["res.partner"].with_user(self.clerk).create({"name": "Clerk (private)"})
        self.env["res.partner.bank"].with_user(self.clerk).create(
            {"partner_id": private.id, "acc_number": "GB29NWBK60161331926819"})
        res = self.check._check_ccm_shared_bank_account()
        self.assertEqual(res["status"], "fail")
        event = self.env["shield.risk.event"].search([("rule", "=", "shared_bank_account")])
        self.assertEqual(event.severity, "critical")
        self.assertIn("Clerk (private)", event.detail)

    def test_shared_iban_exposure_ignores_payments_before_the_change(self):
        bank = self._trusted_vendor_bank("BE68539007547034")
        old = self._pay(self.env.user, 1000, bank=bank)
        self.env.cr.execute("UPDATE account_payment SET create_date = now() - interval '90 days' WHERE id = %s", old.ids)
        self.env.cr.execute("UPDATE res_partner_bank SET create_date = now() - interval '200 days' WHERE id = %s",
                            bank.ids)
        self.env.invalidate_all()
        bank.with_user(self.clerk).write({"allow_out_payment": False, "acc_number": "GB29NWBK60161331926819"})
        bank.with_user(self.clerk).write({"allow_out_payment": True})
        new_pay = self._pay(self.clerk, 500, bank=bank)
        # Test transactions share one timestamp; place the change and the payment in a realistic order.
        self.env.cr.execute("UPDATE mail_message SET date = now() - interval '1 day' WHERE id IN (SELECT mail_message_id "
                            "FROM mail_tracking_value WHERE new_value_char = 'GB29NWBK60161331926819')")
        self.env.cr.execute("UPDATE account_payment SET create_date = now() - interval '1 hour' WHERE id = %s",
                            new_pay.ids)
        self.env.invalidate_all()
        private = self.env["res.partner"].with_user(self.clerk).create({"name": "Clerk (private)"})
        self.env["res.partner.bank"].with_user(self.clerk).create(
            {"partner_id": private.id, "acc_number": "GB29NWBK60161331926819"})
        self.check._check_ccm_shared_bank_account()
        event = self.env["shield.risk.event"].search([("rule", "=", "shared_bank_account")])
        self.assertAlmostEqual(event.amount, 500)  # the genuine 1,000 paid to the old number is not at risk

    # -- cycle 3: cases, prevention, vendor-master fraud -------------------------------------------

    def _enforce_hold(self):
        self.env["ir.config_parameter"].set_param("shield.payment_hold", "enforce")

    def test_related_alerts_become_one_case(self):
        bank = self.env["res.partner.bank"].with_user(self.clerk).create({
            "partner_id": self.partner_a.id, "acc_number": "NL91ABNA0417164300", "allow_out_payment": True})
        self._pay(self.clerk, 2500, bank=bank)
        assessment = self.env["shield.assessment"]._run()
        case = self.env["shield.risk.case"].search([("bank_id", "=", bank.id)])
        self.assertEqual(len(case), 1)
        self.assertGreaterEqual(case.alert_count, 2)  # payment to new account + self-trusted account
        self.assertAlmostEqual(case.amount, 2500)    # the money once, not per alert
        self.assertEqual(assessment.case_count, 1)

    def test_one_attacker_iban_against_two_vendors_is_one_case(self):
        vendor_b = self.env["res.partner"].create({"name": "Second Vendor", "supplier_rank": 1, "is_company": True})
        for partner, amount in ((self.partner_a, 3000), (vendor_b, 2000)):
            bank = self.env["res.partner.bank"].with_user(self.clerk).create(
                {"partner_id": partner.id, "acc_number": "DE44500105175407324931", "allow_out_payment": True})
            self._pay(self.clerk, amount, bank=bank, partner=partner)
        self.env["shield.assessment"]._run()
        cases = self.env["shield.risk.case"].search([("state", "in", ("open", "escalated"))])
        self.assertEqual(len(cases), 1)
        self.assertAlmostEqual(cases.amount, 5000)

    def test_case_review_by_second_person_cascades(self):
        bank = self.env["res.partner.bank"].with_user(self.clerk).create({
            "partner_id": self.partner_a.id, "acc_number": "NL91ABNA0417164300", "allow_out_payment": True})
        self._pay(self.clerk, 2500, bank=bank)
        self.env["shield.assessment"]._run()
        case = self.env["shield.risk.case"].search([("bank_id", "=", bank.id)])
        case.review_note = "Called vendor on the number in our 2024 contract."
        with self.assertRaises(AccessError):
            case.with_user(self.clerk).action_mark_legitimate()  # cannot clear own case
        case.with_user(self.controller).action_mark_legitimate()
        self.assertEqual(set(case.event_ids.mapped("state")), {"legitimate"})
        self.assertAlmostEqual(self.env["shield.assessment"]._run().transaction_exposure, 0)

    def test_payment_hold_blocks_until_second_person_verifies(self):
        self._enforce_hold()
        bank = self.env["res.partner.bank"].with_user(self.clerk).create({
            "partner_id": self.partner_a.id, "acc_number": "GB29NWBK60161331926819", "allow_out_payment": True})
        with self.assertRaises(UserError):
            self._pay(self.clerk, 18400, bank=bank)
        with self.assertRaises(AccessError):
            bank.with_user(self.clerk).action_shield_verify()  # the person who set the number
        verifier = new_test_user(self.env, login="shield_verifier", company_id=self.company_data["company"].id,
                                 groups="base.group_user,account.group_validate_bank_account")
        bank.with_user(verifier).action_shield_verify()
        self.assertFalse(bank._shield_hold_reason())
        self._pay(self.clerk, 18400, bank=bank)  # now allowed

    def test_payment_hold_returns_after_the_number_changes_again(self):
        self._enforce_hold()
        bank = self._trusted_vendor_bank("BE68539007547034")
        bank.sudo().write({"shield_verified_hash": self.check._acc_digest(bank), "shield_verified_by": self.env.uid})
        self.assertFalse(bank._shield_hold_reason())
        bank.with_user(self.clerk).write({"allow_out_payment": False, "acc_number": "DE44500105175407324931"})
        bank.with_user(self.clerk).write({"allow_out_payment": True})
        self.assertTrue(bank._shield_hold_reason())

    def test_payment_hold_ignores_old_unchanged_accounts(self):
        self._enforce_hold()
        bank = self._trusted_vendor_bank("BE68539007547034")
        self.env.cr.execute("UPDATE res_partner_bank SET create_date = now() - interval '400 days' WHERE id = %s",
                            bank.ids)
        self.env.invalidate_all()
        self._pay(self.clerk, 100, bank=bank)  # legacy account: not blocked

    def test_payment_hold_control_and_fix(self):
        self.assertEqual(self.check._check_payment_hold()["status"], "fail")
        self.check._fix_payment_hold()
        self.assertEqual(self.check._check_payment_hold()["status"], "pass")

    def test_lookalike_vendor_paid_fast(self):
        real = self.env["res.partner"].create({"name": "Northwind Logistics", "supplier_rank": 1, "is_company": True})
        self.env.cr.execute("UPDATE res_partner SET create_date = now() - interval '300 days' WHERE id = %s", real.ids)
        self.env.invalidate_all()
        fake = self.env["res.partner"].with_user(self.clerk).create(
            {"name": "N0rthwind Logistics Ltd", "supplier_rank": 1, "is_company": True})
        bank = self.env["res.partner.bank"].with_user(self.clerk).create(
            {"partner_id": fake.id, "acc_number": "DE89370400440532013000", "allow_out_payment": True})
        self._pay(self.clerk, 7300, bank=bank, partner=fake)
        res = self.check._check_ccm_lookalike_vendor()
        self.assertEqual(res["status"], "fail")
        self.assertIn("Northwind Logistics", res["detail"])
        fast = self.check._check_ccm_new_vendor_fast_payment()
        self.assertEqual(fast["status"], "fail")
        event = self.env["shield.risk.event"].search([("rule", "=", "new_vendor_fast_payment")])
        self.assertEqual(event.severity, "critical")  # same person created vendor, bank and payment
        self.assertEqual(self.check._vendor_key("N0rthwind Logistics Ltd."), self.check._vendor_key("Northwind Logistics"))

    def test_shared_iban_survives_changing_the_number_again(self):
        """Found by lab wave 3: changing the number again must not erase a past payment to a staff IBAN."""
        bank = self._trusted_vendor_bank("BE68539007547034")
        bank.with_user(self.clerk).write({"allow_out_payment": False, "acc_number": "GB29NWBK60161331926819"})
        bank.with_user(self.clerk).write({"allow_out_payment": True})
        payment = self._pay(self.clerk, 18400, bank=bank)
        private = self.env["res.partner"].with_user(self.clerk).create({"name": "Clerk (private)"})
        self.env["res.partner.bank"].with_user(self.clerk).create(
            {"partner_id": private.id, "acc_number": "GB29NWBK60161331926819"})
        # One test transaction shares a single timestamp; spread the story over days as in real life.
        cr = self.env.cr
        cr.execute("UPDATE res_partner_bank SET create_date = now() - interval '10 days' WHERE id = %s", bank.ids)
        cr.execute("UPDATE mail_message SET date = now() - interval '3 days' WHERE id IN (SELECT mail_message_id "
                   "FROM mail_tracking_value WHERE new_value_char = 'GB29NWBK60161331926819')")
        cr.execute("UPDATE account_payment SET create_date = now() - interval '2 days' WHERE id = %s", payment.ids)
        self.env.invalidate_all()
        bank.with_user(self.clerk).write({"allow_out_payment": False, "acc_number": "ES9121000418450200051332"})
        res = self.check._check_ccm_shared_bank_account()
        self.assertEqual(res["status"], "fail")
        event = self.env["shield.risk.event"].search([("rule", "=", "shared_bank_account")])
        self.assertAlmostEqual(event.amount, 18400)
        self.assertIn("no longer hold it", event.detail)

    def test_assessment_reports_money_at_risk(self):
        bank = self.env["res.partner.bank"].with_user(self.clerk).create({
            "partner_id": self.partner_a.id, "acc_number": "FR7630006000011234567890189", "allow_out_payment": True})
        self._pay(self.clerk, 5000, bank=bank)
        assessment = self.env["shield.assessment"]._run()
        self.assertAlmostEqual(assessment.transaction_exposure, 5000)  # same payment, counted once
        self.assertGreaterEqual(assessment.access_exposure, 5000)
        self.assertIn(self.clerk, assessment.conflict_ids.user_id)
        self.assertEqual(assessment.action_verify_chain()["params"]["type"], "success")
        html, _fmt = self.env["ir.actions.report"]._render_qweb_html(
            "odoo_shield_warden.report_scorecard", assessment.ids)
        self.assertIn(b"Money at risk", html)

    def test_empty_state_is_honest_about_staleness(self):
        cases = self.env["shield.risk.case"]
        self.assertIn("Not assessed yet", cases.get_empty_list_help(""))
        self.env["shield.assessment"].action_run_assessment()
        self.assertIn("No money at risk", cases.get_empty_list_help(""))
        # One test shares one transaction time: age the assessment so later records are newer.
        self.env.flush_all()
        self.env.cr.execute("UPDATE shield_assessment SET create_date = create_date - interval '1 hour'")
        self.env.invalidate_all()
        self.assertIn("No money at risk", cases.get_empty_list_help(""))
        self._pay(self.clerk, 100)
        self.assertIn("Not assessed since", cases.get_empty_list_help(""))

    def test_run_assessment_button_passes_record_id(self):
        first = self.env["shield.assessment"].action_run_assessment()
        again = self.env["shield.assessment"].action_run_assessment([first["res_id"]])
        self.assertNotEqual(first["res_id"], again["res_id"])

    def test_run_wizard_writes_only_on_confirm(self):
        count = self.env["shield.assessment"].search_count
        before = count([])
        wizard = self.env["shield.run.wizard"].create({})
        self.assertIn("assessment", wizard.last_run.lower())
        self.assertEqual(count([]), before, "opening the wizard must not create an assessment")
        action = wizard.action_confirm()
        self.assertEqual(count([]), before + 1)
        self.assertEqual(action["res_model"], "shield.assessment")

    def test_assessment_name_is_numbered_and_delta_vs_previous(self):
        first = self.env["shield.assessment"].browse(self.env["shield.assessment"].action_run_assessment()["res_id"])
        second = self.env["shield.assessment"].browse(self.env["shield.assessment"].action_run_assessment()["res_id"])
        self.assertNotEqual(first.name, second.name)
        self.assertFalse(first.has_previous)
        self.assertTrue(second.has_previous)
        self.assertEqual(second.score_delta, second.security_score - first.security_score)

    def test_empty_state_works_for_a_reviewer_without_accounting_rights(self):
        # The action loads this help on every open, so a Shield manager with no accounting groups must not hit an AccessError.
        self.env["shield.assessment"].action_run_assessment()
        self.assertTrue(self.env["shield.risk.case"].with_user(self.controller).get_empty_list_help(""))
