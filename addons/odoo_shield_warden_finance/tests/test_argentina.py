"""Argentina: CBU bank accounts and withholding payments go through the payment hold.

Runs only when ``l10n_ar_withholding`` is installed (the kaizen loop installs it in a throwaway database); in any other
database the whole class is skipped.
"""

import unittest

from odoo import Command, fields
from odoo.exceptions import AccessError, UserError
from odoo.modules.registry import Registry
from odoo.tests import new_test_user, tagged
from odoo.tests.common import get_db_name

try:
    from odoo.addons.l10n_ar.tests.common import TestArCommon
except ImportError:  # pragma: no cover - l10n_ar not shipped with this Odoo
    TestArCommon = None

CBU_A = "2850590940090418135201"  # valid CBU (python-stdnum's own example)
CBU_B = "0170099220000067797370"  # valid CBU, the attacker's account
CVU = "0000003100010000000001"  # CVU: 22 digits, wallet prefix 000000


def _ar_withholding_installed():
    with Registry(get_db_name()).cursor() as cr:
        cr.execute("SELECT 1 FROM ir_module_module WHERE name = 'l10n_ar_withholding' AND state = 'installed'")
        return bool(cr.fetchone())


if TestArCommon:

    @tagged("post_install", "post_install_l10n", "-at_install")
    class TestArgentina(TestArCommon):

        @classmethod
        def setUpClass(cls):
            if not _ar_withholding_installed():
                raise unittest.SkipTest("l10n_ar_withholding is not installed in this database")
            super().setUpClass()
            company = cls.company_ri
            cls.env.user.groups_id |= cls.env.ref("odoo_shield_warden.group_shield_manager")
            cls.clerk = new_test_user(
                cls.env, login="ar_clerk", company_id=company.id, company_ids=[(6, 0, company.ids)],
                groups="base.group_user,base.group_partner_manager,account.group_account_invoice,"
                       "account.group_validate_bank_account")
            cls.approver = new_test_user(
                cls.env, login="ar_approver", company_id=company.id, company_ids=[(6, 0, company.ids)],
                groups="base.group_user,base.group_partner_manager,account.group_account_invoice,"
                       "account.group_validate_bank_account")
            cls.vendor = cls.env["res.partner"].create({
                "name": "Proveedor SA", "country_id": cls.env.ref("base.ar").id,
                "l10n_ar_afip_responsibility_type_id": cls.env.ref("l10n_ar.res_IVARI").id,
                "l10n_latam_identification_type_id": cls.env.ref("l10n_ar.it_cuit").id, "vat": "30500010912",
            })
            cls.env["ir.config_parameter"].sudo().set_param("shield.payment_hold", "enforce")
            cls.wth_tax = cls.env.ref("account.%i_ex_tax_withholding_iibb_caba_applied" % company.id)
            cls.wth_tax.write({
                "amount": 10, "amount_type": "percent",
                "l10n_ar_withholding_sequence_id": cls.env["ir.sequence"].create(
                    {"name": "wth test", "implementation": "standard", "padding": 8}).id,
            })
            cls.tax_21 = cls.env.ref("account.%s_ri_tax_vat_21_compras" % company.id)

        def _bank(self, number, user=None):
            return self.env["res.partner.bank"].with_user(user or self.clerk).create(
                {"acc_number": number, "partner_id": self.vendor.id})

        def _bill(self, bank, amount=1000.0, number="1-1"):
            bill = self.env["account.move"].create({
                "move_type": "in_invoice", "partner_id": self.vendor.id, "partner_bank_id": bank.id,
                "invoice_date": fields.Date.today(), "l10n_latam_document_number": number,
                "invoice_line_ids": [Command.create({"product_id": self.product_a.id, "price_unit": amount,
                                                     "tax_ids": [Command.set(self.tax_21.ids)]})],
            })
            bill.action_post()
            return bill

        def _register(self, bill, withhold=False):
            vals = {"payment_date": fields.Date.today()}
            if withhold:
                vals["l10n_ar_withholding_ids"] = [Command.create(
                    {"tax_id": self.wth_tax.id, "base_amount": bill.amount_untaxed, "amount": 0})]
            wizard = self.env["account.payment.register"].with_context(
                active_model="account.move", active_ids=bill.ids).create(vals)
            if withhold:
                wizard.l10n_ar_withholding_ids._compute_amount()
            return wizard

        def test_cbu_is_a_recognised_account_type_and_cvu_is_not_rejected(self):
            self.assertEqual(self._bank(CBU_A).acc_type, "cbu")
            self.assertTrue(self._bank(CVU).id)  # a CVU (digital wallet) is stored as a plain number; still guarded

        def test_payment_order_to_new_cbu_is_held_until_a_second_person_verifies(self):
            bank = self._bank(CBU_A)
            bill = self._bill(bank)
            wizard = self._register(bill)
            self.assertEqual(wizard.partner_bank_id, bank, "the bank on the bill must reach the payment")
            with self.assertRaisesRegex(UserError, "held by Odoo Shield Warden"):
                wizard.action_create_payments()
            with self.assertRaises(AccessError):
                bank.with_user(self.clerk).action_shield_verify()  # cannot verify what you set yourself
            bank.with_user(self.approver).action_shield_verify()
            payment = self.env["account.payment"].browse(self._register(bill).action_create_payments()["res_id"])
            self.assertIn(payment.state, ("in_process", "paid"))

        def test_withholding_payment_is_held_too(self):
            bank = self._bank(CBU_A)
            bill = self._bill(bank, number="1-2")
            wizard = self._register(bill, withhold=True)
            self.assertTrue(wizard.l10n_ar_withholding_ids, "the withholding line must exist for this test to mean anything")
            with self.assertRaisesRegex(UserError, "held by Odoo Shield Warden"):
                wizard.action_create_payments()

        def test_swapped_cbu_after_verification_is_held_again(self):
            bank = self._bank(CBU_A)
            bank.with_user(self.approver).action_shield_verify()
            self.assertFalse(bank._shield_hold_reason())
            bank.sudo().write({"acc_number": CBU_B})  # the swap
            self.assertTrue(bank._shield_hold_reason(), "a changed CBU must invalidate the earlier verification")
