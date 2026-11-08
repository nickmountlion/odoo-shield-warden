# LAB FIXTURE - DELIBERATELY MISCONFIGURED. Never install outside the local attack lab.
# Imitates two common third-party module mistakes (an access rule with no group granting
# write/delete to everyone, and an unsanitized HTML field) so Shield's checks can be tested.
# It exposes no routes.
{
    "name": "LAB ONLY - Misconfigured Portal Extension",
    "summary": "Inert misconfiguration fixture for the Odoo Shield Warden attack lab",
    "version": "18.0.0.1",
    "author": "Some Vendor Ltd",
    "license": "LGPL-3",
    "depends": ["base"],
    "data": ["security/ir.model.access.csv"],
    "installable": True,
}
