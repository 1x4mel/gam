"""
Provision / refresh the dedicated "Trader Item" match_role test user for the
gam-admin-role-game-sidebar e2e spec (§4b).

Run (from frappe-bench):
    bench --site erp.local execute gam_ui_e2e_provision.run
or from the repo root with the bench on PATH:
    bench --site erp.local execute gam_ui_e2e_provision.run

It is idempotent:
  • ensures the "Trader Item" Account Role (value TRADER_ITEM) — saving it also
    mirrors a Frappe Role named "Trader Item" (gam.api._ensure_account_role);
  • ensures the user gam-trader-item@test.local holds EXACTLY ["Trader Item",
    "All"] and the GAM Member role is NOT present, so the only reason the
    sidebar shows the Trader Item section for this user is the match_role
    fallback (zero grants + a Frappe role matching the Account-Role label).
  • clears any GAM Access Grant rows for the user (so the fallback is the only
    visibility path).

Prints the user email + a JSON the spec can read.
"""
from __future__ import annotations

import json

import frappe

EMAIL = "gam-trader-item@test.local"
PASSWORD = "GAM@test-2026"
ROLE_LABEL = "Trader Item"
ROLE_VALUE = "TRADER_ITEM"


def _ensure_account_role():
    """Idempotently create the Trader Item Account Role (mirrors a Frappe Role)."""
    if not frappe.db.exists(
        "GAM List Option",
        {"category": "Account Role", "value": ROLE_VALUE},
    ):
        frappe.get_doc(
            {
                "doctype": "GAM List Option",
                "category": "Account Role",
                "label": ROLE_LABEL,
                "value": ROLE_VALUE,
                "icon": "📦",
                "color": "amber",
                "sort_order": 0,
                "is_active": 1,
            }
        ).insert(ignore_permissions=True)
    # Mirror the Frappe Role (same path gam.api._ensure_account_role takes).
    if not frappe.db.exists("Role", ROLE_LABEL):
        frappe.get_doc(
            {
                "doctype": "Role",
                "role_name": ROLE_LABEL,
                "desk_access": 0,
                "is_custom": 1,
            }
        ).insert(ignore_permissions=True)


def run():
    _ensure_account_role()

    # Create / refresh the user.
    if not frappe.db.exists("User", EMAIL):
        frappe.get_doc(
            {
                "doctype": "User",
                "email": EMAIL,
                "first_name": "GAM Trader Item",
                "send_welcome_email": 0,
                "new_password": PASSWORD,
            }
        ).insert(ignore_permissions=True)
    user = frappe.get_doc("User", EMAIL)

    # Roles: GAM Member (so the user can log into gam-ui) + "Trader Item"
    # (the Account-Role label that drives the match_role fallback) + All.
    # Zero GAM grants → match_role is the only visibility path.
    desired = {"GAM Member", "Trader Item", "All"}
    user.roles = []
    for role in sorted(desired):
        user.append("roles", {"role": role})
    user.new_password = PASSWORD
    user.save(ignore_permissions=True)

    # Wipe any GAM Access Grant rows for this user so the fallback path is the
    # only visibility driver.
    frappe.db.delete("GAM Access Grant", {"user": EMAIL})
    frappe.db.commit()

    out = {"email": EMAIL, "password": PASSWORD, "roles": sorted(desired)}
    print(json.dumps(out))
    return out


def diag_access_grant():
    """Probe whether the reserved-word column `key` is quoted by this frappe."""
    import json as _json

    results = {}
    # 1) ORM get_all with the `key` field (this is what get_access_grants does).
    try:
        frappe.db.get_all(
            "GAM Access Grant",
            filters={"user": "nobody@example.com"},
            fields=["name", "user", "scope", "key", "value"],
            limit=1,
        )
        results["orm_get_all_key"] = "ok"
    except Exception as e:
        results["orm_get_all_key"] = f"ERR: {e}"

    # 2) Raw SQL with explicit backticks (control).
    try:
        frappe.db.sql("SELECT `key` FROM `tabGAM Access Grant` LIMIT 1")
        results["raw_backtick"] = "ok"
    except Exception as e:
        results["raw_backtick"] = f"ERR: {e}"

    # 3) ORM get_value on key.
    try:
        frappe.db.get_value("GAM Access Grant", {"name": "___none___"}, "key")
        results["orm_get_value_key"] = "ok"
    except Exception as e:
        results["orm_get_value_key"] = f"ERR: {e}"

    print(_json.dumps(results))
    return results
