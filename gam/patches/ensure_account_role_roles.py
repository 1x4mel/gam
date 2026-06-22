"""Create a Frappe Role for each existing Account Role list option.

Pairs with ``gam.api._ensure_account_role`` (which creates roles on save) so the
pre-seeded Account Roles (Trader / Booster / Item) become assignable to users
via the standard User > Roles screen. Idempotent and safe — custom roles with
no permissions, desk access disabled.

Run as a one-time post-model-sync patch on existing installs.
"""
import frappe


def execute():
	if not frappe.db.table_exists("GAM List Option"):
		return

	rows = frappe.db.get_all(
		"GAM List Option",
		filters={"category": "Account Role"},
		fields=["label", "value"],
	)
	for r in rows:
		name = (r.label or r.value or "").strip()
		if not name or frappe.db.exists("Role", name):
			continue
		try:
			frappe.get_doc({
				"doctype": "Role",
				"role_name": name,
				"desk_access": 0,
				"is_custom": 1,
			}).insert(ignore_permissions=True)
		except Exception:
			frappe.log_error(title="GAM: ensure_account_role_roles patch")
