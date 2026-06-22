"""Purge orphan rows from `tabGAM Account Role Game`.

A binding row references an account that no longer exists in
`tabGAM Account`. These orphans inflate the sidebar/role-game section counts
(`get_role_game_sections`, `get_account_stats`) which aggregate over the binding
table without joining the parent, while `get_accounts_list` (which requires the
account to exist) returns 0 — producing the "badge shows 9 but list shows 0"
phantom-account symptom.

This patch removes every orphan binding row so the counts become consistent.
Idempotent — safe to run repeatedly.
"""
import frappe


def execute():
	if not frappe.db.table_exists("GAM Account Role Game"):
		return
	if not frappe.db.table_exists("GAM Account"):
		return

	orphans = frappe.db.sql_list(
		"""
		SELECT arg.name
		FROM `tabGAM Account Role Game` arg
		LEFT JOIN `tabGAM Account` a ON a.name = arg.account
		WHERE a.name IS NULL
		"""
	)
	if not orphans:
		return

	for name in orphans:
		# force=True so we don't trip on link-integrity checks for the dangling row.
		frappe.delete_doc(
			"GAM Account Role Game", name, force=True, ignore_permissions=True
		)

	frappe.db.commit()
