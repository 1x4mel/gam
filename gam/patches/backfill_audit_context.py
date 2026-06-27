# Copyright (c) 2026, GAM and contributors
# License: MIT
"""One-time backfill of security-audit context on historical log rows.

Denormalizes ``account_username`` / ``account_email_address`` / ``game`` onto
existing GAM Code Request Log rows (newly added fields) so the audit timeline
is self-contained without N+1 lookups. IP/user-agent cannot be reconstructed
for historical rows and are intentionally left blank.

Idempotent: only fills NULL/empty fields.
"""
import frappe


def execute():
	fixed = 0
	for row in frappe.get_all(
		"GAM Code Request Log",
		filters=[["account_username", "in", [None, ""]]],
		pluck="name",
	):
		log = frappe.db.get_value(
			"GAM Code Request Log", row,
			["name", "target_account", "target_email", "game"],
			as_dict=True,
		)
		updates = {}
		acc = log.target_account
		if acc and not log.game:
			# reuse the request-time game resolver
			from gam.api import _resolve_account_game
			updates["game"] = _resolve_account_game(acc) or ""
		if acc:
			a = frappe.db.get_value("GAM Account", acc, ["username", "email"], as_dict=True)
			if a:
				updates["account_username"] = a.username or ""
				if a.email:
					updates["account_email_address"] = (
						frappe.db.get_value("GAM Email", a.email, "address") or ""
					)
		if updates:
			frappe.db.set_value("GAM Code Request Log", row, updates)
			fixed += 1
	frappe.db.commit()
	print(f"GAM backfill_audit_context: {fixed} Code Request Log rows enriched")
