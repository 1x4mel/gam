"""Backfill chain fields on GAM Account Usage for the shift-handoff feature.

Each new ``checkout_account`` now sets ``chain_head = <self>`` and
``prev_lease = null`` (start of a fresh online chain). Existing rows predate
these columns, so this post-model-sync patch sets every existing usage row to be
its own chain head (``chain_head = name``) with no previous lease — i.e. each
historical lease is treated as a one-element chain.

This is intentionally conservative: we never synthesise a chain across separate
past leases (we cannot reliably tell which were "continuous" handoffs), so the
continuous-online cap only starts applying to chains created from now on.

Idempotent — only fills rows whose ``chain_head`` is empty.
"""
import frappe


def execute():
	if not frappe.db.has_column("GAM Account Usage", "chain_head"):
		return

	names = frappe.db.get_all(
		"GAM Account Usage",
		filters={"chain_head": ("in", [None, ""])},
		pluck="name",
	)
	for name in names:
		frappe.db.set_value(
			"GAM Account Usage", name, "chain_head", name, update_modified=False
		)
