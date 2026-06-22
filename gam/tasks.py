# Copyright (c) 2026, GAM and contributors
# License: MIT
"""Scheduled jobs (see hooks.py scheduler_events)."""
import frappe
from frappe.utils import now_datetime


def expire_email_codes():
	"""Mark AVAILABLE codes past their expires_at as EXPIRED (Design §7.4)."""
	now = now_datetime()
	names = frappe.get_all(
		"GAM Email Code",
		filters={"status": "AVAILABLE", "expires_at": ["<", now]},
		pluck="name",
	)
	for name in names:
		frappe.db.set_value("GAM Email Code", name, "status", "EXPIRED", update_modified=False)


def force_release_leases():
	"""Force-release IN_USE account leases past their lease_until (Design §4B)."""
	now = now_datetime()
	names = frappe.get_all(
		"GAM Account Usage",
		filters={"status": "IN_USE", "lease_until": ["<", now]},
		pluck="name",
	)
	for name in names:
		usage = frappe.get_doc("GAM Account Usage", name)
		usage.status = "FORCE_RELEASED"
		usage.ended_at = now
		usage.end_reason = "TIMEOUT"
		usage.save(ignore_permissions=True)
