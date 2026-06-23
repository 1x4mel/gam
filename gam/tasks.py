# Copyright (c) 2026, GAM and contributors
# License: MIT
"""Scheduled jobs (see hooks.py scheduler_events)."""
import frappe
from frappe.utils import now_datetime

from gam.realtime import emit_renewals_changed


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


def flag_expiring_accounts():
	"""Surface PLATFORM/standalone-GAME accounts within their renewal window.

	Plan §2.4: any account whose billing_type != ONE_TIME, status is ACTIVE,
	and active_until falls within ``renewal_lead_days`` of now is "due". The job
	only needs to nudge the dashboard — the renewal_state is computed on read —
	so here we just broadcast ``gam_renewals_changed`` once when due rows exist.
	"""
	now = now_datetime()
	due = frappe.db.sql(
		"""
		SELECT name
		FROM `tabGAM Account`
		WHERE account_level IN ('PLATFORM', 'GAME')
		  AND billing_type != 'ONE_TIME'
		  AND status = 'ACTIVE'
		  AND active_until IS NOT NULL
		  AND active_until <= DATE_ADD(%s, INTERVAL IFNULL(renewal_lead_days, 3) DAY)
		""",
		(now,),
		as_dict=True,
	)
	if due:
		emit_renewals_changed()
