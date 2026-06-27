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
	"""Force-release IN_USE account leases past their lease_until (Design §4B),
	AND any lease whose online *chain* has hit the continuous-online cap.

	The chain cap (global ``continuous_online_cap_hours`` or per-game override)
	is the real ban-prevention safety net: a forgotten handoff chain would
	otherwise keep an account online 24/7 across shifts. The cap is enforced
	lazily on handoff, but this sweep catches chains that are never handed off
	again (or whose holder abandoned the session)."""
	# Local import to avoid a heavy import at module load.
	from gam.api import _chain_online_seconds, _resolve_continuous_cap_hours

	now = now_datetime()

	# 1) Past lease_until (existing behaviour).
	names = frappe.get_all(
		"GAM Account Usage",
		filters={"status": "IN_USE", "lease_until": ["<", now]},
		pluck="name",
	)

	# 2) Over the continuous-online chain cap.
	over_cap = []
	if frappe.db.has_column("GAM Account Usage", "chain_head"):
		active = frappe.get_all(
			"GAM Account Usage",
			filters={"status": "IN_USE"},
			fields=["name", "account"],
		)
		seen_accounts = set()
		for row in active:
			if row["account"] in seen_accounts:
				continue
			seen_accounts.add(row["account"])
			try:
				online_seconds, _ = _chain_online_seconds(row["account"], now)
			except Exception:
				continue
			cap_seconds = _resolve_continuous_cap_hours(row["account"]) * 3600
			if cap_seconds > 0 and online_seconds >= cap_seconds:
				over_cap.append(row["name"])

	for name in list(dict.fromkeys(names + over_cap)):
		usage = frappe.get_doc("GAM Account Usage", name)
		if usage.status != "IN_USE":
			continue
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


def archive_audit_logs():
	"""Retention monitor for security audit logs (daily).

	Counts rows in the three audit doctypes older than
	``GAM Settings.audit_log_retention_days`` and logs a warning. It NEVER
	deletes — audit trails must be preserved for accountability; archival
	(export → cold store) is a manual operator step triggered by this signal.
	"""
	from frappe.utils import add_to_date
	from frappe.utils import cint

	settings = frappe.get_single("GAM Settings")
	days = cint(settings.get("audit_log_retention_days")) or 365
	threshold = add_to_date(now_datetime(), days=-days)
	stats = {}
	for doctype, col in (
		("GAM Code Request Log", "requested_at"),
		("GAM Reveal Log", "viewed_at"),
		("GAM Account Usage", "started_at"),
	):
		stats[doctype] = frappe.db.count(doctype, filters={col: ["<", threshold]})
	total = sum(stats.values())
	if total:
		frappe.logger("gam").warning(
			f"GAM audit retention: {total} rows older than {days}d (export+archive "
			f"manually — never auto-deleted). breakdown={stats}"
		)
	return {"threshold_days": days, "older_than_threshold": stats, "total": total}
