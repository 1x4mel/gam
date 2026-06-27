# Copyright (c) 2026, GAM and contributors
# License: MIT
"""One-time backlink of orphaned GAM Email Codes.

A code is "orphaned" when it was ingested BEFORE the owning GAM Email existed:
at ingest time ``gam_email`` resolved to nothing, so the code row was created
with ``email = NULL``. Later the admin adds the GAM Email (unrecognized panel →
"Add"), which re-links the inbound log but never the code — so ``request_code``
(``WHERE email = ...``) can never see it.

This patch re-links every NULL-email code through its creating inbound log's
now-resolved ``gam_email``. Idempotent and safe (only touches NULL rows).
"""
import frappe


def execute():
	orphaned = frappe.get_all("GAM Email Code", filters={"email": ["is", "not set"]}, pluck="name")
	fixed = 0
	for code_name in orphaned:
		owner = frappe.db.get_value("GAM Email Inbound Log", {"email_code": code_name}, "gam_email")
		if owner:
			frappe.db.set_value("GAM Email Code", code_name, "email", owner)
			fixed += 1
	frappe.db.commit()
	print(f"GAM backlink_orphan_codes: {fixed}/{len(orphaned)} codes re-linked")
