# Copyright (c) 2026, GAM and contributors
# License: MIT
"""Permission callbacks for the Frappe app switcher (co-tenancy, Design §6.1).

`has_app_permission` gates whether the GAM tile is shown in the apps screen.
Only users holding a GAM role (or Administrator) may see / open GAM — this is
the desk-side companion to the gam-ui router guard (router/index.js).
"""
import frappe


def has_app_permission():
	"""Return True if the current user should see the GAM app tile."""
	if frappe.session.user == "Administrator":
		return True
	roles = set(frappe.get_roles())
	return "GAM Admin" in roles or "GAM Member" in roles
