# Copyright (c) 2026, GAM and contributors
# License: MIT
"""App-agnostic session helpers consumed by the gam-ui SPA."""
import frappe


@frappe.whitelist(allow_guest=True)
def get_session_csrf_token():
	"""Return a fresh CSRF token (guest-callable) for same-origin SPAs."""
	return frappe.sessions.get_csrf_token()


@frappe.whitelist()
def get_current_user_roles():
	"""Return ALL roles of the logged-in user (app-agnostic).

	Each co-tenant SPA is responsible for filtering its own app roles.
	"""
	if frappe.session.user == "Guest":
		return []
	return sorted(set(frappe.get_roles()))


@frappe.whitelist(allow_guest=True)
def get_gam_session():
	"""Single-round-trip boot payload for the gam-ui SPA (B4).

	Returns everything the router guard + AppLayout need in ONE call instead of
	the legacy getLoggedInUser() + get_current_user_roles() pair (3 round-trips):

		{
		  "user": "member@x.com" | "Guest",
		  "full_name": "...",
		  "roles": [...],            # ALL roles (app-agnostic; co-tenant site)
		  "is_gam_admin": bool,
		  "is_gam_member": bool,
		  "csrf_token": "..."        # refreshed guest token (handy for first POST)
		}

	Callable as Guest (returns user='Guest', empty roles) so the SPA can probe
	session state before login without a separate endpoint.
	"""
	user = frappe.session.user
	if user == "Guest":
		return {
			"user": "Guest",
			"full_name": "",
			"roles": [],
			"is_gam_admin": False,
			"is_gam_member": False,
			"csrf_token": frappe.sessions.get_csrf_token(),
		}

	roles = set(frappe.get_roles())

	# L2 access grants (role+game / section visibility) — fetched here so the
	# SPA boot is still a single round-trip. Wrapped so a not-yet-migrated site
	# (doctype missing on first deploy) boots safely with empty grants.
	access = {"is_admin": False, "default_policy": "match_role", "grants": []}
	try:
		is_admin = bool({"GAM Admin", "System Manager", "Administrator"} & roles)
		if is_admin:
			access = {"is_admin": True, "default_policy": "match_role", "grants": []}
		else:
			rows = frappe.db.get_all(
				"GAM Access Grant",
				filters={"user": user, "app": "GAM", "granted": 1},
				fields=["scope", "key", "value"],
			)
			policy = (
				frappe.db.get_value("GAM Settings", "GAM Settings", "grant_default_policy")
				or "match_role"
			)
			access = {
				"is_admin": False,
				"default_policy": policy,
				"grants": [
					{"scope": r["scope"], "key": r["key"], "value": r["value"]} for r in rows
				],
			}
	except Exception:
		pass

	return {
		"user": user,
		"full_name": (frappe.db.get_value("User", user, "full_name") or "").strip(),
		"roles": sorted(roles),
		"is_gam_admin": "GAM Admin" in roles,
		"is_gam_member": "GAM Member" in roles,
		"access": access,
		"csrf_token": frappe.sessions.get_csrf_token(),
	}
