# Copyright (c) 2026, GAM and contributors
# License: MIT
"""Operational helpers for ops/admins.

	create_test_users / run_smoke / audit_all_members  — `bench execute` only:
		bench --site erp.local execute gam.ops.create_test_users
		bench --site erp.local execute gam.ops.run_smoke
		bench --site erp.local execute gam.ops.audit_all_members

	setup_2fa_test / teardown_2fa_test  — whitelisted + admin-only so the e2e
	suite can provision a DEDICATED 2FA test user (role-scoped: it does NOT
	challenge any other co-tenant user). Gated behind `gam_allow_2fa_test=1`
	(dev/staging only); the plaintext TOTP secret is returned ONLY when
	``reveal=1`` is passed (P1.6). Also runnable via `bench execute`:
		bench --site erp.local execute gam.ops.setup_2fa_test
		bench --site erp.local execute gam.ops.teardown_2fa_test
"""
import os

import frappe
from frappe import _

# Isolated test users for smoke-testing B4 role isolation (dev/staging only).
TEST_USERS = [
	{
		"email": "gam-admin@test.local",
		"full_name": "GAM Test Admin",
		"roles": ["GAM Admin"],
	},
	{
		"email": "gam-member@test.local",
		"full_name": "GAM Test Member",
		"roles": ["GAM Member"],
	},
]
DEFAULT_TEST_PASSWORD = "GAM@test-2026"

# Roles that, when held by a GAM Member, break co-tenancy isolation.
ISOLATION_BREAKING_ROLES = ["System Manager", "Administrator"]


def create_test_users(password=DEFAULT_TEST_PASSWORD):
	"""Create isolated GAM test users (each holds ONLY its GAM role + 'All').

	Returns the list of created/ensured emails. Re-runnable (idempotent).
	"""
	ensured = []
	for spec in TEST_USERS:
		email = spec["email"]
		if not frappe.db.exists("User", email):
			frappe.get_doc(
				{
					"doctype": "User",
					"email": email,
					"first_name": spec["full_name"],
					"enabled": 1,
					"send_welcome_email": 0,
					"new_password": password,
				}
			).insert(ignore_permissions=True)

		user = frappe.get_doc("User", email)
		# Pin the role set to EXACTLY the GAM role(s) + 'All' so no erpnext /
		# trader-ui / System Manager role can leak in (co-tenancy isolation).
		# Rebuild the roles child-table via append() — assigning raw dicts
		# breaks _set_defaults (child rows lack is_new()).
		desired = set(spec["roles"]) | {"All"}
		user.roles = []
		for role in sorted(desired):
			user.append("roles", {"role": role})
		user.new_password = password
		user.save(ignore_permissions=True)
		# NOTE: Frappe's User doctype re-grants "Desk User"/"Guest" as mandatory
		# defaults on save (cannot be stripped). These are surfaced — NOT flagged
		# — by get_role_audit()/other_roles so admins can review. They grant Desk
		# UI access but NOT erpnext/trader-ui data (no DATA isolation break).
		ensured.append(email)
	frappe.db.commit()
	return ensured


def audit_all_members():
	"""Print a role-isolation audit for every GAM Member.

	Flags any member holding an isolation-breaking role. Exits non-zero on
	violations so it can gate CI / go-live checks.
	"""
	members = frappe.get_all("Has Role", filters={"role": "GAM Member"}, pluck="parent")
	violations = 0
	print("=== GAM role-isolation audit ===")
	for user in sorted(set(members)):
		roles = set(frappe.get_roles(user))
		bad = sorted(roles & set(ISOLATION_BREAKING_ROLES))
		flag = "  ✗ " + ", ".join(bad) if bad else "  ✓"
		print(f"{user:<40} {flag}")
		if bad:
			violations += 1
	print(f"=== {len(set(members))} member(s), {violations} violation(s) ===")
	return violations


def run_smoke():
	"""Self-check the B4 stack: role audit + isolated test users.

	NOTE: get_gam_session() is exercised over HTTP (it needs a request for
	the CSRF token) — see the deploy README's curl smoke. This CLI smoke only
	covers what is callable from `bench execute`.
	"""
	from gam.api import get_role_audit

	print("=== B4 smoke ===")
	audit = get_role_audit()
	print(f"[1] role_audit (self): isolated={audit.get('is_isolated')} warnings={audit.get('warnings')}")

	created = create_test_users()
	print(f"[2] test users ensured: {created}")

	violations = audit_all_members()
	ok = violations == 0
	print("=== B4 smoke %s ===" % ("PASS" if ok else "FAIL"))
	return ok


# ===========================================================================
# Two-Factor Authentication test harness (dev / staging only)
# ===========================================================================
#
# Frappe 2FA is ROLE-scoped: `System Settings.enable_two_factor_auth` gates the
# feature globally, but a user is only challenged if they hold a Role with
# `two_factor_auth = 1`. We exploit that so the e2e suite can exercise the
# LoginView 2-step flow against a DEDICATED test role/user WITHOUT challenging
# the other test users (gam-admin/gam-member) or anyone else on the co-tenant
# site — even if global 2FA is accidentally left on by a crashed run.
#
# Call from bench CLI for a manual smoke, or via REST from the e2e suite:
#	bench --site erp.local execute gam.ops.setup_2fa_test
#	bench --site erp.local execute gam.ops.teardown_2fa_test

TWOFA_TEST_ROLE = "GAM 2FA Test"
TWOFA_TEST_USER = "gam-2fa@test.local"
TWOFA_TEST_PASSWORD = "GAM@2fa-2026"


def _require_admin():
	"""Guard whitelisted ops helpers to GAM Admin / Administrator only."""
	roles = set(frappe.get_roles())
	if "GAM Admin" not in roles and "Administrator" not in roles:
		frappe.throw(_("Not permitted"), frappe.PermissionError)


def _gam_allow_2fa_test():
	"""True only when explicitly opted-in (dev/staging). Never by default — a
	production site must NOT be able to provision a 2FA test user (P1.6)."""
	return bool(frappe.conf.get("gam_allow_2fa_test") or os.environ.get("GAM_ALLOW_2FA_TEST"))


def _log_2fa_secret_reveal():
	"""Audit the plaintext TOTP reveal to GAM Reveal Log (mirrors api._log_reveal)."""
	try:
		frappe.get_doc(
			{
				# action must be one of the GAM Reveal Log Select options
				# (REVEAL/COPY); the target is recorded via target_doctype +
				# fieldname.
				"doctype": "GAM Reveal Log",
				"action": "REVEAL",
				"viewed_by": frappe.session.user,
				"target_doctype": "User",
				"target_name": TWOFA_TEST_USER,
				"fieldname": "totp_secret",
				"viewed_at": frappe.utils.now_datetime(),
			}
		).insert(ignore_permissions=True)
		frappe.db.commit()
	except Exception:
		frappe.db.rollback()
		frappe.log_error(title="GAM 2FA test secret reveal audit failed")


@frappe.whitelist()
def setup_2fa_test(reveal=None):
	"""Provision a dedicated 2FA test role + user.

	Returns ``{"user", "password"}`` by default. The plaintext ``totp_secret``
	is ONLY returned when ``reveal=1`` is passed (audited via GAM Reveal Log),
	so a default call never leaks it (P1.6). Idempotent. Admin-only.

	Requires ``gam_allow_2fa_test=1`` (common_site_config / env) — this MUST stay
	off on production. Enabling global 2FA here is otherwise SAFE: only holders
	of the dedicated ``GAM 2FA Test`` role are challenged.
	"""
	_require_admin()
	if not _gam_allow_2fa_test():
		frappe.throw(
			_(
				"2FA test provisioning is disabled on this site. Enable only on "
				"dev/staging by setting `gam_allow_2fa_test=1` in "
				"common_site_config.json (or env GAM_ALLOW_2FA_TEST)."
			),
			frappe.PermissionError,
		)

	# 1. Dedicated role carrying the 2FA flag.
	if not frappe.db.exists("Role", TWOFA_TEST_ROLE):
		frappe.get_doc(
			{
				"doctype": "Role",
				"role_name": TWOFA_TEST_ROLE,
				"two_factor_auth": 1,
				"desk_access": 0,
			}
		).insert(ignore_permissions=True)
	else:
		frappe.db.set_value("Role", TWOFA_TEST_ROLE, "two_factor_auth", 1)

	# 2. Dedicated user: GAM Member (so the gam-ui router guard admits it) +
	#    the 2FA role (so Frappe challenges it on login).
	if not frappe.db.exists("User", TWOFA_TEST_USER):
		frappe.get_doc(
			{
				"doctype": "User",
				"email": TWOFA_TEST_USER,
				"first_name": "GAM 2FA Test",
				"enabled": 1,
				"send_welcome_email": 0,
				"new_password": TWOFA_TEST_PASSWORD,
			}
		).insert(ignore_permissions=True)
	user = frappe.get_doc("User", TWOFA_TEST_USER)
	user.roles = []
	for role in sorted({"GAM Member", "All", TWOFA_TEST_ROLE}):
		user.append("roles", {"role": role})
	user.new_password = TWOFA_TEST_PASSWORD
	user.save(ignore_permissions=True)

	# 3. Enable global 2FA + select the OTP App method (TOTP, no email/SMS).
	frappe.db.set_single_value("System Settings", "enable_two_factor_auth", 1)
	frappe.db.set_single_value("System Settings", "two_factor_method", "OTP App")

	# 4. Provision (or read) the user's OTP secret. ``get_otpsecret_for_``
	#    auto-generates + stores it encrypted on first call and returns the
	#    plaintext base32 secret the client TOTP generator needs to derive codes.
	from frappe.twofactor import get_otpsecret_for_

	totp_secret = get_otpsecret_for_(TWOFA_TEST_USER)

	# 5. Mark first-time OTP login as DONE so Frappe runs the TOTP challenge
	#    directly (process_2fa_for_otp_app) instead of emailing a setup QR.
	#    Reuse twofactor's own set_default() — it writes under parent="__2fa"
	#    (which its get_default() reads back); frappe.defaults.set_default uses
	#    "__default" and would NOT be seen by the 2FA flow.
	from frappe.twofactor import set_default as set_2fa_default

	set_2fa_default(TWOFA_TEST_USER + "_otplogin", 1)

	frappe.db.commit()
	result = {
		"user": TWOFA_TEST_USER,
		"password": TWOFA_TEST_PASSWORD,
	}
	# Only surface the plaintext secret on explicit, audited request (P1.6).
	if frappe.utils.cint(reveal):
		_log_2fa_secret_reveal()
		result["totp_secret"] = totp_secret
	return result


@frappe.whitelist()
def teardown_2fa_test():
	"""Disable global 2FA again. Idempotent. Admin-only.

	Leaves the dedicated role/user in place (harmless once global 2FA is off)
	so re-running ``setup_2fa_test`` is cheap and the secret stays stable.
	"""
	_require_admin()
	frappe.db.set_single_value("System Settings", "enable_two_factor_auth", 0)
	frappe.db.commit()
	return {"disabled": True}
