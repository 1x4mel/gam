# Copyright (c) 2026, GAM and contributors
# License: MIT
"""Shared fixtures for the GAM backend test suite.

Each helper is idempotent (defensive delete-first) so tests are robust even
when Frappe's per-method transaction rollback is not in effect.
"""
import frappe

TEST_ADDRESS = "unit-test@gam.test"
TEST_USERNAME = "unit_test_steam"


def _delete_if(doctype, filters):
	"""Force-delete docs matching *filters* (ignore missing)."""
	for name in frappe.get_all(doctype, filters=filters, pluck="name"):
		frappe.delete_doc(doctype, name, force=True, ignore_permissions=True)


def purge_fixtures():
	"""Remove any leftover GAM rows produced by this suite (dependency order)."""
	_delete_if("GAM Reveal Log", {"target_name": ["like", "unit%"]})
	_delete_if("GAM Code Request Log", {"target_email": ["like", "%@gam.test%"]})
	_delete_if("GAM Email Inbound Log", {"email_account": ["like", "%@gam.test%"]})
	_delete_if("GAM Email Code", {"email_address": ["like", "%@gam.test%"]})
	_delete_if("GAM Account Usage", {"account": ["like", "unit%"]})
	_delete_if("GAM Account Link", {"source_account": ["like", "unit%"]})
	_delete_if("GAM Account", {"username": ["like", "unit%"]})
	_delete_if("GAM Email", {"address": ["like", "%@gam.test%"]})


def make_email(address=TEST_ADDRESS, password="emailpw", provider="Gmail"):
	"""Create (or recreate) a GAM Email; return its doc name."""
	purge_email(address)
	doc = frappe.get_doc(
		{
			"doctype": "GAM Email",
			"address": address,
			"email_password": password,
			"provider": provider,
			"is_active": 1,
		}
	)
	doc.insert(ignore_permissions=True)
	return doc.name


def purge_email(address):
	name = frappe.db.get_value("GAM Email", {"address": address})
	if name:
		frappe.delete_doc("GAM Email", name, force=True, ignore_permissions=True)


def make_account(platform, username, email_name, password="accpw456",
                 totp_secret="", status="ACTIVE", source="Unit Test"):
	"""Create (or recreate) a GAM Account; return its doc name."""
	purge_account(username)
	doc = frappe.get_doc(
		{
			"doctype": "GAM Account",
			"platform": platform,
			"username": username,
			"account_password": password,
			"totp_secret": totp_secret,
			"email": email_name,
			"status": status,
			"source": source,
		}
	)
	doc.insert(ignore_permissions=True)
	return doc.name


def purge_account(username):
	name = frappe.db.get_value("GAM Account", {"username": username})
	if name:
		frappe.delete_doc("GAM Account", name, force=True, ignore_permissions=True)


def ensure_user(email, roles):
	"""Create/ensure a User with EXACTLY the given roles (plus 'All')."""
	if not frappe.db.exists("User", email):
		frappe.get_doc(
			{
				"doctype": "User",
				"email": email,
				"first_name": email.split("@")[0].title(),
				"enabled": 1,
				"send_welcome_email": 0,
			}
		).insert(ignore_permissions=True)
	user = frappe.get_doc("User", email)
	user.roles = []
	for role in sorted(set(roles) | {"All"}):
		user.append("roles", {"role": role})
	user.save(ignore_permissions=True)
	return email


def set_webhook_secret(secret, active=1):
	"""Set the GAM Webhook Config singleton secret + active flag."""
	cfg = frappe.get_doc("GAM Webhook Config", "GAM Webhook Config")
	cfg.webhook_secret = secret
	cfg.is_active = 1 if active else 0
	cfg.save(ignore_permissions=True)
