# Copyright (c) 2026, GAM and contributors
# License: MIT
"""Install lifecycle: create GAM roles (before) + seed (after)."""
import frappe
from frappe import _

GAM_ROLES = [
	{"role_name": "GAM Admin", "desk_access": 1, "disabled": 0},
	{"role_name": "GAM Member", "desk_access": 0, "disabled": 0},
]

# Default Code Patterns (Design §7.2). code_regex group 1 = the code.
CODE_PATTERNS = [
	{
		"platform": "STEAM",
		"sender_pattern": r"@steampowered\.com",
		"subject_keywords": "code,guard,login,verification",
		"code_regex": r"(?:code|guard|verification)[:\s]+([A-Z0-9]{5})\b",
		"ttl_minutes": 15,
		"priority": 10,
	},
	{
		"platform": "BATTLENET",
		"sender_pattern": r"@(?:battle\.net|blizzard\.com)",
		"subject_keywords": "code,security,login,verification",
		"code_regex": r"(?:code|auth|verification)[:\s]+(\d{6,8})\b",
		"ttl_minutes": 10,
		"priority": 10,
	},
	{
		"platform": "POE",
		"sender_pattern": r"@grindinggear\.com",
		"subject_keywords": "path of exile,exile,code,verification,login,locked,location",
		# Real PoE unlock code is 3-3-4 dashed (e.g. 8a9-342-832b), on its own
		# line — NOT right after the word "code". The old [A-Za-z0-9]{5,8} could
		# never match the dashes → every real email NO_MATCH. Boundary anchors stop
		# it matching codes embedded in URLs / longer tokens.
		"code_regex": r"(?<![\w/.-])([0-9A-Za-z]{3}-[0-9A-Za-z]{3}-[0-9A-Za-z]{4})(?![\w-])",
		"ttl_minutes": 15,
		"priority": 10,
	},
]


def before_install():
	"""Create GAM roles BEFORE doctype sync so permission rows resolve."""
	for role in GAM_ROLES:
		if not frappe.db.exists("Role", role["role_name"]):
			frappe.get_doc({"doctype": "Role", **role}).insert(ignore_permissions=True)
	frappe.db.commit()


def after_install():
	seed_code_patterns()
	ensure_webhook_config()
	frappe.clear_cache()


def seed_code_patterns():
	for pattern in CODE_PATTERNS:
		exists = frappe.db.exists(
			"GAM Code Pattern",
			{"platform": pattern["platform"], "sender_pattern": pattern["sender_pattern"]},
		)
		if exists:
			continue
		frappe.get_doc(
			{"doctype": "GAM Code Pattern", "is_active": 1, **pattern}
		).insert(ignore_permissions=True)


def upgrade_code_patterns():
	"""One-time upgrade of seeded pattern fields (re-runnable / idempotent).

	Patches existing POE patterns to the real 3-3-4 dashed code format (the seed
	is insert-only, so an existing record keeps its old regex until this runs).

	bench --site erp.local execute gam.setup.upgrade_code_patterns
	"""
	updates = {
		"POE": {
			"code_regex": r"(?<![\w/.-])([0-9A-Za-z]{3}-[0-9A-Za-z]{3}-[0-9A-Za-z]{4})(?![\w-])",
			"subject_keywords": "path of exile,exile,code,verification,login,locked,location",
		},
	}
	for platform, fields in updates.items():
		for name in frappe.get_all("GAM Code Pattern", filters={"platform": platform}, pluck="name"):
			doc = frappe.get_doc("GAM Code Pattern", name)
			changed = False
			for k, v in fields.items():
				if getattr(doc, k, None) != v:
					setattr(doc, k, v)
					changed = True
			if changed:
				doc.save(ignore_permissions=True)
	frappe.db.commit()


def ensure_webhook_config():
	"""Ensure the GAM Webhook Config singleton exists with sane defaults."""
	doc = frappe.get_doc("GAM Webhook Config", "GAM Webhook Config")
	doc.is_active = 1
	doc.total_received = 0
	doc.save(ignore_permissions=True)


# Demo dataset for browser smoke-testing (Design §3 + §8.2). Idempotent.
GAMES = [
	{"game_name": "Counter-Strike 2", "publisher": "Valve"},
	{"game_name": "Path of Exile 2", "publisher": "Grinding Gear Games"},
	{"game_name": "Overwatch 2", "publisher": "Blizzard"},
]


def seed_games():
	"""Seed a small set of GAM Games (idempotent).

	bench --site erp.local execute gam.setup.seed_games
	"""
	for g in GAMES:
		# DocType names are auto-generated — dedup by game_name, not by name.
		if frappe.db.exists("GAM Game", {"game_name": g["game_name"]}):
			continue
		frappe.get_doc(
			{"doctype": "GAM Game", "is_active": 1, **g}
		).insert(ignore_permissions=True)
	frappe.db.commit()


def seed_demo():
	"""Seed a full demo dataset for browser smoke-testing (idempotent).

	Creates: games + recovery emails + accounts (Password fields encrypted on
	save) so the gam-ui SPA has rows to list / reveal / request-code / checkout.

	bench --site erp.local execute gam.setup.seed_demo
	"""
	seed_games()
	seed_code_patterns()

	emails = [
		{"address": "recovery.steam@gam.demo", "provider": "Gmail", "email_password": "steam-recovery-pw"},
		{"address": "recovery.poe@gam.demo", "provider": "Outlook", "email_password": "poe-recovery-pw"},
	]
	for e in emails:
		if not frappe.db.exists("GAM Email", {"address": e["address"]}):
			frappe.get_doc({"doctype": "GAM Email", "is_active": 1, **e}).insert(
				ignore_permissions=True
			)

	accounts = [
		{
			"platform": "STEAM",
			"username": "demo_steam_01",
			"account_password": "steam-account-pw",
			"totp_secret": "JBSWY3DPEHPK3PXP",
			"email": frappe.db.get_value("GAM Email", {"address": "recovery.steam@gam.demo"}),
			"status": "ACTIVE",
			"source": "Demo",
		},
		{
			"platform": "STANDALONE",
			"username": "demo_poe_01",
			"account_password": "poe-account-pw",
			"email": frappe.db.get_value("GAM Email", {"address": "recovery.poe@gam.demo"}),
			"status": "ACTIVE",
			"source": "Demo",
		},
	]
	for a in accounts:
		if not frappe.db.exists("GAM Account", {"username": a["username"]}):
			frappe.get_doc({"doctype": "GAM Account", **a}).insert(ignore_permissions=True)

	frappe.db.commit()
