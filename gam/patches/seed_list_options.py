"""Seed default GAM List Option records (Platform / Account Role / Account Status).

Idempotent — only inserts options that don't already exist. Run as a
post-model-sync patch after the GAM List Option doctype is migrated.
"""
import frappe


# category -> [ (value, label, code_platform, icon, color, sort_order), ... ]
DEFAULTS = {
	"Platform": [
		("STEAM", "Steam", "STEAM", "🎮", "blue", 10),
		("BATTLENET", "Battle.net", "BATTLENET", "⚔️", "indigo", 20),
		("EPIC", "Epic", "EPIC", "🛍️", "slate", 30),
		("XBOX", "Xbox", "XBOX", "🎯", "emerald", 40),
		("STANDALONE", "Standalone", "POE", "🕹️", "amber", 50),
	],
	"Account Status": [
		("ACTIVE", "Active", None, "✅", "emerald", 10),
		("INACTIVE", "Inactive", None, "⏸️", "slate", 20),
		("SUSPENDED", "Suspended", None, "⛔", "amber", 30),
		("BANNED", "Banned", None, "🚫", "red", 40),
	],
	"Account Role": [
		("BOOSTER", "Booster", None, "🚀", "indigo", 10),
		("TRADER", "Trader", None, "💱", "emerald", 20),
		("ITEM", "Item", None, "📦", "amber", 30),
	],
}


def execute():
	for category, rows in DEFAULTS.items():
		for value, label, code_platform, icon, color, sort_order in rows:
			if frappe.db.exists("GAM List Option", {"category": category, "value": value}):
				continue
			doc = frappe.new_doc("GAM List Option")
			doc.category = category
			doc.label = label
			doc.value = value
			doc.code_platform = code_platform or ""
			doc.icon = icon
			doc.color = color
			doc.sort_order = sort_order
			doc.is_active = 1
			doc.insert(ignore_permissions=True)
	frappe.db.commit()
