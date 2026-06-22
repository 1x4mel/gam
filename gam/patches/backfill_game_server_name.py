"""Backfill GAM Game Server.server_name from the legacy region column.

The fixed ``region`` Select was replaced by a free-text ``server_name``
(required) field so admins can name servers freely (Issue 2). This
post-model-sync patch migrates existing rows so they remain valid.

Idempotent — only fills rows whose server_name is empty.
"""
import frappe


def execute():
	if not frappe.db.has_column("GAM Game Server", "server_name"):
		return

	# server_name is now mandatory; backfill empties from the legacy region
	# (falling back to the game name, then the doc name).
	has_region = frappe.db.has_column("GAM Game Server", "region")
	servers = frappe.db.get_all(
		"GAM Game Server",
		filters={"server_name": ("in", [None, ""])},
		pluck="name",
	)
	for name in servers:
		region = ""
		if has_region:
			region = (frappe.db.get_value("GAM Game Server", name, "region") or "").strip()
		game = frappe.db.get_value("GAM Game Server", name, "game") or ""
		game_title = ""
		if game and frappe.db.exists("GAM Game", game):
			game_title = (frappe.db.get_value("GAM Game", game, "game_name") or "").strip()
		server_name = region or game_title or name
		frappe.db.set_value(
			"GAM Game Server", name, "server_name", server_name, update_modified=False
		)
