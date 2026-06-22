"""Migrate legacy account-level role + ``GAM Account Game`` child rows into the
first-class ``GAM Account Role Game`` binding table (Phương án B).

Before this patch, a GAM Account carried:
  - one account-level ``role`` (Data) field, and
  - many game child rows in ``tabGAM Account Game`` (game, server, is_main, ...).

After migration the single source of truth is the top-level ``GAM Account Role
Game`` doctype: one binding per (account, game) with the account's role copied
onto it. DLCs are carried over too.

Accounts that had games but no role cannot be bound (role is now mandatory) —
those legacy game rows are counted + reported so an admin can re-assign.

Idempotent — binding creation is guarded by an (account, game) existence check,
so re-running the patch (e.g. after a partial failure or a second migrate) is a
no-op. Safe on fresh installs where neither the ``role`` column nor the legacy
child table exist.
"""
import frappe


def _canonical_role(raw):
	"""Map a legacy role value/label to its GAM List Option *value*.

	Historical rows may store either the option value or its human label; the
	sidebar keys everything off the canonical value, so normalise here.
	"""
	raw = (raw or "").strip()
	if not raw:
		return ""
	opts = frappe.db.get_all(
		"GAM List Option",
		filters={"category": "Account Role"},
		fields=["value", "label"],
	)
	for o in opts:
		if (o.get("value") or "").strip() == raw:
			return o["value"]
	for o in opts:
		if (o.get("label") or "").strip().lower() == raw.lower():
			return o["value"]
	return raw  # unknown option — preserve verbatim


def execute():
	if not frappe.db.table_exists("GAM Account Role Game"):
		return  # target doctype not installed yet

	has_role_col = frappe.db.has_column("GAM Account", "role")
	legacy_games_exist = frappe.db.table_exists("GAM Account Game")
	if not (has_role_col or legacy_games_exist):
		return  # nothing legacy to migrate

	accounts = frappe.db.get_all("GAM Account", pluck="name")
	if not accounts:
		return

	has_dlc_table = frappe.db.table_exists("GAM Account Game DLC")
	created = 0
	skipped_no_role = 0

	for acc_name in accounts:
		role = ""
		if has_role_col:
			# Raw SQL (not get_value): ``role`` is dropped from the doctype *meta*
			# at sync time, so ORM access would reject it even though Frappe
			# leaves the physical column in place (delete_fields defaults to 0).
			role = _canonical_role(
				frappe.db.sql(
					"SELECT role FROM `tabGAM Account` WHERE name = %s", (acc_name,)
				)[0][0]
			)

		if not role:
			# Games with no account-level role cannot be bound (role is mandatory).
			if legacy_games_exist:
				n = frappe.db.count(
					"GAM Account Game",
					{"parent": acc_name, "parenttype": "GAM Account"},
				)
				skipped_no_role += int(n or 0)
			continue

		if not legacy_games_exist:
			continue

		rows = frappe.db.get_all(
			"GAM Account Game",
			filters={"parent": acc_name, "parenttype": "GAM Account"},
			fields=["name", "game", "server", "is_main", "purchased_at", "notes", "idx"],
			order_by="idx asc",
		)

		for r in rows:
			game = (r.get("game") or "").strip()
			if not game:
				continue
			if frappe.db.exists(
				"GAM Account Role Game", {"account": acc_name, "game": game}
			):
				continue  # idempotent — already migrated

			dlcs = []
			if has_dlc_table:
				dlcs = frappe.db.get_all(
					"GAM Account Game DLC",
					filters={"parent": r["name"], "parenttype": "GAM Account Game"},
					fields=["dlc", "purchased_at"],
					order_by="idx asc",
				)

			doc = frappe.get_doc(
				{
					"doctype": "GAM Account Role Game",
					"account": acc_name,
					"role": role,
					"game": game,
					"server": r.get("server") or "",
					"is_main": 1 if r.get("is_main") else 0,
					"purchased_at": r.get("purchased_at"),
					"notes": r.get("notes") or "",
					"dlcs": [
						{"dlc": d["dlc"], "purchased_at": d.get("purchased_at")}
						for d in dlcs
						if d.get("dlc")
					],
				}
			)
			doc.flags.ignore_permissions = True
			doc.insert()
			created += 1

	if created or skipped_no_role:
		print(
			"gam migrate_account_role_game: created {0} binding(s); "
			"skipped {1} legacy game row(s) whose account had no role.".format(
				created, skipped_no_role
			)
		)
