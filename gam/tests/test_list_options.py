# Copyright (c) 2026, GAM and contributors
# License: MIT
"""Integration tests for the configurable-list + account/email lifecycle APIs.

Covers Phases 1-5 of the accounts/email redesign:
  * GAM List Option CRUD + fallback shape (get/save/delete_list_option)
  * platform -> code-platform mapping driven from config (the critical
    regression: STANDALONE must still resolve to POE so forwarded POE codes
    keep matching a STANDALONE account after the platform list went data-driven)
  * save_account / delete_account (incl. IN_USE block + dependent cleanup)
  * get_account_stats (role / status / platform grouping for dashboards)
  * delete_email_account (blocked when an account references the email)
  * ignore_unrecognized_email (dismiss by candidate address)

Run:  bench --site erp.local run-tests --module gam.tests.test_list_options
"""
import frappe
from frappe.tests.utils import FrappeTestCase
from frappe.utils import add_to_date, now_datetime

from gam import api
from gam.tests.utils import make_account, make_email, purge_fixtures


def _clear_mapping_cache():
	"""The platform->code map is cached per request in frappe.local.flags."""
	frappe.local.flags.pop("gam_platform_code_map", None)


def _purge_list_options(label_like):
	for name in frappe.get_all(
		"GAM List Option", filters={"label": ["like", label_like]}, pluck="name"
	):
		frappe.delete_doc("GAM List Option", name, force=True, ignore_permissions=True)


class TestListOptions(FrappeTestCase):
	def setUp(self):
		super().setUp()
		frappe.set_user("Administrator")
		_purge_list_options("UT%")

	def tearDown(self):
		_purge_list_options("UT%")
		super().tearDown()

	def test_save_and_get_list_option(self):
		created = api.save_list_option(
			values={
				"category": "Platform",
				"label": "UT Game",
				"value": "UTGAME",
				"code_platform": "STEAM",
				"icon": "🎮",
				"color": "blue",
			}
		)
		self.assertTrue(created["name"])
		self.assertEqual(created["value"], "UTGAME")

		rows = api.get_list_options("Platform")
		mine = [r for r in rows if r.get("value") == "UTGAME"]
		self.assertTrue(mine)
		self.assertEqual(mine[0]["code_platform"], "STEAM")

	def test_save_account_role_creates_frappe_role(self):
		# Saving an Account Role mirrors it as a real Frappe Role so admins can
		# grant it to users (User > Roles) and the sidebar can scope accounts by
		# the user's roles (Issue 3).
		role_label = "UT Trader"
		try:
			api.save_list_option(values={
				"category": "Account Role",
				"label": role_label,
				"value": "UTTRADER",
				"icon": "🧪",
				"color": "indigo",
			})
			self.assertTrue(frappe.db.exists("Role", role_label))
		finally:
			if frappe.db.exists("Role", role_label):
				frappe.delete_doc("Role", role_label, force=True, ignore_permissions=True)

	def test_save_list_option_auto_derives_value(self):
		# Leaving `value` blank must auto-derive UPPER_SNAKE_CASE from the label
		# (the doctype's documented contract). Without this the save silently
		# fails because `value` is mandatory on GAM List Option.
		created = api.save_list_option(
			values={"category": "Platform", "label": "UT Pvp Arena"}
		)
		self.assertEqual(created["value"], "UT_PVP_ARENA")
		doc = frappe.get_doc("GAM List Option", created["name"])
		self.assertEqual(doc.value, "UT_PVP_ARENA")

	def test_save_list_option_update(self):
		created = api.save_list_option(
			values={"category": "Account Role", "label": "UT Role", "value": "UTROLE"}
		)
		updated = api.save_list_option(
			values={"label": "UT Role Renamed", "value": "UTROLE2"},
			name=created["name"],
		)
		self.assertEqual(updated["name"], created["name"])
		doc = frappe.get_doc("GAM List Option", created["name"])
		self.assertEqual(doc.value, "UTROLE2")
		self.assertEqual(doc.label, "UT Role Renamed")

	def test_delete_list_option_reports_in_use(self):
		# A role referenced by an account must be REPORTED (not blocking).
		created = api.save_list_option(
			values={"category": "Account Role", "label": "UT InUse", "value": "UTINUSE"}
		)
		email = make_email()
		acc = make_account("STEAM", "unit_test_inuse_role", email)
		frappe.db.set_value("GAM Account", acc, "role", "UTINUSE")

		res = api.delete_list_option(created["name"])
		self.assertTrue(res["deleted"])
		self.assertIn(acc, res["in_use"])

	def test_delete_list_option_clean(self):
		created = api.save_list_option(
			values={"category": "Platform", "label": "UT Clean", "value": "UTCLEAN"}
		)
		res = api.delete_list_option(created["name"])
		self.assertTrue(res["deleted"])
		self.assertEqual(res["in_use"], [])

	def test_get_list_options_spans_known_categories(self):
		cats = {r["category"] for r in api.get_list_options()}
		# Seeded defaults (or fallback) span all three categories.
		self.assertTrue(cats & {"Platform", "Account Role", "Account Status"})


class TestPlatformCodeMapping(FrappeTestCase):
	"""Critical regression: STANDALONE -> POE must hold so forwarded POE codes
	still match a STANDALONE account after the platform list became data-driven."""

	def setUp(self):
		super().setUp()
		frappe.set_user("Administrator")
		_purge_list_options("UT%")

	def tearDown(self):
		_purge_list_options("UT%")
		_clear_mapping_cache()
		super().tearDown()

	def test_standalone_resolves_to_poe(self):
		_clear_mapping_cache()
		self.assertEqual(api._platform_to_code_platform("STANDALONE"), "POE")

	def test_built_in_platforms_resolve(self):
		_clear_mapping_cache()
		self.assertEqual(api._platform_to_code_platform("STEAM"), "STEAM")
		self.assertEqual(api._platform_to_code_platform("BATTLENET"), "BATTLENET")

	def test_custom_platform_maps_from_config(self):
		api.save_list_option(
			values={
				"category": "Platform",
				"label": "UT Game",
				"value": "UTGAME",
				"code_platform": "EPIC",
			}
		)
		_clear_mapping_cache()
		self.assertEqual(api._platform_to_code_platform("UTGAME"), "EPIC")

	def test_unknown_platform_resolves_empty(self):
		_clear_mapping_cache()
		self.assertEqual(api._platform_to_code_platform("NOPE-NOT-A-PLATFORM"), "")

	def test_empty_platform_resolves_empty(self):
		_clear_mapping_cache()
		self.assertEqual(api._platform_to_code_platform(""), "")


class TestAccountLifecycle(FrappeTestCase):
	GAME_TITLE = "UT Lifecycle Game"

	def _seed_role(self, value, label):
		"""Ensure an Account Role GAM List Option exists (idempotent)."""
		if not frappe.db.exists(
			"GAM List Option", {"category": "Account Role", "value": value}
		):
			frappe.get_doc(
				{
					"doctype": "GAM List Option",
					"category": "Account Role",
					"label": label,
					"value": value,
					"is_active": 1,
				}
			).insert(ignore_permissions=True)

	def _ensure_game(self, title):
		name = frappe.db.get_value("GAM Game", {"game_name": title})
		if name:
			return name
		doc = frappe.get_doc(
			{"doctype": "GAM Game", "game_name": title, "is_active": 1}
		)
		doc.insert(ignore_permissions=True)
		return doc.name

	def _bindings(self, account):
		return frappe.get_all(
			"GAM Account Role Game",
			{"account": account},
			["name", "role", "game", "is_main"],
			order_by="creation",
		)

	def setUp(self):
		super().setUp()
		frappe.set_user("Administrator")
		purge_fixtures()
		self._seed_role("UT_BOOSTER", "UT Booster")
		self._seed_role("UT_TRADER", "UT Trader")
		self._seed_role("UT_STATROLE", "UT Stat Role")
		self.game = self._ensure_game(self.GAME_TITLE)
		self.email = make_email()

	def tearDown(self):
		purge_fixtures()
		super().tearDown()

	def _save(self, username, **extra):
		values = {"platform": "STEAM", "username": username, "email": self.email}
		values.update(extra)
		return api.save_account(values=values)

	def test_save_account_creates_with_role(self):
		# Role now lives on a GAM Account Role Game binding, not on the account.
		res = self._save(
			"unit_test_save1",
			role_games=[{"game": self.game, "role": "UT_BOOSTER", "is_main": 1}],
		)
		self.assertTrue(res["name"])
		b = self._bindings(res["name"])
		self.assertEqual(len(b), 1)
		self.assertEqual(b[0]["role"], "UT_BOOSTER")
		self.assertEqual(b[0]["game"], self.game)

	def test_save_account_update_role(self):
		created = self._save(
			"unit_test_save2",
			role_games=[{"game": self.game, "role": "UT_BOOSTER", "is_main": 1}],
		)
		# The frontend AccountFormModal always sends the complete form on edit,
		# so the required-field validation still holds for updates. Re-sending
		# role_games replaces the binding set (upsert by game).
		api.save_account(
			values={
				"platform": "STEAM",
				"username": "unit_test_save2",
				"email": self.email,
				"role_games": [{"game": self.game, "role": "UT_TRADER", "is_main": 1}],
			},
			name=created["name"],
		)
		b = self._bindings(created["name"])
		self.assertEqual(len(b), 1)
		self.assertEqual(b[0]["role"], "UT_TRADER")

	def test_save_account_password_stored(self):
		res = self._save("unit_test_save3", account_password="hunter2!")
		doc = frappe.get_doc("GAM Account", res["name"])
		self.assertEqual(doc.get_password("account_password"), "hunter2!")

	def test_delete_account_blocked_when_in_use(self):
		name = make_account("STEAM", "unit_test_delblock", self.email)
		api.checkout_account(name)  # creates an IN_USE lease
		res = api.delete_account(name)
		self.assertTrue(res["blocked"])
		self.assertEqual(res["in_use_by"], "Administrator")
		self.assertTrue(frappe.db.exists("GAM Account", name))

	def test_delete_account_clears_links_usage_and_code_log_link(self):
		a = make_account("STEAM", "unit_test_delA", self.email)
		b = make_account("STEAM", "unit_test_delB", self.email)

		# active link A -> B
		frappe.get_doc(
			{
				"doctype": "GAM Account Link",
				"source_account": a,
				"target_account": b,
			}
		).insert(ignore_permissions=True)
		# historical (released) usage for A
		now = now_datetime()
		frappe.get_doc(
			{
				"doctype": "GAM Account Usage",
				"account": a,
				"status": "RELEASED",
				"used_by": "Administrator",
				"purpose": "LOGIN",
				"started_at": add_to_date(now, hours=-2),
				"lease_until": add_to_date(now, hours=-1),
			}
		).insert(ignore_permissions=True)
		# code request log pointing at A (Link must be nulled, doc kept)
		crl = frappe.get_doc(
			{
				"doctype": "GAM Code Request Log",
				"requested_by": "Administrator",
				"target_email": self.email,
				"target_account": a,
				"platform": "STEAM",
				"code_value": "ZZ123",
				"status": "FULFILLED",
				"requested_at": now,
			}
		)
		crl.insert(ignore_permissions=True)

		res = api.delete_account(a)
		self.assertTrue(res["deleted"])
		self.assertFalse(frappe.db.exists("GAM Account", a))
		self.assertFalse(frappe.db.exists("GAM Account Link", {"source_account": a}))
		self.assertFalse(frappe.db.exists("GAM Account Link", {"target_account": a}))
		self.assertFalse(frappe.db.exists("GAM Account Usage", {"account": a}))
		# Code request log retained but unlinked (audit history preserved).
		crl.reload()
		self.assertIsNone(crl.target_account)

	def test_get_account_stats_shape(self):
		stats = api.get_account_stats()
		for key in ("total", "by_role", "by_status", "by_platform"):
			self.assertIn(key, stats)
		# ``total`` (GAM Account rows) always equals the sum of ``by_status``
		# and ``by_platform`` (every account has exactly one of each). Under the
		# first-class binding model an account may have 0 roles or several, so
		# ``by_role`` (DISTINCT accounts per role) is allowed to diverge.
		self.assertEqual(
			sum(stats["by_status"].values()),
			stats["total"],
			"by_status must sum to total account count",
		)
		self.assertEqual(
			sum(stats["by_platform"].values()),
			stats["total"],
			"by_platform must sum to total account count",
		)

	def test_stats_reflect_created_role(self):
		# Creating an account with a (role, game) binding bumps by_role[role].
		role = "UT_STATROLE"
		before = api.get_account_stats().get("by_role", {}).get(role, 0)
		self._save(
			"unit_test_statrole",
			role_games=[{"game": self.game, "role": role, "is_main": 1}],
		)
		after = api.get_account_stats().get("by_role", {}).get(role, 0)
		self.assertEqual(after, before + 1)


class TestEmailAndIgnore(FrappeTestCase):
	def setUp(self):
		super().setUp()
		frappe.set_user("Administrator")
		purge_fixtures()

	def tearDown(self):
		purge_fixtures()
		super().tearDown()

	def test_delete_email_account_blocked_when_linked(self):
		email = make_email()
		acc = make_account("STEAM", "unit_test_emailblock", email)
		res = api.delete_email_account(email)
		self.assertTrue(res["blocked"])
		names = [r["name"] for r in res["linked_accounts"]]
		self.assertIn(acc, names)

	def test_delete_email_account_clean(self):
		email = make_email("ut-clean@gam.test")
		# nothing references this email
		res = api.delete_email_account(email)
		self.assertTrue(res["deleted"])
		self.assertFalse(frappe.db.exists("GAM Email", email))

	def test_delete_email_account_snapshots_audit_logs(self):
		# Regression for Issue 1: a GAM Email referenced by a read-only
		# GAM Code Request Log (target_email is a mandatory Link) must still be
		# deletable — the address is snapshotted and the link detached.
		address = "ut-audit@gam.test"
		email = make_email(address)
		crl = frappe.get_doc({
			"doctype": "GAM Code Request Log",
			"requested_by": "Administrator",
			"target_email": email,
			"status": "NO_CODE",
			"platform": "STEAM",
			"requested_at": now_datetime(),
		})
		crl.insert(ignore_permissions=True)
		try:
			res = api.delete_email_account(email)
			self.assertTrue(res["deleted"])
			self.assertGreaterEqual(res["unlinked"]["code_request_log"], 1)
			# The log survives with a snapshot of the address and a cleared link.
			crl.reload()
			self.assertIsNone(crl.target_email)
			self.assertEqual(crl.target_email_address, address)
			self.assertFalse(frappe.db.exists("GAM Email", email))
		finally:
			if frappe.db.exists("GAM Code Request Log", crl.name):
				frappe.delete_doc("GAM Code Request Log", crl.name, force=True, ignore_permissions=True)

	def test_ignore_unrecognized_email_marks_log(self):
		sender = "ut-spammer@gam.test"
		log = frappe.get_doc(
			{
				"doctype": "GAM Email Inbound Log",
				"email_account": "ut-inbox@gam.test",
				"email_from": sender,
				"email_subject": "hello",
				"status": "NO_MATCH",
				"received_at": now_datetime(),
			}
		)
		log.insert(ignore_permissions=True)

		res = api.ignore_unrecognized_email(log.name)
		self.assertTrue(res["ignored"])
		self.assertEqual(res["address"], sender)
		log.reload()
		self.assertEqual(log.ignored, 1)
