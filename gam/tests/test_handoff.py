# Copyright (c) 2026, GAM and contributors
# License: MIT
"""Tests for shift handoff (bàn giao ca) + online session chain governance.

Covers:
  * happy path: holder hands off to a granted receiver → same chain, no gap.
  * L2 for the receiver: an ungranted receiver is rejected.
  * self-handoff rejected.
  * concurrent-change guard (race) re-checks the lease is still IN_USE.
  * continuous-online cap blocks a handoff past the cap (member) but admin force works.
  * per-game override of the cap is honoured.
  * decline_handoff reopens the chain for the previous holder.

Run:  bench --site erp.local run-tests --module gam.tests.test_handoff
"""
import frappe
from frappe.tests.utils import FrappeTestCase
from frappe.utils import add_to_date, now_datetime

from gam import api
from gam.tests.utils import ensure_user, make_account, make_email, purge_fixtures

ADMIN = "Administrator"
HOLDER = "handoff.holder@gam.test"
RECEIVER = "handoff.receiver@gam.test"
NOGRANT = "handoff.nogrant@gam.test"

GAME = "Steam"
ROLE = "BOOSTER"


class TestShiftHandoff(FrappeTestCase):
	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		frappe.set_user(ADMIN)
		purge_fixtures()

		cls.email = make_email("handoff@gam.test")
		cls.game = cls._ensure_game(GAME)
		cls.account = make_account("STEAM", "unit_handoff_acc", cls.email)
		cls._bind(cls.account, ROLE, cls.game)

		cls.holder = ensure_user(HOLDER, ["GAM Member"])
		cls.receiver = ensure_user(RECEIVER, ["GAM Member"])
		cls.nogrant = ensure_user(NOGRANT, ["GAM Member"])
		# Both holder and receiver are granted the same (role, game).
		for u in (cls.holder, cls.receiver):
			cls._grant(u, "ROLE_GAME", "{0}|{1}".format(ROLE, cls.game))

		cls._orig_cap = frappe.db.get_value(
			"GAM Settings", "GAM Settings", "continuous_online_cap_hours"
		)

	@classmethod
	def tearDownClass(cls):
		frappe.set_user(ADMIN)
		# restore cap
		try:
			frappe.db.set_value(
				"GAM Settings", "GAM Settings", "continuous_online_cap_hours",
				cls._orig_cap or 16, update_modified=False,
			)
		except Exception:
			pass
		for u in (HOLDER, RECEIVER, NOGRANT):
			if frappe.db.exists("User", u):
				frappe.delete_doc("User", u, force=True, ignore_permissions=True)
		for n in frappe.get_all(
			"GAM Access Grant", {"user": ["in", [HOLDER, RECEIVER]]}, pluck="name"
		):
			frappe.delete_doc("GAM Access Grant", n, force=True, ignore_permissions=True)
		purge_fixtures()
		super().tearDownClass()

	def setUp(self):
		super().setUp()
		# handoff_account commits mid-call, which defeats Frappe's per-test
		# rollback — so purge any leftover usage on this account first.
		frappe.set_user(ADMIN)
		for name in frappe.get_all(
			"GAM Account Usage", {"account": self.account}, pluck="name"
		):
			frappe.delete_doc("GAM Account Usage", name, force=True, ignore_permissions=True)
		# default to a generous cap so happy-path handoffs are not cap-blocked.
		frappe.db.set_value(
			"GAM Settings", "GAM Settings", "continuous_online_cap_hours",
			72, update_modified=False,
		)
		frappe.db.set_value(
			"GAM Game", self.game, "continuous_online_cap_hours", 0, update_modified=False
		)

	# ---- helpers -------------------------------------------------------------
	@staticmethod
	def _ensure_game(title):
		name = frappe.db.get_value("GAM Game", {"game_name": title})
		if name:
			return name
		doc = frappe.get_doc({"doctype": "GAM Game", "game_name": title, "is_active": 1})
		doc.insert(ignore_permissions=True)
		return doc.name

	@staticmethod
	def _bind(account, role, game):
		frappe.get_doc(
			{
				"doctype": "GAM Account Role Game",
				"account": account,
				"role": role,
				"game": game,
				"is_main": 1,
			}
		).insert(ignore_permissions=True)

	@staticmethod
	def _grant(user, scope, key):
		for n in frappe.get_all(
			"GAM Access Grant", {"user": user, "scope": scope, "key": key}, pluck="name"
		):
			frappe.delete_doc("GAM Access Grant", n, force=True, ignore_permissions=True)
		frappe.get_doc(
			{
				"doctype": "GAM Access Grant",
				"user": user,
				"app": "GAM",
				"scope": scope,
				"key": key,
				"granted": 1,
			}
		).insert(ignore_permissions=True)

	def _checkout_as(self, user):
		frappe.set_user(user)
		try:
			usage = api.checkout_account(self.account)
		finally:
			frappe.set_user(ADMIN)
		return usage

	# ---- tests ---------------------------------------------------------------
	def test_happy_path_continues_chain(self):
		old = self._checkout_as(self.holder)
		res = api.handoff_account(self.account, self.receiver, notes="ca sang")

		new_lease = res["new_lease"]
		# old lease closed as HANDED_OFF
		old_doc = frappe.get_doc("GAM Account Usage", old["name"])
		self.assertEqual(old_doc.status, "RELEASED")
		self.assertEqual(old_doc.end_reason, "HANDED_OFF")
		# new lease: receiver, same chain head, prev points to old, no online gap
		self.assertEqual(new_lease["status"], "IN_USE")
		self.assertEqual(new_lease["used_by"], self.receiver)
		self.assertEqual(new_lease["chain_head"], old["name"])
		self.assertEqual(new_lease["prev_lease"], old["name"])
		self.assertEqual(new_lease["handoff_by"], ADMIN)
		self.assertEqual(new_lease["started_at"], old_doc.ended_at)
		# chain telemetry present (instant handoff may be ~0s, so >= 0)
		self.assertGreaterEqual(res["chain_online_seconds"], 0)
		self.assertGreater(res["cap_hours"], 0)

	def test_receiver_without_grant_rejected(self):
		self._checkout_as(self.holder)
		with self.assertRaises(frappe.PermissionError):
			api.handoff_account(self.account, self.nogrant)

	def test_self_handoff_rejected(self):
		self._checkout_as(self.holder)
		with self.assertRaises(frappe.ValidationError):
			api.handoff_account(self.account, self.holder)

	def test_concurrent_change_guard(self):
		"""If the holder lease is released between the pre-checks and the close,
		handoff must abort rather than open a dangling lease."""
		old = self._checkout_as(self.holder)
		# Simulate a concurrent release right before the atomic close.
		frappe.db.set_value(
			"GAM Account Usage", old["name"], "status", "RELEASED", update_modified=False
		)
		with self.assertRaises(frappe.ValidationError):
			api.handoff_account(self.account, self.receiver)

	def test_cap_blocks_member_handoff_but_admin_force_ok(self):
		old = self._checkout_as(self.holder)
		# Pretend the chain has already been online 2h (cap set to 1h below).
		frappe.db.set_value(
			"GAM Account Usage", old["name"], "started_at",
			add_to_date(now_datetime(), hours=-2), update_modified=False,
		)
		frappe.db.set_value(
			"GAM Settings", "GAM Settings", "continuous_online_cap_hours",
			1, update_modified=False,
		)
		# Member holder cannot force → blocked.
		frappe.set_user(self.holder)
		try:
			with self.assertRaises(frappe.ValidationError):
				api.handoff_account(self.account, self.receiver)
		finally:
			frappe.set_user(ADMIN)
		# Admin forcing past the cap succeeds.
		res = api.handoff_account(self.account, self.receiver, force=1)
		self.assertEqual(res["new_lease"]["used_by"], self.receiver)

	def test_per_game_override_honoured(self):
		old = self._checkout_as(self.holder)
		frappe.db.set_value(
			"GAM Account Usage", old["name"], "started_at",
			add_to_date(now_datetime(), hours=-2), update_modified=False,
		)
		# Global cap 1h, but this game overrides to 5h → 2h chain is allowed.
		frappe.db.set_value(
			"GAM Settings", "GAM Settings", "continuous_online_cap_hours",
			1, update_modified=False,
		)
		frappe.db.set_value(
			"GAM Game", self.game, "continuous_online_cap_hours",
			5, update_modified=False,
		)
		telemetry = api.get_chain_online(self.account)
		self.assertEqual(telemetry["cap_hours"], 5)
		res = api.handoff_account(self.account, self.receiver)
		self.assertEqual(res["cap_hours"], 5)

	def test_decline_reopens_chain_for_previous_holder(self):
		old = self._checkout_as(self.holder)
		api.handoff_account(self.account, self.receiver)
		# Receiver declines.
		frappe.set_user(self.receiver)
		try:
			reopened = api.decline_handoff(self.account)
		finally:
			frappe.set_user(ADMIN)
		self.assertEqual(reopened["status"], "IN_USE")
		self.assertEqual(reopened["used_by"], self.holder)
		self.assertEqual(reopened["chain_head"], old["name"])
		self.assertEqual(reopened["prev_lease"], frappe.db.get_value(
			"GAM Account Usage", {"account": self.account, "status": "IN_USE"}, "prev_lease"))

	def test_candidates_exclude_holder(self):
		self._checkout_as(self.holder)
		candidates = api.get_handoff_candidates(self.account)
		names = {c["name"] for c in candidates}
		self.assertIn(self.receiver, names)
		self.assertNotIn(self.holder, names)
