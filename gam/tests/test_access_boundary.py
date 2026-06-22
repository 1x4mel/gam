# Copyright (c) 2026, GAM and contributors
# License: MIT
"""Access-boundary tests (plans/review-remediation-plan.md Track A).

Locks in the L2 authorization fixes applied in Track A:

  * A1 — ``_require_account_access`` / ``_require_email_access`` helpers +
         per-document gates on reveal_password, request_code, checkout,
         checkin, get_account_role_games, get_account_activity, account notes.
  * A2 — ``_require_gam_user()`` on aggregate endpoints (dashboard/account
         stats, role-game sections, list options) + L2 filter on global_search.
  * A5 — fail-closed audit logging in ``_log_reveal`` / ``_log_code_request``.

Run:  bench --site erp.local run-tests --module gam.tests.test_access_boundary
"""
from unittest.mock import patch

import frappe
from frappe.tests.utils import FrappeTestCase

from gam import api
from gam.tests.utils import ensure_user, make_account, make_email, purge_fixtures

ADMIN = "Administrator"
MEMBER_A = "member.a@gam.test"   # granted (BOOSTER, Steam)
MEMBER_B = "member.b@gam.test"   # no grants, holds a non-matching role
MEMBER_C = "member.c@gam.test"   # no grants, holds the "Booster" role (match_role fallback)
NON_GAM = "non.gam@gam.test"     # authenticated but no GAM role

GAME = "Steam"          # GAM Game name reused as the binding `game` value
ROLE_GRANTED = "BOOSTER"
ROLE_OTHER = "TRADER"


class _AccessBoundaryBase(FrappeTestCase):
	"""Shared fixture: one email, two accounts bound to (BOOSTER, Steam),
	one member granted that ROLE_GAME key, one member with nothing."""

	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		frappe.set_user(ADMIN)
		purge_fixtures()

		cls.email = make_email("access-boundary@gam.test")
		# Ensure the GAM Game link target exists before binding (the role-game
		# child table validates its `game` link).
		cls.game = cls._ensure_game(GAME)
		# Account whose bindings intersect the grant → accessible to member A.
		cls.acc_granted = make_account("STEAM", "unit_acc_granted", cls.email)
		# Account with a different (TRADER, Steam) binding → NOT accessible to A.
		cls.acc_other = make_account("STEAM", "unit_acc_other", cls.email)

		cls._bind(cls.acc_granted, ROLE_GRANTED, cls.game)
		cls._bind(cls.acc_other, ROLE_OTHER, cls.game)

		cls.member_a = ensure_user(MEMBER_A, ["GAM Member"])
		cls.member_b = ensure_user(MEMBER_B, ["GAM Member"])
		cls.member_c = ensure_user(MEMBER_C, ["GAM Member", "Booster"])
		cls.non_gam = ensure_user(NON_GAM, [])

		# Grant keys carry the GAM Game DOC NAME (not the display name), because
		# that is what the account binding rows store in `game`.
		cls._grant(cls.member_a, "ROLE_GAME", "{0}|{1}".format(ROLE_GRANTED, cls.game))
		cls._grant(cls.member_a, "ROLE_GAME", "{0}|{1}".format(ROLE_OTHER, cls.game))
		# member_a is granted both combos, so acc_other is accessible too. We
		# therefore ALSO create a dedicated "denied" scenario via member_b.

	@classmethod
	def tearDownClass(cls):
		frappe.set_user(ADMIN)
		for u in (MEMBER_A, MEMBER_B, MEMBER_C, NON_GAM):
			if frappe.db.exists("User", u):
				frappe.delete_doc("User", u, force=True, ignore_permissions=True)
		# member_a's grants are removed by the cascade on User delete; clean any
		# stragglers defensively.
		for name in frappe.get_all(
			"GAM Access Grant", {"user": ["in", [MEMBER_A, MEMBER_B]]}, pluck="name"
		):
			frappe.delete_doc("GAM Access Grant", name, force=True, ignore_permissions=True)
		purge_fixtures()
		super().tearDownClass()

	@staticmethod
	def _ensure_game(title):
		"""Create (if missing) a GAM Game by display name; return its doc name."""
		name = frappe.db.get_value("GAM Game", {"game_name": title})
		if name:
			return name
		doc = frappe.get_doc(
			{"doctype": "GAM Game", "game_name": title, "is_active": 1}
		)
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
		# Idempotent: clear any existing grant for this (user, scope, key).
		existing = frappe.get_all(
			"GAM Access Grant",
			{"user": user, "scope": scope, "key": key},
			pluck="name",
		)
		for n in existing:
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


# ───────────────────────── A1 — helper-level L2 evaluation ────────────────────
class TestAccountAccessHelpers(_AccessBoundaryBase):
	def test_grant_keys_reflect_bindings(self):
		frappe.set_user(ADMIN)
		keys = api._account_grant_keys_for(self.acc_granted)
		# grant keys carry the GAM Game doc name, not the display name.
		self.assertIn("ROLE_GAME|{0}|{1}".format(ROLE_GRANTED, self.game), keys)

	def test_admin_bypasses_account_gate(self):
		frappe.set_user(ADMIN)
		# Must not raise.
		api._require_account_access(self.acc_granted)

	def test_member_with_grant_passes_for_granted_account(self):
		# member_b: grant them ONLY the TRADER combo, then they may access
		# acc_other but NOT acc_granted.
		frappe.set_user(ADMIN)
		self._grant(MEMBER_B, "ROLE_GAME", "{0}|{1}".format(ROLE_OTHER, self.game))
		try:
			frappe.set_user(MEMBER_B)
			api._require_account_access(self.acc_other)  # passes
			with self.assertRaises(frappe.PermissionError):
				api._require_account_access(self.acc_granted)  # denied
		finally:
			frappe.set_user(ADMIN)
			for n in frappe.get_all(
				"GAM Access Grant", {"user": MEMBER_B}, pluck="name"
			):
				frappe.delete_doc("GAM Access Grant", n, force=True, ignore_permissions=True)

	def test_member_without_grants_nor_matching_role_is_denied(self):
		frappe.set_user(MEMBER_B)  # no grants, role "GAM Member" matches nothing
		with self.assertRaises(frappe.PermissionError):
			api._require_account_access(self.acc_granted)

	def test_match_role_fallback_for_zero_grant_member(self):
		# member_c holds the "Booster" Frappe role and has zero grants → under
		# the default match_role policy they fall back to role match.
		frappe.set_user(MEMBER_C)
		# Must not raise: account's role BOOSTER matches their Frappe role.
		api._require_account_access(self.acc_granted)

	def test_admin_bypasses_account_with_zero_bindings(self):
		# Regression: admin bypass must be evaluated BEFORE the empty-binding
		# check, so an admin can act on an account that has no (role, game)
		# bindings yet.
		frappe.set_user(ADMIN)
		empty = make_account("STEAM", "unit_acc_nobinding", self.email)
		try:
			# No bindings → allowed keys empty, but admin must still bypass.
			api._require_account_access(empty)
			self.assertEqual(api._account_grant_keys_for(empty), set())
		finally:
			frappe.set_user(ADMIN)

	def test_require_account_access_rejects_empty_and_missing(self):
		frappe.set_user(ADMIN)
		with self.assertRaises(frappe.PermissionError):
			api._require_account_access("")
		with self.assertRaises(frappe.PermissionError):
			api._require_account_access("does-not-exist-zzz")

	def test_email_access_derived_from_bound_accounts(self):
		# member_c (match_role fallback for BOOSTER) may reach the email that
		# backs the granted account.
		frappe.set_user(MEMBER_C)
		api._require_email_access(self.email)
		# member_b (no grant, no matching role) may NOT.
		frappe.set_user(MEMBER_B)
		with self.assertRaises(frappe.PermissionError):
			api._require_email_access(self.email)


# ──────────────────── A1 — endpoint-level enforcement ─────────────────────────
class TestEndpointAccessGates(_AccessBoundaryBase):
	def test_reveal_password_denied_without_grant(self):
		# member_b has no grant for acc_granted → reveal must throw BEFORE the
		# secret is read (no Reveal Log created).
		frappe.set_user(MEMBER_B)
		with self.assertRaises(frappe.PermissionError):
			api.reveal_password("GAM Account", self.acc_granted, "account_password")
		self.assertFalse(
			frappe.db.exists(
				"GAM Reveal Log",
				{"target_name": self.acc_granted, "viewed_by": MEMBER_B},
			)
		)

	def test_reveal_password_allowed_with_match_role(self):
		frappe.set_user(MEMBER_C)
		res = api.reveal_password("GAM Account", self.acc_granted, "account_password")
		self.assertEqual(res["password"], "accpw456")

	def test_checkout_denied_without_grant(self):
		frappe.set_user(MEMBER_B)
		with self.assertRaises(frappe.PermissionError):
			api.checkout_account(self.acc_granted)

	def test_get_account_activity_denied_without_grant(self):
		frappe.set_user(MEMBER_B)
		with self.assertRaises(frappe.PermissionError):
			api.get_account_activity(self.acc_granted)

	def test_get_account_notes_denied_without_grant(self):
		frappe.set_user(MEMBER_B)
		with self.assertRaises(frappe.PermissionError):
			api.get_account_notes(self.acc_granted)

	def test_add_account_note_denied_without_grant(self):
		frappe.set_user(MEMBER_B)
		with self.assertRaises(frappe.PermissionError):
			api.add_account_note(self.acc_granted, "should not persist")

	def test_admin_can_read_everything(self):
		frappe.set_user(ADMIN)
		# All read endpoints succeed for admin.
		self.assertIsInstance(api.get_account_role_games(self.acc_granted), list)
		self.assertIn("data", api.get_account_activity(self.acc_granted))


# ──────────────────────── A2 — aggregate endpoint guards ──────────────────────
class TestAggregateGuards(_AccessBoundaryBase):
	def test_non_gam_user_blocked_from_dashboard_stats(self):
		frappe.set_user(NON_GAM)
		with self.assertRaises(frappe.PermissionError):
			api.get_dashboard_stats()

	def test_non_gam_user_blocked_from_account_stats(self):
		frappe.set_user(NON_GAM)
		with self.assertRaises(frappe.PermissionError):
			api.get_account_stats()

	def test_non_gam_user_blocked_from_role_game_sections(self):
		frappe.set_user(NON_GAM)
		with self.assertRaises(frappe.PermissionError):
			api.get_role_game_sections()

	def test_non_gam_user_blocked_from_list_options(self):
		frappe.set_user(NON_GAM)
		with self.assertRaises(frappe.PermissionError):
			api.get_list_options()

	def test_non_gam_user_blocked_from_global_search(self):
		frappe.set_user(NON_GAM)
		with self.assertRaises(frappe.PermissionError):
			api.global_search("unit")

	def test_member_global_search_filters_accounts_by_grant(self):
		# member_b (no grants) sees NO accounts even when the query matches.
		frappe.set_user(MEMBER_B)
		res = api.global_search("unit_acc")
		self.assertEqual(res["accounts"], [])

	def test_admin_global_search_returns_matching_accounts(self):
		frappe.set_user(ADMIN)
		res = api.global_search("unit_acc_granted")
		names = [a["name"] for a in res["accounts"]]
		self.assertIn(self.acc_granted, names)


# ───────────────────────── A5 — fail-closed audit logging ─────────────────────
class TestFailClosedAudit(_AccessBoundaryBase):
	def _breaking_get_doc(self, blocked_doctype):
		"""Return a get_doc replacement that raises ONLY for ``blocked_doctype``;
		everything else (incl. frappe.log_error's Error Log) delegates to the
		real implementation so the audit helpers still record the failure."""
		real = frappe.get_doc

		def _proxy(*args, **kwargs):
			doc = args[0] if args else kwargs.get("doctype")
			target = None
			if isinstance(doc, dict):
				target = doc.get("doctype")
			elif isinstance(doc, str):
				target = doc
			if target == blocked_doctype:
				raise Exception("simulated insert failure")
			return real(*args, **kwargs)

		return _proxy

	def test_log_reveal_raises_on_insert_failure(self):
		# If the Reveal-Log insert blows up, the helper must re-raise (the secret
		# is never disclosed without an audit trail).
		frappe.set_user(ADMIN)
		with patch("frappe.get_doc", side_effect=self._breaking_get_doc("GAM Reveal Log")):
			with self.assertRaises(frappe.ValidationError):
				api._log_reveal("GAM Account", self.acc_granted, "account_password", "REVEAL")

	def test_log_code_request_raises_on_insert_failure(self):
		frappe.set_user(ADMIN)
		with patch(
			"frappe.get_doc",
			side_effect=self._breaking_get_doc("GAM Code Request Log"),
		):
			with self.assertRaises(frappe.ValidationError):
				api._log_code_request(
					target_email=self.email,
					target_account=self.acc_granted,
					platform="STEAM",
					code_value="",
					status="NO_CODE",
					email_code=None,
				)

	def test_log_reveal_succeeds_normally(self):
		frappe.set_user(ADMIN)
		# No exception → returns None; an audit row exists.
		api._log_reveal("GAM Account", self.acc_granted, "totp_secret", "COPY")
		self.assertTrue(
			frappe.db.exists(
				"GAM Reveal Log",
				{"target_name": self.acc_granted, "fieldname": "totp_secret"},
			)
		)
