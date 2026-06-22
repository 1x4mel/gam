# Copyright (c) 2026, GAM and contributors
# License: MIT
"""Unit tests for gam.api — the whitelisted surface consumed by gam-ui.

Run:  bench --site erp.local run-tests --app gam
"""
import frappe
from unittest.mock import patch
from frappe.tests.utils import FrappeTestCase
from frappe.utils import add_to_date, now_datetime

from gam import api
from gam.tests.utils import (
	TEST_ADDRESS,
	TEST_USERNAME,
	ensure_user,
	make_account,
	make_email,
	purge_fixtures,
	set_webhook_secret,
)


class _MockRequest:
	"""Minimal stand-in for flask.request consumed by receive_email_webhook."""

	def __init__(self, json_data=None, headers=None, method="POST"):
		self.method = method
		self._json = json_data
		self.headers = headers or {}
		self.remote_addr = "127.0.0.1"
		self.form = {}

	def get_json(self, silent=True):
		return self._json


class TestWebhookParse(FrappeTestCase):
	"""Code-pattern matching + regex extraction (Design §7.2)."""

	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		from gam.setup import seed_code_patterns
		seed_code_patterns()

	def test_steam_code_extracted(self):
		p = api._match_pattern(
			"noreply@steampowered.com",
			"Steam Guard verification code",
			"Your verification code: 5QR9Z",
		)
		self.assertIsNotNone(p)
		self.assertEqual(p.platform, "STEAM")
		self.assertEqual(p.extracted, "5QR9Z")

	def test_battlenet_code_extracted(self):
		p = api._match_pattern(
			"noreply@battle.net",
			"Battle.net security code",
			"Your security code: 482917",
		)
		self.assertIsNotNone(p)
		self.assertEqual(p.platform, "BATTLENET")
		self.assertEqual(p.extracted, "482917")

	def test_poe_code_extracted(self):
		# The seeded POE pattern matches the XXX-XXX-XXXX verification-code
		# format (same shape the forwarded-code e2e uses, e.g. 8a9-342-832b).
		p = api._match_pattern(
			"support@grindinggear.com",
			"Path of Exile verification",
			"Your verification code: PoE-423-832b",
		)
		self.assertIsNotNone(p)
		self.assertEqual(p.platform, "POE")
		self.assertEqual(p.extracted, "PoE-423-832b")

	def test_unknown_sender_no_match(self):
		self.assertIsNone(
			api._match_pattern("spam@example.com", "verification code", "code: ABCDE")
		)

	def test_subject_keyword_gate_blocks(self):
		# Right sender + body but an unrelated subject must NOT match.
		self.assertIsNone(
			api._match_pattern(
				"noreply@steampowered.com", "Newsletter", "verification code: 5QR9Z"
			)
		)

	def test_parse_received_at_rfc2822(self):
		self.assertIsNotNone(api._parse_received_at("Mon, 15 Jun 2026 12:00:00 +0000"))

	def test_parse_received_at_invalid(self):
		self.assertIsNone(api._parse_received_at(None))
		self.assertIsNone(api._parse_received_at("not-a-date"))

	def test_parse_received_at_converts_utc_to_system_timezone(self):
		# Regression for the "Chưa có code mới" bug: the Cloudflare worker sends
		# received_at in UTC, but every expiry check compares against
		# now_datetime() (Frappe system timezone, NOT the OS timezone). Parsing
		# MUST convert UTC -> system tz, otherwise a freshly-arrived code looks
		# already-expired by the full tz offset. Feed the current UTC moment and
		# assert the parsed value tracks now_datetime(), not datetime.utcnow().
		from datetime import datetime, timezone
		from email.utils import format_datetime

		utc_now = datetime.now(timezone.utc)
		parsed = api._parse_received_at(format_datetime(utc_now))
		sys_now = frappe.utils.now_datetime()
		delta = abs((parsed - sys_now).total_seconds())
		self.assertLess(
			delta,
			120,
			f"parsed {parsed} != now_datetime() {sys_now} (delta {delta}s) "
			"— UTC receipt time not converted to system timezone",
		)


class TestRevealPassword(FrappeTestCase):
	def setUp(self):
		super().setUp()
		frappe.set_user("Administrator")
		purge_fixtures()
		self.email = make_email()
		self.account = make_account("STEAM", TEST_USERNAME, self.email, password="accpw456")

	def test_reveal_returns_plaintext_and_audits(self):
		res = api.reveal_password("GAM Account", self.account, "account_password")
		self.assertEqual(res["password"], "accpw456")
		log = frappe.get_last_doc(
			"GAM Reveal Log",
			filters={"target_name": self.account, "fieldname": "account_password"},
		)
		self.assertEqual(log.action, "REVEAL")
		self.assertEqual(log.viewed_by, "Administrator")

	def test_reveal_non_whitelisted_field_denied(self):
		with self.assertRaises(frappe.ValidationError):
			api.reveal_password("GAM Account", self.account, "notes")


class TestRequestCode(FrappeTestCase):
	"""Atomic claim lifecycle (Design §5.3)."""

	def setUp(self):
		super().setUp()
		frappe.set_user("Administrator")
		purge_fixtures()
		self.email = make_email()
		self.account = make_account("STEAM", TEST_USERNAME, self.email)

	def _make_code(self, code="AB12C", platform="STEAM", expires_in_min=10):
		now = now_datetime()
		return frappe.get_doc(
			{
				"doctype": "GAM Email Code",
				"email": self.email,
				"email_address": TEST_ADDRESS,
				"platform": platform,
				"code": code,
				"received_at": now,
				"expires_at": add_to_date(now, minutes=expires_in_min),
				"status": "AVAILABLE",
			}
		).insert(ignore_permissions=True)

	def test_claim_returns_code_and_marks_claimed(self):
		code_doc = self._make_code("AB12C")
		res = api.request_code(email_name=self.email, platform="STEAM")
		self.assertEqual(res["status"], "ok")
		self.assertEqual(res["code"], "AB12C")
		code_doc.reload()
		self.assertEqual(code_doc.status, "CLAIMED")
		self.assertEqual(code_doc.claimed_by, "Administrator")
		log = frappe.get_last_doc("GAM Code Request Log", {"target_email": self.email})
		self.assertEqual(log.status, "FULFILLED")

	def test_second_request_after_claim_is_no_code(self):
		self._make_code("AB12C")
		api.request_code(email_name=self.email, platform="STEAM")
		res = api.request_code(email_name=self.email, platform="STEAM")
		self.assertEqual(res["status"], "no_code")
		log = frappe.get_last_doc("GAM Code Request Log", {"target_email": self.email})
		self.assertEqual(log.status, "NO_CODE")

	def test_expired_code_not_claimed(self):
		self._make_code("AB12C", expires_in_min=-5)  # already expired
		res = api.request_code(email_name=self.email, platform="STEAM")
		self.assertEqual(res["status"], "no_code")

	def test_resolve_platform_from_account(self):
		# request_code without an explicit platform should resolve STEAM from the account.
		self._make_code("CD34E")
		res = api.request_code(account_name=self.account)
		self.assertEqual(res["status"], "ok")
		self.assertEqual(res["code"], "CD34E")


class TestCheckoutLease(FrappeTestCase):
	def setUp(self):
		super().setUp()
		frappe.set_user("Administrator")
		purge_fixtures()
		self.email = make_email()
		self.account = make_account("STEAM", TEST_USERNAME, self.email)

	def test_checkout_creates_in_use_lease(self):
		usage = api.checkout_account(self.account, purpose="LOGIN", lease_minutes=60)
		self.assertEqual(usage["status"], "IN_USE")
		self.assertEqual(usage["used_by"], "Administrator")

	def test_same_user_recheckout_returns_existing(self):
		first = api.checkout_account(self.account)
		second = api.checkout_account(self.account)
		self.assertEqual(second["name"], first["name"])

	def test_checkin_releases(self):
		api.checkout_account(self.account)
		released = api.checkin_account(self.account, end_reason="DONE")
		self.assertEqual(released["status"], "RELEASED")

	def test_other_user_checkout_blocked(self):
		api.checkout_account(self.account)
		other = ensure_user("checkout-other@gam.test", ["GAM Admin"])
		frappe.set_user(other)
		try:
			with self.assertRaises(frappe.ValidationError):
				api.checkout_account(self.account)
		finally:
			frappe.set_user("Administrator")
			frappe.delete_doc("User", other, force=True, ignore_permissions=True)

	def test_expired_lease_auto_released_on_checkout(self):
		# create a stale IN_USE lease whose lease_until is in the past
		now = now_datetime()
		frappe.get_doc(
			{
				"doctype": "GAM Account Usage",
				"account": self.account,
				"status": "IN_USE",
				"used_by": "Administrator",
				"purpose": "LOGIN",
				"started_at": add_to_date(now, minutes=-200),
				"lease_until": add_to_date(now, minutes=-100),
			}
		).insert(ignore_permissions=True)
		usage = api.checkout_account(self.account)  # should auto-release the stale one
		self.assertEqual(usage["status"], "IN_USE")


class TestWebhookEndpoint(FrappeTestCase):
	def setUp(self):
		super().setUp()
		frappe.set_user("Administrator")
		purge_fixtures()
		from gam.setup import seed_code_patterns
		seed_code_patterns()
		set_webhook_secret("unit-test-secret", active=1)
		self.email = make_email()

	def _post(self, payload, secret):
		old = getattr(frappe.local, "request", None)
		frappe.local.request = _MockRequest(
			json_data=payload, headers={"X-Webhook-Secret": secret} if secret else {}
		)
		try:
			return api.receive_email_webhook()
		finally:
			frappe.local.request = old

	def test_wrong_secret_denied(self):
		with self.assertRaises(frappe.PermissionError):
			self._post({"from": "x@steampowered.com"}, "WRONG")

	def test_disabled_webhook_denied(self):
		set_webhook_secret("unit-test-secret", active=0)
		with self.assertRaises(frappe.PermissionError):
			self._post({"from": "x@steampowered.com"}, "unit-test-secret")

	def test_happy_path_creates_email_code(self):
		result = self._post(
			{
				"email_account": TEST_ADDRESS,
				"from": "noreply@steampowered.com",
				"subject": "Steam Guard verification code",
				"body": "Your verification code: 5QR9Z",
				"message_id": "unit-test-msg-001",
				"received_at": "Mon, 15 Jun 2026 12:00:00 +0000",
			},
			"unit-test-secret",
		)
		self.assertEqual(result["status"], "ok")
		code_doc = frappe.get_last_doc(
			"GAM Email Code", {"email_address": TEST_ADDRESS, "code": "5QR9Z"}
		)
		self.assertEqual(code_doc.platform, "STEAM")
		self.assertEqual(code_doc.status, "AVAILABLE")
		log = frappe.get_last_doc("GAM Email Inbound Log", {"message_id": "unit-test-msg-001"})
		self.assertEqual(log.status, "OK")

	def test_no_match_logs_and_returns_no_match(self):
		result = self._post(
			{
				"email_account": TEST_ADDRESS,
				"from": "random@example.com",
				"subject": "Hello",
				"body": "nothing useful here",
				"message_id": "unit-test-msg-002",
			},
			"unit-test-secret",
		)
		self.assertEqual(result["status"], "no_match")
		log = frappe.get_last_doc("GAM Email Inbound Log", {"message_id": "unit-test-msg-002"})
		self.assertEqual(log.status, "NO_MATCH")

	def test_duplicate_message_id(self):
		payload = {
			"email_account": TEST_ADDRESS,
			"from": "noreply@steampowered.com",
			"subject": "Steam Guard verification code",
			"body": "Your verification code: 6RQ1Y",
			"message_id": "unit-test-msg-dup",
			"received_at": "Mon, 15 Jun 2026 12:00:00 +0000",
		}
		self.assertEqual(self._post(payload, "unit-test-secret")["status"], "ok")
		# same message_id again -> duplicate
		self.assertEqual(self._post(payload, "unit-test-secret")["status"], "duplicate")


class TestDashboardAndSearch(FrappeTestCase):
	def setUp(self):
		super().setUp()
		frappe.set_user("Administrator")
		purge_fixtures()
		self.email = make_email()
		self.account = make_account("STEAM", TEST_USERNAME, self.email)

	def test_dashboard_stats_shape(self):
		stats = api.get_dashboard_stats()
		for key in (
			"total_accounts",
			"banned_accounts",
			"total_emails",
			"available_codes",
			"expiring_links_count",
			"expiring_links",
		):
			self.assertIn(key, stats)
		self.assertGreaterEqual(stats["total_accounts"], 1)
		self.assertGreaterEqual(stats["total_emails"], 1)

	def test_global_search_finds_account(self):
		res = api.global_search(TEST_USERNAME)
		self.assertTrue(any(a["username"] == TEST_USERNAME for a in res["accounts"]))

	def test_global_search_short_query_empty(self):
		self.assertEqual(
			api.global_search("a"),
			{"accounts": [], "emails": [], "games": []},
		)


class TestRoleAudit(FrappeTestCase):
	"""Role-isolation audit (B4 — co-tenancy hardening)."""

	def setUp(self):
		super().setUp()
		frappe.set_user("Administrator")

	def test_admin_can_audit_self(self):
		res = api.get_role_audit()
		self.assertIn("Administrator", res["roles"])
		self.assertTrue(res["is_gam_admin"] or "Administrator" in res["roles"])

	def test_member_with_breaking_role_flagged(self):
		user = ensure_user("iso-member@gam.test", ["GAM Member", "System Manager"])
		try:
			audit = api.get_role_audit(user=user)
			self.assertFalse(audit["is_isolated"])
			warned = [w["role"] for w in audit["warnings"]]
			self.assertIn("System Manager", warned)
		finally:
			frappe.delete_doc("User", user, force=True, ignore_permissions=True)

	def test_clean_member_isolated(self):
		user = ensure_user("clean-member@gam.test", ["GAM Member"])
		try:
			audit = api.get_role_audit(user=user)
			self.assertTrue(audit["is_isolated"])
			self.assertEqual(audit["warnings"], [])
		finally:
			frappe.delete_doc("User", user, force=True, ignore_permissions=True)

	def test_member_denied_audit(self):
		user = ensure_user("plain-member@gam.test", ["GAM Member"])
		frappe.set_user(user)
		try:
			with self.assertRaises(frappe.PermissionError):
				api.get_role_audit()
		finally:
			frappe.set_user("Administrator")
			frappe.delete_doc("User", user, force=True, ignore_permissions=True)


class TestAccountRoleGameReflow(FrappeTestCase):
	"""First-class (role, game) bindings — dynamic sidebar sections.

	Role no longer lives on GAM Account; the single source of truth is the
	top-level ``GAM Account Role Game`` doctype (one binding per
	(account, game)). The sidebar aggregates it via ``get_role_game_sections``
	and reflows live on the dedicated ``gam_role_sections_changed`` event.

	These tests pin: role canonicalization, binding upsert/uniqueness, the
	single is_main rule, add/remove + the realtime emits, and the section
	aggregation.
	"""

	GAME_A = "Unit Test Game A"
	GAME_B = "Unit Test Game B"

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

	def setUp(self):
		super().setUp()
		frappe.set_user("Administrator")
		purge_fixtures()
		self._seed_role("BOOSTER", "Booster")
		self._seed_role("TRADER", "Trader")
		self.game_a = self._ensure_game(self.GAME_A)
		self.game_b = self._ensure_game(self.GAME_B)
		self.email = make_email()
		self.account = make_account("STEAM", TEST_USERNAME, self.email)
		self._purge_bindings()

	def _bindings(self):
		"""First-class (role, game) bindings for the test account."""
		return frappe.get_all(
			"GAM Account Role Game",
			filters={"account": self.account},
			fields=["name", "role", "game", "is_main"],
			order_by="idx asc",
		)

	def _purge_bindings(self):
		"""Clear this account's bindings + any orphans left from prior runs.

		Accounts are recreated with a fresh name each run, so bindings from a
		previous run would otherwise dangle (and pollute the section aggregate).
		"""
		frappe.db.delete("GAM Account Role Game", {"account": self.account})
		orphans = frappe.db.sql_list(
			"""
			SELECT arg.name FROM `tabGAM Account Role Game` arg
			LEFT JOIN `tabGAM Account` a ON a.name = arg.account
			WHERE a.name IS NULL
			"""
		)
		for name in orphans or []:
			frappe.delete_doc(
				"GAM Account Role Game", name, force=True, ignore_permissions=True
			)

	# ---- _normalize_role_value: the canonicalization at the heart of the fix ----
	def test_normalize_label_to_value(self):
		self.assertEqual(api._normalize_role_value("Booster"), "BOOSTER")

	def test_normalize_value_passthrough(self):
		self.assertEqual(api._normalize_role_value("TRADER"), "TRADER")

	def test_normalize_case_insensitive(self):
		self.assertEqual(api._normalize_role_value("booster"), "BOOSTER")
		self.assertEqual(api._normalize_role_value("TrAdEr"), "TRADER")

	def test_normalize_blank(self):
		self.assertEqual(api._normalize_role_value(""), "")
		self.assertEqual(api._normalize_role_value(None), "")

	def test_normalize_unknown_returned_as_is(self):
		# A role that is neither a known value nor label is returned verbatim
		# (defensive — never silently coerced to another role).
		self.assertEqual(api._normalize_role_value("Ghost"), "Ghost")

	# ---- save_account persists (role, game) bindings + canonicalizes role ----
	def test_save_account_stores_role_games_with_canonical_role(self):
		api.save_account(
			{
				"platform": "STEAM",
				"username": TEST_USERNAME,
				"email": self.email,
				"role_games": [
					{"game": self.game_a, "role": "Booster", "is_main": 1},  # label
				],
			},
			name=self.account,
		)
		b = self._bindings()
		self.assertEqual(len(b), 1)
		self.assertEqual(b[0]["game"], self.game_a)
		self.assertEqual(b[0]["role"], "BOOSTER")  # label -> canonical value
		self.assertEqual(int(b[0]["is_main"] or 0), 1)

	def test_save_account_role_games_requires_role(self):
		# one role per (account, game): a row without a role is invalid
		with self.assertRaises(frappe.ValidationError):
			api.save_account(
				{
					"platform": "STEAM",
					"username": TEST_USERNAME,
					"email": self.email,
					"role_games": [{"game": self.game_a}],  # no role
				},
				name=self.account,
			)

	def test_save_account_emits_both_events_when_bindings_change(self):
		with patch("gam.api.emit_account_changed") as mock_account, patch(
			"gam.api.emit_role_sections_changed"
		) as mock_sections:
			api.save_account(
				{
					"platform": "STEAM",
					"username": TEST_USERNAME,
					"email": self.email,
					"role_games": [{"game": self.game_a, "role": "TRADER"}],
				},
				name=self.account,
			)
		mock_account.assert_called_once_with(self.account, "save")
		mock_sections.assert_called_once_with()

	# ---- add_account_role_game: upsert by (account, game) + single is_main ----
	def test_add_role_game_creates_binding(self):
		api.add_account_role_game(self.account, "BOOSTER", self.game_a, is_main=1)
		b = self._bindings()
		self.assertEqual(len(b), 1)
		self.assertEqual(b[0]["role"], "BOOSTER")
		self.assertEqual(b[0]["game"], self.game_a)
		self.assertEqual(int(b[0]["is_main"] or 0), 1)

	def test_add_role_game_upserts_existing_game(self):
		# adding the same game again updates role/is_main instead of duplicating
		api.add_account_role_game(self.account, "BOOSTER", self.game_a, is_main=1)
		api.add_account_role_game(self.account, "TRADER", self.game_a)  # flip role
		b = self._bindings()
		self.assertEqual(len(b), 1)
		self.assertEqual(b[0]["role"], "TRADER")

	def test_add_second_role_game_demotes_previous_main(self):
		api.add_account_role_game(self.account, "BOOSTER", self.game_a, is_main=1)
		api.add_account_role_game(self.account, "TRADER", self.game_b, is_main=1)
		b = {x["game"]: x for x in self._bindings()}
		self.assertEqual(int(b[self.game_a]["is_main"] or 0), 0)
		self.assertEqual(int(b[self.game_b]["is_main"] or 0), 1)

	def test_add_role_game_emits_both_events(self):
		with patch("gam.api.emit_account_changed") as mock_account, patch(
			"gam.api.emit_role_sections_changed"
		) as mock_sections:
			api.add_account_role_game(self.account, "BOOSTER", self.game_a, is_main=1)
		mock_account.assert_called_once_with(self.account, "add_game")
		mock_sections.assert_called_once_with()

	# ---- remove_account_role_game ----
	def test_remove_role_game_by_row_name(self):
		api.add_account_role_game(self.account, "BOOSTER", self.game_a, is_main=1)
		api.add_account_role_game(self.account, "TRADER", self.game_b)
		# Select target by game value — idx ordering is unreliable on a
		# top-level doctype (no guaranteed insertion-order sort).
		target = next(
			b["name"] for b in self._bindings() if b["game"] == self.game_b
		)
		api.remove_account_role_game(self.account, row_name=target)
		b = self._bindings()
		self.assertEqual(len(b), 1)
		self.assertEqual(b[0]["game"], self.game_a)

	def test_remove_role_game_by_game(self):
		api.add_account_role_game(self.account, "BOOSTER", self.game_a, is_main=1)
		api.add_account_role_game(self.account, "TRADER", self.game_b)
		api.remove_account_role_game(self.account, game=self.game_b)
		b = self._bindings()
		self.assertEqual(len(b), 1)
		self.assertEqual(b[0]["game"], self.game_a)

	def test_remove_main_role_game_re_picks_main(self):
		api.add_account_role_game(self.account, "BOOSTER", self.game_a, is_main=1)
		api.add_account_role_game(self.account, "TRADER", self.game_b)  # is_main=0
		main = self._bindings()[0]["name"]
		api.remove_account_role_game(self.account, row_name=main)
		b = self._bindings()
		self.assertEqual(len(b), 1)
		self.assertEqual(int(b[0]["is_main"] or 0), 1)

	def test_remove_role_game_emits_both_events(self):
		api.add_account_role_game(self.account, "BOOSTER", self.game_a, is_main=1)
		row = self._bindings()[0]["name"]
		with patch("gam.api.emit_account_changed") as mock_account, patch(
			"gam.api.emit_role_sections_changed"
		) as mock_sections:
			api.remove_account_role_game(self.account, row_name=row)
		mock_account.assert_called_once_with(self.account, "remove_game")
		mock_sections.assert_called_once_with()

	def test_remove_nonexistent_binding_raises(self):
		with self.assertRaises(frappe.ValidationError):
			api.remove_account_role_game(self.account, row_name="no-such-row")

	# ---- get_role_game_sections aggregates the binding table ----
	def test_sections_aggregate_by_role_and_game(self):
		api.add_account_role_game(self.account, "BOOSTER", self.game_a, is_main=1)
		sections = api.get_role_game_sections()
		self.assertIn("BOOSTER", sections)
		games = [g["game"] for g in sections["BOOSTER"]]
		self.assertIn(self.game_a, games)
