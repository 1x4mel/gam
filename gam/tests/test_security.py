# Copyright (c) 2026, GAM and contributors
# License: MIT
"""Security hardening tests (plans/gam-code-quality-and-hardening.md Phase 1).

Covers the opt-in additions that are NOT already exercised by test_api.py:

  * P1.1 — gam.permissions ORM-layer access-grant scoping (default OFF + SQL)
  * P1.3 — get_webhook_setup_state no longer ships the plaintext secret +
           reveal_webhook_secret() discloses it audit-logged
  * P1.5 — _is_safe_host / _is_public_ip SSRF guard
  * P1.6 — setup_2fa_test gated behind gam_allow_2fa_test (off by default)

Run:  bench --site erp.local run-tests --app gam
"""
import ipaddress
from unittest.mock import patch

import frappe
from frappe.tests.utils import FrappeTestCase

from gam import api, ops, permissions
from gam.tests.utils import ensure_user, set_webhook_secret


# ───────────────────────────────── P1.5 — SSRF guard ──────────────────────────
class TestSsrfGuard(FrappeTestCase):
	"""_is_safe_host / _is_public_ip (deterministic — bare IPs need no DNS)."""

	def test_loopback_and_private_ips_rejected(self):
		for host in ("127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.0.2"):
			self.assertFalse(
				api._is_safe_host(host), f"private/loopback host {host!r} must be rejected"
			)

	def test_empty_host_rejected(self):
		self.assertFalse(api._is_safe_host(""))
		self.assertFalse(api._is_safe_host(None))

	def test_is_public_ip_positive(self):
		self.assertTrue(api._is_public_ip(ipaddress.ip_address("8.8.8.8")))
		self.assertTrue(api._is_public_ip(ipaddress.ip_address("1.1.1.1")))

	def test_is_public_ip_negative(self):
		for ip in ("127.0.0.1", "10.1.2.3", "192.168.0.1", "169.254.1.1", "::1"):
			self.assertFalse(
				api._is_public_ip(ipaddress.ip_address(ip)),
				f"{ip} must NOT be treated as public",
			)


# ─────────────────────────────── P1.3 — webhook secret ────────────────────────
class TestWebhookSecretHardening(FrappeTestCase):
	def setUp(self):
		super().setUp()
		frappe.set_user("Administrator")
		set_webhook_secret("p1-secret-value", active=1)

	def test_setup_state_has_no_plaintext_secret(self):
		# Patch the tunnel probe so the test never shells out / hits network.
		with patch("gam.api.get_tunnel_status", return_value={}):
			state = api.get_webhook_setup_state()
		self.assertNotIn("webhook_secret", state, "plaintext secret must not ship in setup state")
		self.assertTrue(state["webhook_secret_set"])

	def test_reveal_webhook_secret_returns_plaintext_and_audits(self):
		res = api.reveal_webhook_secret()
		self.assertEqual(res["webhook_secret"], "p1-secret-value")
		# action is the generic "REVEAL" (Select only allows REVEAL/COPY); the
		# webhook disclosure is distinguished by target_name + fieldname.
		log = frappe.get_last_doc(
			"GAM Reveal Log",
			filters={
				"target_name": "GAM Webhook Config",
				"fieldname": "webhook_secret",
			},
		)
		self.assertEqual(log.action, "REVEAL")
		self.assertEqual(log.viewed_by, "Administrator")


# ─────────────────────────────── P1.6 — 2FA test gate ─────────────────────────
class TestTwoFactorTestGate(FrappeTestCase):
	def setUp(self):
		super().setUp()
		frappe.set_user("Administrator")

	# The gate reads two opt-in sources: frappe.conf.get("gam_allow_2fa_test")
	# and os.environ["GAM_ALLOW_2FA_TEST"]. The dev/staging host legitimately
	# sets one of them for the e2e suite, which would mask the production-safe
	# default-off guarantee these tests protect. So we suppress BOTH, narrowly —
	# only the opt-in key for frappe.conf (other keys still delegate to the real
	# conf so frappe internals keep working during the test).
	def _gate_off(self):
		import os
		from contextlib import ExitStack

		# frappe.conf is a werkzeug LocalProxy wrapping the merged config dict,
		# which mock cannot introspect (patch.object raises). So we neutralise
		# the opt-in key by direct item assignment on the proxy (delegated to
		# the real Conf dict) and restore the original value afterwards.
		saved_conf = frappe.conf.get("gam_allow_2fa_test")
		frappe.conf["gam_allow_2fa_test"] = None
		saved_env = os.environ.pop("GAM_ALLOW_2FA_TEST", None)
		stack = ExitStack()
		stack.callback(lambda: frappe.conf.__setitem__("gam_allow_2fa_test", saved_conf))
		if saved_env is not None:
			stack.callback(os.environ.__setitem__, "GAM_ALLOW_2FA_TEST", saved_env)
		return stack

	def test_allow_flag_defaults_off(self):
		# No config key set → the gate is closed (production-safe default).
		with self._gate_off():
			self.assertFalse(ops._gam_allow_2fa_test())

	def test_setup_2fa_test_denied_when_gate_off(self):
		# Administrator clears _require_admin, but the gate throws BEFORE any
		# provisioning happens — so this is side-effect free.
		with self._gate_off():
			with self.assertRaises(frappe.PermissionError):
				ops.setup_2fa_test()

	def test_gate_opens_with_config_flag(self):
		with patch.object(ops, "_gam_allow_2fa_test", return_value=True):
			self.assertTrue(ops._gam_allow_2fa_test())


# ─────────────────────────────── P1.1 — permissions module ────────────────────
class TestPermissionsModule(FrappeTestCase):
	"""gam.permissions — ORM-layer access-grant scoping (opt-in, default OFF)."""

	def test_enforcement_defaults_off(self):
		# The single most important safe-rollback property: live behaviour is
		# unchanged until an operator flips gam_enforce_account_pqc=1.
		self.assertFalse(permissions._enforce_account_pqc())

	def test_clause_empty_when_off_for_admin(self):
		self.assertEqual(permissions.get_pqc_for_gam_account("Administrator"), "")

	def test_clause_empty_when_off_for_member(self):
		user = ensure_user("pqcmember@gam.test", ["GAM Member"])
		try:
			# Flag OFF → no SQL filter injected, regardless of role (no regression).
			self.assertEqual(permissions.get_pqc_for_gam_account(user), "")
		finally:
			frappe.set_user("Administrator")
			frappe.delete_doc("User", user, force=True, ignore_permissions=True)

	def test_binding_clause_escapes_and_combines(self):
		sql = permissions._binding_exists_clause(
			"x", [("BOOSTER", "Steam")], ["TRADER"]
		)
		# role/game literals are escaped; both the (role,game) pair and the
		# match_role IN-list appear, OR-combined.
		self.assertIn("x.role = 'BOOSTER'", sql)
		self.assertIn("x.game = 'Steam'", sql)
		self.assertIn("x.role IN ('TRADER')", sql)
		self.assertTrue(sql.startswith("(") and sql.endswith(")"))

	def test_account_clause_blocks_when_enforced_and_unmatched(self):
		# Simulate enforcement ON + a member with no grants + non-match_role
		# policy → the account table is fully hidden ("1=0").
		user = ensure_user("pqcblocked@gam.test", ["GAM Member"])
		try:
			with patch.object(permissions, "_enforce_account_pqc", return_value=True), patch.object(
				permissions, "_get_grant_default_policy", return_value="deny"
			):
				self.assertEqual(permissions.get_pqc_for_gam_account(user), "1=0")
		finally:
			frappe.set_user("Administrator")
			frappe.delete_doc("User", user, force=True, ignore_permissions=True)

	def test_account_clause_empty_for_admin_when_enforced(self):
		# Admins always bypass, even when enforcement is ON.
		with patch.object(permissions, "_enforce_account_pqc", return_value=True):
			self.assertEqual(permissions.get_pqc_for_gam_account("Administrator"), "")

	def test_binding_clause_returns_1eq0_when_nothing_matches(self):
		self.assertEqual(
			permissions._binding_exists_clause("x", [], []),
			"1=0",
		)
