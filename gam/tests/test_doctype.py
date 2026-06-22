# Copyright (c) 2026, GAM and contributors
# License: MIT
"""Controller validation tests for GAM Account Link (anti-self + unique)."""
import frappe
from frappe.tests.utils import FrappeTestCase

from gam.tests.utils import make_account, make_email, purge_fixtures


class TestAccountLinkValidation(FrappeTestCase):
	def setUp(self):
		super().setUp()
		frappe.set_user("Administrator")
		purge_fixtures()
		self.email = make_email("link-test@gam.test")
		self.acc_a = make_account("STEAM", "unit_link_a", self.email)
		self.acc_b = make_account("STEAM", "unit_link_b", self.email)

	def _link(self, source, target):
		return frappe.get_doc(
			{
				"doctype": "GAM Account Link",
				"source_account": source,
				"target_account": target,
				"status": "ACTIVE",
			}
		)

	def test_valid_link_inserts(self):
		name = self._link(self.acc_a, self.acc_b).insert(ignore_permissions=True).name
		self.assertTrue(frappe.db.exists("GAM Account Link", name))

	def test_anti_self_link(self):
		with self.assertRaises(frappe.ValidationError):
			self._link(self.acc_a, self.acc_a).insert(ignore_permissions=True)

	def test_duplicate_blocked_both_directions(self):
		self._link(self.acc_a, self.acc_b).insert(ignore_permissions=True)
		# reverse direction is also a duplicate
		with self.assertRaises(frappe.ValidationError):
			self._link(self.acc_b, self.acc_a).insert(ignore_permissions=True)
