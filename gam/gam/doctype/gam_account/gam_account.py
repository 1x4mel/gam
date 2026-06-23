import frappe
from frappe import _
from frappe.model.document import Document


class GAMAccount(Document):
	def validate(self):
		self._enforce_hierarchy_rules()
		self._enforce_billing_rules()

	def _enforce_hierarchy_rules(self):
		"""Apply GỐC→Thân→Cành tree rules (plan §1.2)."""
		if self.account_level == "PLATFORM":
			# A PLATFORM (Thân) node must not reference a parent and cannot be standalone.
			if self.parent_account:
				frappe.throw(
					_("A PLATFORM account cannot have a parent account."),
					title=_("Invalid Hierarchy"),
				)
			self.standalone = 0
			return

		# account_level == "GAME" (Cành)
		if self.parent_account:
			# GAME node on a platform → not standalone.
			self.standalone = 0
			if self.parent_account == self.name:
				frappe.throw(
					_("An account cannot be its own parent."),
					title=_("Invalid Hierarchy"),
				)
			parent_level = frappe.db.get_value(
				"GAM Account", self.parent_account, "account_level"
			)
			if parent_level != "PLATFORM":
				frappe.throw(
					_("Parent account must be a PLATFORM-level account."),
					title=_("Invalid Hierarchy"),
				)
			# Email must match (or auto-inherit) the parent's email.
			parent_email = frappe.db.get_value(
				"GAM Account", self.parent_account, "email"
			)
			if parent_email and self.email != parent_email:
				self.email = parent_email
			# Prevent cycles: walk up the parent chain.
			self._prevent_parent_cycle()
		else:
			# GAME node created directly on an email.
			self.standalone = 1

	def _prevent_parent_cycle(self):
		"""Ensure this node is not its own ancestor (cycle guard)."""
		seen = set()
		current = self.parent_account
		while current:
			if current == self.name or current in seen:
				frappe.throw(
					_("Parent account references create a cycle."),
					title=_("Invalid Hierarchy"),
				)
			seen.add(current)
			current = frappe.db.get_value("GAM Account", current, "parent_account")

	def _enforce_billing_rules(self):
		"""active_until is required for any non-ONE_TIME billing (plan §1.2)."""
		if self.billing_type and self.billing_type != "ONE_TIME" and not self.active_until:
			frappe.throw(
				_("{0} accounts must have an Active Until date.").format(self.billing_type),
				title=_("Missing Expiry"),
			)


