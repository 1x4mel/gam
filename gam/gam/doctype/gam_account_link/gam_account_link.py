import frappe
from frappe import _
from frappe.model.document import Document


class GAMAccountLink(Document):
	def validate(self):
		if self.source_account and self.target_account and self.source_account == self.target_account:
			frappe.throw(_("An account cannot be linked to itself."))

		# prevent duplicate links in either direction
		if self.source_account and self.target_account:
			exists = frappe.db.exists(
				"GAM Account Link",
				{
					"name": ["!=", self.name or ""],
					"status": "ACTIVE",
					"source_account": ["in", [self.source_account, self.target_account]],
					"target_account": ["in", [self.source_account, self.target_account]],
				},
			)
			if exists:
				frappe.throw(_("An active link between these two accounts already exists."))
