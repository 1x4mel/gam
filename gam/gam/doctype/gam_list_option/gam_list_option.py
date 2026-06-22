import frappe
from frappe import _
from frappe.model.document import Document


class GAMListOption(Document):
	def validate(self):
		# Auto-derive a stored value from the label when left blank.
		if not (self.value or "").strip() and self.label:
			self.value = (
				self.label.strip().upper().replace(" ", "_").replace("-", "_")
			)
		if not (self.value or "").strip():
			frappe.throw(_("Value is required."))

		# Enforce one active option per (category, value).
		dup = frappe.db.exists(
			"GAM List Option",
			{
				"category": self.category,
				"value": self.value,
				"name": ["!=", self.name or ""],
			},
		)
		if dup:
			frappe.throw(
				_("A {0} option with value {1} already exists.").format(
					self.category, self.value
				)
			)
