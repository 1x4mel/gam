import frappe
from frappe import _
from frappe.model.document import Document


class GAMAccountNote(Document):
	def before_insert(self):
		if not self.note_by:
			self.note_by = frappe.session.user
		if not self.created_at:
			self.created_at = frappe.utils.now_datetime()
