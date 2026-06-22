# Copyright (c) 2026, GAM and contributors
# License: MIT
"""GAM Access Grant — fine-grained, app-scoped access-control backbone (L2).

See plans/active-view-and-access-grant-matrix.md (§B.2). One doctype shared
across every custom app: each row grants a (scope, key) to a user within an
``app``. The matrix UI in gam-ui reads/writes these rows; backend APIs use the
``_has_access`` helper to gate visibility + data-scope.

L1 (app-entry / admin tier) is still handled by Frappe Roles
(``GAM Admin`` / ``GAM Member`` …); this doctype only adds the fine layer.
"""
import frappe
from frappe.model.document import Document


class GAMAccessGrant(Document):
    def validate(self):
        # Normalise the app/scope/key identifiers (trim, uppercase tokens).
        if self.app:
            self.app = self.app.strip()
        if self.scope:
            self.scope = self.scope.strip()
        if self.key:
            self.key = self.key.strip()

        # Audit stamp: who granted this and when.
        if not self.granted_by:
            self.granted_by = frappe.session.user
        if not self.granted_on:
            self.granted_on = frappe.utils.now_datetime()

        self._enforce_unique()

    def _enforce_unique(self):
        """A (user, app, scope, key) combination must be unique."""
        if not (self.user and self.app and self.scope and self.key):
            return
        existing = frappe.db.get_value(
            "GAM Access Grant",
            {
                "user": self.user,
                "app": self.app,
                "scope": self.scope,
                "key": self.key,
                "name": ["!=", self.name or "___"],
            },
            "name",
        )
        if existing:
            frappe.throw(
                frappe._(
                    "Đã tồn tại phân quyền {0}/{1} cho user {2}."
                ).format(self.scope, self.key, self.user),
                frappe.DuplicateEntryError,
            )
