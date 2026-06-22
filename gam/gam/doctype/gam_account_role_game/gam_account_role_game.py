import frappe
from frappe.model.document import Document


class GAMAccountRoleGame(Document):
	"""First-class binding of a GAM Account to a (role, game) combination.

	This doctype is the single source of truth for "which account is used as
	which role for which game". It replaces the legacy split of `GAM Account.role`
	(account-level) + the `GAM Account Game` child table (game-level), so that:

	  * the Trader/Booster/Item sidebar sections aggregate ONE table (no JOIN),
	  * the permission unit ``ROLE_GAME|role|game`` maps 1:1 to a row here,
	  * an account can carry different roles for different games.

	Validation (defense-in-depth; the API layer also enforces these):
	  * unique (account, game) — one role per (account, game) per the agreed default,
	  * `is_main` is at most one per account (enforced in the API on write).
	"""

	def validate(self):
		self._validate_unique_account_game()

	def _validate_unique_account_game(self):
		"""One role per (account, game). Reject duplicates (different name)."""
		if not (self.account and self.game):
			return
		dup = frappe.db.exists(
			"GAM Account Role Game",
			{"account": self.account, "game": self.game, "name": ["!=", self.name]},
		)
		if dup:
			frappe.throw(
				frappe._(
					"Account {0} already has a role for game {1} (row {2}). "
					"Use one role per (account, game)."
				).format(self.account, self.game, dup)
			)
