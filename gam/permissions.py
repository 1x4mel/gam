# Copyright (c) 2026, GAM and contributors
# License: MIT
"""ORM-layer access-grant scoping (P1.1, plans/gam-code-quality-and-hardening.md).

Frappe ``permission_query_conditions`` + ``has_permission`` callbacks that push
the L2 access-grant layer from the API surface (where
:func:`gam.api.get_accounts_list` already gates by ROLE_GAME) down to the ORM,
so a plain REST ``frappe.client.get_list("GAM Account")`` can no longer
enumerate every account. Visibility mirrors :func:`gam.api.has_access` exactly:

  * Admins (GAM Admin / System Manager / Administrator) bypass — see everything.
  * Users with explicit ROLE_GAME grants see only accounts carrying a matching
    (role, game) binding.
  * Under the ``match_role`` default policy, a user with zero grants sees
    accounts whose binding role matches one of their Frappe roles (directly or
    via a GAM List Option "Account Role" label).
  * Otherwise the user sees nothing.

Enforcement is opt-in via ``gam_enforce_account_pqc`` (site_config /
common_site_config) and defaults to OFF, so live behaviour is unchanged until an
operator smoke-tests with a real member and flips it on. Rollback is a single
config change — no code edit required.
"""
import frappe
from frappe.utils import cint

from gam.api import (
	_get_grant_default_policy,
	_is_access_admin,
	_user_grant_keys,
)

_ACCOUNT_TABLE = "`tabGAM Account`"
_BINDING_TABLE = "`tabGAM Account Role Game`"


def _enforce_account_pqc():
	"""True when ORM-layer account scoping is active (default OFF — opt-in)."""
	return cint(frappe.conf.get("gam_enforce_account_pqc")) == 1


def _is_admin(user):
	roles = set(frappe.get_roles(user)) if user and user != "Guest" else set()
	return bool({"GAM Admin", "System Manager", "Administrator"} & roles)


def _role_game_pairs(user):
	"""[(role, game), ...] explicitly granted to ``user`` (ROLE_GAME scope)."""
	pairs = []
	for needle in _user_grant_keys(user, "GAM"):
		if not needle.startswith("ROLE_GAME|"):
			continue
		payload = needle.split("|", 1)[1]  # "role|game" (game may be empty)
		role, _, game = payload.partition("|")
		role = (role or "").strip()
		if role:
			pairs.append((role, (game or "").strip()))
	return pairs


def _match_role_values(user):
	"""Role VALUES the user may see under the match_role fallback.

	A binding role value is visible if it equals one of the user's Frappe roles
	directly, OR a GAM List Option (category "Account Role") maps that value to a
	label the user holds as a Frappe role.
	"""
	frappe_roles = {str(r) for r in frappe.get_roles(user)}
	acceptable = set(frappe_roles)
	try:
		for r in frappe.get_all(
			"GAM List Option",
			{"category": "Account Role"},
			["value", "label"],
		):
			label = (r.get("label") or "").strip()
			value = (r.get("value") or "").strip()
			if value and label and label in frappe_roles:
				acceptable.add(value)
	except Exception:
		pass
	acceptable.discard("")
	return acceptable


def _esc(value):
	return frappe.db.escape(value or "")


def _binding_exists_clause(alias, pairs, role_values):
	"""SQL fragment: TRUE when the row's (role, game) matches the user's grants."""
	parts = []
	if pairs:
		pair_sql = " OR ".join(
			"({a}.role = {r} AND {a}.game = {g})".format(a=alias, r=_esc(role), g=_esc(game))
			for role, game in pairs
		)
		parts.append("(" + pair_sql + ")")
	if role_values:
		in_list = ", ".join(_esc(r) for r in role_values)
		parts.append("{a}.role IN ({l})".format(a=alias, l=in_list))
	if not parts:
		return "1=0"
	return "(" + " OR ".join(parts) + ")"


def _account_clause(user):
	"""SQL WHERE fragment scoping tabGAM Account. "" = no filter (admin / off)."""
	if not _enforce_account_pqc() or _is_admin(user):
		return ""
	pairs = _role_game_pairs(user)
	if pairs:
		inner = _binding_exists_clause("x", pairs, [])
		return (
			"EXISTS (SELECT 1 FROM {b} x "
			"WHERE x.account = {t}.name AND {inner})".format(
				b=_BINDING_TABLE, t=_ACCOUNT_TABLE, inner=inner
			)
		)
	if _get_grant_default_policy() == "match_role":
		role_values = _match_role_values(user)
		if not role_values:
			return "1=0"
		inner = _binding_exists_clause("x", [], role_values)
		return (
			"EXISTS (SELECT 1 FROM {b} x "
			"WHERE x.account = {t}.name AND {inner})".format(
				b=_BINDING_TABLE, t=_ACCOUNT_TABLE, inner=inner
			)
		)
	return "1=0"


def get_pqc_for_gam_account(user=None, doctype="GAM Account"):
	return _account_clause(user or frappe.session.user)


def get_pqc_for_gam_account_role_game(user=None, doctype="GAM Account Role Game"):
	"""Scope the binding table: a binding row is visible iff its own (role, game)
	is one the user may access (mirrors the account scoping logic)."""
	user = user or frappe.session.user
	if not _enforce_account_pqc() or _is_admin(user):
		return ""
	pairs = _role_game_pairs(user)
	if pairs:
		return _binding_exists_clause(_BINDING_TABLE, pairs, [])
	if _get_grant_default_policy() == "match_role":
		role_values = _match_role_values(user)
		if not role_values:
			return "1=0"
		return _binding_exists_clause(_BINDING_TABLE, [], role_values)
	return "1=0"


def has_perm_gam_account(doc, ptype="read", user=None):
	"""``has_permission`` for a single GAM Account document (P1.1)."""
	user = user or frappe.session.user
	if not _enforce_account_pqc() or _is_admin(user):
		return True
	name = getattr(doc, "name", None)
	if not name:
		name = doc if isinstance(doc, str) else None
	if not name:
		return True  # new / unsaved doc — defer to standard perms
	clause = _account_clause(user)
	if not clause:
		return True
	exists = frappe.db.sql(
		"SELECT 1 FROM {t} WHERE {t}.name = %s AND {c} LIMIT 1".format(
			t=_ACCOUNT_TABLE, c=clause
		),
		(name,),
	)
	return bool(exists)
