# Copyright (c) 2026, GAM and contributors
# License: MIT
"""GAM whitelisted API surface consumed by the gam-ui SPA.

Contracts (must match gam-ui/src/composables/* and views/*):
  reveal_password(doctype, name, fieldname, action)        -> {password}
  request_code(email_name, account_name, platform)         -> {status, code, platform, expires_at} | {status:"no_code"}
  checkout_account(account, purpose, lease_minutes, ...)    -> usage doc
  checkin_account(account, end_reason, notes)              -> usage doc
  get_dashboard_stats()                                    -> stats dict
  global_search(query)                                     -> {accounts, emails, games}
  receive_email_webhook()                                  -> allow_guest, X-Webhook-Secret
"""
import hmac
import ipaddress
import re
import socket
from email.utils import parsedate_to_datetime

try:
	from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover - py<3.9
	ZoneInfo = None

import frappe
from frappe import _
from frappe.rate_limiter import rate_limit
from frappe.utils import (
	add_to_date,
	cint,
	convert_utc_to_system_timezone,
	get_system_timezone,
	now_datetime,
)

from gam.realtime import (
	emit_new_code,
	emit_account_changed,
	emit_role_sections_changed,
	emit_renewals_changed,
)

# Password fields that may be revealed. Design §4.4/§6.2.
REVEALABLE_FIELDS = {"account_password", "email_password", "totp_secret"}

# GAM Account.platform -> code platform (matches gam-ui AccountDetailView.codePlatform).
PLATFORM_TO_CODE_PLATFORM = {
	"STEAM": "STEAM",
	"BATTLENET": "BATTLENET",
	"STANDALONE": "POE",
	"EPIC": "EPIC",
	"XBOX": "XBOX",
}


def _get_platform_code_mapping():
	"""Build {platform_value: code_platform} from GAM List Option.

	Falls back to the hardcoded PLATFORM_TO_CODE_PLATFORM mapping for built-in
	platforms and when the table is empty (pre-migration safety). Cached per
	request via frappe.local.flags.
	"""
	if "gam_platform_code_map" in frappe.local.flags:
		return frappe.local.flags.gam_platform_code_map

	mapping = dict(PLATFORM_TO_CODE_PLATFORM)  # baseline (built-in platforms)
	try:
		rows = frappe.db.get_all(
			"GAM List Option",
			filters={"category": "Platform"},
			fields=["value", "code_platform"],
		)
	except Exception:
		rows = []
	for r in rows:
		# An explicit (possibly blank) code_platform from config wins.
		mapping[(r.get("value") or "").strip()] = (r.get("code_platform") or "").strip()

	frappe.local.flags.gam_platform_code_map = mapping
	return mapping


def _platform_to_code_platform(platform_value):
	"""Resolve a GAM Account platform value to its code-platform for code matching.

	Returns "" when no mapping applies (skip platform filtering in _claim_latest_code).
	"""
	if not platform_value:
		return ""
	return _get_platform_code_mapping().get((platform_value or "").strip()) or ""


# ============================================================================
# 1. Reveal password (audit-logged)
# ============================================================================
@frappe.whitelist()
@rate_limit(limit=20, seconds=60)
def reveal_password(doctype, name, fieldname, action="REVEAL"):
	if fieldname not in REVEALABLE_FIELDS:
		frappe.throw(_("Reveal not allowed for field {0}").format(fieldname))

	# L2 access gate (P1.1): the secret lives on a GAM Account (account_password
	# / totp_secret) or a GAM Email (email_password). The doctype+name must
	# resolve to an account/email the session user is granted (admins bypass).
	if doctype == "GAM Email":
		_require_email_access(name)
	else:
		_require_account_access(name)

	# frappe.get_doc enforces read permission by role
	doc = frappe.get_doc(doctype, name)
	# get_password() raises "Password not found" when the doc carries no value
	# (e.g. a GAME node that inherits its credentials from a PLATFORM parent).
	# Treat that as an empty reveal rather than a hard error so the UI can show
	# a graceful "inherited / not set" state instead of an error toast.
	try:
		password = doc.get_password(fieldname) or ""
	except Exception:
		password = ""

	# Only persist an audit row (and risk its fail-closed throw) when there was
	# actually a secret to disclose — logging a no-op reveal would be noise.
	if password:
		_log_reveal(doctype, name, fieldname, action)
	return {"password": password}


def _log_reveal(doctype, name, fieldname, action):
	"""Persist a Reveal-Log audit row.

	Fail-closed (P1.5): a logging failure aborts the request so a secret is
	NEVER disclosed without a surviving audit trail. We commit immediately so
	the audit row survives any later request-teardown rollback; on failure we
	rollback, record via ``frappe.log_error`` for diagnosis, and re-raise so
	the caller does not return the password.
	"""
	request = getattr(frappe.local, "request", None)
	ip = ""
	user_agent = ""
	if request is not None:
		ip = request.headers.get("X-Forwarded-For") or request.remote_addr or ""
		user_agent = (request.headers.get("User-Agent") or "")[:1400]

	try:
		frappe.get_doc(
			{
				"doctype": "GAM Reveal Log",
				"action": action,
				"viewed_by": frappe.session.user,
				"target_doctype": doctype,
				"target_name": name,
				"fieldname": fieldname,
				"ip_address": (ip or "").split(",")[0].strip()[:140],
				"user_agent": user_agent,
				"viewed_at": now_datetime(),
			}
		).insert(ignore_permissions=True)
		frappe.db.commit()
	except Exception:
		frappe.log_error(title="GAM Reveal Log insert failed")
		frappe.db.rollback()
		frappe.throw(
			_("Could not record this action; the secret was not revealed."),
			frappe.ValidationError,
		)


# ============================================================================
# 2. Request verification code (atomic claim)
# ============================================================================
@frappe.whitelist()
@rate_limit(limit=30, seconds=60)
def request_code(email_name=None, account_name=None, platform=None):

	target_email, target_account, resolved_platform = _resolve_request_target(
		email_name, account_name, platform
	)

	# L2 access gate (P1.1): the target account/email must be one the session
	# user is granted (admins bypass).
	if target_account:
		_require_account_access(target_account)
	else:
		_require_email_access(target_email)

	now = now_datetime()
	claimed = _claim_latest_code(target_email, resolved_platform, now)

	if claimed:
		status = "FULFILLED"
		_log_code_request(
			target_email=target_email,
			target_account=target_account,
			platform=claimed["platform"],
			code_value=claimed["code"],
			status=status,
			email_code=claimed["name"],
		)
		return {
			"status": "ok",
			"code": claimed["code"],
			"platform": claimed["platform"],
			"expires_at": claimed["expires_at"],
		}

	_log_code_request(
		target_email=target_email,
		target_account=target_account,
		platform=resolved_platform,
		code_value="",
		status="NO_CODE",
		email_code=None,
	)
	return {"status": "no_code"}


def _resolve_request_target(email_name, account_name, platform):
	target_email = email_name
	target_account = account_name or None
	resolved_platform = platform

	if account_name:
		acc = frappe.db.get_value(
			"GAM Account", account_name, ["email", "platform"], as_dict=True
		)
		if not acc:
			frappe.throw(_("Account {0} not found").format(account_name))
		target_email = acc.email
		if not resolved_platform and acc.platform:
			resolved_platform = _platform_to_code_platform(acc.platform)

	if not target_email:
		frappe.throw(_("Could not resolve a target email for this request."))

	return target_email, target_account, resolved_platform


def _claim_latest_code(target_email, platform, now):
	"""Atomically claim the freshest AVAILABLE code with SELECT ... FOR UPDATE."""
	platform_clause = " AND platform = %(platform)s" if platform else ""
	row = frappe.db.sql(
		f"""
		SELECT name
		FROM `tabGAM Email Code`
		WHERE status = 'AVAILABLE'
		  AND expires_at > %(now)s
		  AND email = %(email)s
		  {platform_clause}
		ORDER BY received_at DESC
		LIMIT 1
		FOR UPDATE
		""",
		{"now": now, "email": target_email, "platform": platform},
		as_dict=True,
	)
	if not row:
		return None

	code_doc = frappe.get_doc("GAM Email Code", row[0].name)
	code_doc.status = "CLAIMED"
	code_doc.claimed_by = frappe.session.user
	code_doc.claimed_at = now
	code_doc.save(ignore_permissions=True)

	return {
		"name": code_doc.name,
		"code": code_doc.code,
		"platform": code_doc.platform,
		"expires_at": code_doc.expires_at,
	}


def _log_code_request(target_email, target_account, platform, code_value, status, email_code):
	"""Persist a Code-Request-Log audit row.

	Fail-closed (P1.5): a logging failure aborts the request so a code is never
	handed out without a surviving audit row. If the insert fails we rollback
	(also undoing the code's CLAIMED transition, leaving it AVAILABLE for a
	retry), record the error, and re-raise."""
	try:
		frappe.get_doc(
			{
				"doctype": "GAM Code Request Log",
				"requested_by": frappe.session.user,
				"email_code": email_code,
				"target_email": target_email,
				"target_account": target_account,
				"platform": platform or "",
				"code_value": code_value or "",
				"status": status,
				"requested_at": now_datetime(),
			}
		).insert(ignore_permissions=True)
		frappe.db.commit()
	except Exception:
		frappe.log_error(title="GAM Code Request Log insert failed")
		frappe.db.rollback()
		frappe.throw(
			_("Could not record this request; no code was returned."),
			frappe.ValidationError,
		)


# ============================================================================
# 3. Checkout / check-in account leases
# ============================================================================
@frappe.whitelist()
def checkout_account(account, purpose="LOGIN", lease_minutes=None, order_ref=None, notes=None):
	"""Start using an account (UI label: "Checkin").

	Creates a GAM Account Usage row (status=IN_USE). ``lease_minutes`` is now
	OPTIONAL: when omitted the lease is open-ended and ``lease_until`` is set to
	``started_at + hard_cap_online_hours`` (from GAM Settings) so the existing
	``_auto_release_expired`` sweep can still reclaim a forgotten lease.
	"""
	# L2 access gate (P1.1): the session user must be granted this account.
	_require_account_access(account)
	# read permission on the account is enforced here
	frappe.get_doc("GAM Account", account)

	now = now_datetime()
	# auto-release any expired lease first
	_auto_release_expired(account, now)

	active = frappe.db.get_value(
		"GAM Account Usage",
		{"account": account, "status": "IN_USE"},
		["name", "used_by"],
		as_dict=True,
	)
	if active:
		if active.used_by != frappe.session.user:
			frappe.throw(_("Account is already checked out by another user."))
		# same user re-checkout: return the existing lease
		return frappe.get_doc("GAM Account Usage", active.name).as_dict()

	# Open-ended lease: cap by hard_cap_online_hours so abandoned leases self-release.
	if lease_minutes:
		lease_until = add_to_date(now, minutes=cint(lease_minutes))
	else:
		hard_cap = cint(_get_settings().get("hard_cap_online_hours")) or 12
		lease_until = add_to_date(now, hours=hard_cap)

	usage = frappe.get_doc(
		{
			"doctype": "GAM Account Usage",
			"account": account,
			"status": "IN_USE",
			"used_by": frappe.session.user,
			"purpose": (purpose or "LOGIN")[:140],
			"order_ref": order_ref or "",
			"started_at": now,
			"lease_until": lease_until,
			"notes": notes or "",
		}
	)
	usage.insert(ignore_permissions=True)
	emit_account_changed(account, "checkin")
	return usage.as_dict()


@frappe.whitelist()
def checkin_account(account, end_reason="DONE", notes=None):
	# L2 access gate (P1.1): the session user must be granted this account.
	_require_account_access(account)
	active = frappe.db.get_value(
		"GAM Account Usage",
		{"account": account, "status": "IN_USE"},
		["name", "used_by"],
		as_dict=True,
	)
	if not active:
		frappe.throw(_("This account is not currently checked out."))

	usage = frappe.get_doc("GAM Account Usage", active.name)
	usage.status = "RELEASED"
	usage.ended_at = now_datetime()
	usage.end_reason = end_reason
	if notes:
		usage.notes = notes
	usage.save(ignore_permissions=True)
	emit_account_changed(account, "checkout")
	return usage.as_dict()


def _auto_release_expired(account, now):
	names = frappe.get_all(
		"GAM Account Usage",
		filters={"account": account, "status": "IN_USE", "lease_until": ["<", now]},
		pluck="name",
	)
	for name in names:
		usage = frappe.get_doc("GAM Account Usage", name)
		usage.status = "FORCE_RELEASED"
		usage.ended_at = now
		usage.end_reason = "TIMEOUT"
		usage.save(ignore_permissions=True)


# ----------------------------------------------------------------------------
# 3b. Usage governance: settings + active leases + force release
# ----------------------------------------------------------------------------
def _get_settings():
	"""Cached GAM Settings singleton as a plain dict (sane defaults if missing)."""
	try:
		doc = frappe.get_cached_doc("GAM Settings", "GAM Settings")
		return {
			"max_online_hours": cint(doc.max_online_hours) or 8,
			"min_rested_hours": cint(doc.min_rested_hours) or 8,
			"hard_cap_online_hours": cint(doc.hard_cap_online_hours) or 12,
			"block_logout_with_active_lease": cint(doc.block_logout_with_active_lease),
			"grant_default_policy": (doc.grant_default_policy or "match_role"),
		}
	except Exception:
		return {
			"max_online_hours": 8,
			"min_rested_hours": 8,
			"hard_cap_online_hours": 12,
			"block_logout_with_active_lease": 1,
			"grant_default_policy": "match_role",
		}


@frappe.whitelist()
def get_gam_settings():
	"""Public GAM thresholds. Needed client-side for badges/timers/warnings.

	Any GAM user may read (values are operational thresholds, not secrets).
	"""
	_require_gam_user()
	return _get_settings()


@frappe.whitelist()
def save_gam_settings(
	max_online_hours=None,
	min_rested_hours=None,
	hard_cap_online_hours=None,
	block_logout_with_active_lease=None,
	grant_default_policy=None,
):
	"""Persist the GAM governance thresholds (singleton). GAM Admin only.

	Hour fields are clamped to sane non-negative bounds so a typo can't brick
	the app (e.g. a 0 hard-cap would auto-release instantly). Returns the
	refreshed settings dict so the client can update its shared cache.
	"""
	_require_gam_admin()

	def _clamp(value, lo, hi, default):
		try:
			n = cint(value)
		except Exception:
			return None
		if not n:
			return None
		return max(lo, min(hi, n))

	doc = frappe.get_doc("GAM Settings", "GAM Settings")
	for field, value, lo, hi, default in (
		("max_online_hours", max_online_hours, 1, 168, 8),
		("min_rested_hours", min_rested_hours, 0, 720, 8),
		("hard_cap_online_hours", hard_cap_online_hours, 1, 168, 12),
	):
		clamped = _clamp(value, lo, hi, default)
		if clamped is not None:
			doc.set(field, clamped)
	if block_logout_with_active_lease is not None and str(block_logout_with_active_lease) != "":
		doc.set("block_logout_with_active_lease", 1 if cint(block_logout_with_active_lease) else 0)
	if grant_default_policy in ("match_role", "none"):
		doc.set("grant_default_policy", grant_default_policy)
	doc.save(ignore_permissions=True)
	frappe.db.commit()
	frappe.clear_cache()
	return _get_settings()


def _naive_system_dt_to_utc_epoch(naive_dt):
	"""True UTC epoch *seconds* for a naive datetime stored in the system tz.

	Frappe persists ``Datetime`` fields as naive wall-clock values in the system
	timezone (System Settings → time_zone). The DB connection, however, often
	runs with ``time_zone = SYSTEM`` on a UTC host, so ``UNIX_TIMESTAMP(col)``
	reads the stored value as if it were UTC — off by the system-tz offset. That
	skew made the active-usage elapsed clock freeze on "0s" (the lease start
	appeared to be ~7h in the future). Localising in Python makes the value
	independent of the DB session timezone, so it matches ``server_epoch_now_ms``
	(which is already a true UTC epoch).
	"""
	if not naive_dt:
		return None
	dt = naive_dt
	if getattr(dt, "tzinfo", None) is not None:  # already aware → just convert
		return dt.timestamp()
	tzname = get_system_timezone()
	try:
		if ZoneInfo is not None:
			dt = dt.replace(tzinfo=ZoneInfo(tzname))
		else:  # pragma: no cover - py<3.9 fallback
			import pytz
			dt = pytz.timezone(tzname).localize(dt)
		return dt.timestamp()
	except Exception:
		return None


def _active_usage_select(extra_where="", params=()):
	"""Shared SELECT for active (IN_USE) leases with account + user resolution.

	Note: ``usage`` is a reserved word in MariaDB — the alias is ``usage_name``.

	``started_at_epoch`` / ``lease_until_epoch`` are TRUE UTC epoch seconds,
	computed in Python (see ``_naive_system_dt_to_utc_epoch``) by interpreting
	the stored naive datetime in the system timezone. We intentionally do NOT
	use SQL ``UNIX_TIMESTAMP(col)`` here: that interprets the naive value in the
	DB *session* timezone, which is UTC on this host while Frappe stored the
	value in Asia/Ho_Chi_Minh — a ~7h skew that froze the client timer on "0s".
	"""
	rows = frappe.db.sql(
		"""
		SELECT u.name AS usage_name, u.account, a.username, a.platform,
		       (SELECT arg.role FROM `tabGAM Account Role Game` arg
		         WHERE arg.account = a.name AND arg.is_main = 1
		         ORDER BY arg.idx LIMIT 1) AS role,
		       u.used_by, u.purpose, u.started_at, u.lease_until,
		       uu.full_name AS used_by_full_name,
		       (SELECT gg.game_name
		          FROM `tabGAM Account Role Game` arg
		          LEFT JOIN `tabGAM Game` gg ON gg.name = arg.game
		         WHERE arg.account = a.name AND arg.is_main = 1
		         ORDER BY arg.idx LIMIT 1) AS main_game
		FROM `tabGAM Account Usage` u
		INNER JOIN `tabGAM Account` a ON a.name = u.account
		LEFT JOIN `tabUser` uu ON uu.name = u.used_by
		WHERE u.status = 'IN_USE' {extra}
		ORDER BY u.started_at DESC
		""".format(extra=extra_where),
		tuple(params),
		as_dict=True,
	)
	# Attach timezone-correct epochs (true UTC seconds) per row.
	for r in rows:
		r["started_at_epoch"] = _naive_system_dt_to_utc_epoch(r.get("started_at"))
		r["lease_until_epoch"] = _naive_system_dt_to_utc_epoch(r.get("lease_until"))
	return rows


def _server_epoch_now_ms():
	"""Current DB-server clock as epoch *milliseconds*.

	The frontend elapsed timer is driven by the DB clock (via
	``started_at_epoch``) so it stays consistent with the server-side
	auto-release sweep. Returning the matching "now" lets the client compute a
	clock offset and never show a bogus "0s" when the DB clock runs ahead of the
	browser clock. ``NOW(6)`` gives sub-second precision (MariaDB/MySQL 5.6+).
	"""
	val = frappe.db.sql("SELECT UNIX_TIMESTAMP(NOW(6))")[0][0]
	return int(round(float(val) * 1000))


def _wrap_active(rows):
	"""Wrap active-usage rows with the server clock so the client timer is
	timezone- and clock-skew-independent. Shape: {server_epoch_now_ms, leases}.
	"""
	return {"server_epoch_now_ms": _server_epoch_now_ms(), "leases": rows or []}


def _resting_usage_select():
	"""Accounts đang "nghỉ" (cooling) sau khi checkout, chưa đủ min_rested_hours.

	Đối xứng với ``_active_usage_select`` nhưng cho trạng thái OFFLINE: lấy bản
	release (RELEASED/FORCE_RELEASED) gần nhất của mỗi account (MAX(ended_at)),
	loại trừ account đang có lease IN_USE, và chỉ trong cửa sổ ``min_rested_hours``
	gần đây. ``ended_at_epoch`` là true-UTC epoch seconds (cùng cơ chế
	``_naive_system_dt_to_utc_epoch``) để FE đếm countdown không lệch clock-skew.
	"""
	settings = _get_settings()
	min_rested_h = cint(settings.get("min_rested_hours")) or 8
	cutoff = add_to_date(now_datetime(), hours=-min_rested_h)
	rows = frappe.db.sql(
		"""
		SELECT u.name AS usage_name, u.account, a.username, a.platform,
		       u.used_by, u.purpose, u.ended_at, u.end_reason,
		       uu.full_name AS used_by_full_name,
		       (SELECT gg.game_name
		          FROM `tabGAM Account Role Game` arg
		          LEFT JOIN `tabGAM Game` gg ON gg.name = arg.game
		         WHERE arg.account = a.name AND arg.is_main = 1
		         ORDER BY arg.idx LIMIT 1) AS main_game
		FROM `tabGAM Account Usage` u
		INNER JOIN `tabGAM Account` a ON a.name = u.account
		LEFT JOIN `tabUser` uu ON uu.name = u.used_by
		WHERE u.status IN ('RELEASED', 'FORCE_RELEASED')
		  AND u.ended_at IS NOT NULL
		  AND u.ended_at >= %(cutoff)s
		  AND NOT EXISTS (
		         SELECT 1 FROM `tabGAM Account Usage` u2
		          WHERE u2.account = u.account AND u2.status = 'IN_USE')
		  AND u.ended_at = (
		         SELECT MAX(ended_at) FROM `tabGAM Account Usage`
		          WHERE account = u.account
		            AND status IN ('RELEASED', 'FORCE_RELEASED'))
		ORDER BY u.ended_at DESC
		""",
		{"cutoff": cutoff},
		as_dict=True,
	)
	for r in rows:
		r["ended_at_epoch"] = _naive_system_dt_to_utc_epoch(r.get("ended_at"))
	return rows


@frappe.whitelist()
def get_active_usage():
	"""All currently-checked-in leases (IN_USE). Aggregate, safe for any GAM user.

	Drives: list dimming (locked-by-other), admin "Đang hoạt động" view + sidebar
	system-wide badge.
	"""
	_require_gam_user()
	return _wrap_active(_active_usage_select())


@frappe.whitelist()
def get_resting_usage():
	"""Accounts đang "nghỉ" (cooling) sau checkout, chưa đủ min_rested_hours.

	Đối xứng ``get_active_usage`` nhưng cho trạng thái OFFLINE. Drives: section
	"Đang nghỉ" với bộ đếm countdown realtime đến khi "Sẵn sàng & an toàn".
	Bao gồm ``min_rested_hours`` để FE tính ``rest_until = ended_at + min*3600``
	mà không phụ thuộc cache settings.
	"""
	_require_gam_user()
	return {
		"server_epoch_now_ms": _server_epoch_now_ms(),
		"min_rested_hours": cint(_get_settings().get("min_rested_hours")) or 8,
		"resting": _resting_usage_select(),
	}


@frappe.whitelist()
def get_my_active_usage():
	"""Leases held by the session user (IN_USE). Drives the "Đang hoạt động" tab +
	sidebar badge for the current user, and the logout guard.
	"""
	_require_gam_user()
	return _wrap_active(_active_usage_select("AND u.used_by = %s", (frappe.session.user,)))


@frappe.whitelist()
def admin_force_release(account, reason=None):
	"""Force-release an active lease (admin / System Manager only). UI label:
	"Force Checkout". Records who held the lease + an optional reason.
	"""
	_require_gam_user()
	roles = set(frappe.get_roles())
	if "GAM Admin" not in roles and "System Manager" not in roles:
		frappe.throw(_("Only GAM Admin or System Manager may force-release a lease."),
		             frappe.PermissionError)

	account = (account or "").strip()
	active = frappe.db.get_value(
		"GAM Account Usage",
		{"account": account, "status": "IN_USE"},
		["name", "used_by"],
		as_dict=True,
	)
	if not active:
		frappe.throw(_("This account is not currently checked in."))

	usage = frappe.get_doc("GAM Account Usage", active.name)
	usage.status = "FORCE_RELEASED"
	usage.ended_at = now_datetime()
	usage.end_reason = "FORCE_RELEASED"

	note_lines = []
	if active.used_by:
		note_lines.append("Force-released from: {0}".format(active.used_by))
	reason = (reason or "").strip()
	if reason:
		note_lines.append("Reason: {0}".format(reason[:280]))
	if note_lines:
		existing = (usage.notes or "").strip()
		usage.notes = (existing + "\n" if existing else "") + "\n".join(note_lines)

	usage.save(ignore_permissions=True)
	frappe.db.commit()
	emit_account_changed(account, "checkout")
	return usage.as_dict()


# ============================================================================
# 4. Dashboard stats
# ============================================================================
@frappe.whitelist()
def get_dashboard_stats():
	_require_gam_user()
	now = now_datetime()
	week_ahead = add_to_date(now, days=7)

	total_accounts = frappe.db.count("GAM Account")
	banned_accounts = frappe.db.count("GAM Account", {"status": "BANNED"})
	total_emails = frappe.db.count("GAM Email", {"is_active": 1})
	available_codes = frappe.db.count(
		"GAM Email Code", {"status": "AVAILABLE", "expires_at": [">", now]}
	)

	expiring = frappe.get_all(
		"GAM Account Link",
		filters={"status": "ACTIVE", "expiry_date": ["between", [now, week_ahead]]},
		fields=["name", "source_account", "target_account", "link_type", "expiry_date"],
		order_by="expiry_date asc",
		limit_page_length=20,
	)
	for link in expiring:
		link["days_left"] = max(
			0, int((link["expiry_date"] - now).total_seconds() // 86400) if link.get("expiry_date") else 0
		)

	return {
		"total_accounts": total_accounts,
		"banned_accounts": banned_accounts,
		"total_emails": total_emails,
		"available_codes": available_codes,
		"expiring_links_count": len(expiring),
		"expiring_links": expiring,
	}


@frappe.whitelist()
def get_account_stats():
	"""Account counts grouped by role / status / platform for dashboards.

	``by_role`` is now sourced from the first-class ``GAM Account Role Game``
	binding table (an account with two roles counts in both), since the account
	no longer carries a single role. ``by_status`` / ``by_platform`` / ``total``
	still come from ``GAM Account`` (identity-level fields).
	"""
	_require_gam_user()
	rows = frappe.db.sql(
		"""
		SELECT IFNULL(status, '') AS status,
		       IFNULL(platform, '') AS platform,
		       COUNT(*) AS count
		FROM `tabGAM Account`
		GROUP BY status, platform
		""",
		as_dict=True,
	)
	by_status = {}
	by_platform = {}
	total = 0
	for r in rows:
		c = cint(r["count"])
		total += c
		by_status[r["status"]] = by_status.get(r["status"], 0) + c
		by_platform[r["platform"]] = by_platform.get(r["platform"], 0) + c

	# by_role: distinct accounts per role, from the binding table.
	role_rows = frappe.db.sql(
		"""
		SELECT arg.role AS role, COUNT(DISTINCT arg.account) AS count
		FROM `tabGAM Account Role Game` arg
		INNER JOIN `tabGAM Account` a ON a.name = arg.account
		WHERE IFNULL(arg.role, '') != ''
		GROUP BY arg.role
		""",
		as_dict=True,
	)
	by_role = {r["role"]: cint(r["count"]) for r in role_rows}

	return {
		"total": total,
		"by_role": by_role,
		"by_status": by_status,
		"by_platform": by_platform,
	}


@frappe.whitelist()
def get_role_game_sections():
	"""Dynamic Trader/Booster/Item section catalog, aggregated from the
	first-class ``GAM Account Role Game`` binding table (single-table query,
	no JOIN to GAM Account).

	Returns: { "<ROLE_VALUE>": [ {game, game_name, count}, ... ], ... }
	Only (role, game) combos with >=1 binding are included. Aggregate-only
	(counts + names) so it is safe to expose to any GAM user.

	The L2 ``ROLE_GAME|role|game`` gate mirrors the permission layer used by
	``get_accounts_list`` — this is what makes a user see exactly the sections
	(and accounts) they were granted.
	"""
	_require_gam_user()
	rows = frappe.db.sql(
		"""
		SELECT arg.role AS role,
		       arg.game AS game,
		       gg.game_name AS game_name,
		       COUNT(DISTINCT arg.account) AS count
		FROM `tabGAM Account Role Game` arg
		INNER JOIN `tabGAM Account` a ON a.name = arg.account
		LEFT JOIN `tabGAM Game` gg ON gg.name = arg.game
		WHERE IFNULL(arg.role, '') != ''
		GROUP BY arg.role, arg.game, gg.game_name
		ORDER BY arg.role, gg.game_name
		""",
		as_dict=True,
	)
	out = {}
	for r in rows:
		# L2 gate: only surface role/game combos the session user may access.
		# Admins bypass (has_access -> True); members see explicit grants or,
		# under the match_role fallback, games whose role matches their Frappe role.
		grant_key = "{0}|{1}".format(r["role"], r["game"])
		if not has_access(frappe.session.user, "GAM", "ROLE_GAME", grant_key):
			continue
		out.setdefault(r["role"], []).append(
			{
				"game": r["game"],
				"game_name": r["game_name"] or r["game"],
				"count": cint(r["count"]),
			}
		)
	return out


@frappe.whitelist()
def get_games_by_role():
	"""Backward-compatible alias for ``get_role_game_sections`` (the sidebar
	composable still calls ``gam.api.get_games_by_role``). Kept until the FE
	fully migrates; delegates to the new single-table aggregate."""
	return get_role_game_sections()


# ============================================================================
# Access Grant (L2 fine-scoping) — app-scoped backbone.
# L1 (app-entry / admin) is Frappe Roles; these methods add the role+game /
# section visibility layer. See plans/active-view-and-access-grant-matrix.md.
# ============================================================================
def _is_access_admin():
	"""True for any role that bypasses grants (sees everything)."""
	caller_roles = set(frappe.get_roles())
	return bool({"GAM Admin", "System Manager", "Administrator"} & caller_roles)


def _require_gam_admin_or_sysmgr():
	"""Guard for grant-management endpoints."""
	if not _is_access_admin():
		frappe.throw(
			_("Only GAM Admin / System Manager can manage access grants."),
			frappe.PermissionError,
		)


def _get_grant_default_policy():
	return _get_settings().get("grant_default_policy", "match_role")


def _user_grant_keys(user, app="GAM"):
	"""Set of 'scope|key' strings currently granted to user for app."""
	if not user:
		return set()
	rows = frappe.db.sql(
		# `key` is a MySQL/MariaDB reserved word — must be backtick-quoted
		# (the API surface only ever hit the admin bypass before, so this
		# latent syntax error went unnoticed until ORM-layer scoping (P1.1)
		# started evaluating real members).
		"SELECT scope, `key` FROM `tabGAM Access Grant` "
		"WHERE user=%s AND app=%s AND granted=1",
		(user, app),
		as_dict=True,
	)
	return {"{0}|{1}".format(r["scope"], r["key"]) for r in rows}


def _frappe_role_matches_role_value(role_value):
	"""match_role fallback: does the user hold a Frappe role whose name matches
	this Account Role value (case-insensitive), directly OR via the GAM List
	Option label? Mirrors the legacy sidebar scoping (AppLayout.roleSections),
	which matched the option LABEL against the user's Frappe roles."""
	role_value = (role_value or "").strip()
	if not role_value:
		return False
	roles = {str(r).lower() for r in frappe.get_roles()}
	if role_value.lower() in roles:
		return True
	try:
		label = frappe.db.get_value(
			"GAM List Option",
			{"category": "Account Role", "value": role_value},
			"label",
		)
	except Exception:
		label = None
	return bool(label and str(label).lower() in roles)


def has_access(user, app, scope, key):
	"""Public L2 check (callable server-side). Admin bypass + default-policy
	fallback. Fallback applies ONLY when the user has zero grants for the app
	(so granting even one item switches them into explicit mode)."""
	if not user:
		return False
	if _is_access_admin():
		return True
	app = (app or "GAM").strip()
	granted = _user_grant_keys(user, app)
	needle = "{0}|{1}".format(scope, key)
	if needle in granted:
		return True
	if not granted and _get_grant_default_policy() == "match_role":
		if scope == "ROLE_GAME":
			role_value = (key or "").split("|", 1)[0]
			if role_value:
				return _frappe_role_matches_role_value(role_value)
		if scope == "SECTION":
			return True
	return False


def _require_access(app, scope, key):
	if not has_access(frappe.session.user, app, scope, key):
		frappe.throw(
			_("You do not have access to {0} {1}.").format(scope, key),
			frappe.PermissionError,
		)


# ---------------------------------------------------------------------------
# L2 account / email access gates (P1.1 — per-document authorization).
#
# ``get_accounts_list`` already enforced the ROLE_GAME grant on the *query*,
# but action / read-by-name endpoints (reveal_password, checkout, activity,
# notes, request_code) could be called directly with an arbitrary doc name and
# bypass the scoped list. These helpers close that gap: a member may only act
# on an account/email whose (role, game) bindings intersect their grants
# (admins bypass; match_role fallback when the user has zero grants).
# ---------------------------------------------------------------------------
def _has_any_role_game_grant(allowed_keys):
	"""True iff the session user may access at least one of ``allowed_keys``
	(a set of ``ROLE_GAME|<role>|<game>`` strings). Mirrors ``has_access`` but
	batched over many keys to avoid one round-trip per binding.

	Admin bypass is evaluated FIRST so an admin can act on an account that has
	no (role, game) bindings yet."""
	if _is_access_admin():
		return True
	if not allowed_keys:
		return False
	user_keys = _user_grant_keys(frappe.session.user)
	if user_keys & allowed_keys:
		return True
	if not user_keys and _get_grant_default_policy() == "match_role":
		# match_role fallback: grant access when the user holds a Frappe role
		# matching any role bound to the account.
		roles = set()
		for k in allowed_keys:
			parts = k.split("|", 2)
			if len(parts) >= 2 and parts[1]:
				roles.add(parts[1])
		for role_value in roles:
			if _frappe_role_matches_role_value(role_value):
				return True
	return False


def _account_grant_keys_for(account_name):
	"""Set of ``ROLE_GAME|<role>|<game>`` grant keys for one account's bindings."""
	rows = frappe.db.sql(
		"""SELECT role, game FROM `tabGAM Account Role Game`
		   WHERE account=%s AND IFNULL(role,'')!=''""",
		(account_name,),
		as_dict=True,
	)
	return {"ROLE_GAME|{0}|{1}".format(r["role"], r["game"]) for r in rows}


def _require_account_access(account_name):
	"""L2 gate: the session user must be granted at least one (role, game)
	binding of this account (admins bypass). Throws PermissionError otherwise."""
	account_name = (account_name or "").strip()
	if not account_name:
		frappe.throw(_("Account is required."), frappe.PermissionError)
	if not frappe.db.exists("GAM Account", account_name):
		frappe.throw(_("Account not found."), frappe.PermissionError)
	if not _has_any_role_game_grant(_account_grant_keys_for(account_name)):
		frappe.throw(
			_("You do not have access to this account."),
			frappe.PermissionError,
		)


def _email_bound_account_grants(email_name):
	"""ROLE_GAME grant keys aggregated from every GAM Account bound to email."""
	keys = set()
	for acc in frappe.get_all("GAM Account", filters={"email": email_name}, pluck="name"):
		keys |= _account_grant_keys_for(acc)
	return keys


def _accessible_email_names():
	"""Set of GAM Email names the session user may see — emails bound to at
	least one account they are granted. Returns ``None`` for admins (no
	restriction). Used to scope list endpoints (codes / inbound logs)."""
	if _is_access_admin():
		return None
	allowed = set()
	rows = frappe.get_all(
		"GAM Account", filters=[["email", "is", "set"]], fields=["name", "email"]
	)
	for a in rows:
		email = (a.get("email") or "").strip()
		if email and _has_any_role_game_grant(_account_grant_keys_for(a["name"])):
			allowed.add(email)
	return allowed


def _normalize_array_filters(filters):
	"""Accept the SPA's array-style filter list (JSON string or Python list) and
	return a plain ``[[field, op, value], ...]`` list (never None)."""
	if isinstance(filters, str):
		filters = frappe.parse_json(filters)
	if not filters:
		return []
	if isinstance(filters, dict):
		return [[k, "=", v] for k, v in filters.items() if v not in (None, "", [])]
	return [list(f) for f in filters]


def _require_email_access(email_name):
	"""L2 gate for a GAM Email: access is derived transitively from any account
	bound to that email. An email with no bound accounts is not accessible to
	members (admins bypass)."""
	email_name = (email_name or "").strip()
	if not email_name:
		frappe.throw(_("Email is required."), frappe.PermissionError)
	if not _has_any_role_game_grant(_email_bound_account_grants(email_name)):
		frappe.throw(
			_("You do not have access to this email."),
			frappe.PermissionError,
		)


@frappe.whitelist()
def get_my_access_grants(app="GAM"):
	"""Granted (scope,key) for the session user + default policy. Drives the
	client sidebar/router visibility (L2)."""
	_require_gam_user()
	app = (app or "GAM").strip()
	grants = frappe.db.get_all(
		"GAM Access Grant",
		filters={"user": frappe.session.user, "app": app, "granted": 1},
		fields=["scope", "key", "value"],
	)
	return {
		"app": app,
		"is_admin": _is_access_admin(),
		"default_policy": _get_grant_default_policy(),
		"grants": [
			{"scope": g["scope"], "key": g["key"], "value": g["value"]} for g in grants
		],
	}


@frappe.whitelist()
def get_access_grants(user=None, app="GAM"):
	"""Admin: all grants for a user (or all) — for the matrix UI."""
	_require_gam_admin_or_sysmgr()
	app = (app or "GAM").strip()
	filters = {"app": app}
	if user:
		filters["user"] = user
	return frappe.db.get_all(
		"GAM Access Grant",
		filters=filters,
		fields=[
			"name", "user", "scope", "key", "value",
			"granted", "granted_by", "granted_on",
		],
		order_by="user, scope, `key`",
	)


@frappe.whitelist()
def save_access_grants(user, app="GAM", grants=None):
	"""Admin: replace a user's grant set for an app (diff-based upsert/delete).

	``grants`` is a JSON/array of {scope, key, value?}. Entries present are
	ensured (granted=1); entries absent are deleted.
	"""
	_require_gam_admin_or_sysmgr()
	if isinstance(grants, str):
		grants = frappe.parse_json(grants)
	user = (user or "").strip()
	app = (app or "GAM").strip()
	if not user:
		frappe.throw(_("user is required"))

	wanted = {}
	for g in (grants or []):
		scope = (g.get("scope") or "").strip()
		key = (g.get("key") or "").strip()
		if not scope or not key:
			continue
		wanted["{0}|{1}".format(scope, key)] = {
			"scope": scope,
			"key": key,
			"value": (g.get("value") or "").strip(),
		}

	existing = frappe.db.get_all(
		"GAM Access Grant",
		filters={"user": user, "app": app},
		fields=["name", "scope", "key", "value", "granted"],
	)
	existing_map = {
		"{0}|{1}".format(e["scope"], e["key"]): e for e in existing
	}

	# delete entries no longer wanted
	for k, e in existing_map.items():
		if k not in wanted:
			frappe.delete_doc("GAM Access Grant", e["name"], ignore_permissions=True)
	# upsert wanted entries
	for k, g in wanted.items():
		ex = existing_map.get(k)
		if ex:
			if cint(ex.get("granted")) != 1 or (ex.get("value") or "") != g["value"]:
				doc = frappe.get_doc("GAM Access Grant", ex["name"])
				doc.value = g["value"]
				doc.granted = 1
				doc.save(ignore_permissions=True)
		else:
			frappe.get_doc(
				{
					"doctype": "GAM Access Grant",
					"user": user,
					"app": app,
					"scope": g["scope"],
					"key": g["key"],
					"value": g["value"],
					"granted": 1,
				}
			).insert(ignore_permissions=True)
	frappe.db.commit()
	return get_access_grants(user=user, app=app)


@frappe.whitelist()
def get_grantable_role_games():
	"""Grantable ROLE_GAME items for the matrix UI: every (role, game) that has
	>=1 account, with the canonical key 'role|game', plus the distinct role list
	(for the grid columns). Admin only."""
	_require_gam_admin_or_sysmgr()
	rows = frappe.db.sql(
		"""
		SELECT arg.role AS role,
		       arg.game AS game,
		       gg.game_name AS game_name,
		       COUNT(DISTINCT arg.account) AS count
		FROM `tabGAM Account Role Game` arg
		LEFT JOIN `tabGAM Game` gg ON gg.name = arg.game
		WHERE IFNULL(arg.role, '') != ''
		GROUP BY arg.role, arg.game, gg.game_name
		ORDER BY arg.role, gg.game_name
		""",
		as_dict=True,
	)
	items = [
		{
			"role": r["role"],
			"game": r["game"],
			"key": "{0}|{1}".format(r["role"], r["game"]),
			"label": "{0} · {1}".format(r["role"], r["game_name"] or r["game"]),
			"count": cint(r["count"]),
		}
		for r in rows
	]
	role_opts = frappe.db.get_all(
		"GAM List Option",
		filters={"category": "Account Role"},
		fields=["value", "label"],
		order_by="sort_order asc",
	)
	return {"roles": role_opts, "items": items}


@frappe.whitelist()
def get_grantable_sections():
	"""Grantable SECTION items (nav sections) for the matrix UI. Admin only."""
	_require_gam_admin_or_sysmgr()
	return [
		{"key": "active", "label": "Đang hoạt động"},
		{"key": "accounts", "label": "Tài khoản (tất cả)"},
		{"key": "emails", "label": "Mã Code"},
	]
@frappe.whitelist()
def get_gam_users():
	"""GAM user pool for the access-grant matrix UI: every enabled user who holds
	at least one of {GAM Member, GAM Admin, System Manager}. Admin only.
	Returns [{name, full_name, email, roles, is_admin}]."""
	_require_gam_admin_or_sysmgr()
	rows = frappe.db.sql(
		"""
		SELECT DISTINCT usr.name, usr.full_name, usr.email
		FROM `tabUser` usr
		INNER JOIN `tabHas Role` hr
		  ON hr.parent = usr.name AND hr.parenttype = 'User'
		WHERE usr.enabled = 1
		  AND usr.name NOT IN ('Guest', 'Administrator')
		  AND hr.role IN ('GAM Member', 'GAM Admin', 'System Manager')
		ORDER BY usr.full_name, usr.name
		""",
		as_dict=True,
	)
	adm_roles = {"GAM Admin", "System Manager", "Administrator"}
	out = []
	for r in rows:
		roles = set(frappe.get_roles(r["name"]) or [])
		out.append(
			{
				"name": r["name"],
				"full_name": r.get("full_name") or r["name"],
				"email": r.get("email") or r["name"],
				"roles": sorted(roles & {"GAM Member", "GAM Admin", "System Manager", "Administrator"}),
				"is_admin": bool(adm_roles & roles),
			}
		)
	return out


@frappe.whitelist()
def get_account_names_for_game(game):
	"""GAM Account names bound to a given game (any role).

	Used by the Accounts view game filter. Raw SQL over the first-class
	``tabGAM Account Role Game`` binding table. Account names are already
	visible to GAM users via the account list, so this is safe to expose.
	"""
	game = (game or "").strip()
	if not game:
		return []
	rows = frappe.db.sql(
		"""
		SELECT DISTINCT arg.account AS name
		FROM `tabGAM Account Role Game` arg
		WHERE arg.game = %s
		""",
		(game,),
		as_dict=False,
	)
	return [r[0] for r in rows] if rows else []


@frappe.whitelist()
def get_accounts_list(filters=None, limit_start=0, limit_page_length=20):
	"""List GAM Accounts (read for any GAM user) with each account's games
	expanded inline (game_name + server name + is_main).

	Replaces the REST ``frappe.client.get_list`` for the Accounts view: get_list
	does NOT return child-table rows, so the account cards could never show the
	assigned games. This endpoint returns the games inline so the redesigned
	account card can display them.

	``filters`` (JSON or object), all optional:
	  platform, role, status -> exact match
	  username               -> LIKE %x%
	  game                   -> restrict to accounts owning this GAM Game
	Returns ``{"data": [...], "total": n}``.
	"""
	_require_gam_user()
	if isinstance(filters, str):
		filters = frappe.parse_json(filters)
	filters = filters or {}

	# L2 access gate: a role/game-scoped query requires the matching ROLE_GAME
	# grant (admins bypass; match_role fallback for users with no grants yet).
	# Returns empty rather than throwing — the FE sidebar only links to allowed
	# combos; this is the defense-in-depth server guard against crafted URLs.
	_role_filter = (filters.get("role") or "").strip()
	_game_filter = (filters.get("game") or "").strip()
	if _role_filter or _game_filter:
		_grant_key = "{0}|{1}".format(_role_filter, _game_filter)
		if not has_access(frappe.session.user, "GAM", "ROLE_GAME", _grant_key):
			return {"data": [], "total": 0}

	cond = ["1=1"]
	vals = []
	# ---- Hierarchy / billing filters (plan §2.2) ------------------------
	# Default to GAME nodes so the member-facing account list keeps showing
	# the operational entities; callers (admin views) pass account_level
	# explicitly. Use the literal "ALL" to opt out of the level filter.
	_account_level = (filters.get("account_level") or "").strip().upper()
	if _account_level and _account_level != "ALL":
		cond.append("a.account_level = %s")
		vals.append(_account_level)
	else:
		cond.append("a.account_level = %s")
		vals.append("GAME")
	if filters.get("parent_account"):
		cond.append("a.parent_account = %s")
		vals.append(filters["parent_account"])
	if filters.get("billing_type"):
		cond.append("a.billing_type = %s")
		vals.append(filters["billing_type"])
	if filters.get("renewal_due"):
		# billing_type != ONE_TIME and active_until within renewal lead window.
		cond.append(
			"a.billing_type != 'ONE_TIME' "
			"AND a.active_until IS NOT NULL "
			"AND a.active_until <= DATE_ADD(NOW(), INTERVAL IFNULL(a.renewal_lead_days,3) DAY)"
		)
	if filters.get("platform"):
		cond.append("a.platform = %s")
		vals.append(filters["platform"])
	if filters.get("status"):
		cond.append("a.status = %s")
		vals.append(filters["status"])
	term = (filters.get("username") or "").strip()
	if term:
		cond.append("a.username LIKE %s")
		vals.append("%" + term + "%")

	limit_start = cint(limit_start)
	limit_page_length = cint(limit_page_length) or 20

	role = (filters.get("role") or "").strip()
	game = (filters.get("game") or "").strip()
	if role and game:
		cond.append(
			"EXISTS (SELECT 1 FROM `tabGAM Account Role Game` x "
			"WHERE x.account = a.name AND x.role = %s AND x.game = %s)"
		)
		vals.extend([role, game])
	elif role:
		cond.append(
			"EXISTS (SELECT 1 FROM `tabGAM Account Role Game` x "
			"WHERE x.account = a.name AND x.role = %s)"
		)
		vals.append(role)
	elif game:
		cond.append(
			"EXISTS (SELECT 1 FROM `tabGAM Account Role Game` x "
			"WHERE x.account = a.name AND x.game = %s)"
		)
		vals.append(game)

	where = " AND ".join(cond)

	accounts = frappe.db.sql(
		"""
		SELECT a.name AS name, a.platform, a.username, a.email, a.source,
		       a.status, a.account_level, a.parent_account, a.standalone,
		       a.billing_type, a.active_until, a.renewal_lead_days,
		       a.auto_renew
		FROM `tabGAM Account` a
		WHERE {where}
		ORDER BY a.modified DESC
		LIMIT %s, %s
		""".format(where=where),
		tuple(vals) + (limit_start, limit_page_length),
		as_dict=True,
	)
	total = frappe.db.sql(
		"SELECT COUNT(*) FROM `tabGAM Account` a WHERE {where}".format(where=where),
		tuple(vals),
	)[0][0]

	names = [a["name"] for a in accounts]
	if accounts:
		game_rows = frappe.db.sql(
			"""
			SELECT arg.account AS account, arg.role AS role,
			       arg.game AS game, gg.game_name AS game_name,
			       arg.server AS server, gs.server_name AS server_name,
			       arg.is_main AS is_main
			FROM `tabGAM Account Role Game` arg
			LEFT JOIN `tabGAM Game` gg ON gg.name = arg.game
			LEFT JOIN `tabGAM Game Server` gs ON gs.name = arg.server
			WHERE arg.account IN %s
			ORDER BY arg.account, arg.idx
			""",
			(names,),
			as_dict=True,
		)
		by_account = {}
		for gr in game_rows:
			by_account.setdefault(gr["account"], []).append({
				"role": gr["role"],
				"game": gr["game"],
				"game_name": gr["game_name"] or gr["game"],
				"server": gr["server"],
				"server_name": gr["server_name"],
				"is_main": cint(gr["is_main"]),
			})
		for a in accounts:
			# `games` is kept for UI back-compat; `role_games` is the new shape.
			a["games"] = by_account.get(a["name"], [])
			a["role_games"] = a["games"]

	# --- usage governance: rested status + active-lease lock info -----------
	settings = _get_settings()
	min_rested = cint(settings.get("min_rested_hours")) or 8
	now = now_datetime()
	last_rel = {}
	active_map = {}
	if names:
		for r in frappe.db.sql(
			"""
			SELECT account, MAX(ended_at) AS last_ended
			FROM `tabGAM Account Usage`
			WHERE status IN ('RELEASED', 'FORCE_RELEASED') AND account IN %s
			GROUP BY account
			""",
			(names,), as_dict=True,
		):
			last_rel[r["account"]] = r["last_ended"]
		for u in _active_usage_select(
			"AND u.account IN %s", (tuple(names),),
		):
			active_map[u["account"]] = u
	for a in accounts:
		lease = active_map.get(a["name"])
		a["active_used_by"] = None
		a["active_used_by_full_name"] = None
		a["active_purpose"] = None
		a["active_started_at"] = None
		a["rested_hours"] = 0.0
		a["is_rested_enough"] = 0
		if lease:
			a["active_used_by"] = lease.get("used_by")
			a["active_used_by_full_name"] = lease.get("used_by_full_name")
			a["active_purpose"] = lease.get("purpose")
			started = lease.get("started_at")
			a["active_started_at"] = str(started) if started else None
			continue
		last = last_rel.get(a["name"])
		rested_h = 0.0
		if last:
			try:
				rested_h = round(max(0.0, (now - last).total_seconds() / 3600.0), 1)
			except Exception:
				rested_h = 0.0
		a["rested_hours"] = rested_h
		a["is_rested_enough"] = 1 if rested_h >= min_rested else 0

	return {"data": accounts, "total": cint(total)}


@frappe.whitelist()
def get_account_role_games(account):
	"""Return one account's (role, game) bindings with game name, server name
	and DLCs expanded.

	The detail view used to read the legacy ``GAM Account Game`` child table via
	``frappe.client.get``; now that role lives on the first-class binding, this
	is the single endpoint that rebuilds that Games section (with DLCs) for one
	account. Safe for any GAM user (read-only).
	"""
	_require_gam_user()
	_require_account_access(account)
	if not account or not frappe.db.exists("GAM Account", account):
		return []
	rows = frappe.db.sql(
		"""
		SELECT arg.name AS name, arg.role AS role, arg.game AS game,
		       arg.server AS server, arg.is_main AS is_main,
		       arg.purchased_at AS purchased_at, arg.notes AS notes,
		       gg.game_name AS game_name, gs.server_name AS server_name
		FROM `tabGAM Account Role Game` arg
		LEFT JOIN `tabGAM Game` gg ON gg.name = arg.game
		LEFT JOIN `tabGAM Game Server` gs ON gs.name = arg.server
		WHERE arg.account = %s
		ORDER BY arg.is_main DESC, arg.idx ASC
		""",
		(account,),
		as_dict=True,
	)
	names = [r["name"] for r in rows]
	dlc_by_parent = {}
	if names:
		for d in frappe.db.get_all(
			"GAM Account Game DLC",
			filters={"parent": ["in", names]},
			fields=["parent", "dlc"],
		):
			dlc_by_parent.setdefault(d["parent"], []).append({"dlc": d["dlc"]})
	for r in rows:
		r["is_main"] = cint(r["is_main"])
		r["game_name"] = r["game_name"] or r["game"]
		r["dlcs"] = dlc_by_parent.get(r["name"], [])
	return rows


@frappe.whitelist()
def resolve_doc_names(mappings):
	"""Batch-resolve human-readable labels for GAM doc-name IDs (Req #2/#3).

	Used by the log views (Reveal Log, Code Request Log, Account Usage) to turn
	raw doc names (e.g. ``k8c0p9vgvh``) into friendly labels (account username,
	email address) with the account's main game for context.

	``mappings`` (JSON or dict): ``{"GAM Account": ["id1", ...], "GAM Email": ["id2"]}``.
	Returns ``{"GAM Account": {id: {"label","platform","main_game_name"}},
	           "GAM Email": {id: {"label"}}}``.
	Names that no longer exist are simply omitted.
	"""
	_require_gam_user()
	if isinstance(mappings, str):
		mappings = frappe.parse_json(mappings)
	mappings = mappings or {}
	result = {}

	acc_names = [n for n in (mappings.get("GAM Account") or []) if n]
	if acc_names:
		rows = frappe.db.sql(
			"""
			SELECT a.name, a.username, a.platform,
			       (SELECT gg.game_name
			        FROM `tabGAM Account Role Game` arg
			        JOIN `tabGAM Game` gg ON gg.name = arg.game
			        WHERE arg.account = a.name
			        ORDER BY arg.is_main DESC, arg.idx LIMIT 1) AS main_game_name
			FROM `tabGAM Account` a
			WHERE a.name IN %s
			""",
			(acc_names,),
			as_dict=True,
		)
		result["GAM Account"] = {
			r["name"]: {
				"label": r["username"] or r["name"],
				"platform": r["platform"] or "",
				"main_game_name": r["main_game_name"] or "",
			}
			for r in rows
		}

	email_names = [n for n in (mappings.get("GAM Email") or []) if n]
	if email_names:
		rows = frappe.db.sql(
			"SELECT name, address FROM `tabGAM Email` WHERE name IN %s",
			(email_names,),
			as_dict=True,
		)
		result["GAM Email"] = {r["name"]: {"label": r["address"] or r["name"]} for r in rows}

	return result


@frappe.whitelist()
def get_account_activity(account, limit=50):
	"""Unified activity timeline for a GAM Account (Req #4.1).

	Merges three event sources newest-first: Account Usage (lease lifecycle),
	Code Request Log, and Reveal Log — all scoped to ``account``.

	Returns ``{"data": [...], "total": n}``.  Each row is normalised to
	``{type, timestamp, end_timestamp, user, title, detail, status, name}``.
	"""
	_require_gam_user()
	account = (account or "").strip()
	if not account:
		return {"data": [], "total": 0}
	_require_account_access(account)
	limit = cint(limit) or 50
	events = []

	# 1. Usage (checkout / check-in lease lifecycle)
	for r in frappe.db.sql(
		"""
		SELECT name, status, used_by, purpose, order_ref,
		       started_at, lease_until, ended_at, end_reason
		FROM `tabGAM Account Usage`
		WHERE account = %s
		ORDER BY started_at DESC LIMIT %s
		""",
		(account, limit),
		as_dict=True,
	):
		if r["status"] == "IN_USE":
			title = "Mượn tài khoản"
		elif r["status"] == "FORCE_RELEASED":
			title = "Buông ép"
		else:
			title = "Trả tài khoản"
		detail = r["purpose"] or ""
		if r["order_ref"]:
			detail = (detail + " · #" if detail else "#") + str(r["order_ref"])
		events.append({
			"type": "usage",
			"timestamp": str(r["started_at"]) if r["started_at"] else "",
			"end_timestamp": str(r["ended_at"]) if r["ended_at"] else "",
			"user": r["used_by"] or "",
			"title": title,
			"detail": detail,
			"status": r["status"] or "",
			"name": r["name"],
		})

	# 2. Code Request Log
	for r in frappe.db.sql(
		"""
		SELECT name, requested_by, platform, code_value, status, requested_at
		FROM `tabGAM Code Request Log`
		WHERE target_account = %s
		ORDER BY requested_at DESC LIMIT %s
		""",
		(account, limit),
		as_dict=True,
	):
		detail = r["platform"] or ""
		if r["code_value"]:
			detail = (detail + " · " if detail else "") + str(r["code_value"])
		events.append({
			"type": "code_request",
			"timestamp": str(r["requested_at"]) if r["requested_at"] else "",
			"end_timestamp": "",
			"user": r["requested_by"] or "",
			"title": "Yêu cầu mã",
			"detail": detail,
			"status": r["status"] or "",
			"name": r["name"],
		})

	# 3. Reveal Log
	for r in frappe.db.sql(
		"""
		SELECT name, action, viewed_by, fieldname, viewed_at
		FROM `tabGAM Reveal Log`
		WHERE target_doctype = 'GAM Account' AND target_name = %s
		ORDER BY viewed_at DESC LIMIT %s
		""",
		(account, limit),
		as_dict=True,
	):
		events.append({
			"type": "reveal",
			"timestamp": str(r["viewed_at"]) if r["viewed_at"] else "",
			"end_timestamp": "",
			"user": r["viewed_by"] or "",
			"title": "Xem mật khẩu" if r["action"] != "COPY" else "Copy mật khẩu",
			"detail": r["fieldname"] or "",
			"status": r["action"] or "",
			"name": r["name"],
		})

	events.sort(key=lambda e: e["timestamp"] or "", reverse=True)
	events = events[:limit]
	return {"data": events, "total": len(events)}


@frappe.whitelist()
def get_account_notes(account, limit=100):
	"""Collaborative notes for a GAM Account (Req #4.3), newest first."""
	_require_gam_user()
	account = (account or "").strip()
	if not account:
		return []
	_require_account_access(account)
	return frappe.db.sql(
		"""
		SELECT name, note_by, content, created_at
		FROM `tabGAM Account Note`
		WHERE account = %s
		ORDER BY created_at DESC
		LIMIT %s
		""",
		(account, cint(limit) or 100),
		as_dict=True,
	)


@frappe.whitelist()
def add_account_note(account, content):
	"""Append a collaborative note to a GAM Account (Req #4.3).

	Any GAM user may post; ``note_by`` is pinned to the session user.
	"""
	_require_gam_user()
	account = (account or "").strip()
	_require_account_access(account)
	content = (content or "").strip()
	if not account:
		frappe.throw(_("Account is required."))
	if not content:
		frappe.throw(_("Note content cannot be empty."))
	doc = frappe.get_doc(
		{
			"doctype": "GAM Account Note",
			"account": account,
			"note_by": frappe.session.user,
			"content": content,
			"created_at": now_datetime(),
		}
	)
	doc.insert(ignore_permissions=True)
	frappe.db.commit()
	emit_account_changed(account, "note")
	return {
		"name": doc.name,
		"note_by": doc.note_by,
		"content": doc.content,
		"created_at": str(doc.created_at),
	}


@frappe.whitelist()
def delete_account_note(name):
	"""Delete a note.  Only the author or a GAM Admin may delete (Req #4.3)."""
	_require_gam_user()
	name = (name or "").strip()
	if not name:
		frappe.throw(_("Note name is required."))
	author = frappe.db.get_value("GAM Account Note", name, "note_by")
	if not author:
		frappe.throw(_("Note not found."))
	# L2 access gate (P1.1): the note's account must be one the session user is
	# granted before allowing deletion.
	note_account = frappe.db.get_value("GAM Account Note", name, "account")
	if note_account:
		_require_account_access(note_account)
	if author != frappe.session.user and "GAM Admin" not in frappe.get_roles():
		frappe.throw(_("You can only delete your own notes."))
	frappe.delete_doc("GAM Account Note", name, ignore_permissions=True)
	frappe.db.commit()
	return {"deleted": True}


# ============================================================================
# 5. Global search
@frappe.whitelist()
def get_email_codes(filters=None, limit_start=0, limit_page_length=20, order_by=None):
	"""Whitelist (L2-scoped) list of GAM Email Codes.

	Admins see every code; members only see codes whose owning email is bound
	to at least one account they are granted. Replaces the direct REST
	``frappe.client.get_list``/``get_count`` used by the Codes view so the
	secret-bearing docs are never reachable via raw REST by a scoped member.

	``filters``: JSON array of ``[field, op, value]`` (e.g. ``["platform","=","STEAM"]``).
	Returns ``{"data": [...], "total": n}``.
	"""
	_require_gam_user()
	filters = _normalize_array_filters(filters)
	accessible = _accessible_email_names()
	if accessible is not None:
		if not accessible:
			return {"data": [], "total": 0}
		filters.append(["email", "in", list(accessible)])
	fields = [
		"name", "platform", "code", "status", "email", "email_address",
		"email_from", "email_subject", "received_at", "expires_at", "claimed_by",
	]
	data = frappe.get_all(
		"GAM Email Code",
		filters=filters or None,
		fields=fields,
		order_by=order_by or "received_at desc",
		limit_start=cint(limit_start),
		limit_page_length=cint(limit_page_length) or 20,
	)
	total = frappe.db.count("GAM Email Code", filters=filters or None)
	return {"data": data, "total": cint(total)}


@frappe.whitelist()
def get_email_inbound_logs(filters=None, limit_start=0, limit_page_length=20, order_by=None):
	"""Whitelist (L2-scoped) list of GAM Email Inbound Logs.

	Admins see every log; members only see logs attached to a ``gam_email``
	they can access (unrecognized / unmatched logs are admin-only diagnostic
	data). Replaces the direct REST ``frappe.client.get_list``/``get_count``
	used by the Inbound Log view.

	``filters``: JSON array of ``[field, op, value]``.
	Returns ``{"data": [...], "total": n}``.
	"""
	_require_gam_user()
	filters = _normalize_array_filters(filters)
	accessible = _accessible_email_names()
	if accessible is not None:
		if not accessible:
			return {"data": [], "total": 0}
		filters.append(["gam_email", "in", list(accessible)])
	fields = [
		"name", "email_account", "gam_email", "email_from", "email_subject",
		"message_id", "received_at", "fetched_at", "status", "matched_platform",
		"matched_pattern", "email_code", "raw_snippet", "error_message",
		"detected_platform",
	]
	data = frappe.get_all(
		"GAM Email Inbound Log",
		filters=filters or None,
		fields=fields,
		order_by=order_by or "received_at desc",
		limit_start=cint(limit_start),
		limit_page_length=cint(limit_page_length) or 20,
	)
	total = frappe.db.count("GAM Email Inbound Log", filters=filters or None)
	return {"data": data, "total": cint(total)}


# ============================================================================
@frappe.whitelist()
def global_search(query):
	_require_gam_user()
	q = (query or "").strip()
	if len(q) < 2:
		return {"accounts": [], "emails": [], "games": []}
	like = f"%{q}%"

	accounts = frappe.get_all(
		"GAM Account",
		filters=[["username", "like", like]],
		fields=["name", "platform", "username", "email", "status"],
		limit_page_length=10,
	)
	# L2 gate (P1.2): members only see accounts (and their bound emails) they
	# are granted. Admins see everything.
	access_email_names = set()
	if not _is_access_admin():
		accounts = [
			a for a in accounts
			if _has_any_role_game_grant(_account_grant_keys_for(a["name"]))
		]
		access_email_names = {a.get("email") for a in accounts if a.get("email")}

	# resolve email link -> address for nicer display
	email_names = list({a["email"] for a in accounts if a.get("email")})
	email_map = {}
	if email_names:
		for em in frappe.get_all(
			"GAM Email", filters=[["name", "in", email_names]], fields=["name", "address"]
		):
			email_map[em.name] = em.address
	for a in accounts:
		a["email"] = email_map.get(a.get("email"), a.get("email"))

	# Emails search: admins see all matches; members only emails bound to an
	# accessible account.
	if _is_access_admin():
		emails = frappe.get_all(
			"GAM Email",
			filters=[["address", "like", like]],
			fields=["name", "address", "provider"],
			limit_page_length=10,
		)
	elif access_email_names:
		emails = frappe.get_all(
			"GAM Email",
			filters=[["name", "in", list(access_email_names)], ["address", "like", like]],
			fields=["name", "address", "provider"],
			limit_page_length=10,
		)
	else:
		emails = []
	# Games are a shared global catalog (names only) — safe for any GAM user.
	games = frappe.get_all(
		"GAM Game",
		filters=[["game_name", "like", like]],
		fields=["name", "game_name", "publisher"],
		limit_page_length=10,
	)

	return {"accounts": accounts, "emails": emails, "games": games}


# ============================================================================
# 6. Receive email webhook (Cloudflare Email Worker)
# ============================================================================
@frappe.whitelist(allow_guest=True)
def receive_email_webhook():
	"""Inbound endpoint for the Cloudflare Email Worker.

	The Worker POSTs JSON: { email_account, from, subject, body, html,
	message_id, received_at, raw }. Authenticated via X-Webhook-Secret.
	"""
	_verify_webhook_secret()
	data = _webhook_payload()
	return _ingest_email_payload(data)


def _ingest_email_payload(data):
	"""Shared ingestion for a single webhook payload dict.

	Called by :func:`receive_email_webhook` (after secret check) and by
	:func:`drain_email_dlq` (admin re-submit of 5xx dead-lettered messages).
	Idempotent: de-duplicated by ``message_id`` and exact-code-within-TTL.
	"""
	email_account = (data.get("email_account") or "").strip().lower()
	sender = (data.get("from") or data.get("sender") or "").strip()
	subject = data.get("subject") or ""
	html = data.get("html") or ""
	body = data.get("body") or data.get("text") or html or ""
	message_id = data.get("message_id") or ""
	raw = (data.get("raw") or "")[:5000]
	received_at = _parse_received_at(data.get("received_at")) or now_datetime()

	inbound = frappe.new_doc("GAM Email Inbound Log")
	inbound.email_account = email_account
	inbound.email_from = sender[:140]
	inbound.email_subject = subject[:140]
	inbound.message_id = message_id[:140]
	inbound.received_at = received_at
	inbound.fetched_at = now_datetime()
	inbound.raw_snippet = raw
	# Persist the full content for inspection + future code-extraction tuning.
	inbound.email_body = (body or "")[:50000]
	inbound.email_html = (html or "")[:262144]
	# Detect the account-system platform from sender/subject — independent of
	# whether a code extracts, so NO_MATCH emails still get tagged for triage.
	inbound.detected_platform = _detect_platform(sender, subject, body)

	original_to = (data.get("original_to") or "").strip()
	inbound.original_to = original_to[:140]
	# Forwarded-email owner resolution (Design §7.3).  For forwards the
	# ``email_account`` (to) is the destination inbox, not the owner — so we
	# walk a priority chain to find the real GAM Email.
	gam_email_name, resolved_via = _resolve_gam_email(email_account, sender, original_to, body)
	inbound.gam_email = gam_email_name
	inbound.resolved_via = resolved_via

	# de-dup by message id
	if message_id and frappe.db.exists("GAM Email Inbound Log", {"message_id": message_id}):
		inbound.status = "DUPLICATE"
		inbound.insert(ignore_permissions=True)
		_update_webhook_status("OK")
		return {"status": "duplicate"}

	pattern = _match_pattern(sender, subject, body)
	if not pattern:
		inbound.status = "NO_MATCH"
		inbound.insert(ignore_permissions=True)
		_update_webhook_status("OK")
		return {"status": "no_match"}

	code = pattern["extracted"]
	ttl = cint(pattern.ttl_minutes) or 15
	expires_at = add_to_date(received_at, minutes=ttl)

	# de-dup exact code for this email within its TTL window
	if (
		inbound.gam_email
		and frappe.db.exists(
			"GAM Email Code",
			{"email": inbound.gam_email, "code": code, "expires_at": [">", received_at]},
		)
	):
		inbound.status = "DUPLICATE"
		inbound.matched_platform = pattern.platform
		inbound.matched_pattern = pattern.name
		inbound.insert(ignore_permissions=True)
		_update_webhook_status("OK")
		return {"status": "duplicate"}

	code_doc = frappe.new_doc("GAM Email Code")
	code_doc.email = inbound.gam_email
	code_doc.email_address = email_account
	code_doc.platform = pattern.platform
	code_doc.code = code
	code_doc.email_subject = subject[:140]
	code_doc.email_from = sender[:140]
	code_doc.received_at = received_at
	code_doc.fetched_at = now_datetime()
	code_doc.expires_at = expires_at
	code_doc.status = "AVAILABLE"
	code_doc.raw_snippet = raw
	code_doc.source_uid = message_id[:140]
	code_doc.insert(ignore_permissions=True)

	inbound.status = "OK"
	inbound.matched_platform = pattern.platform
	inbound.matched_pattern = pattern.name
	inbound.email_code = code_doc.name
	inbound.insert(ignore_permissions=True)

	_update_webhook_status("OK")
	emit_new_code(pattern.platform, code_doc.name)
	return {"status": "ok", "name": code_doc.name}


@frappe.whitelist()
def drain_email_dlq():
	"""Admin-only re-ingest of dead-lettered payloads (Phase 4.2).

	The Cloudflare Email Worker buffers transient failures (webhook HTTP >= 500)
	into a KV namespace ``GAM_DLQ`` instead of permanently bouncing them. The
	worker's ``fetch()`` handler re-posts those payloads here on demand. This
	endpoint loops over the submitted payloads and re-runs ingestion; the
	shared :func:`_ingest_email_payload` is idempotent (de-dup by message_id),
	so re-draining is safe.
	"""
	_require_gam_admin_or_sysmgr()
	data = _webhook_payload()
	payloads = data.get("payloads") if isinstance(data, dict) else None
	if not payloads and isinstance(data, dict) and data.get("email_account"):
		# Single payload submitted directly.
		payloads = [data]
	if not isinstance(payloads, list):
		frappe.throw(_("payloads must be a JSON array of webhook payloads"))

	results = []
	for item in payloads:
		if not isinstance(item, dict):
			results.append({"status": "skipped", "reason": "not_an_object"})
			continue
		try:
			results.append({"message_id": item.get("message_id"), **_ingest_email_payload(item)})
		except Exception as exc:  # noqa: PEP8 — keep draining the rest
			frappe.logger("gam").exception("drain_email_dlq payload failed")
			results.append({"message_id": item.get("message_id"), "status": "error", "error": str(exc)})
	return {"drained": len([r for r in results if r.get("status") not in ("error", "skipped")]), "results": results}


def _webhook_payload():
	request = getattr(frappe.local, "request", None)
	if request is None:
		return frappe.form_dict or {}
	if request.method == "POST":
		try:
			payload = request.get_json(silent=True)
			if payload:
				return payload
		except Exception:
			pass
		return request.form or frappe.form_dict or {}
	return frappe.form_dict or {}


def _verify_webhook_secret():
	"""Verify X-Webhook-Secret against the GAM Webhook Config singleton (§6.5)."""
	config = frappe.get_doc("GAM Webhook Config", "GAM Webhook Config")
	if not cint(config.is_active):
		frappe.throw(_("Webhook endpoint is disabled."), frappe.PermissionError)

	expected = config.get_password("webhook_secret") or ""
	if not expected:
		frappe.throw(_("Webhook secret is not configured. Set it in GAM Webhook Config."), frappe.PermissionError)

	request = getattr(frappe.local, "request", None)
	provided = request.headers.get("X-Webhook-Secret") if request is not None else ""
	# Constant-time compare to avoid timing side-channels (P1.3).
	if not provided or not hmac.compare_digest(str(provided), str(expected)):
		frappe.throw(_("Invalid webhook secret."), frappe.PermissionError)


@frappe.whitelist()
def reveal_webhook_secret():
	"""Return the webhook secret plaintext (admin-only, audit-logged).

	The setup state never ships the secret in the boot payload (P1.3); the admin
	must explicitly reveal it here so every plaintext disclosure is recorded in
	the GAM Reveal Log, mirroring the account/email password reveal flow.
	"""
	_require_gam_admin()
	cfg = frappe.get_doc("GAM Webhook Config", "GAM Webhook Config")
	secret = cfg.get_password("webhook_secret") or ""
	# action stays "REVEAL" (the GAM Reveal Log Select only allows
	# REVEAL/COPY); the disclosure target is recorded via fieldname +
	# target_doctype, mirroring reveal_password.
	_log_reveal(
		"GAM Webhook Config",
		"GAM Webhook Config",
		"webhook_secret",
		"REVEAL",
	)
	return {
		"webhook_secret": secret,
		"webhook_secret_set": bool(secret) and set(secret) != {"*"},
	}


def _parse_received_at(raw):
	"""Parse the worker-supplied receipt timestamp into a naive *system-local* datetime.

	The Cloudflare Email Worker sends ``received_at`` in UTC (RFC-2822 / ISO
	with an offset). Every expiry check — :func:`_claim_latest_code`, the
	``expire_email_codes`` scheduler, and the dashboard "available codes" count
	— compares ``expires_at`` against :func:`now_datetime`, which is in the
	Frappe **system** timezone (``System Settings > Time Zone``), **not** the OS
	timezone.

	``parsedate_to_datetime(...).astimezone()`` converts using the *OS*
	timezone, so when the host runs in UTC but the site is configured for
	another zone (e.g. ``Asia/Ho_Chi_Minh`` = UTC+7) the stored value silently
	stays in UTC while every comparison uses local time — every real-webhook
	code then looks already-expired by the full UTC offset (so it appears
	"unavailable" within ~1 second of arrival). Convert explicitly to the
	system timezone so the stored value matches :func:`now_datetime`.
	"""
	if not raw:
		return None
	try:
		aware = parsedate_to_datetime(str(raw))
		return convert_utc_to_system_timezone(aware).replace(tzinfo=None)
	except Exception:
		try:
			dt = frappe.utils.get_datetime(raw)
			if getattr(dt, "tzinfo", None) is not None:
				return convert_utc_to_system_timezone(dt).replace(tzinfo=None)
			return dt
		except Exception:
			return None


def _extract_email_address(raw):
	"""Extract the first bare email address from a 'Name <email>' or plain string."""
	if not raw:
		return ""
	# Prefer the angle-bracket form  Name <user@domain>
	m = re.search(r"<([^<>@\s]+@[^<>@\s]+)>", raw)
	if m:
		return m.group(1).strip().lower()
	m = re.search(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", raw)
	if m:
		return m.group(0).strip().lower()
	return ""


def _resolve_gam_email(email_account, sender, original_to="", body=""):
	"""Resolve the owning GAM Email record for an inbound message.

	For forwarded emails the ``email_account`` (to) field is the forward
	destination, not the original owner.  We try a priority chain:

	1. ``original_to`` — header extracted by the Worker (X-Gm-Original-To /
		  Delivered-To / Received ``for<>``).
	2. ``email_account`` — the to address (direct, non-forwarded emails).
	3. ``sender`` (from) — the forwarder; for manual forwards the forwarder
		  IS the owner (e.g. TrishPavlica322 forwards to the inbox).
	4. Body ``To:`` header line — last-resort for forwarded bodies.

	Returns ``(gam_email_name, resolved_via)`` or ``(None, None)``.
	"""
	candidates = [
		("original_to", _extract_email_address(original_to)),
		("email_account", _extract_email_address(email_account)),
		("sender", _extract_email_address(sender)),
	]
	for label, addr in candidates:
		if not addr:
			continue
		name = frappe.db.get_value("GAM Email", {"address": addr})
		if name:
			return name, label

	# Last resort: parse the forwarded "To:" header line from the body.
	if body:
		m = re.search(r"(?:^|\n)\s*To:\s*(.+)", body, re.I)
		if m:
			addr = _extract_email_address(m.group(1))
			if addr:
				name = frappe.db.get_value("GAM Email", {"address": addr})
				if name:
					return name, "body_to"

	return None, None


def _extract_forwarded_senders(text):
	"""Pull original-sender addresses from forwarded email content.

	Forwarded messages embed the original headers (From / Reply-To /
	X-Gm-Original-From) inside the body text. We collect every address on such
	lines so platform ``sender_patterns`` can still match a forward (e.g. an
	email forwarded by a personal Hotmail address whose real sender is
	``@grindinggear.com``).
	"""
	if not text:
		return []
	addrs = []
	for m in re.finditer(
		r"(?:X-Gm-Original-From|Reply-To|From)\s*:\s*(.+)",
		text,
		re.I,
	):
		addr = _extract_email_address(m.group(1))
		if addr and addr not in addrs:
			addrs.append(addr)
	return addrs


def _effective_sender(sender, body="", raw=""):
	"""Effective sender context = envelope sender + forwarded original senders.

	Returns a newline-joined list of candidate addresses. A multi-line result
	implies the message is a forward (the original platform header lives in the
	body, not the envelope ``from``).
	"""
	parts = []
	s = _extract_email_address(sender)
	if s:
		parts.append(s)
	for addr in _extract_forwarded_senders(body) + _extract_forwarded_senders(raw):
		if addr not in parts:
			parts.append(addr)
	return "\n".join(parts)


def _subject_keywords_match(subject_keywords, subject):
	"""True if any comma-separated keyword appears in the subject."""
	keywords = [k.strip().lower() for k in (subject_keywords or "").split(",") if k.strip()]
	return any(k in (subject or "").lower() for k in keywords)


def _ordered_pattern_candidates(sender_ctx, is_forward, subject):
	"""Return active code patterns in (sender_hits, forward_hits) confidence order.

	Two-pass matching keeps personally-forwarded emails correct:

	* **Pass 1 — sender-trusted** (high confidence): patterns whose
	  ``sender_pattern`` actually matches one of the known senders (envelope
	  sender + forwarded originals found in the body), plus patterns that impose
	  no sender restriction. A platform whose own sender header is present always
	  wins, e.g. a POE forward carrying ``From: ...@grindinggear.com`` matches the
	  POE pattern directly here.
	* **Pass 2 — forward fallback**: only when the message is a forward and Pass
	  1 produced nothing. We relax the sender gate and rely on
	  ``subject_keywords`` to recognise a forwarded platform email whose original
	  sender header did not survive into the body text. The boundary-anchored
	  ``code_regex`` keeps this heuristic safe.

	Within both passes, ``subject_keywords`` (if defined) must match the subject,
	and patterns are ordered by ``priority`` descending. Returns two lists.
	"""
	patterns = frappe.get_all(
		"GAM Code Pattern",
		filters={"is_active": 1},
		fields=[
			"name",
			"platform",
			"sender_pattern",
			"subject_keywords",
			"code_regex",
			"ttl_minutes",
		],
		order_by="priority desc",
	)
	sender_hits = []
	forward_hits = []
	for p in patterns:
		if p.subject_keywords and not _subject_keywords_match(p.subject_keywords, subject):
			continue
		if not p.sender_pattern:
			sender_hits.append(p)
		elif re.search(p.sender_pattern, sender_ctx, re.I):
			sender_hits.append(p)
		elif is_forward:
			# Only eligible as a forward fallback; never beats a sender-trusted hit.
			forward_hits.append(p)
	return sender_hits, forward_hits


def _detect_platform(sender, subject, body=""):
	"""Best-effort platform detection from sender/subject — forward-aware.

	Returns the platform of the first candidate from
	:func:`_ordered_pattern_candidates` (sender-trusted first, then forward
	fallback). Returns "" if nothing applies.
	"""
	sender_ctx = _effective_sender(sender, body)
	is_forward = "\n" in sender_ctx
	sender_hits, forward_hits = _ordered_pattern_candidates(sender_ctx, is_forward, subject)
	for p in sender_hits + forward_hits:
		return p.platform or ""
	return ""


def _match_pattern(sender, subject, body):
	"""Match an active code pattern and extract the code — forward-aware.

	Uses the two-pass candidate ordering from
	:func:`_ordered_pattern_candidates`: sender-trusted patterns are tried first,
	and the forward fallback only runs if none of those extract a code. This
	prevents a loosely-keyworded pattern (e.g. STEAM's ``verification`` keyword)
	from stealing a personally-forwarded POE email whose real sender
	(``@grindinggear.com``) is already recognised. Returns a frappe._dict with
	``extracted`` set to the code, or ``None``.
	"""
	sender_ctx = _effective_sender(sender, body or "")
	is_forward = "\n" in sender_ctx
	sender_hits, forward_hits = _ordered_pattern_candidates(sender_ctx, is_forward, subject)
	for p in sender_hits + forward_hits:
		if not p.code_regex:
			continue
		match = re.search(p.code_regex, body or subject, re.I | re.M)
		if not match:
			continue
		code = (match.group(1) if match.groups() else match.group(0)).strip()
		if not code:
			continue
		p["extracted"] = code
		return frappe._dict(p)
	return None


@frappe.whitelist()
def test_code_pattern(sender="", subject="", body=""):
	"""Dry-run the code-pattern matcher against a sample email.

	Used by the Code Patterns "Test" panel so an admin can paste a real
	from/subject/body and see which active pattern matches, on what platform,
	and what code it extracts — without waiting for a webhook round-trip.

	Returns ``{matched, platform, pattern_name, code, detected_platform}``.
	Safe (read-only): it never creates rows or claims codes.
	"""
	hit = _match_pattern(sender or "", subject or "", body or "")
	detected = _detect_platform(sender or "", subject or "", body or "")
	if not hit:
		return {
			"matched": False,
			"platform": detected or "",
			"pattern_name": "",
			"code": "",
			"detected_platform": detected or "",
		}
	return {
		"matched": True,
		"platform": hit.get("platform") or "",
		"pattern_name": hit.get("name") or "",
		"code": hit.get("extracted") or "",
		"detected_platform": detected or "",
	}


def _update_webhook_status(status):
	"""Bump GAM Webhook Config singleton counters (ignore if missing)."""
	if not frappe.db.exists("GAM Webhook Config", "GAM Webhook Config"):
		return
	config = frappe.get_doc("GAM Webhook Config", "GAM Webhook Config")
	config.last_received_at = now_datetime()
	config.last_status = status
	config.total_received = cint(config.total_received) + 1
	config.save(ignore_permissions=True)


# ============================================================================
# 6b. Email account management (GAM Admin)
# ============================================================================
@frappe.whitelist()
def get_unrecognized_emails():
	"""List inbound logs whose owner could not be auto-resolved (gam_email is NULL).

	Surfaces forwarded emails from addresses not yet in GAM Email so the admin
	can add them with one click.  Returns the most recent record per sender.
	"""
	_require_gam_admin()
	rows = frappe.db.sql(
		"""
		SELECT name, email_account, email_from, email_subject,
		       detected_platform, received_at, resolved_via
		FROM `tabGAM Email Inbound Log`
		WHERE IFNULL(gam_email, '') = ''
		  AND status IN ('OK', 'NO_MATCH')
		  AND IFNULL(ignored, 0) = 0
		ORDER BY received_at DESC
		LIMIT 100
		""",
		as_dict=True,
	)
	seen = {}
	for r in rows:
		candidate = _extract_email_address(r.get("email_from")) or _extract_email_address(r.get("email_account")) or r.get("name")
		if candidate not in seen:
			r["candidate_address"] = _extract_email_address(r.get("email_from") or r.get("email_account"))
			seen[candidate] = r
	return list(seen.values())


@frappe.whitelist()
def ignore_unrecognized_email(inbound_name):
	"""Dismiss an unrecognized sender so it no longer appears in the panel.

	Marks all unrecognized inbound logs from the same candidate address as
	ignored (simple dismiss). New emails from that sender will reappear later.
	"""
	_require_gam_admin()
	log = frappe.db.get_value(
		"GAM Email Inbound Log",
		inbound_name,
		["name", "email_account", "email_from", "original_to"],
		as_dict=True,
	)
	if not log:
		frappe.throw(_("Inbound log not found."))

	candidate = (
		_extract_email_address(log.email_from)
		or _extract_email_address(log.original_to)
		or _extract_email_address(log.email_account)
	)
	if not candidate:
		# Cannot resolve an address — dismiss just this single log.
		frappe.db.set_value("GAM Email Inbound Log", inbound_name, "ignored", 1)
		return {"ignored": True, "address": ""}

	frappe.db.sql(
		"""
		UPDATE `tabGAM Email Inbound Log`
		SET ignored = 1
		WHERE IFNULL(gam_email, '') = ''
		  AND status IN ('OK', 'NO_MATCH')
		  AND (
			email_from LIKE %(cand)s
			OR IFNULL(original_to, '') LIKE %(cand)s
			OR email_account LIKE %(cand)s
		  )
		""",
		{"cand": f"%{candidate}%"},
	)
	return {"ignored": True, "address": candidate}


@frappe.whitelist()
def add_email_from_inbound(inbound_name, provider="Other", notes=None):
	"""Create a GAM Email from an unrecognized inbound log and link it back."""
	_require_gam_admin()
	inbound = frappe.db.get_value(
		"GAM Email Inbound Log",
		inbound_name,
		["name", "email_account", "email_from", "original_to"],
		as_dict=True,
	)
	if not inbound:
		frappe.throw(_("Inbound log not found."))

	addr = (
		_extract_email_address(inbound.original_to)
		or _extract_email_address(inbound.email_from)
		or _extract_email_address(inbound.email_account)
	)
	if not addr:
		frappe.throw(_("Could not determine an email address from this inbound log."))

	if frappe.db.exists("GAM Email", {"address": addr}):
		gam_name = frappe.db.get_value("GAM Email", {"address": addr})
	else:
		doc = frappe.new_doc("GAM Email")
		doc.address = addr
		doc.provider = provider or "Other"
		doc.notes = notes or ""
		doc.is_active = 1
		doc.insert(ignore_permissions=True)
		gam_name = doc.name

	frappe.db.set_value("GAM Email Inbound Log", inbound_name, "gam_email", gam_name)
	return {"name": gam_name, "address": addr}


@frappe.whitelist()
def save_email_account(values, name=None):
	"""Create or update a GAM Email record (handles the Password field safely)."""
	_require_gam_admin()
	values = frappe.parse_json(values) if isinstance(values, str) else values
	addr = (values.get("address") or "").strip().lower()
	if not addr:
		frappe.throw(_("Address is required."))

	if name:
		doc = frappe.get_doc("GAM Email", name)
	else:
		if frappe.db.exists("GAM Email", {"address": addr}):
			frappe.throw(_("An email with this address already exists."))
		doc = frappe.new_doc("GAM Email")

	doc.address = addr
	doc.provider = values.get("provider") or "Other"
	doc.notes = values.get("notes") or ""
	doc.is_active = cint(values.get("is_active", 1))
	doc.forward_verified = cint(values.get("forward_verified", 0))
	pwd = values.get("email_password")
	if pwd:
		doc.email_password = pwd

	if name:
		doc.save(ignore_permissions=True)
	else:
		doc.insert(ignore_permissions=True)
	return {"name": doc.name, "address": doc.address}


@frappe.whitelist()
def delete_email_account(email_name):
	"""Delete a GAM Email.

	Historical/audit records (GAM Code Request Log, GAM Email Code,
	GAM Email Inbound Log) keep a denormalised snapshot of the address and have
	their Link field cleared so they no longer block deletion.

	Returns:
	  {"deleted": True, "unlinked": {...}}      - removed; audit logs detached.
	  {"blocked": True, "linked_accounts": [...]} - accounts still reference it;
	                                             the admin must reassign them first.
	"""
	_require_gam_admin()

	# 1) Active game accounts must be reassigned first (business data).
	linked = frappe.db.get_all(
		"GAM Account",
		filters={"email": email_name},
		fields=["name", "username", "platform", "status"],
	)
	if linked:
		return {"blocked": True, "linked_accounts": linked}

	addr = frappe.db.get_value("GAM Email", email_name, "address")

	def _detach(doctype, link_field, snapshot_field):
		"""Snapshot the address into snapshot_field then nullify the link.

		Uses frappe.db.set_value so mandatory-Link constraints on read-only
		audit doctypes (e.g. GAM Code Request Log.target_email) are bypassed.
		"""
		names = frappe.db.get_all(doctype, filters={link_field: email_name}, pluck="name")
		for n in names:
			if snapshot_field and frappe.db.has_column(doctype, snapshot_field):
				if not frappe.db.get_value(doctype, n, snapshot_field) and addr:
					frappe.db.set_value(doctype, n, snapshot_field, addr, update_modified=False)
			frappe.db.set_value(doctype, n, link_field, None, update_modified=False)
		return len(names)

	unlinked = {
		"code_request_log": _detach("GAM Code Request Log", "target_email", "target_email_address"),
		"email_code": _detach("GAM Email Code", "email", "email_address"),
		"inbound_log": _detach("GAM Email Inbound Log", "gam_email", "gam_email_address"),
	}

	frappe.delete_doc("GAM Email", email_name, ignore_permissions=True)
	return {"deleted": True, "unlinked": unlinked}


def _parse_dlc_list(value):
	"""Coerce a flexible DLC input into a list of stripped non-empty names.

	Accepts: None, "name1,name2", a JSON array string, or a list/tuple.
	The SPA may pass arrays as JSON or comma-separated strings.
	"""
	if value is None or value == "":
		return []
	if isinstance(value, str):
		value = value.strip()
		if value[:1] in "[{":
			try:
				parsed = frappe.parse_json(value)
			except Exception:
				parsed = None
			if isinstance(parsed, list):
				return [str(x).strip() for x in parsed if str(x).strip()]
		return [p.strip() for p in value.split(",") if p.strip()]
	if isinstance(value, (list, tuple)):
		return [str(x).strip() for x in value if str(x).strip()]
	return []


def _validate_dlc_names(game, dlcs_value):
	"""Validate a flexible DLC input against a game; return the DLC name list.

	Throws if a DLC does not exist or belongs to a different game.
	"""
	out = []
	for dlc_name in _parse_dlc_list(dlcs_value):
		if not frappe.db.exists("GAM DLC", dlc_name):
			frappe.throw(_("DLC {0} does not exist.").format(dlc_name))
		dlc_game = frappe.db.get_value("GAM DLC", dlc_name, "game")
		if dlc_game and dlc_game != game:
			frappe.throw(_("DLC {0} does not belong to game {1}.").format(dlc_name, game))
		out.append(dlc_name)
	return out


def _normalize_role_game_row(raw, idx):
	"""Validate + normalize one (role, game) binding input.

	`raw`: {game(reqd), role(reqd), server?, is_main?, notes?, dlcs?: [name,...]}
	Returns a clean dict. Throws on missing game/role (no orphan rows).
	The role is canonicalized via ``_normalize_role_value`` so the section
	filters (``role = <value>``) always match.
	"""
	game = raw.get("game")
	game = game.strip() if isinstance(game, str) else game
	role = _normalize_role_value(raw.get("role"))
	if not game:
		frappe.throw(_("Binding {0}: Game is required.").format(idx + 1))
	if not role:
		frappe.throw(_("Binding {0} (game {1}): Role is required.").format(idx + 1, game))
	return {
		"game": game,
		"role": role,
		"server": raw.get("server") or "",
		"is_main": 1 if cint(raw.get("is_main")) else 0,
		"notes": raw.get("notes") or "",
		"dlcs": _validate_dlc_names(game, raw.get("dlcs")),
	}


def _set_role_game_dlcs(row_doc, dlc_names):
	"""Replace the DLC child of a GAM Account Role Game row doc."""
	row_doc.set("dlcs", [])
	for dlc_name in dlc_names:
		row_doc.append("dlcs", {"dlc": dlc_name})


def _apply_account_role_games(account_name, rows_value):
	"""Replace an account's GAM Account Role Game bindings (first-class).

	Called only when the caller explicitly passes a `role_games` (or legacy
	`games`) key:
	  - absent / None => keep existing bindings untouched
	  - []            => clear all bindings for the account
	  - [ {...}, ... ]=> upsert from the list (delete the rest)

	Enforces (account, game) uniqueness + a single is_main per account.
	"""
	rows_in = rows_value
	if isinstance(rows_in, str):
		rows_in = frappe.parse_json(rows_in)
	if rows_in is None or not isinstance(rows_in, list):
		return

	# Normalize + validate every row first (fail fast before any write).
	clean = [
		_normalize_role_game_row(r, i)
		for i, r in enumerate(rows_in)
		if isinstance(r, dict)
	]

	# Existing bindings, keyed by game (one role per (account, game)).
	existing = {
		r["game"]: r["name"]
		for r in frappe.db.get_all(
			"GAM Account Role Game",
			{"account": account_name},
			["name", "game"],
		)
	}
	incoming_games = {r["game"] for r in clean}

	# Platform-level game uniqueness (plan §2.1): a GAME node bound to a
	# PLATFORM parent shares that parent with its siblings. Two sibling nodes
	# under the same platform must NOT bind the same game (one game per
	# platform). On-platform binding resolves up the tree, so a duplicate would
	# be ambiguous. Reject before any write happens.
	parent_account = frappe.db.get_value(
		"GAM Account", account_name, "parent_account"
	)
	if parent_account and incoming_games:
		clashes = frappe.db.sql(
			"""
			SELECT rg.game, rg.account
			FROM `tabGAM Account Role Game` rg
			JOIN `tabGAM Account` a ON a.name = rg.account
			WHERE a.parent_account = %s
			  AND rg.account != %s
			  AND rg.game IN %s
			""",
			(parent_account, account_name, tuple(incoming_games)),
			as_dict=True,
		)
		if clashes:
			game_names = {
				c["game"]: c["account"] for c in clashes
			}
			label = frappe.db.get_value(
				"GAM Game", list(game_names.keys())[0], "game_name"
			) or list(game_names.keys())[0]
			frappe.throw(
				_(
					"Game {0} is already bound to another account under this "
					"platform. One game binding per platform is allowed."
				).format(label)
			)

	# Enforce single is_main per account: first flagged row wins.
	main_picked = False
	for r in clean:
		if r["is_main"]:
			if main_picked:
				r["is_main"] = 0
			else:
				main_picked = True

	# Upsert incoming rows.
	for r in clean:
		ex_name = existing.get(r["game"])
		if ex_name:
			doc = frappe.get_doc("GAM Account Role Game", ex_name)
		else:
			doc = frappe.new_doc("GAM Account Role Game")
			doc.account = account_name
			doc.game = r["game"]
		doc.role = r["role"]
		doc.server = r["server"]
		doc.is_main = r["is_main"]
		doc.notes = r["notes"]
		_set_role_game_dlcs(doc, r["dlcs"])
		if ex_name:
			doc.save(ignore_permissions=True)
		else:
			doc.insert(ignore_permissions=True)

	# Delete bindings whose game is no longer present.
	for game, name in existing.items():
		if game not in incoming_games:
			frappe.delete_doc("GAM Account Role Game", name, ignore_permissions=True)


def _normalize_role_value(value):
	"""Canonicalize a GAM Account role input to its GAM List Option *value*.

	Accepts either the option value or its label (case-insensitive) and returns
	the canonical value so the sidebar/list filters (``a.role = <value>``) always
	match. Blank input -> "". Prevents label-vs-value drift that can otherwise
	make an account invisible in some filters and phantom in others.
	"""
	raw = (value or "").strip()
	if not raw:
		return ""
	try:
		rows = frappe.db.get_all(
			"GAM List Option",
			{"category": "Account Role"},
			["value", "label"],
		)
	except Exception:
		return raw
	low = raw.lower()
	for r in rows:
		if (r.get("value") or "").lower() == low:
			return r.get("value") or raw
	for r in rows:
		if (r.get("label") or "").lower() == low:
			return r.get("value") or raw
	return raw


@frappe.whitelist()
def save_account(values, name=None):
	"""Create or update a GAM Account (identity/credentials only).

	Optional `values["role_games"]` = list of {game(reqd), role(reqd), server?,
	is_main?, notes?, dlcs?: [name,...]} that fully replaces the account's
	GAM Account Role Game bindings. The legacy `values["games"]` key is
	accepted as an alias (each row must still carry a `role`).
	"""
	_require_gam_admin()
	values = frappe.parse_json(values) if isinstance(values, str) else values
	platform = (values.get("platform") or "").strip()
	username = (values.get("username") or "").strip()
	email = (values.get("email") or "").strip()
	account_level = (values.get("account_level") or "GAME").strip().upper()
	parent_account = (values.get("parent_account") or "").strip()

	# ---- Hierarchy-aware validation (plan §2.1) -------------------------
	# A GAME node on a platform may resolve credentials from its parent, so
	# username/password/totp/email are only strictly required for PLATFORM
	# nodes and standalone GAME nodes.
	if account_level == "PLATFORM":
		if not (platform and username and email):
			frappe.throw(_("Platform, username and email are required."))
	elif account_level == "GAME":
		if parent_account:
			# On-platform game node: email auto-inherits from parent; username
			# is optional (resolved up the tree by resolve_account_credentials).
			if not email:
				parent_email = frappe.db.get_value(
					"GAM Account", parent_account, "email"
				)
				if not parent_email:
					frappe.throw(_("Parent account has no email to inherit."))
				email = parent_email
			# Username is optional for child nodes, but the doctype marks it
			# mandatory (reqd=1) and Frappe enforces that BEFORE validate().
			# Inherit the parent's username at save time so the mandatory
			# check passes; resolve_account_credentials() still prefers an
			# explicit value when present.
			if not username:
				username = frappe.db.get_value(
					"GAM Account", parent_account, "username"
				) or ""
				if not username:
					frappe.throw(_("Parent account has no username to inherit."))
		else:
			# Standalone game node: it owns its own identity. Platform defaults to
			# "STANDALONE" since standalone accounts do not belong to any platform.
			if not (username and email):
				frappe.throw(_("Username and email are required."))
			if not platform:
				platform = "STANDALONE"
	else:
		frappe.throw(_("account_level must be PLATFORM or GAME."))

	if name:
		doc = frappe.get_doc("GAM Account", name)
		# Capture the previous parent so we can notify the old platform when a
		# node is re-parented (its child tree must drop the node live).
		old_parent = (frappe.db.get_value("GAM Account", name, "parent_account") or "").strip()
	else:
		doc = frappe.new_doc("GAM Account")
		old_parent = ""

	doc.account_level = account_level
	doc.parent_account = parent_account if account_level == "GAME" else ""
	# standalone is derived in validate(), but mirror it here so the caller
	# sees the correct state in the returned doc without a second read.
	doc.standalone = 1 if account_level == "GAME" and not parent_account else 0

	doc.platform = platform
	doc.username = username
	doc.email = email
	doc.source = values.get("source") or ""
	doc.status = values.get("status") or "ACTIVE"
	doc.notes = values.get("notes") or ""

	pwd = values.get("account_password")
	if pwd:
		doc.account_password = pwd
	totp = values.get("totp_secret")
	if totp:
		doc.totp_secret = totp

	# ---- Billing / renewal fields (plan §2.1) ---------------------------
	doc.billing_type = values.get("billing_type") or "ONE_TIME"
	doc.active_until = values.get("active_until") or ""
	doc.auto_renew = 1 if values.get("auto_renew") else 0
	if values.get("renewal_lead_days") is not None:
		try:
			doc.renewal_lead_days = int(values.get("renewal_lead_days"))
		except (TypeError, ValueError):
			doc.renewal_lead_days = 3
	if values.get("renewal_cost") is not None:
		doc.renewal_cost = values.get("renewal_cost")
	# last_renewed_at is managed by the renewal action, not by save_account.

	if name:
		doc.save(ignore_permissions=True)
	else:
		doc.account_created_at = now_datetime()
		doc.insert(ignore_permissions=True)

	# Bindings live on the first-class GAM Account Role Game doctype. The
	# account must exist (have a name) before we can attach bindings to it.
	role_games_payload = values.get("role_games")
	if role_games_payload is None and "games" in values:
		# Legacy alias: games -> role_games (each row must still carry a role).
		role_games_payload = values.get("games")
	bindings_changed = role_games_payload is not None
	if bindings_changed:
		_apply_account_role_games(doc.name, role_games_payload)

	# Always broadcast the account change so detail/lock state refreshes.
	emit_account_changed(doc.name, "save")
	# Hierarchy bidirectional sync: when a GAME node is attached to / detached
	# from / re-parented onto a PLATFORM, that platform's open detail page must
	# rebuild its child tree live. save_account stores the link once (on the
	# child's parent_account); the parent only reads children via a query, so a
	# realtime nudge is all that's missing. Emit for the new parent (if any) and,
	# when the parent changed, the previous one too — an open platform-detail
	# listens on `gam_account_changed` keyed by its own name.
	new_parent = (doc.parent_account or "").strip()
	if new_parent and new_parent != doc.name:
		emit_account_changed(new_parent, "save")
	if old_parent and old_parent != new_parent and old_parent != doc.name:
		emit_account_changed(old_parent, "save")
	# Only reflow the dynamic section catalog when bindings actually changed
	# (a password/status edit must NOT trigger a sidebar reflow).
	if bindings_changed:
		emit_role_sections_changed()
	return {"name": doc.name, "username": doc.username}


@frappe.whitelist()
def add_account_role_game(account, role, game, server=None, is_main=0, notes=None, dlcs=None):
	"""Attach a (role, game) binding to an existing GAM Account.

	Admin-only. Enforces (account, game) uniqueness + a single is_main per
	account. `dlcs` accepts a JSON/comma list of GAM DLC names. Emits both
	``gam_account_changed`` (detail/lock refresh) and ``gam_role_sections_changed``
	(sidebar section reflow).
	"""
	_require_gam_admin()
	if not game:
		frappe.throw(_("Game is required."))
	role = _normalize_role_value(role)
	if not role:
		frappe.throw(_("Role is required."))
	if not frappe.db.exists("GAM Account", account):
		frappe.throw(_("Account {0} does not exist.").format(account))

	existing_name = frappe.db.get_value(
		"GAM Account Role Game", {"account": account, "game": game}, "name"
	)
	if existing_name:
		doc = frappe.get_doc("GAM Account Role Game", existing_name)
	else:
		doc = frappe.new_doc("GAM Account Role Game")
		doc.account = account
		doc.game = game
	doc.role = role
	doc.server = server or ""
	doc.notes = notes or ""
	doc.is_main = 1 if cint(is_main) else 0
	_set_role_game_dlcs(doc, _validate_dlc_names(game, dlcs))
	if existing_name:
		doc.save(ignore_permissions=True)
	else:
		doc.insert(ignore_permissions=True)

	# Enforce a single is_main per account: clear is_main on every other row.
	if cint(is_main):
		for r in frappe.db.get_all(
			"GAM Account Role Game",
			{"account": account, "name": ["!=", doc.name], "is_main": 1},
			["name"],
		):
			frappe.db.set_value(
				"GAM Account Role Game", r["name"], "is_main", 0, update_modified=False
			)
	emit_account_changed(account, "add_game")
	emit_role_sections_changed()
	return {"name": doc.name, "account": account, "role": role, "game": game}


@frappe.whitelist()
def remove_account_role_game(account, role=None, game=None, row_name=None):
	"""Remove one GAM Account Role Game binding from an account.

	Admin-only. Identify by ``row_name`` (docname) OR by (account, game)
	(first matching row). Re-picks is_main if the removed row carried it.
	Emits both ``gam_account_changed`` and ``gam_role_sections_changed``.
	"""
	_require_gam_admin()
	if not game and not row_name and not role:
		frappe.throw(_("Provide a game/role or row_name to remove."))
	filters = {"account": account}
	if row_name:
		filters["name"] = row_name
	elif game:
		filters["game"] = game
		if role:
			filters["role"] = _normalize_role_value(role)
	target_name = frappe.db.get_value("GAM Account Role Game", filters, "name")
	if not target_name:
		frappe.throw(_("Binding not found for this account."))
	was_main = cint(frappe.db.get_value("GAM Account Role Game", target_name, "is_main"))
	removed_game = frappe.db.get_value("GAM Account Role Game", target_name, "game")
	frappe.delete_doc("GAM Account Role Game", target_name, ignore_permissions=True)
	# Re-pick a main game if the removed row carried the is_main flag.
	if was_main:
		remain = frappe.db.get_all(
			"GAM Account Role Game",
			{"account": account},
			["name"],
			order_by="idx asc",
			limit=1,
		)
		if remain:
			frappe.db.set_value(
				"GAM Account Role Game", remain[0]["name"], "is_main", 1, update_modified=False
			)
	emit_account_changed(account, "remove_game")
	emit_role_sections_changed()
	return {"removed": True, "account": account, "game": removed_game}


@frappe.whitelist()
def delete_account(name):
	"""Delete a GAM Account after clearing its dependents.

	Returns:
	  {"blocked": True, "in_use_by": "<user>"} - an active IN_USE lease exists.
	  {"deleted": True}                        - removed cleanly.
	"""
	_require_gam_admin()
	active = frappe.db.get_value(
		"GAM Account Usage",
		{"account": name, "status": "IN_USE"},
		["name", "used_by"],
		as_dict=True,
	)
	if active:
		return {"blocked": True, "in_use_by": active.used_by}

	# 1. Account links (the account may appear on either side)
	frappe.db.delete("GAM Account Link", {"source_account": name})
	frappe.db.delete("GAM Account Link", {"target_account": name})

	# 2. Historical usage / lease records
	frappe.db.delete("GAM Account Usage", {"account": name})

	# 2b. Role/game bindings (first-class GAM Account Role Game rows)
	frappe.db.delete("GAM Account Role Game", {"account": name})

	# 3. Code request log keeps audit history, but its Link must be cleared
	#    so deleting the account does not trip link integrity.
	frappe.db.set_value(
		"GAM Code Request Log",
		{"target_account": name},
		"target_account",
		None,
		update_modified=False,
	)

	# If the deleted node was a GAME child, nudge its PLATFORM parent so an open
	# platform-detail rebuilds its child tree (the node is about to vanish).
	parent_of_deleted = (frappe.db.get_value("GAM Account", name, "parent_account") or "").strip()
	# Broadcast BEFORE the delete so listeners (detail/lock state, other tabs)
	# refresh live; the realtime payload only carries the name.
	emit_account_changed(name, "delete")
	if parent_of_deleted and parent_of_deleted != name:
		emit_account_changed(parent_of_deleted, "delete")
	# Bindings were just cleared -> reflow the dynamic section catalog too.
	emit_role_sections_changed()
	frappe.delete_doc("GAM Account", name, ignore_permissions=True)
	return {"deleted": True}


# ============================================================================
# 6a. Account hierarchy (Gốc→Thân→Cành) + billing/renewal helpers
# ============================================================================
@frappe.whitelist()
def resolve_account_credentials(game_account_name):
	"""Resolve effective credentials for a GAME node (plan §2.3).

	Returns ``{"username","account_password","totp_secret","email"}``. When the
	GAME node has its own password/TOTP they win; otherwise credentials are
	inherited from its ``parent_account`` (the PLATFORM node). Returns ``None``
	when neither the node nor its parent carries anything usable.

	The result also carries two boolean flags — ``own_has_password`` and
	``own_has_totp`` — describing whether the GAME node itself (not the
	inherited parent) owns a value. The detail UI uses these to decide whether
	to render a reveal affordance on the node's own credential block versus a
	"not set / inherited" hint.

	Access: any session user granted this account (admins bypass), mirroring the
	reveal_password gate so this never leaks secrets to ungranted users.
	"""
	_require_account_access(game_account_name)

	def _creds(doc_name):
		if not doc_name or not frappe.db.exists("GAM Account", doc_name):
			return None
		doc = frappe.get_doc("GAM Account", doc_name)
		password = ""
		try:
			password = doc.get_password("account_password") or ""
		except Exception:
			password = ""
		totp = ""
		try:
			totp = doc.get_password("totp_secret") or ""
		except Exception:
			totp = ""
		return {
			"username": doc.username or "",
			"account_password": password,
			"totp_secret": totp,
			"email": doc.email or "",
		}

	own = _creds(game_account_name)
	own_has_password = bool(own and own["account_password"])
	own_has_totp = bool(own and own["totp_secret"])

	def _stamp(result):
		"""Attach the own-flags so the caller can render its own-vs-inherited UI."""
		if result is None:
			result = {"username": "", "account_password": "", "totp_secret": "", "email": ""}
		result["own_has_password"] = own_has_password
		result["own_has_totp"] = own_has_totp
		return result

	if own and (own["account_password"] or own["totp_secret"]):
		return _stamp(own)

	parent = frappe.db.get_value("GAM Account", game_account_name, "parent_account")
	if parent:
		inherited = _creds(parent)
		if inherited:
			# Prefer the node's own username/email, fall back to the parent's.
			inherited["username"] = (own and own["username"]) or inherited["username"]
			inherited["email"] = (own and own["email"]) or inherited["email"]
			return _stamp(inherited)
	return _stamp(own)


@frappe.whitelist()
def get_platform_accounts():
	"""Admin-only list of PLATFORM-level (Thân) accounts (plan §2.3).

	Each row carries a computed ``children_count`` (GAME nodes bound to it) and a
	``renewal_state`` (``OK`` / ``DUE`` / ``OVERDUE`` / ``ONE_TIME``).
	"""
	_require_gam_admin()
	rows = frappe.db.sql(
		"""
		SELECT a.name, a.platform, a.username, a.email, a.source, a.status,
		       a.billing_type, a.active_until, a.renewal_lead_days,
		       a.auto_renew, a.renewal_cost, a.last_renewed_at,
		       e.address AS email_address
		FROM `tabGAM Account` a
		LEFT JOIN `tabGAM Email` e ON e.name = a.email
		WHERE a.account_level = 'PLATFORM'
		ORDER BY a.platform, a.username
		""",
		as_dict=True,
	)
	# children_count + renewal_state are cheaper to compute in Python.
	children = frappe.db.sql(
		"""
		SELECT parent_account, COUNT(*) AS n
		FROM `tabGAM Account`
		WHERE account_level = 'GAME' AND parent_account IS NOT NULL
		GROUP BY parent_account
		""",
		as_dict=True,
	)
	counts = {r.parent_account: r.n for r in children}
	now = frappe.utils.now_datetime()
	for r in rows:
		r["children_count"] = counts.get(r.name, 0)
		r["renewal_state"] = _renewal_state(r.billing_type, r.active_until, r.renewal_lead_days, now)
	return rows


@frappe.whitelist()
def get_platform_children(parent):
	"""List the GAME child nodes of a PLATFORM account (Thân→Cành tree), each
	enriched with its bound ``(role, game)`` bindings + server name + main flag.

	Drives the platform-detail "Tài khoản Game con" section so a platform shows
	the actual games living on its child nodes (the platform itself carries no
	games — they live on the GAME branches). Read-only; any GAM user (gated by
	the GAM Account doctype read permission, same surface as the link tree).
	"""
	_require_gam_user()
	parent = (parent or "").strip()
	if not parent or not frappe.db.exists("GAM Account", parent):
		return []
	# Only GAME nodes bound to this platform count as children.
	rows = frappe.db.sql(
		"""
		SELECT a.name, a.username, a.platform, a.status, a.source,
		       a.account_created_at
		FROM `tabGAM Account` a
		WHERE a.account_level = 'GAME'
		  AND a.parent_account = %s
		  AND a.docstatus < 2
		ORDER BY a.creation DESC
		""",
		(parent,),
		as_dict=True,
	)
	if not rows:
		return []
	names = [r["name"] for r in rows]
	# Bindings (role, game, server, is_main) for every child in one query.
	binds = frappe.db.sql(
		"""
		SELECT arg.account AS account, arg.role AS role, arg.game AS game,
		       arg.server AS server, arg.is_main AS is_main,
		       gg.game_name AS game_name, gs.server_name AS server_name
		FROM `tabGAM Account Role Game` arg
		LEFT JOIN `tabGAM Game` gg ON gg.name = arg.game
		LEFT JOIN `tabGAM Game Server` gs ON gs.name = arg.server
		WHERE arg.account IN %s
		ORDER BY arg.is_main DESC, arg.idx ASC
		""",
		(tuple(names),),
		as_dict=True,
	)
	by_account = {}
	for b in binds:
		b["is_main"] = cint(b.get("is_main"))
		b["game_name"] = b.get("game_name") or b.get("game") or ""
		by_account.setdefault(b["account"], []).append(b)
	for r in rows:
		r["role_games"] = by_account.get(r["name"], [])
	return rows


@frappe.whitelist()
def get_game_accounts(filters=None):
	"""Admin-only list of GAME-level (Cành) accounts (plan §2.3).

	Joins the parent PLATFORM account for ``parent_username`` + ``email_address``
	when the node is bound, and surfaces ``standalone`` + billing fields.
	"""
	_require_gam_admin()
	if isinstance(filters, str):
		filters = json.loads(filters) if filters else {}
	filters = filters or {}

	cond = ["a.account_level = 'GAME'"]
	vals = []
	if filters.get("parent_account"):
		cond.append("a.parent_account = %s")
		vals.append(filters["parent_account"])
	if filters.get("standalone"):
		cond.append("a.standalone = 1")
	if filters.get("platform"):
		cond.append("a.platform = %s")
		vals.append(filters["platform"])
	if filters.get("billing_type"):
		cond.append("a.billing_type = %s")
		vals.append(filters["billing_type"])
	if filters.get("renewal_due"):
		cond.append(
			"a.billing_type != 'ONE_TIME' AND a.active_until IS NOT NULL "
			"AND a.active_until <= DATE_ADD(NOW(), INTERVAL IFNULL(a.renewal_lead_days,3) DAY)"
		)

	rows = frappe.db.sql(
		"""
		SELECT a.name, a.platform, a.username, a.email, a.source, a.status,
		       a.standalone, a.parent_account, a.billing_type, a.active_until,
		       a.renewal_lead_days, a.auto_renew, a.renewal_cost, a.last_renewed_at,
		       p.username AS parent_username,
		       e1.address AS own_email_address,
		       pe.address AS parent_email_address
		FROM `tabGAM Account` a
		LEFT JOIN `tabGAM Account` p ON p.name = a.parent_account
		LEFT JOIN `tabGAM Email` e1 ON e1.name = a.email
		LEFT JOIN `tabGAM Email` pe ON pe.name = p.email
		WHERE {where}
		ORDER BY a.platform, a.username
		""".format(where=" AND ".join(cond)),
		tuple(vals),
		as_dict=True,
	)
	now = frappe.utils.now_datetime()
	# Attach bound game + role values per GAME node so the admin card can show
	# role/game badges and the client can filter by role/game without an extra
	# round-trip per row.
	bound = {}
	if rows:
		names = [r["name"] for r in rows]
		for b in frappe.db.sql(
			"""
			SELECT account, game, role
			FROM `tabGAM Account Role Game`
			WHERE account IN %s
			""",
			(tuple(names),),
			as_dict=True,
		):
			bound.setdefault(b["account"], {"games": set(), "roles": set()})
			if b.game:
				bound[b["account"]]["games"].add(b.game)
			if b.role:
				bound[b["account"]]["roles"].add(b.role)
	for r in rows:
		# Resolve the GAM Email *link* docname to its human-readable address.
		# Own email wins; on-platform nodes without their own link inherit the
		# parent platform's address. Raw `email` link is kept for form round-trips.
		r["email_address"] = r.get("own_email_address") or r.get("parent_email_address") or ""
		r["renewal_state"] = _renewal_state(r.billing_type, r.active_until, r.renewal_lead_days, now)
		entry = bound.get(r["name"], {"games": set(), "roles": set()})
		r["games"] = sorted(entry["games"])
		r["roles"] = sorted(entry["roles"])
	return rows


def _renewal_state(billing_type, active_until, lead_days, now):
	"""Classify an account's renewal urgency (plan §6 board buckets)."""
	if not billing_type or billing_type == "ONE_TIME" or not active_until:
		return "ONE_TIME"
	try:
		expiry = frappe.utils.get_datetime(active_until)
	except Exception:
		return "ONE_TIME"
	lead = lead_days if lead_days is not None else 3
	try:
		lead = int(lead)
	except (TypeError, ValueError):
		lead = 3
	window = frappe.utils.add_to_date(now, days=lead, as_datetime=True)
	if expiry <= now:
		return "OVERDUE"
	if expiry <= window:
		return "DUE"
	return "OK"


@frappe.whitelist()
def renew_account(account, new_active_until, renewal_cost=None, notes=None, auto_renew=None):
	"""Record a manual renewal for a PLATFORM or standalone GAME account.

	Extends ``active_until``, stamps ``last_renewed_at``, writes a
	``GAM Renewal Log`` row for cost reporting, and broadcasts
	``gam_renewals_changed``. GAM Admin only.
	"""
	_require_gam_admin()
	if not account or not new_active_until:
		frappe.throw(_("account and new_active_until are required."))

	doc = frappe.get_doc("GAM Account", account)
	previous = doc.active_until
	level = doc.account_level
	billing = doc.billing_type or "ONE_TIME"

	if billing == "ONE_TIME":
		frappe.throw(
			_("ONE_TIME accounts have no expiry to renew."),
			title=_("Not Renewable"),
		)

	cost = 0
	if renewal_cost not in (None, ""):
		try:
			cost = float(renewal_cost)
		except (TypeError, ValueError):
			cost = 0

	new_dt = frappe.utils.get_datetime(new_active_until)
	renewal_days = 0
	try:
		if previous:
			renewal_days = (new_dt - frappe.utils.get_datetime(previous)).days
	except Exception:
		renewal_days = 0

	doc.active_until = new_active_until
	doc.last_renewed_at = frappe.utils.now_datetime()
	doc.renewal_cost = cost
	if auto_renew is not None:
		doc.auto_renew = 1 if auto_renew else 0
	doc.save(ignore_permissions=True)

	log = frappe.new_doc("GAM Renewal Log")
	log.account = account
	log.account_level = level
	log.billing_type = billing
	log.previous_active_until = previous
	log.new_active_until = new_active_until
	log.renewal_days = renewal_days
	log.renewal_cost = cost
	log.auto_renew = 1 if (auto_renew or doc.auto_renew) else 0
	log.renewed_by = frappe.session.user
	log.renewed_at = frappe.utils.now_datetime()
	log.notes = notes or ""
	log.insert(ignore_permissions=True)

	frappe.db.commit()
	emit_renewals_changed(account)
	emit_account_changed(account, "renew")
	return {"renewed": True, "name": log.name, "active_until": new_active_until}


@frappe.whitelist()
def get_renewals(filters=None, limit_start=0, limit_page_length=50):
	"""List GAM Renewal Log rows for the cost/renewal dashboard. GAM Admin only."""
	_require_gam_admin()
	if isinstance(filters, str):
		filters = json.loads(filters) if filters else {}
	filters = filters or {}

	cond = []
	vals = []
	if filters.get("account"):
		cond.append("account = %s")
		vals.append(filters["account"])
	if filters.get("billing_type"):
		cond.append("billing_type = %s")
		vals.append(filters["billing_type"])
	if filters.get("renewed_by"):
		cond.append("renewed_by = %s")
		vals.append(filters["renewed_by"])
	if filters.get("from_date"):
		cond.append("renewed_at >= %s")
		vals.append(filters["from_date"])
	if filters.get("to_date"):
		cond.append("renewed_at <= %s")
		vals.append(filters["to_date"])
	where = ("WHERE " + " AND ".join(cond)) if cond else ""

	rows = frappe.db.sql(
		"""
		SELECT name, account, account_level, billing_type, previous_active_until,
		       new_active_until, renewal_days, renewal_cost, auto_renew,
		       renewed_by, renewed_at, notes
		FROM `tabGAM Renewal Log`
		{where}
		ORDER BY renewed_at DESC
		LIMIT %s, %s
		""".format(where=where),
		tuple(vals + [int(limit_start or 0), int(limit_page_length or 50)]),
		as_dict=True,
	)
	total = frappe.db.count("GAM Renewal Log") if not cond else frappe.db.sql(
		"SELECT COUNT(*) FROM `tabGAM Renewal Log` {where}".format(where=where),
		tuple(vals),
	)[0][0]
	return {"items": rows, "total": total}


# ============================================================================
# 6b. Configurable list options (Platform / Account Role / Account Status)
# ============================================================================
def _default_list_options(category=None):
	"""Hardcoded fallbacks used when GAM List Option is empty (pre-migration)."""
	out = []
	data = {
		"Platform": [
			("STEAM", "Steam", "STEAM", "🎮", "blue"),
			("BATTLENET", "Battle.net", "BATTLENET", "⚔️", "indigo"),
			("EPIC", "Epic", "EPIC", "🛍️", "slate"),
			("XBOX", "Xbox", "XBOX", "🎯", "emerald"),
			("STANDALONE", "Standalone", "POE", "🕹️", "amber"),
		],
		"Account Status": [
			("ACTIVE", "Active", "", "✅", "emerald"),
			("INACTIVE", "Inactive", "", "⏸️", "slate"),
			("SUSPENDED", "Suspended", "", "⛔", "amber"),
			("BANNED", "Banned", "", "🚫", "red"),
		],
		"Account Role": [
			("BOOSTER", "Booster", "", "🚀", "indigo"),
			("TRADER", "Trader", "", "💱", "emerald"),
			("ITEM", "Item", "", "📦", "amber"),
		],
	}
	cats = [category] if category else list(data.keys())
	for c in cats:
		for value, label, code_platform, icon, color in data.get(c, []):
			out.append({
				"name": "", "category": c, "label": label, "value": value,
				"code_platform": code_platform, "icon": icon, "color": color,
				"sort_order": 0,
			})
	return out


@frappe.whitelist()
def get_list_options(category=None):
	"""Return configurable list options for Platform / Account Role / Account Status.

	Open to any GAM user (members need it for the account form/filters).
	Returns hardcoded fallbacks when the table is empty (pre-migration safety).
	"""
	_require_gam_user()
	filters = {"is_active": 1}
	if category:
		filters["category"] = category
	rows = frappe.db.get_all(
		"GAM List Option",
		filters=filters,
		fields=["name", "category", "label", "value", "code_platform", "icon", "color", "sort_order"],
		order_by="category asc, sort_order asc, label asc",
	)
	if not rows and not frappe.db.count("GAM List Option"):
		rows = _default_list_options(category)
	return rows


def _ensure_account_role(role_name):
	"""Create a matching Frappe Role for an Account Role list option so admins
	can grant it to users via the standard User > Roles screen.

	Idempotent and non-destructive — it never overrides an existing role.
	"""
	role_name = (role_name or "").strip()
	if not role_name:
		return
	try:
		if frappe.db.exists("Role", role_name):
			return
		frappe.get_doc({
			"doctype": "Role",
			"role_name": role_name,
			"desk_access": 0,
			"is_custom": 1,
		}).insert(ignore_permissions=True)
	except Exception:
		frappe.log_error(title="GAM: ensure_account_role failed")


@frappe.whitelist()
def save_list_option(values, name=None):
	"""Create or update a GAM List Option (GAM Admin only)."""
	_require_gam_admin()
	values = frappe.parse_json(values) if isinstance(values, str) else values
	if name:
		doc = frappe.get_doc("GAM List Option", name)
	else:
		doc = frappe.new_doc("GAM List Option")
	doc.category = values.get("category") or "Platform"
	doc.label = (values.get("label") or "").strip()
	doc.value = (values.get("value") or "").strip()
	if not doc.value:
		# Auto-derive the stored value as UPPER_SNAKE_CASE from the label
		# (per the GAM List Option.value doctype contract) so admins don't
		# have to hand-type a value for a simple option.
		doc.value = re.sub(r"[^0-9A-Za-z]+", "_", doc.label).strip("_").upper()
	doc.code_platform = values.get("code_platform") or ""
	doc.icon = values.get("icon") or ""
	doc.color = values.get("color") or ""
	doc.sort_order = cint(values.get("sort_order", 0))
	doc.is_active = cint(values.get("is_active", 1))
	if name:
		doc.save(ignore_permissions=True)
	else:
		doc.insert(ignore_permissions=True)
	if doc.category == "Account Role":
		# Mirror the option as a real Frappe Role so it can be assigned to users
		# (User > Roles) and surfaced as a sidebar section in the UI.
		_ensure_account_role(doc.label or doc.value)
	return {"name": doc.name, "value": doc.value, "label": doc.label}


@frappe.whitelist()
def delete_list_option(name):
	"""Delete a GAM List Option (GAM Admin only).

	Reports (does not block) when the value is still referenced on accounts so
	the admin understands the impact of removing it.
	"""
	_require_gam_admin()
	doc = frappe.get_doc("GAM List Option", name)
	category_to_field = {
		"Platform": "platform",
		"Account Status": "status",
		"Account Role": "role",
	}
	field = category_to_field.get(doc.category)
	in_use = []
	if field and frappe.db.has_column("GAM Account", field):
		in_use = frappe.db.get_all("GAM Account", filters={field: doc.value}, pluck="name")
	if doc.category == "Account Role":
		# Disable (do not delete) the matching Frappe Role to avoid orphaning
		# users who still hold it; admins can re-enable/recreate as needed.
		role_name = (doc.label or doc.value or "").strip()
		if role_name and frappe.db.exists("Role", role_name):
			try:
				frappe.db.set_value("Role", role_name, "disabled", 1)
			except Exception:
				pass
	frappe.delete_doc("GAM List Option", name, ignore_permissions=True)
	return {"deleted": True, "in_use": in_use}


# ============================================================================
# 7. Role-isolation audit (B4 — co-tenancy hardening)
# ============================================================================
# Roles that, when held by a GAM Member, break co-tenancy isolation on a shared
# site (erpnext + trader-ui live on the same erp.local).
ISOLATION_BREAKING_ROLES = {
	"System Manager": "Grants Desk + admin access to EVERY app on the site.",
	"Administrator": "Super-user — full control of the whole site.",
}
GAM_ROLES = {"GAM Admin", "GAM Member"}
# Built-in Frappe roles that are always present and safe.
_BUILTIN_ROLES = {"All", "Guest", "Desktop"}


def _require_gam_admin():
	"""Defense-in-depth guard: only GAM Admin / Administrator may call."""
	caller_roles = set(frappe.get_roles())
	if (
		"GAM Admin" not in caller_roles
		and "Administrator" not in caller_roles
	):
		frappe.throw(
			_("Only GAM Admin can perform this action."),
			frappe.PermissionError,
		)


def _require_gam_user():
	"""Guard: allow any GAM role (Admin / Member) or Administrator / System Manager.

	Used by read endpoints (e.g. ``get_accounts_list``) that return account data
	to regular GAM members. The GAM Account doctype is readable by GAM roles, so
	this mirrors the REST ``get_list`` permission surface.
	"""
	caller_roles = set(frappe.get_roles())
	if not (
		({"GAM Admin", "GAM Member", "Administrator"} & caller_roles)
		or "System Manager" in caller_roles
	):
		frappe.throw(_("Not permitted."), frappe.PermissionError)


@frappe.whitelist()
def get_role_audit(user=None):
	"""Audit role isolation for a GAM user (GAM Admin only).

	Returns the user's full role set plus flags for any isolation-breaking
	roles and a list of non-GAM roles to review (erpnext / trader-ui leakage
	on the co-tenant site erp.local).

		{
		  "user": "...",
		  "roles": [...],
		  "is_gam_admin": bool,
		  "is_gam_member": bool,
		  "is_isolated": bool,            # True when no breaking role found
		  "warnings": [{role, reason}],
		  "other_roles": [...]            # non-GAM, non-builtin, non-breaking
		}
	"""
	_require_gam_admin()

	target = user or frappe.session.user
	roles = set(frappe.get_roles(target))
	is_member = "GAM Member" in roles
	is_admin = "GAM Admin" in roles

	warnings = []
	if is_member:
		for role, reason in ISOLATION_BREAKING_ROLES.items():
			if role in roles:
				warnings.append({"role": role, "reason": reason})

	review = sorted(
		roles - GAM_ROLES - _BUILTIN_ROLES - set(ISOLATION_BREAKING_ROLES)
	)

	return {
		"user": target,
		"roles": sorted(roles),
		"is_gam_admin": is_admin,
		"is_gam_member": is_member,
		"is_isolated": len(warnings) == 0,
		"warnings": warnings,
		"other_roles": review,
	}


# ============================================================================
# 8. Cloudflare Worker deployment (API-token based auto-setup)
# ============================================================================
import os as _cf_os
import json as _cf_json

_CF_PKG_DIR = _cf_os.path.dirname(_cf_os.path.abspath(__file__))


def _cf_get_password(fieldname):
	"""Safely retrieve a Password field from the Webhook Config singleton.

	Returns '' when the field has never been set (avoids the
	PasswordNotSetError that ``get_password`` raises on empty fields).
	Clears the message log so the internal error doesn't leak to the UI.
	"""
	try:
		doc = frappe.get_doc("GAM Webhook Config", "GAM Webhook Config")
		return doc.get_password(fieldname) or ""
	except Exception:
		frappe.local.message_log = []
		return ""


def _read_cf_worker_bundled():
	"""Read the esbuild-bundled worker (postal-mime inlined) for API upload."""
	path = _cf_os.path.join(_CF_PKG_DIR, "cloudflare_worker_bundled.mjs")
	if not _cf_os.path.exists(path):
		frappe.throw(_("Worker bundle not found: {0}").format(path))
	with open(path, "r", encoding="utf-8") as f:
		return f.read()


# ---------------------------------------------------------------------------
# Cloudflare Tunnel (Zero Trust remote-managed tunnel). The eyJ... connector
# token is base64 JSON {"a": account_id, "t": tunnel_id, "s": secret}.
# ---------------------------------------------------------------------------

_CF_TUNNEL_INSTALL_CMDS = """\
# 1) Cai cloudflared (official Cloudflare apt repo)
sudo mkdir -p --mode=0755 /usr/share/keyrings
curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg \\
  | sudo tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null
echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared $(lsb_release -cs) main" \\
  | sudo tee /etc/apt/sources.list.d/cloudflared.list
sudo apt-get update && sudo apt-get install -y cloudflared

# 2) Sau khi cai xong, quay lai app bam "Thiet lap" lan nua
#    backend se tu chay: sudo cloudflared service install <token>
"""


def _cf_decode_tunnel_token(token):
	"""Validate + decode a Cloudflare Tunnel connector token.

	Returns {"a": account_id, "t": tunnel_id, "s": secret}; raises on bad format.
	"""
	import base64 as _b64
	pad = "=" * (-len(token) % 4)
	try:
		data = _cf_json.loads(_b64.b64decode(token + pad))
	except Exception:
		frappe.throw(_(
			"Token khong dung dinh dang Cloudflare Tunnel token "
			"(can chuoi eyJ... tu dashboard -> Networks -> Tunnels)."
		))
	if not all(k in data for k in ("a", "t", "s")):
		frappe.throw(_(
			"Token thieu truong account/tunnel/secret — kiem tra lai token."
		))
	return data


def _cf_run(cmd):
	"""Run a subprocess (argv list, no shell) -> (rc, stdout, stderr)."""
	import subprocess as _sp
	proc = _sp.run(cmd, capture_output=True, text=True, timeout=180)
	return proc.returncode, (proc.stdout or "").strip(), (proc.stderr or "").strip()


@frappe.whitelist()
def install_cloudflare_tunnel(tunnel_token=None):
	"""Install / refresh the Cloudflare Tunnel connector from the UI.

	Hybrid flow:
	  * cloudflared NOT installed  -> return the apt install commands to copy.
	  * cloudflared installed      -> run ``cloudflared service install <token>``
	    via passwordless sudo, then report ``systemctl`` status.
	"""
	_require_gam_admin()

	token = (tunnel_token or "").strip()
	if not token:
		frappe.throw(_("Cloudflare Tunnel Token la bat buoc."))

	info = _cf_decode_tunnel_token(token)  # raises on bad format
	tunnel_id = info["t"]
	account_id = info["a"]

	# Persist the token (Password field).
	cfg = frappe.get_doc("GAM Webhook Config", "GAM Webhook Config")
	cfg.cloudflare_tunnel_token = token
	cfg.save(ignore_permissions=True)

	# Locate cloudflared.
	import shutil as _sh
	cf_bin = _sh.which("cloudflared") or None

	if not cf_bin:
		return {
			"installed": False,
			"cloudflared_installed": False,
			"tunnel_id": tunnel_id,
			"account_id": account_id,
			"command": _CF_TUNNEL_INSTALL_CMDS,
			"message": "cloudflared chua cai — chay cac lenh tren roi bam Thiet lap lai.",
		}

	# cloudflared present -> run service install via passwordless sudo.
	# argv list (no shell) prevents injection; token already format-validated.
	rc, out, err = _cf_run(["sudo", "-n", cf_bin, "service", "install", token])

	# Check service status.
	_st_rc, st_out, _st_err = _cf_run(["sudo", "-n", "systemctl", "is-active", "cloudflared"])
	service_active = (st_out == "active")

	if rc != 0 and not service_active:
		return {
			"installed": True,
			"cloudflared_installed": True,
			"service_active": False,
			"tunnel_id": tunnel_id,
			"account_id": account_id,
			"error": (err or out or f"exit {rc}"),
			"command": f"sudo {cf_bin} service install <token>",
			"message": "cloudflared service install that bai — xem chi tiet.",
		}

	return {
		"installed": True,
		"cloudflared_installed": True,
		"service_active": service_active,
		"tunnel_id": tunnel_id,
		"account_id": account_id,
		"detail": out or "cloudflared service installed.",
		"message": (
			"Tunnel connector da cai va dang chay." if service_active
			else "Da cai service (dang cho active)."
		),
	}


@frappe.whitelist()
def get_tunnel_status():
	"""Report cloudflared install + service status for the status panel."""
	_require_gam_admin()
	import shutil as _sh
	cf_bin = _sh.which("cloudflared") or None
	service_active = False
	if cf_bin:
		_rc, out, _err = _cf_run(["sudo", "-n", "systemctl", "is-active", "cloudflared"])
		service_active = (out == "active")

	tunnel_id = account_id = ""
	tok = _cf_get_password("cloudflare_tunnel_token")
	token_saved = bool(tok) and set(tok) != {"*"}
	if token_saved:
		try:
			info = _cf_decode_tunnel_token(tok)
			tunnel_id, account_id = info["t"], info["a"]
		except Exception:
			frappe.local.message_log = []

	return {
		"cloudflared_installed": bool(cf_bin),
		"cloudflared_path": cf_bin or "",
		"service_active": service_active,
		"tunnel_id": tunnel_id,
		"account_id": account_id,
		"token_saved": token_saved,
	}


# ---------------------------------------------------------------------------
# Setup wizard — gated, step-by-step (verify host / add-domain / progress state)
# ---------------------------------------------------------------------------

def _cf_truthy(v):
	return str(v).strip().lower() in ("1", "true", "yes", "on")


def _cf_clean_host(host):
	"""Normalise a pasted host to a bare hostname (strip scheme/path/slash)."""
	h = (host or "").strip()
	if "://" in h:
		h = h.split("://", 1)[1]
	h = h.split("/", 1)[0].strip().rstrip(".")
	return h.lower()

def _is_public_ip(ip):
	"""True for a globally-routable IP (SSRF guard helper, P1.5)."""
	return not (
		ip.is_private
		or ip.is_loopback
		or ip.is_link_local
		or ip.is_unspecified
		or ip.is_reserved
		or ip.is_multicast
	)


def _is_safe_host(host):
	"""Reject private/loopback/link-local hosts (SSRF guard, P1.5).

	Returns True only when the host resolves to one or more PUBLIC IPs. Bare-IP
	inputs are checked directly; hostnames are resolved via getaddrinfo. A host
	that resolves to *any* private IP (e.g. a DNS rebinding attack) is rejected.
	"""
	h = (host or "").strip().lower().rstrip(".")
	if not h:
		return False
	try:
		return _is_public_ip(ipaddress.ip_address(h))
	except ValueError:
		pass  # not a bare IP — resolve as a hostname below
	try:
		infos = socket.getaddrinfo(h, None)
	except socket.gaierror:
		return False
	resolved = {ipaddress.ip_address(info[4][0]) for info in infos}
	return bool(resolved) and all(_is_public_ip(ip) for ip in resolved)


@frappe.whitelist()
def verify_public_host(host=None):
	"""Wizard step-2 gate: confirm the public host routes back to this Frappe site.

	Server-side GET ``https://<host>/api/method/ping`` round-trips through the
	Cloudflare tunnel → nginx → Frappe. ok=True means the host is live and Frappe
	responds (``{"message":"pong"}``), so the webhook URL is reachable from the
	Worker. A *connection error* (caught below) almost always means the tunnel is
	down or its Service is mis-set (e.g. ``https://localhost:80`` instead of
	``http://localhost:80``) — cloudflared then fails the TLS handshake.
	"""
	_require_gam_admin()
	import requests as _rq

	h = _cf_clean_host(host)
	if not h:
		frappe.throw(_("Public Host la bat buoc (vi du gam.gegeteam.xyz)."))
	if not _is_safe_host(h):
		frappe.throw(
			_("Public Host phai la ten mien cong khai (KHONG duoc la IP noi bo/localhost)."),
			frappe.PermissionError,
		)
	url = f"https://{h}/api/method/ping"
	try:
		resp = _rq.get(url, timeout=10, allow_redirects=True)
		body = (resp.text or "")[:300]
		# Healthy = Frappe responds with a non-5xx body and (in dns_multitenant
		# mode) not the "site does not exist" 404. With serve_default_site (this
		# bench) any host that reaches nginx is served by the default site.
		ok = resp.status_code < 500 and ("does not exist" not in body.lower())
		return {"ok": ok, "status": resp.status_code, "url": url, "detail": body}
	except Exception as e:
		return {"ok": False, "status": 0, "url": url, "detail": str(e)[:240]}


@frappe.whitelist()
def setup_frappe_domain(host=None, webhook_email=None):
	"""Wizard step-2: record the public host + inbox, then verify reachability.

	This bench runs with ``serve_default_site`` (common_site_config.json), so
	Frappe serves the default site (erp.local) for *any* Host header that nginx
	forwards on :80. That means the public host routes to this site **automatically**
	once the Cloudflare Tunnel is up — no nginx ``server_name`` edit or reload is
	required (and a ``bench setup nginx`` regen would wipe the /gam-ui/ block).

	This method:
	  1. persists ``public_host`` (+ ``webhook_email`` if given) on GAM Webhook Config;
	  2. records the domain on the site (``bench setup add-domain``) idempotently —
	     best-effort, for future dns_multitenant mode; never blocks the wizard;
	  3. verifies the host round-trips via :func:`verify_public_host`.

	The returned ``ok`` is the reachability verdict, so the wizard can gate step 3
	(Worker source, which needs the correct ``GAM_WEBHOOK_URL``) on a reachable host.
	"""
	_require_gam_admin()
	import shutil

	h = _cf_clean_host(host)
	if not h:
		frappe.throw(_("Public Host la bat buoc (vi du gam.gegeteam.xyz)."))
	if not _is_safe_host(h):
		frappe.throw(
			_("Public Host phai la ten mien cong khai (KHONG duoc la IP noi bo/localhost)."),
			frappe.PermissionError,
		)

	cfg = frappe.get_doc("GAM Webhook Config", "GAM Webhook Config")
	cfg.public_host = h
	if (webhook_email or "").strip():
		cfg.webhook_email = webhook_email.strip().lower()
	cfg.save(ignore_permissions=True)

	logs = [f"public_host = {h}"]
	# Best-effort domain record (idempotent). Routing already works via
	# serve_default_site, so this is just future-proofing for dns_multitenant —
	# wrap it so a bench version change can never block the wizard.
	try:
		site = frappe.local.site or "erp.local"
		bench = shutil.which("bench") or "/home/frappe/.local/bin/bench"
		_rc, out, err = _cf_run([bench, "setup", "add-domain", "--site", site, h])
		logs.append(f"$ bench setup add-domain --site {site} {h}\n{(err or out).strip()}")
	except Exception as e:
		logs.append(f"(add-domain skipped — harmless with serve_default_site: {e})")

	verdict = verify_public_host(h)
	ok = bool(verdict.get("ok"))
	return {
		"ok": ok,
		"public_host": h,
		"host_reachable": ok,
		"status": verdict.get("status"),
		"detail": verdict.get("detail"),
		"output": "\n".join(logs),
		"message": (
			f"Host {h} da ket noi ve Frappe — webhook URL se hoat dong tu Worker."
			if ok
			else f"Host {h} chua toi duoc (HTTP {verdict.get('status')}). "
			"Yeu cau: Cloudflare Tunnel phai dang chay VA Service = http://localhost:80 "
			"(KHONG phai https://localhost:80)."
		),
	}


@frappe.whitelist()
def get_webhook_setup_state():
	"""One-shot state for the setup wizard: inputs + live signals + persisted flags.

	Live-checks the tunnel service status and (if a host is set) the host reachability
	so the stepper can derive step completion on load.
	"""
	_require_gam_admin()
	cfg = frappe.get_doc("GAM Webhook Config", "GAM Webhook Config")
	tun = get_tunnel_status()
	public_host = (cfg.public_host or "").strip()
	worker_url = (
		f"https://{public_host}/api/method/gam.api.receive_email_webhook" if public_host else ""
	)
	host_reachable = False
	if public_host:
		try:
			host_reachable = bool(verify_public_host(public_host).get("ok"))
		except Exception:
			frappe.local.message_log = []
			host_reachable = False
	secret = _cf_get_password("webhook_secret")
	webhook_secret_set = bool(secret) and set(secret) != {"*"}
	return {
		"public_host": public_host,
		"webhook_email": cfg.webhook_email or "",
		"webhook_secret_set": webhook_secret_set,
		"cloudflared_installed": bool(tun.get("cloudflared_installed")),
		"tunnel_active": bool(tun.get("service_active")),
		"tunnel_id": tun.get("tunnel_id") or "",
		"token_saved": bool(tun.get("token_saved")),
		"host_reachable": host_reachable,
		"worker_url": worker_url,
		"worker_deployed": bool(cfg.cf_worker_deployed),
		"email_routing_done": bool(cfg.cf_email_routing_done),
		"last_status": cfg.last_status or "",
		"total_received": cfg.total_received or 0,
		"is_active": bool(cfg.is_active),
	}


@frappe.whitelist()
def set_webhook_setup_step(step, done=True):
	"""Persist a self-confirmed wizard step ('worker' | 'routing')."""
	_require_gam_admin()
	s = (step or "").strip().lower()
	flag = _cf_truthy(done)
	cfg = frappe.get_doc("GAM Webhook Config", "GAM Webhook Config")
	if s in ("worker", "worker_deployed", "cf_worker_deployed"):
		cfg.cf_worker_deployed = 1 if flag else 0
	elif s in ("routing", "email_routing", "cf_email_routing_done"):
		cfg.cf_email_routing_done = 1 if flag else 0
	else:
		frappe.throw(_("Buoc khong hop le: 'worker' hoac 'routing'."))
	cfg.save(ignore_permissions=True)
	return {
		"ok": True,
		"worker_deployed": bool(cfg.cf_worker_deployed),
		"email_routing_done": bool(cfg.cf_email_routing_done),
	}


@frappe.whitelist()
def get_cloudflare_worker_source():
	"""Return the bundled worker (postal-mime inlined, single-file) for copy.

	Uses the esbuild bundle so it pastes directly into the Cloudflare dashboard
	Quick Editor (which cannot `npm install`). Deploy manually: copy the source
	and set GAM_WEBHOOK_URL + GAM_WEBHOOK_SECRET in the dashboard.
	"""
	_require_gam_admin()
	try:
		source = _read_cf_worker_bundled()
	except Exception:
		frappe.local.message_log = []
		source = ""
	return {"source": source, "bundled": True}
