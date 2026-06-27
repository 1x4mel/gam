import frappe


def emit_new_code(platform=None, email_code=None):
	"""Broadcast that a fresh verification code landed.

	The gam-ui SPA listens on `gam_new_code` (see composables/useRealtime.js)
	and shows a toast + refreshes the dashboard. The owning ``email`` (GAM Email
	name) is included so each account card can match it against its own email and
	blink its "Code" button — WITHOUT exposing the code value itself (still
	fetched on demand via the audited request_code endpoint).
	"""
	email = None
	if email_code:
		try:
			email = frappe.db.get_value("GAM Email Code", email_code, "email")
		except Exception:
			email = None
	try:
		frappe.publish_realtime(
			"gam_new_code",
			{
				"platform": platform,
				"code_platform": platform,
				"email_code": email_code,
				"email": email,
			},
			broadcast=True,
		)
	except Exception:
		frappe.log_error("gam: emit_new_code failed")


def emit_account_changed(account, action="update"):
	"""Broadcast that a GAM Account's usage/lock/notes changed.

	`action` is one of: ``checkin`` (lease started), ``checkout`` (lease ended /
	forced), ``note`` (collaborative note added), ``update`` (catch-all).

	The gam-ui SPA listens on `gam_account_changed`:
	  - AccountDetailView refreshes itself + activity + notes when its account matches.
	  - AccountListView re-evaluates lock/dim state + rested badges.
	  - AppLayout / useActiveUsage refreshes the "Đang hoạt động" tab + sidebar badge.
	"""
	if not account:
		return
	try:
		frappe.publish_realtime(
			"gam_account_changed",
			{"account": account, "action": action, "user": frappe.session.user},
			broadcast=True,
		)
	except Exception:
		frappe.log_error("gam: emit_account_changed failed")


def emit_role_sections_changed():
	"""Broadcast that the dynamic (role, game) section catalog changed.

	Dedicated to the sidebar's Trader/Booster/Item section subsystem so it does
	NOT piggyback on ``gam_account_changed`` (which also fires for password /
	status / usage / notes edits that do not affect sections). The gam-ui
	``AppLayout`` listens on ``gam_role_sections_changed`` and re-runs
	``loadGamesByRole(true)`` only when a role/game binding actually changed.

	Fired by: ``save_account`` (when a ``role_games`` payload is sent),
	``add_account_role_game``, ``remove_account_role_game`` and ``delete_account``.
	"""
	try:
		frappe.publish_realtime(
			"gam_role_sections_changed",
			{"user": frappe.session.user},
			broadcast=True,
		)
	except Exception:
		frappe.log_error("gam: emit_role_sections_changed failed")


def emit_handoff(account=None, from_user=None, to_user=None, action="handoff"):
	"""Broadcast a shift handoff (bàn giao ca) between users.

	`action` is one of: ``handoff`` (lease transferred), ``declined`` (the
	receiver declined and the lease was reopened for the previous holder).

	The gam-ui SPA listens on ``gam_handoff``:
	  - the receiver (``to_user``) gets a toast "Account X vừa được bàn giao cho bạn".
	  - AppLayout / useActiveUsage refresh the "Đang hoạt động" tab + sidebar badge.
	"""
	try:
		frappe.publish_realtime(
			"gam_handoff",
			{
				"account": account,
				"from_user": from_user,
				"to_user": to_user,
				"action": action,
				"user": frappe.session.user,
			},
			broadcast=True,
		)
	except Exception:
		frappe.log_error("gam: emit_handoff failed")


def emit_renewals_changed(account=None):
	"""Broadcast that the renewals/expiry board changed.

	Fired by: ``renew_account`` (manual renewal), the daily
	``flag_expiring_accounts`` scheduler, and ``save_account`` when billing
	fields change. The gam-ui renewals views listen on
	``gam_renewals_changed`` and refresh the due/overdue counts.
	"""
	try:
		frappe.publish_realtime(
			"gam_renewals_changed",
			{"account": account, "user": frappe.session.user},
			broadcast=True,
		)
	except Exception:
		frappe.log_error("gam: emit_renewals_changed failed")
