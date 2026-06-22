"""One-off runtime diagnostic for the Reveal Log (Req #1).

Run: bench --site erp.local execute gam_diag.diag_reveal_log
"""
from __future__ import annotations

import json

import frappe
from frappe.utils import now_datetime


def _section(title):
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def diag_reveal_log():
    _section("CLOCKS")
    print("now_datetime() (Frappe system tz):", now_datetime())
    print("SELECT NOW() (DB / MariaDB):      ", frappe.db.sql("SELECT NOW()")[0][0])
    print("SELECT UTC_TIMESTAMP():           ", frappe.db.sql("SELECT UTC_TIMESTAMP()")[0][0])
    tz = frappe.db.get_single_value("System Settings", "time_zone")
    print("System Settings.time_zone:        ", tz)

    _section("REVEAL LOG — 12 newest by viewed_at")
    rows = frappe.db.sql(
        """SELECT name, viewed_at, modified, creation, viewed_by, action,
                  target_doctype, target_name, fieldname
           FROM `tabGAM Reveal Log`
           ORDER BY viewed_at DESC
           LIMIT 12""",
        as_dict=True,
    )
    if not rows:
        print("  (no rows)")
    for r in rows:
        print(
            "  viewed_at=%s | modified=%s | by=%s | %s | %s/%s | %s"
            % (r.viewed_at, r.modified, r.viewed_by, r.action,
               r.target_doctype, r.target_name, r.fieldname)
        )

    _section("REVEAL LOG — 12 newest by MODIFIED (proxy for true insert order)")
    rows2 = frappe.db.sql(
        """SELECT name, viewed_at, modified, creation, viewed_by, action, target_name
           FROM `tabGAM Reveal Log`
           ORDER BY modified DESC
           LIMIT 12""",
        as_dict=True,
    )
    for r in rows2:
        print("  modified=%s | viewed_at=%s | by=%s | %s | %s"
              % (r.modified, r.viewed_at, r.viewed_by, r.action, r.target_name))

    _section("TOTAL COUNT + today's count")
    total = frappe.db.count("GAM Reveal Log")
    today_utc = frappe.db.sql(
        "SELECT COUNT(*) FROM `tabGAM Reveal Log` WHERE DATE(viewed_at) = CURDATE()"
    )[0][0]
    print("  total rows:", total, "| viewed_at on CURDATE() (UTC):", today_utc)

    _section("live test: insert + rollback (no permanent change)")
    try:
        test_doc = frappe.get_doc({
            "doctype": "GAM Reveal Log",
            "action": "REVEAL",
            "viewed_by": frappe.session.user,
            "target_doctype": "GAM Account",
            "target_name": "__DIAG__",
            "fieldname": "account_password",
            "viewed_at": now_datetime(),
        })
        test_doc.insert(ignore_permissions=True)
        frappe.db.rollback()
        print("  insert OK (rolled back). Log path is functional for session user:",
              frappe.session.user)
    except Exception as e:  # noqa: BLE001
        frappe.db.rollback()
        print("  INSERT FAILED:", repr(e))


def diag_probe_account():
    """Print a real GAM Account name + its password fieldname for the HTTP probe,
    plus the target_doctype distribution of the reveal log."""
    _section("REVEAL LOG target_doctype distribution")
    for r in frappe.db.sql(
        """SELECT target_doctype, COUNT(*) AS c
           FROM `tabGAM Reveal Log` GROUP BY target_doctype""",
        as_dict=True,
    ):
        print("  %s -> %s" % (r.target_doctype, r.c))

    _section("A real GAM Account with account_password")
    acc = frappe.db.sql(
        """SELECT name, account_name, account_password
           FROM `tabGAM Account`
           WHERE account_password IS NOT NULL AND account_password != ''
           ORDER BY modified DESC LIMIT 3""",
        as_dict=True,
    )
    for a in acc:
        print("  name=%s | account_name=%s | has_password=%s"
              % (a.name, a.account_name, bool(a.account_password)))

    _section("Newest 3 reveal rows (for before/after comparison)")
    for r in frappe.db.sql(
        """SELECT name, viewed_at, viewed_by, target_doctype, target_name
           FROM `tabGAM Reveal Log` ORDER BY viewed_at DESC LIMIT 3""",
        as_dict=True,
    ):
        print("  %s | %s | %s | %s/%s" % (r.name, r.viewed_at, r.viewed_by, r.target_doctype, r.target_name))


def diag_test_new_api():
    """Smoke-test the new Req #2/#3/#4 endpoints."""
    _section("resolve_doc_names")
    r = frappe.call("gam.api.resolve_doc_names", {"GAM Account": ["efquhacv6m"], "GAM Email": []})
    print("  ", json.dumps(r, default=str))

    _section("get_account_activity")
    a = frappe.call("gam.api.get_account_activity", account="efquhacv6m", limit=5)
    print("  total events:", a["total"])
    for e in a["data"][:3]:
        print("   ", e.get("type"), "|", e.get("title"), "|", e.get("timestamp"))

    _section("get_account_notes (read)")
    n = frappe.call("gam.api.get_account_notes", account="efquhacv6m")
    print("  notes:", len(n))


def diag_all():
    diag_reveal_log()
