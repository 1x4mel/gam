"""One-off runtime diagnostic for the Reveal Log (Req #1).

Run: bench --site erp.local execute gam_diag.diag_reveal_log
"""
from __future__ import annotations

import json

import frappe
from frappe.utils import now_datetime, cint


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


def diag_webhook():
    """End-to-end webhook-receiver diagnostic.

    Verifies that the inbound email webhook (gam.api.receive_email_webhook)
    is functional: config state -> secret guard -> ingestion -> counters.

    Run: bench --site erp.local execute gam_diag.diag_webhook
    """
    from frappe.utils import now_datetime
    from frappe.utils.data import add_to_date

    try:
        from gam import api as gam_api
    except Exception as e:  # noqa: BLE001
        print("FATAL: cannot import gam.api:", repr(e))
        return

    cfg = frappe.get_doc("GAM Webhook Config", "GAM Webhook Config")
    secret = cfg.get_password("webhook_secret") or ""

    _section("WEBHOOK CONFIG (GAM Webhook Config singleton)")
    print("  is_active            :", bool(cint(cfg.is_active)))
    print("  webhook_secret_set   :", bool(secret) and set(secret) != {"*"})
    print("  public_host          :", cfg.public_host or "(unset)")
    print("  webhook_email        :", cfg.webhook_email or "(unset)")
    print("  cf_worker_deployed   :", bool(cint(cfg.cf_worker_deployed)))
    print("  cf_email_routing_done:", bool(cint(cfg.cf_email_routing_done)))
    print("  total_received       :", cfg.total_received)
    print("  last_status          :", cfg.last_status or "(none)")
    print("  last_received_at     :", cfg.last_received_at or "(none)")

    if not cint(cfg.is_active):
        print("\n  >> is_active = 0 -> endpoint will reject every webhook with 403.")
        print("     Turn it on in the WebhookConfigView master toggle before continuing.")
    if not (bool(secret) and set(secret) != {"*"}):
        print("\n  >> webhook_secret not set -> endpoint will reject with 403.")
        print("     Set a secret in GAM Webhook Config + match it in the Worker (GAM_WEBHOOK_SECRET).")

    # ---- (a) negative test: wrong secret must be rejected -----------------
    _section("GUARD: wrong secret rejected?")
    class _BadReq:
        method = "POST"
        headers = {"X-Webhook-Secret": "definitely-wrong"}
        form = None
        def get_json(self, silent=True):
            return {"email_account": "x", "from": "x", "subject": "x", "body": "x"}

    frappe.local.request = _BadReq()
    try:
        frappe.set_user("Guest")
        gam_api.receive_email_webhook()
        print("  FAIL: endpoint accepted a WRONG secret (should have thrown).")
    except frappe.PermissionError:
        print("  OK: wrong secret -> PermissionError raised (guard works).")
    except Exception as e:  # noqa: BLE001
        print("  WARN: wrong-secret path raised unexpected:", repr(e))
    finally:
        frappe.set_user("Administrator")
        del frappe.local.request

    # ---- (b) positive test: real ingestion with correct secret -----------
    if bool(secret) and set(secret) != {"*"}:
        _section("INGEST: real payload with correct secret (in-process)")
        msg_id = "diag-%s" % now_datetime().strftime("%Y%m%d%H%M%S%f")
        payload = {
            "email_account": "diag-test@example.com",
            "from": "noreply@steampowered.com",
            "subject": "Your Steam Guard code",
            "body": "Your Steam Guard code is 482931",
            "html": "",
            "message_id": msg_id,
            "received_at": now_datetime().isoformat(),
        }

        class _GoodReq:
            method = "POST"
            headers = {"X-Webhook-Secret": secret}
            form = None
            def get_json(self, silent=True):
                return payload

        frappe.local.request = _GoodReq()
        try:
            res = gam_api.receive_email_webhook()
            print("  endpoint returned:", json.dumps(res, default=str))
            print("  -> ingestion path executed successfully (status above: ok/no_match/duplicate).")
        except Exception as e:  # noqa: BLE001
            print("  FAIL: ingestion threw:", repr(e))
            frappe.db.rollback()
        finally:
            del frappe.local.request

        # rollback so the diagnostic leaves no permanent test row
        frappe.db.rollback()
    else:
        print("\n(skipping ingest test: webhook_secret not configured)")

    # ---- (c) latest inbound log rows --------------------------------------
    _section("LATEST 5 GAM Email Inbound Log rows")
    rows = frappe.db.sql(
        """SELECT name, status, detected_platform, email_from,
                  received_at, creation
           FROM `tabGAM Email Inbound Log`
           ORDER BY creation DESC LIMIT 5""",
        as_dict=True,
    )
    if not rows:
        print("  (no inbound rows yet — a real/worker email has never landed)")
    for r in rows:
        print("  %s | %s | %s | %s | recv=%s"
              % (r.name, r.status, r.detected_platform or "-", r.email_from, r.received_at))

    # ---- (d) tunnel reachability (optional) ------------------------------
    if cfg.public_host:
        _section("TUNNEL: verify_public_host (cloudflared -> nginx -> Frappe)")
        try:
            out = gam_api.verify_public_host(host=cfg.public_host)
            print("  ok     :", out.get("ok"))
            print("  status :", out.get("status"))
            print("  url    :", out.get("url"))
            print("  detail :", (out.get("detail") or "")[:200])
        except Exception as e:  # noqa: BLE001
            print("  verify_public_host threw (admin-only?):", repr(e))


def diag_all():
    diag_reveal_log()
