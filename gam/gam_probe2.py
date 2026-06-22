"""Quick probe: write account names + reveal-log snapshot to /tmp for the HTTP test."""
import frappe

accounts = frappe.db.sql(
    "SELECT name FROM `tabGAM Account` ORDER BY modified DESC LIMIT 3", as_dict=True
)
newest = frappe.db.sql(
    "SELECT name, viewed_at, viewed_by, target_doctype, target_name "
    "FROM `tabGAM Reveal Log` ORDER BY creation DESC LIMIT 3", as_dict=True
)

with open("/tmp/gam_probe_data.txt", "w") as f:
    f.write("=== ACCOUNTS ===\n")
    for a in accounts:
        f.write("ACC:%s\n" % a.name)
    f.write("=== NEWEST REVEAL ROWS (before probe) ===\n")
    for r in newest:
        f.write("%s | %s | %s | %s/%s\n" % (r.name, r.viewed_at, r.viewed_by, r.target_doctype, r.target_name))
    f.write("=== TOTAL ===\n%d\n" % frappe.db.count("GAM Reveal Log"))
print("written /tmp/gam_probe_data.txt")
