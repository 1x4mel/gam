app_name = "gam"
app_title = "GAM"
app_publisher = "GAM"
app_description = "Game Account Manager"
app_email = "gam@local"
app_license = "mit"

# Apps
# ------------------

# required_apps = []

# Each item in the list will be shown as an app in the apps page
# add_to_apps_screen = [
# 	{
# 		"name": "gam",
# 		"logo": "/assets/gam/logo.png",
# 		"title": "GAM",
# 		"route": "/gam",
# 		"has_permission": "gam.api.permission.has_app_permission"
# 	}
# ]

# Includes in <head>
# ------------------

# include js, css files in header of desk.html
# app_include_css = "/assets/gam/css/gam.css"
# app_include_js = "/assets/gam/js/gam.js"

# include js, css files in header of web template
# web_include_css = "/assets/gam/css/gam.css"
# web_include_js = "/assets/gam/js/gam.js"

# include custom scss in every website theme (without file extension ".scss")
# website_theme_scss = "gam/public/scss/website"

# include js, css files in header of web form
# webform_include_js = {"doctype": "public/js/doctype.js"}
# webform_include_css = {"doctype": "public/css/doctype.css"}

# include js in page
# page_js = {"page" : "public/js/file.js"}

# include js in doctype views
# doctype_js = {"doctype" : "public/js/doctype.js"}
# doctype_list_js = {"doctype" : "public/js/doctype_list.js"}
# doctype_tree_js = {"doctype" : "public/js/doctype_tree.js"}
# doctype_calendar_js = {"doctype" : "public/js/doctype_calendar.js"}

# Svg Icons
# ------------------
# include app icons in desk
# app_include_icons = "gam/public/icons.svg"

# Home Pages
# ----------

# application home page (will override Website Settings)
# home_page = "login"

# website user home page (by Role)
# role_home_page = {
# 	"Role": "home_page"
# }

# Generators
# ----------

# automatically create page for each record of this doctype
# website_generators = ["Web Page"]

# Jinja
# ----------

# add methods and filters to jinja environment
# jinja = {
# 	"methods": "gam.utils.jinja_methods",
# 	"filters": "gam.utils.jinja_filters"
# }

# Installation
# ------------

# before_install = "gam.install.before_install"
# after_install = "gam.install.after_install"

# Uninstallation
# ------------

# before_uninstall = "gam.uninstall.before_uninstall"
# after_uninstall = "gam.uninstall.after_uninstall"

# Integration Setup
# ------------------
# To set up dependencies/integrations with other apps
# Name of the app being installed is passed as an argument

# before_app_install = "gam.utils.before_app_install"
# after_app_install = "gam.utils.after_app_install"

# Integration Cleanup
# -------------------
# To clean up dependencies/integrations with other apps
# Name of the app being uninstalled is passed as an argument

# before_app_uninstall = "gam.utils.before_app_uninstall"
# after_app_uninstall = "gam.utils.after_app_uninstall"

# Desk Notifications
# ------------------
# See frappe.core.notifications.get_notification_config

# notification_config = "gam.notifications.get_notification_config"

# Permissions
# -----------
# Permissions evaluated in scripted ways

# permission_query_conditions = {
# 	"Event": "frappe.desk.doctype.event.event.get_permission_query_conditions",
# }
#
# has_permission = {
# 	"Event": "frappe.desk.doctype.event.event.has_permission",
# }

# ===== GAM access-grant ORM scoping (P1.1) =====
# Enforce L2 ROLE_GAME visibility at the ORM layer too (the API surface already
# gates via gam.api.get_accounts_list). Default OFF — flip gam_enforce_account_pqc=1
# in site_config after smoke-testing with a real member. See gam/permissions.py.
permission_query_conditions = {
	"GAM Account": "gam.permissions.get_pqc_for_gam_account",
	"GAM Account Role Game": "gam.permissions.get_pqc_for_gam_account_role_game",
}
has_permission = {
	"GAM Account": "gam.permissions.has_perm_gam_account",
}

# DocType Class
# ---------------
# Override standard doctype classes

# override_doctype_class = {
# 	"ToDo": "custom_app.overrides.CustomToDo"
# }

# Document Events
# ---------------
# Hook on document methods and events

# doc_events = {
# 	"*": {
# 		"on_update": "method",
# 		"on_cancel": "method",
# 		"on_trash": "method"
# 	}
# }

# Scheduled Tasks
# ---------------

# scheduler_events = {
# 	"all": [
# 		"gam.tasks.all"
# 	],
# 	"daily": [
# 		"gam.tasks.daily"
# 	],
# 	"hourly": [
# 		"gam.tasks.hourly"
# 	],
# 	"weekly": [
# 		"gam.tasks.weekly"
# 	],
# 	"monthly": [
# 		"gam.tasks.monthly"
# 	],
# }

# Testing
# -------

# before_tests = "gam.install.before_tests"

# Overriding Methods
# ------------------------------
#
# override_whitelisted_methods = {
# 	"frappe.desk.doctype.event.event.get_events": "gam.event.get_events"
# }
#
# each overriding function accepts a `data` argument;
# generated from the base implementation of the doctype dashboard,
# along with any modifications made in other Frappe apps
# override_doctype_dashboards = {
# 	"Task": "gam.task.get_dashboard_data"
# }

# exempt linked doctypes from being automatically cancelled
#
# auto_cancel_exempted_doctypes = ["Auto Repeat"]

# Ignore links to specified DocTypes when deleting documents
# -----------------------------------------------------------

# ignore_links_on_delete = ["Communication", "ToDo"]

# Request Events
# ----------------
# before_request = ["gam.utils.before_request"]
# after_request = ["gam.utils.after_request"]

# Job Events
# ----------
# before_job = ["gam.utils.before_job"]
# after_job = ["gam.utils.after_job"]

# User Data Protection
# --------------------

# user_data_fields = [
# 	{
# 		"doctype": "{doctype_1}",
# 		"filter_by": "{filter_by}",
# 		"redact_fields": ["{field_1}", "{field_2}"],
# 		"partial": 1,
# 	},
# 	{
# 		"doctype": "{doctype_2}",
# 		"filter_by": "{filter_by}",
# 		"partial": 1,
# 	},
# 	{
# 		"doctype": "{doctype_3}",
# 		"strict": False,
# 	},
# 	{
# 		"doctype": "{doctype_4}"
# 	}
# ]

# Authentication and authorization
# --------------------------------

# auth_hooks = [
# 	"gam.auth.validate"
# ]

# Automatically update python controller files with type annotations for this app.
# export_python_type_annotations = True

# default_log_clearing_doctypes = {
# 	"Logging DocType Name": 30  # days to retain logs
# }

# Translation
# ------------
# List of apps whose translatable strings should be excluded from this app's translations.
# ignore_translatable_strings_from = []

# ===== GAM CUSTOM HOOKS (managed) =====

# Install lifecycle: roles created before sync, seed after sync.
before_install = "gam.setup.before_install"
after_install = "gam.setup.after_install"

# App switcher (co-tenancy): GAM tile shown only to GAM roles / Administrator.
add_to_apps_screen = [
	{
		"name": "gam",
		"logo": "/assets/gam/images/gam-logo.svg",
		"title": "GAM",
		"route": "/gam-ui/",
		"has_permission": "gam.permission.has_app_permission",
	},
]

# Scheduled jobs
scheduler_events = {
	"all": [
		"gam.tasks.force_release_leases",
	],
	"daily": [
		"gam.tasks.flag_expiring_accounts",
		"gam.tasks.archive_audit_logs",
	],
	"cron": {
		"*/5 * * * *": ["gam.tasks.expire_email_codes"],
	},
}
