package permit.root

import data.permit.custom
import data.permit.debug
import data.permit.policies

default allow := false

# Fleet Ops demo: the generated policy (RBAC, ReBAC, ABAC) or a grant in custom/root.rego must allow,
# AND the request must satisfy the tenant-isolation rule and the fleet rules in custom/root.rego.
# Custom code adds constraints, and grants only through the second rule.
# Permit may regenerate this file after policy changes in the dashboard. If `make verify` reports
# the rules missing, run `make apply-policy` in fleetops-go to re-apply them.
allow {
	policies.allow
	custom.acting_org_ok
	custom.fleet_rules_ok
}

allow {
	custom.extra_allow
	custom.acting_org_ok
	custom.fleet_rules_ok
}

allowing_sources := policies.__allow_sources

default __data_use_debugger := true

__data_use_debugger = data.use_debugger

default __input_use_debugger := null

__input_use_debugger = input.use_debugger

default debugger_activated := false

debugger_activated {
	__data_use_debugger == true
	__input_use_debugger != false
} else {
	__input_use_debugger == true
}

debug = result {
	debugger_activated
	result := object.union(debug.debug, {"acting_org": custom.acting_org_debug, "fleet_rules": custom.fleet_rules_debug})
}
