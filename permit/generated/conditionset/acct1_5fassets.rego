package permit.generated.conditionset

import future.keywords.in

import data.permit.generated.abac.utils.attributes

default resourceset_acct1_5fassets = false

resourceset_acct1_5fassets {
	attributes.resource.served_account == "Acct1"
	attributes.resource.type == "asset"
}
