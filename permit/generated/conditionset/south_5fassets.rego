package permit.generated.conditionset

import future.keywords.in

import data.permit.generated.abac.utils.attributes

default resourceset_south_5fassets = false

resourceset_south_5fassets {
	attributes.resource.region == "South"
	attributes.resource.type == "asset"
}
