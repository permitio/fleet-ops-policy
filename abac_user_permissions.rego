package permit.abac_user_permissions

import data.permit.abac as abac
import data.permit.generated.abac.utils

import future.keywords.in

default use_contextualized_instances := false
default use_contextualized_role_assignments := false

use_contextualized_instances {
    input.context.data.resource_instances
} else {
    input.context.use_factdb
}

use_contextualized_role_assignments {
  input.context.data.role_assignments
} else {
  input.context.use_factdb
}

get_resource_instances_and_tenants(user_key) := result {
  use_contextualized_instances
  result := object.union(input.context.data.resource_instances, tenants_match_to_user_roles(user_key))
} else = result {
  result := object.union(data.resource_instances, tenants_match_to_user_roles(user_key))
}

get_tenant_attributes_from_data(tenant) := result {
  result := data.tenants[tenant].attributes
} else := result {
  result := {}
}

build_tenant_obj(tenant) := result {
  result := {
    "key":tenant,
    "attributes":get_tenant_attributes_from_data(tenant)
  }
}

# Return custom input for resource_instance and tenant
# Args:
# instance: key of resource_instances_and_tenants can be the key of resource instance or the key of tenant
# instance_data: value of resource_instances_and_tenants can be the value of resource instance or true in case of tenant(no use in case of tenant)
# resource_type: the resource type of resource_instance or tenant (used only in case of resource instance)
# user_key: user key
# parts: array with 2 items the first is the resource_type and the second is the resource key
# allowed_type: the resource type that supplied in the input
custom_input(instance, instance_data, user_key, parts, allowed_type) = result {
    # If it tenant resource
    data.tenants[instance] != null
    result := {
      "user": input.user,
      "resource": {
        "type": allowed_type,
        "tenant": instance
      }
    }
} else = result {
	# If it resource_instnace resource
    result :=  {
      "user": input.user,
      "resource": {
        "type": allowed_type,
        "key": parts[1],
        "attributes":object.get(instance_data,"attributes",{}),
        "tenant": object.get(instance_data,"tenant","default")
      }
    }

}

get_actions(value,_input) := result {
    data.condition_set_rules_expand
    count(data.condition_set_rules_expand) > 0
    result := data.condition_set_rules_expand[value.user][value.resource][_input.resource.type]
} else = result {
    result := data.condition_set_rules[value.user][value.resource][_input.resource.type]
}

# Check if the resources types provided in the input match to resource_instance type
# or if the instace_data value is true (when true the tenant key
# from tenants_match_to_user_roles has a role that related to the user )
resource_instance_or_tenant_match_user(resource_type, allowed_type,instance_data ) {
    resource_type == allowed_type
} else {
    instance_data == true
}

# add prefix of __tenant if the resource is tenant and keep the same if it from resource instance family
add_prefix(instance_data, instance) = result {
    instance_data == true
    result := sprintf("__tenant:%s", [instance])

} else = result {
    result := instance
}

# Optional input.resources filter — scope the response to a specific set of resource keys.
# Mirrors __input_resources / is_filtered_resource handling in user_permissions.rego so that
# ABAC results obey the same filter as RBAC/ReBAC results.
__input_resources := object.get(input, "resources", null)

non_tenant_resources_filter[inst] {
    inst := __input_resources[_]
    not startswith(inst, "__tenant")
}

default has_non_tenant_resource_filter := false
has_non_tenant_resource_filter {
    count(non_tenant_resources_filter) > 0
}

# Resource instances: match by fully-qualified "type:key" or by bare key, or pass through
# when the filter contains no non-tenant entries (empty or tenant-only resources array).
# This mirrors is_filtered_instance in user_permissions.rego.
#
# Tenants (instance_data == true): match ONLY by the fully-qualified "__tenant:key" form,
# or pass through when the filter contains no non-tenant entries. This mirrors the
# `__input_resources` (resources) branch of is_filtered_tenant in user_permissions.rego,
# which matches a tenant by resource.fully_qualified_key ("__tenant:key") and NOT by its
# bare key. Bare-key tenant matching in user_permissions.rego is reserved for the dedicated
# `tenants` input field (_is_filtered_tenant), which this filter intentionally does not model.
instance_passes_resource_filter(_, _, _) {
    not is_array(__input_resources)
}
instance_passes_resource_filter(instance, instance_data, _) {
    is_array(__input_resources)
    instance_data == true
    sprintf("__tenant:%s", [instance]) in __input_resources
}
instance_passes_resource_filter(_, instance_data, _) {
    is_array(__input_resources)
    instance_data == true
    not has_non_tenant_resource_filter
}
instance_passes_resource_filter(instance, instance_data, _) {
    is_array(__input_resources)
    not instance_data == true
    instance in __input_resources
}
instance_passes_resource_filter(_, instance_data, parts) {
    is_array(__input_resources)
    not instance_data == true
    parts[1] in __input_resources
}
instance_passes_resource_filter(_, instance_data, _) {
    is_array(__input_resources)
    not instance_data == true
    not has_non_tenant_resource_filter
}


# Iterate over data.role_assigments and return set of all tenants that user related to in the format { "tenant_key" : true}
tenants_match_to_user_roles(user_key) = {tenant: true |
    role_assigment := data.role_assignments[sprintf("user:%s",[user_key])]
	some key, _ in role_assigment
		parts := split(key, ":")
    parts[0] == "__tenant"
		tenant := parts[1]
}

permissions[ps] {
    user_key := input.user.key
	# create an union set of all the resource instances and a tenants keys that user has a role on them
    resource_instances_and_tenants := get_resource_instances_and_tenants(user_key)
	# implicit iteration over the resource_types input to check matching resource instnaces
    allowed_type := input.resource_types[_]
		some instance, instance_data in resource_instances_and_tenants
			parts := split(instance, ":")
			resource_type := parts[0]

			resource_instance_or_tenant_match_user(resource_type, allowed_type,instance_data )
			instance_passes_resource_filter(instance, instance_data, parts)

			_input := custom_input(instance, instance_data, user_key, parts, allowed_type)
      some value in abac.matching_users_and_resources_set with input as _input
					actions := get_actions(value,_input)
					permissions := {p | action := actions[_]; p := sprintf("%s:%s", [_input.resource.type, action])}
					ps := {add_prefix(instance_data, instance): {
            "permissions": permissions,
            "userset": value.user,
            "resourceset": value.resource,
            "tenant":build_tenant_obj(_input.resource.tenant)
          }}}
