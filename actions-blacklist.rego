# Implements a black list of acions, with optional resource list.
#
# This can be tailored to deny specific actions on all resources or just those in the resource list
#

package terraform

import input.tfplan as tfplan

# Terraform resources this policy applies to.
# Comment this out to apply the black list to ALL resources. 
# This is ignored if `resources[_] == type` is removed from the deny rule
resources = [
	"{resource_type}",
	"{resource_type}",
	"{resource_type}",
]

# Modify the array to only include disallowed actions
actions_black_list := [
	"delete",
	"create",
	"update",
]

deny[reason] {
	r := tfplan.resource_changes[_]
	type := r.type

	# Comment out this line to apply the policy to ALL resources
	resources[_] == type

	action := r.change.actions[_]

	actions_black_list[_] == action

	reason := sprintf("%-40s :: '%s' action is not allowed for resource type '%s'", [r.address, action, type])
}
