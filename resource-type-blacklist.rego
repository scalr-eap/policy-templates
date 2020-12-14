# Implements a blacklist on resource types 

package terraform

import input.tfplan as tfplan

# resource type is checked against this blacklist. 
# If the value IS present in the list the policy is violated.
black_list := [
	"{value}",
	"{value}",
]

# Check if value is in black list for the attribute
deny[reason] {
	r = tfplan.resource_changes[_]
	r.mode == "managed"
	black_list[_] == r.type

	reason := sprintf("%-40s :: Resource type '%s' is not allowed", [r.address, r.type])
}
