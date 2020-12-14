# Implements a whitelist on resource types 

package terraform

import input.tfplan as tfplan

# resource type is checked against this whitelist. 
# If the value IS NOT present in the list the policy is violated.
white_list := [
	"{value}",
	"{value}",
]

array_contains(arr, elem) {
	arr[_] == elem
}

# Check if value is in black list for the attribute
deny[reason] {
	r = tfplan.resource_changes[_]
	r.mode == "managed"
	not array_contains(white_list, r.type)

	reason := sprintf("%-40s :: Resource type '%s' is not allowed", [r.address, r.type])
}
