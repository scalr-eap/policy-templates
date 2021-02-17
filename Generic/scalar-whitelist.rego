# Implements a whitelist on a scalar attribute

package terraform

import input.tfplan as tfplan

resource := "{resource_name}"

# The planned value for this scalr attribute
attribute := "{attribute_name}"

# Is checked against this whitelist. 
# If the value IS NOT present in the list the policy is violated.
# This can be a single value list, and can be numerics, booleans or strings
white_list := [
	"{value}",
	"{value}",
]

array_contains(arr, elem) {
	arr[_] == elem
}

# Check if value is in white list for the attribute
deny[reason] {
	r = tfplan.resource_changes[_]
	r.mode == "managed"
	r.type == resource
	not array_contains(white_list, r.change.after[attribute])

	reason := sprintf("%-40s :: %s value '%s' is not allowed.", 
	                    [r.address, attribute, r.change.after[attribute]])
}
