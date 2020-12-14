# Implements a blacklist on a scalar attribute

package terraform

import input.tfplan as tfplan

resource := "{resource_name}"

# The planned value for this scalr attribute
attribute := "{attribute_name}"

# Is checked against this blacklist. 
# If the value IS present in the list the policy is violated.
# This can be a single value list, and can be numerics, booleans or strings
black_list := [
	"{value}",
	"{value}",
]

# Check if value is in black list for the attribute
deny[reason] {
	r = tfplan.resource_changes[_]
	r.mode == "managed"
	r.type == resource
	black_list[_] == r.change.after[attribute]

	reason := sprintf("%-40s :: %s value '%s' is not allowed", 
	                     [r.address, attribute, r.change.after[attribute]])
}
