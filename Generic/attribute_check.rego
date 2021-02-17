# Checks that required attributes have been specified

package terraform

import input.tfplan as tfplan

resource := "{resource}"

# Attributes in the list must have a planned value (not null). 
attribute_list := [
	"{attribute}",
	"{attribute}",
]

# Check if the attribute has been specified
deny[reason] {
	r = tfplan.resource_changes[_]
	r.mode == "managed"
	r.type == resource
  attribute = attribute_list[_]
	not r.change.after[attribute]

	reason := sprintf("%-40s :: '%s' must be specified in the configuration", [r.address, attribute])
}

# Check if the attribute value is null
deny[reason] {
	r = tfplan.resource_changes[_]
	r.mode == "managed"
	r.type == resource
  attribute = attribute_list[_]
	is_null(r.change.after[attribute])
	
	reason := sprintf("%-40s :: '%s' must have a none null value in the configuration", [r.address, attribute])
}
