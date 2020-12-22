# Implements a REGEX check on an attribute value

package terraform

import input.tfplan as tfplan

resource := "{resource}"

# The planned value for this array attribute
attribute := "{attribute}"

regex := "{regex}"

# Check if value matches the regex
deny[reason] {
	r = tfplan.resource_changes[_]
	r.mode == "managed"
	r.type == resource
	not re_match(regex, r.change.after[attribute])
	
	reason := sprintf("%-40s :: %s value '%s' does not match allowed regex '%s'.", [r.address, attribute, r.change.after[attribute], regex])
}
