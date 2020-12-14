# Implements min/max values for numeric attribute 

# Policy can implement a min value, max value or both.
# Simply set max or min to null to remove these checks

package terraform

import input.tfplan as tfplan

resource := "{resource}"

# Check the planned value for this numeric attribute
attribute := "{attribute}"

# Minimum value allowed. Set to null if no minimum.
min := {N or null}

# Maximum value allowed. Set to null if no maximum.
max := {N or null}

# Check if value is below min
deny[reason] {
	r = tfplan.resource_changes[_]
	r.mode == "managed"
	r.type == resource

  # OPA considers 'null' to be a type rather than an indicator of no value.
  # It has a pecendent for comparing in which a null type is always < a numeric.
  # This when min := null the attribute value is always > min. 
  # This gives the desired result, albeit for the wrong reason.
  r.change.after[attribute] < min

	reason := sprintf("%-40s :: %s value '%d' is less then allowed minimum '%d'.", [r.address, attribute, r.change.after[attribute], min])
}

# Check if value is above max
deny[reason] {
	r = tfplan.resource_changes[_]
	r.mode == "managed"
	r.type == resource

  # This fudge is needed due to an odd use of 'null' in OPA.
  # OPA considers 'null' to be a type rather than an indicator of no value.
  # It has a pecendent for comparing in which a null type is always < a numeric.
  # Thus when comparing the attribute > max this is always true when max := null, 
  # when in fact we want undefined so the rule ends.
  # The rule below forces this.
  not is_null(max)

  r.change.after[attribute] > max

	reason := sprintf("%-40s :: %s value '%d' is greater than allowed maximum '%d'.", [r.address, attribute, r.change.after[attribute], max])
}