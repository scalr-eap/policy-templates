# Implements a whitelist of users allowed to auto-apply runs

package terraform

import input.tfrun as tfrun

allowed_emails := [
	"{value}",
	"{value}",
]

array_contains(arr, elem) {
	arr[_] == elem
}

# Check if value is in white list for the attribute
deny[reason] {
	tfrun.source == "vcs"
  tfrun.workspace.auto_apply == true
  tfrun.is_dry == false
	not array_contains(allowed_emails, tfrun.created_by.email)

	reason := sprintf("%s.%s :: user %s is not allowed to auto-apply runs.", 
	                    [tfrun.environment.name, tfrun.workspace.name, tfrun.created_by.email])
}
