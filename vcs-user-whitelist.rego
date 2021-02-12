# Implements a whitelist of users allowed to perform VCS runs

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
	not array_contains(allowed_emails, tfrun.created_by.email)

	reason := sprintf("%s.%s :: user %s is not allowed to do VCS runs.", 
	                    [tfrun.environment.name, tfrun.workspace.name, tfrun.created_by.email])
}
