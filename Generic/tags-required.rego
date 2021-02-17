# Enforces a set of required tag keys for given resource types. Values are not checked

package terraform

import input.tfplan as tfplan

tags_map := [
	{
		"type": "aws_instance",
		"tags_required": [
			"owner",
      "foo",
			"department",
		],
	},
  {
		"type": "aws_subnet",
		"tags_required": [
			"secure",
      "muppets"
		],
	}
]

array_contains(arr, elem) {
  arr[_] = elem
}

get_basename(path) = basename{
    arr := split(path, "/")
    basename:= arr[count(arr)-1]
}

# Extract the tags catering for Google where they are called "labels"
get_tags(resource) = labels {
    # registry.terraform.io/hashicorp/google -> google
    provider_name := get_basename(resource.provider_name)
    "google" == provider_name
    labels := resource.change.after.labels
} else = tags {
    tags := resource.change.after.tags
} else = empty {
    empty := {}
}

deny[reason] {
    r := tfplan.resource_changes[_]
    action := r.change.actions[count(r.change.actions) - 1]
    array_contains(["create", "update"], action)
    tags := get_tags(r)
    # creates an array of the existing tag keys
    existing_tags := [ key | tags[key] ]
    # Traverse the maps comparing tags by type
    tm := tags_map[_]
    r.type == tm.type
    required_tag := tm.tags_required[_]
    not array_contains(existing_tags, required_tag)

	  reason := sprintf("%-40s :: tag '%s' is required.", 
	                    [r.address, required_tag])
    
}
