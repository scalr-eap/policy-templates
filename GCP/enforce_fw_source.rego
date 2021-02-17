# Enforces the denial of CIDR 0.0.0.0/0 in firewalls

package terraform 

import input.tfplan as tfplan

# Add CIDRS that should be disallowed
invalid_cidrs = [
  "0.0.0.0/0"
]

array_contains(arr, elem) {
  arr[_] = elem
}

# Checks firewall rules
deny[reason] {
  r := tfplan.resource_changes[_]
  r.type == "google_compute_firewall"
  invalid := invalid_cidrs[_]
  array_contains(r.change.after.source_ranges,invalid)
  reason := sprintf(
              "%-40s :: Firewall source range invalid CIDR %s",
              [r.address,invalid]
            )
}