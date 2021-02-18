# Enforces the denial of CIDR 0.0.0.0/0 in Inbound rules

package terraform 

import input.tfplan as tfplan

# Add CIDRS that should be disallowed
invalid_cidrs = [
  "0.0.0.0/0"
]

array_contains(arr, elem) {
  arr[_] = elem
}

types = [
  "azurerm_firewall_nat_rule_collection",
  "azurerm_firewall_network_rule_collection",
  "azurerm_firewall_application_rule_collection"
]

# Checks embdedded rules
deny[reason] {
  r := tfplan.resource_changes[_]
  array_contains(types,r.type)
  in := r.change.after.rule[_]
  invalid := invalid_cidrs[_]
  array_contains(in.source_addresses,invalid)
  reason := sprintf(
              "%-40s :: invalid ingress CIDR %s",
              [r.address,invalid]
            )
}
