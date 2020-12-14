# Scalr Policy Templates

Library of templates to meet common OPA with Terraform requirements.

| Rego                     | Description |
| ------------------------ | -- |
| actions-blacklist.rego | Black list for Actions, Create, Update Delete |
| array-blacklist.rego | Black list for values of an array type attribute |
| array-whitelist.rego | White list for values of an array type attribute  |
| attribute_check.rego | Check that an attribute has been specified and with a non-null value |
| attribute_value_regex.rego | Check attribute value matches a regular expression |
| numeric-range.rego | Check an attribute numeric value is within range (>=min, <=max or both) |
| resource-type-blacklist.rego | Black list of resource types |
| resource-type-whitelist.rego | White list of resource types |
| scalar-blacklist.rego | Black list for values of a scalar type attribute |
| scalar-whitelist.rego | White list for values of a scalar type attribute |

In general these templates can be configured simply by setting the resources, attribute and ...list variables as in this example

```
...
resource := "{resource_name}"
 
# The planned value for this scalr attribute
attribute := "{attribute_name}"
 
# Is checked against this blacklist. If the value IS present in the list the polciy is violated.
# This can be a single value list, and can be numerics, booleans or strings
black_list := [
 "{value}",
 "{value}",
]
...
```