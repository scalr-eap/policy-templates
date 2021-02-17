# Scalr OPA Templates

Library of OPA templates to meet common Terraform requirements.

Organized into folders for convenience.

DISCLAIMER: 

These policies have been tested against limited sets of `terraform plan` outputs. No warranty is given that they will work as desired in all cases and anyone utilizing these policies must test them in their own environments before putting them into live use.

| Folder                     | Description |
| ------------------------ | -- |
| Generic | These templates are cloud agnostic and provide a simple way to implement white or black lists on values for attributes. |
| AWS | Policies specific to Amazon Web Services |
| GCP | Policies specific to Google Cloud Platform |
| Azure | Policies specific to Microsoft Azure |

Please see https://docs.scalr.com/en/latest/opa.html for details of integrating OPA policies with Scalr.


