# AWS Templates

Library of OPA templates to meet common AWS Terraform requirements. 

**Work in Progress**

| Rego                     | Description |
| ------------------------ | -- |
| enforce_aws_resource.rego | Whitelist of allowed AWS resource types |
| enforce_cidr.rego | black list of CIDR's allowed on security group rules |
| enforce_iam_instance_profiles.rego | Whitelist of allowed IAM Instance profiles |
| enforce_instance_subnet.rego | Whitelist of allowed subnets |
| enforce_kms_key_names.rego | Enforces the use of specified KMS Keys in all applicable resource types |
| enforce_lb_subnets.rego | Enforces specified subnets on load balancers |
| enforce_rds_subnets.rego | Enforces specified subnets on RDS |
| enforce_s3_buckets_encryption.rego | Enforces encryption on S3 buckets |
| enforce_s3_private.rego | Ensures S3 buckets are private |
| enforce_sec_group.rego | Enforces the use of specific security group |
