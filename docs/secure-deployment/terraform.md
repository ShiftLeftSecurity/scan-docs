# Terraform secure coding

Terraform scan is powered by tfsec which uses Hashicorp's AST library for improved analysis.

## Rules

Currently, checks are mostly limited to AWS/Azure/GCP resources, but there are also checks which are provider agnostic.

| Rule   | Provider | Description                                                       |
| ------ | -------- | ----------------------------------------------------------------- |
| GEN001 | Generic  | Potentially sensitive data stored in "default" value of variable. |
| GEN002 | Generic  | Potentially sensitive data stored in local value.                 |
| GEN003 | Generic  | Potentially sensitive data stored in block attribute.             |
| AWS001 | aws      | S3 Bucket has an ACL defined which allows public access.          |
| AWS002 | aws      | S3 Bucket does not have logging enabled.                          |
| AWS003 | aws      | AWS Classic resource usage.                                       |
| AWS004 | aws      | Use of plain HTTP.                                                |
| AWS005 | aws      | Load balancer is exposed to the internet.                         |
| AWS006 | aws      | An ingress security group rule allows traffic from `/0`.          |
| AWS007 | aws      | An egress security group rule allows traffic to `/0`.             |
| AWS008 | aws      | An inline ingress security group rule allows traffic from `/0`.   |
| AWS009 | aws      | An inline egress security group rule allows traffic to `/0`.      |
| AWS010 | aws      | An outdated SSL policy is in use by a load balancer.              |
| AWS011 | aws      | A resource is marked as publicly accessible.                      |
| AWS012 | aws      | A resource has a public IP address.                               |
| AWS013 | aws      | Task definition defines sensitive environment variable(s).        |
| AWS014 | aws      | Launch configuration with unencrypted block device.               |
| AWS015 | aws      | Unencrypted SQS queue.                                            |
| AWS016 | aws      | Unencrypted SNS topic.                                            |
| AWS017 | aws      | Unencrypted S3 bucket.                                            |
| AWS018 | aws      | Missing description for security group/security group rule.       |
| AWS019 | aws      | A KMS key is not configured to auto-rotate                        |
| AWS020 | aws      | CloudFront distribution allows unencrypted (HTTP) communications. |
| AWS021 | aws      | CloudFront distribution uses outdated SSL/TSL protocols.          |
| AWS022 | aws      | A MSK cluster allows unencrypted data in transit.                 |
| AZU001 | azurerm  | An inbound network security rule allows traffic from `/0`.        |
| AZU002 | azurerm  | An outbound network security rule allows traffic to `/0`.         |
| AZU003 | azurerm  | Unencrypted managed disk.                                         |
| AZU004 | azurerm  | Unencrypted data lake store.                                      |
| AZU005 | azurerm  | Password authentication in use instead of SSH keys.               |
| GCP001 | google   | Unencrypted compute disk.                                         |
| GCP002 | google   | Unencrypted storage bucket.                                       |
| GCP003 | google   | An inbound firewall rule allows traffic from `/0`.                |
| GCP004 | google   | An outbound firewall rule allows traffic to `/0`.                 |
| GCP005 | google   | Legacy ABAC permissions are enabled.                              |
