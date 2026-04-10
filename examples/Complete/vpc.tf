data "aws_region" "default" {}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.0.0"

  azs                                             = var.azs
  cidr                                            = var.vpc_cidr
  create_flow_log_cloudwatch_iam_role             = true
  create_flow_log_cloudwatch_log_group            = true
  default_network_acl_name                        = "${var.vpc_name}-default-nacl"
  default_security_group_egress                   = []
  default_security_group_ingress                  = []
  default_security_group_name                     = "${var.vpc_name}-default-sg"
  enable_dns_hostnames                            = true
  enable_flow_log                                 = true
  flow_log_cloudwatch_log_group_retention_in_days = 14
  flow_log_log_format                             = "$${account-id} $${az-id} $${vpc-id} $${flow-direction} $${action} $${interface-id} $${srcaddr} $${pkt-srcaddr} $${srcport} $${dstaddr} $${pkt-dstaddr} $${dstport} $${packets} $${type} $${protocol} $${tcp-flags}"
  manage_default_network_acl                      = true
  manage_default_security_group                   = true
  name                                            = var.vpc_name
}
