locals {
  network_firewall_to_nat_gateway = [for i, az in var.azs : {
    az             = az
    route_table_id = aws_route_table.network_firewall[i].id
    nat_gateway_id = aws_nat_gateway.default[i].id
  }]

  nat_gateway_to_internet_gateway = [for i, az in var.azs : {
    az             = az
    route_table_id = aws_route_table.public[i].id
  }]

  nat_gateway_to_network_firewall = flatten([
    for cidr in var.private_subnets : [
      for i, az in var.azs : {
        az          = az
        rt_id       = aws_route_table.public[i].id
        cidr        = cidr
        endpoint_id = lookup(local.network_firewall_attachments, az, "default")
      }
    ]
  ])

  network_firewall_attachments = {
    for sync_state in module.network_firewall.firewall_status[0].sync_states :
    sync_state.availability_zone => sync_state.attachment[0].endpoint_id
  }

  private_subnet_to_network_firewall = [for i, az in var.azs : {
    az             = az
    route_table_id = aws_route_table.private[i].id
    endpoint_id    = lookup(local.network_firewall_attachments, az, "default")
  }]

}

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

################################################################################
# VPC Endpoints
################################################################################

module "endpoint_sg" {
  source              = "terraform-aws-modules/security-group/aws"
  version             = "5.1.0"
  name                = "${var.vpc_name}-vpc_endpoint-access"
  description         = "Allow access to VPC endpoints from the VPC source"
  ingress_cidr_blocks = [var.vpc_cidr]
  ingress_rules       = ["all-all"]
  vpc_id              = module.vpc.vpc_id
}

module "endpoints" {
  source  = "terraform-aws-modules/vpc/aws//modules/vpc-endpoints"
  version = "5.0.0"

  vpc_id             = module.vpc.vpc_id
  security_group_ids = [module.endpoint_sg.security_group_id]

  endpoints = {
    ec2 = {
      service             = "ec2"
      private_dns_enabled = true
      subnet_ids          = aws_subnet.private[*].id
    },
    ec2messages = {
      service             = "ec2messages"
      private_dns_enabled = true
      subnet_ids          = aws_subnet.private[*].id
    },
    ssm = {
      service             = "ssm"
      private_dns_enabled = true
      subnet_ids          = aws_subnet.private[*].id
    },
    ssmmessages = {
      service             = "ssmmessages"
      private_dns_enabled = true
      subnet_ids          = aws_subnet.private[*].id
    },
  }
}

################################################################################
# Public subnets
################################################################################

resource "aws_subnet" "public" {
  count = length(var.public_subnets)

  availability_zone    = length(regexall("^[a-z]{2}-", element(var.azs, count.index))) > 0 ? element(var.azs, count.index) : null
  availability_zone_id = length(regexall("^[a-z]{2}-", element(var.azs, count.index))) == 0 ? element(var.azs, count.index) : null
  cidr_block           = var.public_subnets[count.index]
  vpc_id               = module.vpc.vpc_id
  tags                 = { Name = format("%s-${"public"}-%s", var.vpc_name, element(var.azs, count.index), ) }
}

resource "aws_route_table" "public" {
  count = length(var.public_subnets)

  vpc_id = module.vpc.vpc_id
  tags   = { Name = format("%s-${"public"}-%s", var.vpc_name, element(var.azs, count.index), ) }
}

resource "aws_route_table_association" "public" {
  count = length(var.public_subnets)

  route_table_id = element(aws_route_table.public[*].id, count.index)
  subnet_id      = element(aws_subnet.public[*].id, count.index)
}

################################################################################
# AWS Network Firewall subnets
################################################################################

resource "aws_subnet" "network_firewall" {
  count = length(var.network_firewall_subnets)

  availability_zone    = length(regexall("^[a-z]{2}-", element(var.azs, count.index))) > 0 ? element(var.azs, count.index) : null
  availability_zone_id = length(regexall("^[a-z]{2}-", element(var.azs, count.index))) == 0 ? element(var.azs, count.index) : null
  cidr_block           = var.network_firewall_subnets[count.index]
  vpc_id               = module.vpc.vpc_id
  tags                 = { Name = format("%s-${"network-firewall"}-%s", var.vpc_name, element(var.azs, count.index), ) }
}

resource "aws_route_table" "network_firewall" {
  count = length(var.network_firewall_subnets)

  vpc_id = module.vpc.vpc_id
  tags   = { Name = format("%s-${"network-firewall"}-%s", var.vpc_name, element(var.azs, count.index), ) }
}

resource "aws_route_table_association" "network_firewall" {
  count = length(var.network_firewall_subnets)

  route_table_id = element(aws_route_table.network_firewall[*].id, count.index)
  subnet_id      = element(aws_subnet.network_firewall[*].id, count.index)
}

################################################################################
# Private subnets
################################################################################

resource "aws_subnet" "private" {
  count = length(var.private_subnets)

  availability_zone    = length(regexall("^[a-z]{2}-", element(var.azs, count.index))) > 0 ? element(var.azs, count.index) : null
  availability_zone_id = length(regexall("^[a-z]{2}-", element(var.azs, count.index))) == 0 ? element(var.azs, count.index) : null
  cidr_block           = var.private_subnets[count.index]
  vpc_id               = module.vpc.vpc_id
  tags                 = { Name = format("%s-${"private"}-%s", var.vpc_name, element(var.azs, count.index), ) }
}

resource "aws_route_table" "private" {
  count = length(var.private_subnets)

  vpc_id = module.vpc.vpc_id
  tags   = { Name = format("%s-${"private"}-%s", var.vpc_name, element(var.azs, count.index), ) }
}

resource "aws_route_table_association" "private" {
  count = length(var.private_subnets)

  route_table_id = element(aws_route_table.private[*].id, count.index)
  subnet_id      = element(aws_subnet.private[*].id, count.index)
}

################################################################################
# Internet and Nat Gateway
################################################################################

resource "aws_internet_gateway" "default" {
  vpc_id = module.vpc.vpc_id
  tags   = { Name = format("%s-${"internet-gateway"}", var.vpc_name, ) }
}

resource "aws_eip" "nat" {
  #checkov:skip=CKV2_AWS_19: Ensure that all EIP addresses allocated to a VPC are attached to EC2 instances (false positive, eip's are attached to the nat gateway's)
  count = length(var.public_subnets)

  tags = { Name = format("%s-${"nat-gateway"}-%s", var.vpc_name, element(var.azs, count.index), ) }
}

resource "aws_nat_gateway" "default" {
  count = length(var.public_subnets)

  allocation_id = element(aws_eip.nat[*].id, count.index)
  subnet_id     = element(aws_subnet.public[*].id, count.index)
  tags          = { Name = format("%s-${"nat-gateway"}-%s", var.vpc_name, element(var.azs, count.index), ) }

  depends_on = [aws_internet_gateway.default]
}

################################################################################
# Routing for egress traffic to internet
################################################################################

resource "aws_route" "nat_gateway_to_internet_gateway" {
  for_each = { for obj in local.nat_gateway_to_internet_gateway : "rt_${var.vpc_name}-public-${obj.az}" => obj }

  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.default.id
  route_table_id         = each.value.route_table_id
}


resource "aws_route" "network_firewall_to_nat_gateway" {
  for_each = { for obj in local.network_firewall_to_nat_gateway : "rt_${var.vpc_name}-network-firewall-${obj.az}" => obj }

  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = each.value.nat_gateway_id
  route_table_id         = each.value.route_table_id
}

resource "aws_route" "private_subnet_to_network_firewall" {
  for_each = { for obj in local.private_subnet_to_network_firewall : "rt_${var.vpc_name}-private-${obj.az}" => obj }

  destination_cidr_block = "0.0.0.0/0"
  route_table_id         = each.value.route_table_id
  vpc_endpoint_id        = each.value.endpoint_id
}

################################################################################
# Routing for ingress traffic from internet
################################################################################

resource "aws_route" "nat_gateway_to_network_firewall" {
  for_each = { for obj in local.nat_gateway_to_network_firewall : "rt_${var.vpc_name}-public-${obj.az}_${obj.cidr}" => obj }

  destination_cidr_block = each.value.cidr
  route_table_id         = each.value.rt_id
  vpc_endpoint_id        = each.value.endpoint_id
}


################################################################################
# EC2 test instance
################################################################################

data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.2.20231018.2-kernel-6.1-x86_64"]
  }
}

#Private subnet A
module "ec2_instance_a" {
  source  = "terraform-aws-modules/ec2-instance/aws"
  version = "5.2.1"

  name = "connectivity-test-a"

  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = "t3.micro"
  key_name               = "your-ec2-key"
  monitoring             = true
  vpc_security_group_ids = [module.ec2_security_group.security_group_id]
  subnet_id              = aws_subnet.private[0].id
  iam_instance_profile   = "AmazonSSMManagedInstanceCore"

  metadata_options = { "http_endpoint" : "enabled", "http_put_response_hop_limit" : 1, "http_tokens" : "required" }
}

#Private subnet c
module "ec2_instance_c" {
  source  = "terraform-aws-modules/ec2-instance/aws"
  version = "5.2.1"

  name = "connectivity-test-c"

  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = "t3.micro"
  key_name               = "your-ec2-key"
  monitoring             = true
  vpc_security_group_ids = [module.ec2_security_group.security_group_id]
  subnet_id              = aws_subnet.private[2].id
  iam_instance_profile   = "AmazonSSMManagedInstanceCore"

  metadata_options = { "http_endpoint" : "enabled", "http_put_response_hop_limit" : 1, "http_tokens" : "required" }
}

module "ec2_security_group" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "5.1.0"

  name        = "connectivity-test-ec2"
  description = "Security group for connectivity test EC2 instance"
  vpc_id      = module.vpc.vpc_id

  ingress_cidr_blocks = ["0.0.0.0/0"]
  ingress_rules       = ["http-80-tcp", "all-icmp"]
  egress_rules        = ["all-all"]
}
