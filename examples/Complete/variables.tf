variable "azs" {
  type        = list(string)
  default     = ["eu-west-1a", "eu-west-1b", "eu-west-1c"]
  description = "A list of availability zones names in the region"
}

variable "network_firewall_subnets" {
  type        = list(string)
  description = "List of CIDRS to use for the firewall subnets"
  default     = ["10.0.4.0/24", "10.0.5.0/24", "10.0.6.0/24"]
}

variable "private_subnets" {
  type        = list(string)
  description = "List of CIDRS to use for the private subnets"
  default     = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
}

variable "public_subnets" {
  type        = list(string)
  description = "List of CIDRS to use for the public subnets"
  default     = ["10.0.7.0/24", "10.0.8.0/24", "10.0.9.0/24"]
}

variable "vpc_name" {
  type        = string
  description = "Name of the VPC"
  default     = "aws-network-firewall-vpc"
}

variable "vpc_cidr" {
  type        = string
  description = "CIDR of the VPC"
  default     = "10.0.0.0/16"
}
