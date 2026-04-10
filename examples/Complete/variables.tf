variable "azs" {
  type        = list(string)
  default     = ["eu-west-1a", "eu-west-1b", "eu-west-1c"]
  description = "A list of availability zones names in the region"
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
