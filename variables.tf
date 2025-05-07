variable "cloudwatch_logging_configuration" {
  type = object({
    alert_logs = optional(object({
      enabled           = optional(bool, true)
      log_group_prefix  = optional(string, "/platform/")
      retention_in_days = optional(number, 90)
    }), {})
    flow_logs = optional(object({
      enabled           = optional(bool, true)
      log_group_prefix  = optional(string, "/platform/")
      retention_in_days = optional(number, 90)
    }), {})
  })
  default     = {}
  description = "Cloudwatch logs configuration"
}

variable "delete_protection" {
  type        = bool
  description = "A boolean flag indicating whether it is possible to delete the firewall"
  default     = true
}

variable "description" {
  type        = string
  description = "Description of the firewall instance"
  default     = "AWS Network Firewall"
}

variable "fqdn_rules" {
  type = map(object({
    action    = string
    fqdns     = list(string)
    priority  = number
    source_ip = list(string)
  }))
  default     = {}
  description = "Map with L7 egress firewall rules"
}

variable "fqdn_rules_capacity" {
  type        = number
  description = "Capacity of the rule group"
  default     = 1000
}

variable "fqdn_rule_group_priority" {
  type        = number
  description = "Priority of the rule group"
  default     = 30
}

variable "home_net" {
  type        = list(string)
  description = "List of CIDRs to override the HOME_NET variable with"
  default     = []
}

variable "ip_rules" {
  type = map(object({
    action           = string
    destination_ip   = list(string)
    destination_port = list(string)
    direction        = string
    priority         = number
    protocol         = string
    source_ip        = list(string)
    source_port      = list(string)
  }))
  default     = {}
  description = "Map with L4 firewall rules"
}

variable "ip_rules_capacity" {
  type        = number
  description = "Capacity of the rule group"
  default     = 1000
}

variable "ip_rule_group_priority" {
  type        = number
  description = "Priority of the rule group"
  default     = 40
}

variable "kms_key_arn" {
  type        = string
  description = "The ARN of the KMS key used to encrypt the cloudwatch log group and network firewall"
}

variable "managed_rule_groups" {
  type = object({
    AbusedLegitBotNetCommandAndControlDomains = optional(object({
      enabled   = optional(bool, false)
      drop_mode = optional(bool, false)
      priority  = optional(number, 1)
    }), {})
    AbusedLegitMalwareDomains = optional(object({
      enabled   = optional(bool, false)
      drop_mode = optional(bool, false)
      priority  = optional(number, 2)
    }), {})
    BotNetCommandAndControlDomains = optional(object({
      enabled   = optional(bool, false)
      drop_mode = optional(bool, false)
      priority  = optional(number, 3)
    }), {})
    MalwareDomains = optional(object({
      enabled   = optional(bool, false)
      drop_mode = optional(bool, false)
      priority  = optional(number, 4)
    }), {})
    ThreatSignaturesBotnet = optional(object({
      enabled   = optional(bool, false)
      drop_mode = optional(bool, false)
      priority  = optional(number, 5)
    }), {})
    ThreatSignaturesBotnetWeb = optional(object({
      enabled   = optional(bool, false)
      drop_mode = optional(bool, false)
      priority  = optional(number, 6)
    }), {})
    ThreatSignaturesBotnetWindows = optional(object({
      enabled   = optional(bool, false)
      drop_mode = optional(bool, false)
      priority  = optional(number, 7)
    }), {})
    ThreatSignaturesDoS = optional(object({
      enabled   = optional(bool, false)
      drop_mode = optional(bool, false)
      priority  = optional(number, 8)
    }), {})
    ThreatSignaturesEmergingEvents = optional(object({
      enabled   = optional(bool, false)
      drop_mode = optional(bool, false)
      priority  = optional(number, 9)
    }), {})
    ThreatSignaturesExploits = optional(object({
      enabled   = optional(bool, false)
      drop_mode = optional(bool, false)
      priority  = optional(number, 10)
    }), {})
    ThreatSignaturesFUP = optional(object({
      enabled   = optional(bool, false)
      drop_mode = optional(bool, false)
      priority  = optional(number, 11)
    }), {})
    ThreatSignaturesIOC = optional(object({
      enabled   = optional(bool, false)
      drop_mode = optional(bool, false)
      priority  = optional(number, 12)
    }), {})
    ThreatSignaturesMalwareCoinmining = optional(object({
      enabled   = optional(bool, false)
      drop_mode = optional(bool, false)
      priority  = optional(number, 13)
    }), {})
    ThreatSignaturesMalwareMobile = optional(object({
      enabled   = optional(bool, false)
      drop_mode = optional(bool, false)
      priority  = optional(number, 14)
    }), {})
    ThreatSignaturesMalware = optional(object({
      enabled   = optional(bool, false)
      drop_mode = optional(bool, false)
      priority  = optional(number, 16)
    }), {})
    ThreatSignaturesMalwareWeb = optional(object({
      enabled   = optional(bool, false)
      drop_mode = optional(bool, false)
      priority  = optional(number, 17)
    }), {})
    ThreatSignaturesPhishing = optional(object({
      enabled   = optional(bool, false)
      drop_mode = optional(bool, false)
      priority  = optional(number, 18)
    }), {})
    ThreatSignaturesScanners = optional(object({
      enabled   = optional(bool, false)
      drop_mode = optional(bool, false)
      priority  = optional(number, 19)
    }), {})
    ThreatSignaturesSuspect = optional(object({
      enabled   = optional(bool, false)
      drop_mode = optional(bool, false)
      priority  = optional(number, 20)
    }), {})
    ThreatSignaturesWebAttacks = optional(object({
      enabled   = optional(bool, false)
      drop_mode = optional(bool, false)
      priority  = optional(number, 21)
    }), {})
  })
  default     = {}
  description = "Map with AWS managed ruleset options"
}

variable "name" {
  type        = string
  description = "Name of the firewall instance"
}

variable "subnet_ids" {
  type        = list(string)
  description = "List of subnet IDs onto which the network firewall will be deployed"
}

variable "tags" {
  type        = map(string)
  description = "Map of tags to set on Terraform created resources"
  default     = {}
}

variable "vpc_id" {
  type        = string
  description = "ID of the VPC the network firewall is deployed in"
}
