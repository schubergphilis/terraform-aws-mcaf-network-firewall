# terraform-aws-mcaf-network-firewall

Terraform module to setup and manage a Network Firewall, it supports the following features:

- Filter IP traffic, allow/deny network traffic based on IP source/destination, port and protocol (5-tuple).
- Filter HTTP(S) traffic, allow/deny access to websites based on FQDN.
- IDS/IPS, deny traffic based on AWS managed rulesets.


## Filtering
Below are some characteristics of this firewall module:
 - The firewall operates with an implicit deny, meaning that all traffic will be dropped unless an IP or FQDN rule allows it.

### Order of evaluation
In case you're using IP, FQDN and IDS/IPS rules together the default order of evaluation is as follows:
   - IDS/IPS rules
   - FQDN rules
   - IP rules

This can be changed by altering the `ip_rule_group_priority`, `fqdn_rule_group_priority` for IP and FQDN rules. And the various `priority` variables for the named IDS/IPS managed rule sets.

### FQDN rules
The firewall can filter web traffic based on FQDN's. This is done by inspecting the TLS 'Server Name Indication (SNI)' extension in case of encrypted traffic and the HTTP 'HOST_HEADER' in case of unencrypted web traffic.

#### Matching
- `example.com` only matches `example.com`
- `abc.example.com` only matches `abc.example.com`
- `.example.com` matches `example.com` and all subdomains of `example.com`, such as `www.example.com`, `abc.example.com`.

```
  fqdn_rules = {
    blocked_domains = {
      action    = "DROP"
      fqdns     = ["icanhazip.com", "parrot.live", "www.nu.nl"]
      source_ip = ["10.0.1.0/24", "10.0.2.0/24"]
      priority  = 1
    }

    allow_essential_sites = {
      action    = "PASS"
      fqdns     = ["parrot.live", "www.nu.nl"]
      source_ip = ["10.0.0.0/16"]
      priority  = 2
    }
  }
```

### IP (5-tuple) rules
Filtering of IP traffic can be done by adding rules to the `ip_rules` variable. The order of the rules is determined by setting the priority variable in every rule.

```
  ip_rules = {
    google_dns = {
      action           = "PASS"
      destination_ip   = ["8.8.8.8", "8.8.4.4"]
      destination_port = ["53"]
      direction        = "FORWARD"
      priority         = 1
      protocol         = "UDP"
      source_ip        = ["ANY"]
      source_port      = ["ANY"]
    }

    ping_cloudflare_resolvers = {
      action           = "PASS"
      destination_ip   = ["1.1.1.1", "1.0.0.1"]
      destination_port = ["ANY"]
      direction        = "FORWARD"
      priority         = 2
      protocol         = "ICMP"
      source_ip        = ["10.0.1.0/24", "10.0.2.0/24"]
      source_port      = ["ANY"]
    }

    drop_malicious_destination = {
      action           = "DROP"
      destination_ip   = ["1.2.3.4"]
      destination_port = ["ANY"]
      direction        = "FORWARD"
      priority         = 3
      protocol         = "IP"
      source_ip        = ["ANY"]
      source_port      = ["ANY"]
    }

    allow_smtp = {
      action           = "PASS"
      destination_ip   = ["ANY"]
      destination_port = ["25"]
      direction        = "FORWARD"
      priority         = 4
      protocol         = "SMTP"
      source_ip        = ["10.0.1.10/32"]
      source_port      = ["ANY"]
    }
  }
```

## IDS/IPS
AWS Network Firewall can be used with [AWS managed rules](https://docs.aws.amazon.com/network-firewall/latest/developerguide/aws-managed-rule-groups-list.html) for IDS/IPS functionality. 


The `managed_rule_groups` variable contains the list of rule groups that can be enabled. Setting `drop_mode = true` switches the rule group from IDS mode (detection only) to IPS mode (prevention, dropping those packets).

```
  managed_rule_groups = {
    AbusedLegitBotNetCommandAndControlDomains = { enabled = true }
    MalwareDomains                            = { enabled = true, drop_mode = true }
    ThreatSignaturesBotnetWeb                 = { enabled = true }
  }
```

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.3 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | >= 5.10.0 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | 5.31.0 |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [aws_cloudwatch_log_group.default](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_group) | resource |
| [aws_networkfirewall_firewall.default](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/networkfirewall_firewall) | resource |
| [aws_networkfirewall_firewall_policy.default](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/networkfirewall_firewall_policy) | resource |
| [aws_networkfirewall_logging_configuration.default](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/networkfirewall_logging_configuration) | resource |
| [aws_networkfirewall_rule_group.fqdn_rules](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/networkfirewall_rule_group) | resource |
| [aws_networkfirewall_rule_group.ip_rules](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/networkfirewall_rule_group) | resource |
| [aws_region.default](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/region) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_name"></a> [name](#input\_name) | Name of the firewall instance | `string` | n/a | yes |
| <a name="input_subnet_id"></a> [subnet\_id](#input\_subnet\_id) | List of subnet IDs onto which the network firewall will be deployed | `list(string)` | n/a | yes |
| <a name="input_vpc_id"></a> [vpc\_id](#input\_vpc\_id) | ID of the VPC the network firewall is deployed in | `string` | n/a | yes |
| <a name="input_cloudwatch_logging_configuration"></a> [cloudwatch\_logging\_configuration](#input\_cloudwatch\_logging\_configuration) | Cloudwatch logs configuration | <pre>object({<br>    alert_logs = optional(object({<br>      enabled           = optional(bool, true)<br>      log_group_prefix  = optional(string, "/platform/")<br>      retention_in_days = optional(number, 90)<br>    }), {})<br>    flow_logs = optional(object({<br>      enabled           = optional(bool, true)<br>      log_group_prefix  = optional(string, "/platform/")<br>      retention_in_days = optional(number, 90)<br>    }), {})<br>  })</pre> | `{}` | no |
| <a name="input_delete_protection"></a> [delete\_protection](#input\_delete\_protection) | A boolean flag indicating whether it is possible to delete the firewall | `bool` | `true` | no |
| <a name="input_description"></a> [description](#input\_description) | Description of the firewall instance | `string` | `"AWS Network Firewall"` | no |
| <a name="input_enable_cloudwatch_alert_logs"></a> [enable\_cloudwatch\_alert\_logs](#input\_enable\_cloudwatch\_alert\_logs) | Enable alert logs to be stored in cloudwatch | `bool` | `true` | no |
| <a name="input_enable_cloudwatch_flow_logs"></a> [enable\_cloudwatch\_flow\_logs](#input\_enable\_cloudwatch\_flow\_logs) | Enable flow logs to be stored in cloudwatch | `bool` | `true` | no |
| <a name="input_fqdn_rule_group_priority"></a> [fqdn\_rule\_group\_priority](#input\_fqdn\_rule\_group\_priority) | Priority of the rule group | `number` | `30` | no |
| <a name="input_fqdn_rules"></a> [fqdn\_rules](#input\_fqdn\_rules) | Map with L7 egress firewall rules | <pre>map(object({<br>    action    = string<br>    fqdns     = list(string)<br>    priority  = number<br>    source_ip = list(string)<br>  }))</pre> | `{}` | no |
| <a name="input_fqdn_rules_capacity"></a> [fqdn\_rules\_capacity](#input\_fqdn\_rules\_capacity) | Capacity of the rule group | `number` | `1000` | no |
| <a name="input_home_net"></a> [home\_net](#input\_home\_net) | List of CIDRs to override the HOME\_NET variable with | `list(string)` | `[]` | no |
| <a name="input_ip_rule_group_priority"></a> [ip\_rule\_group\_priority](#input\_ip\_rule\_group\_priority) | Priority of the rule group | `number` | `40` | no |
| <a name="input_ip_rules"></a> [ip\_rules](#input\_ip\_rules) | Map with L4 firewall rules | <pre>map(object({<br>    action           = string<br>    destination_ip   = list(string)<br>    destination_port = list(string)<br>    direction        = string<br>    priority         = number<br>    protocol         = string<br>    source_ip        = list(string)<br>    source_port      = list(string)<br>  }))</pre> | `{}` | no |
| <a name="input_ip_rules_capacity"></a> [ip\_rules\_capacity](#input\_ip\_rules\_capacity) | Capacity of the rule group | `number` | `1000` | no |
| <a name="input_kms_key_arn"></a> [kms\_key\_arn](#input\_kms\_key\_arn) | The ARN of the KMS key used to encrypt the cloudwatch log group and network firewall | `string` | `null` | no |
| <a name="input_managed_rule_groups"></a> [managed\_rule\_groups](#input\_managed\_rule\_groups) | Map with AWS managed ruleset options | <pre>object({<br>    AbusedLegitBotNetCommandAndControlDomains = optional(object({<br>      enabled   = optional(bool, false)<br>      drop_mode = optional(bool, false)<br>      priority  = optional(number, 1)<br>    }), {})<br>    AbusedLegitMalwareDomains = optional(object({<br>      enabled   = optional(bool, false)<br>      drop_mode = optional(bool, false)<br>      priority  = optional(number, 2)<br>    }), {})<br>    BotNetCommandAndControlDomains = optional(object({<br>      enabled   = optional(bool, false)<br>      drop_mode = optional(bool, false)<br>      priority  = optional(number, 3)<br>    }), {})<br>    MalwareDomains = optional(object({<br>      enabled   = optional(bool, false)<br>      drop_mode = optional(bool, false)<br>      priority  = optional(number, 4)<br>    }), {})<br>    ThreatSignaturesBotnet = optional(object({<br>      enabled   = optional(bool, false)<br>      drop_mode = optional(bool, false)<br>      priority  = optional(number, 5)<br>    }), {})<br>    ThreatSignaturesBotnetWeb = optional(object({<br>      enabled   = optional(bool, false)<br>      drop_mode = optional(bool, false)<br>      priority  = optional(number, 6)<br>    }), {})<br>    ThreatSignaturesBotnetWindows = optional(object({<br>      enabled   = optional(bool, false)<br>      drop_mode = optional(bool, false)<br>      priority  = optional(number, 7)<br>    }), {})<br>    ThreatSignaturesDoS = optional(object({<br>      enabled   = optional(bool, false)<br>      drop_mode = optional(bool, false)<br>      priority  = optional(number, 8)<br>    }), {})<br>    ThreatSignaturesEmergingEvents = optional(object({<br>      enabled   = optional(bool, false)<br>      drop_mode = optional(bool, false)<br>      priority  = optional(number, 9)<br>    }), {})<br>    ThreatSignaturesExploits = optional(object({<br>      enabled   = optional(bool, false)<br>      drop_mode = optional(bool, false)<br>      priority  = optional(number, 10)<br>    }), {})<br>    ThreatSignaturesFUP = optional(object({<br>      enabled   = optional(bool, false)<br>      drop_mode = optional(bool, false)<br>      priority  = optional(number, 11)<br>    }), {})<br>    ThreatSignaturesIOCS = optional(object({<br>      enabled   = optional(bool, false)<br>      drop_mode = optional(bool, false)<br>      priority  = optional(number, 12)<br>    }), {})<br>    ThreatSignaturesMalwareCoinmining = optional(object({<br>      enabled   = optional(bool, false)<br>      drop_mode = optional(bool, false)<br>      priority  = optional(number, 13)<br>    }), {})<br>    ThreatSignaturesMalwareMobile = optional(object({<br>      enabled   = optional(bool, false)<br>      drop_mode = optional(bool, false)<br>      priority  = optional(number, 14)<br>    }), {})<br>    ThreatSignaturesMalwareMobile = optional(object({<br>      enabled   = optional(bool, false)<br>      drop_mode = optional(bool, false)<br>      priority  = optional(number, 15)<br>    }), {})<br>    ThreatSignaturesMalware = optional(object({<br>      enabled   = optional(bool, false)<br>      drop_mode = optional(bool, false)<br>      priority  = optional(number, 16)<br>    }), {})<br>    ThreatSignaturesMalwareWeb = optional(object({<br>      enabled   = optional(bool, false)<br>      drop_mode = optional(bool, false)<br>      priority  = optional(number, 17)<br>    }), {})<br>    ThreatSignaturesPhishing = optional(object({<br>      enabled   = optional(bool, false)<br>      drop_mode = optional(bool, false)<br>      priority  = optional(number, 18)<br>    }), {})<br>    ThreatSignaturesScanners = optional(object({<br>      enabled   = optional(bool, false)<br>      drop_mode = optional(bool, false)<br>      priority  = optional(number, 19)<br>    }), {})<br>    ThreatSignaturesSuspect = optional(object({<br>      enabled   = optional(bool, false)<br>      drop_mode = optional(bool, false)<br>      priority  = optional(number, 20)<br>    }), {})<br>    ThreatSignaturesWebAttacks = optional(object({<br>      enabled   = optional(bool, false)<br>      drop_mode = optional(bool, false)<br>      priority  = optional(number, 21)<br>    }), {})<br>  })</pre> | `{}` | no |
| <a name="input_tags"></a> [tags](#input\_tags) | Map of tags to set on Terraform created resources | `map(string)` | `{}` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_firewall_status"></a> [firewall\_status](#output\_firewall\_status) | Information about the current status of the firewall. |
<!-- END_TF_DOCS -->