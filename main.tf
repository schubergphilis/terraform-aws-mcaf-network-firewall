locals {
  # Flatten FQDN rules to create individual entries per FQDN with their destination ports
  flattened_fqdn_rules = flatten([
    for rule_key, rule in var.fqdn_rules : [
      for fqdn, fqdn_config in rule.fqdns : {
        rule_key          = rule_key
        action            = rule.action
        fqdn              = fqdn
        destination_ports = fqdn_config.destination_ports
        priority          = rule.priority
        source_ip         = rule.source_ip
      }
    ]
  ])

  # Create a map with unique keys for each FQDN entry
  fqdn_rules_map = {
    for idx, entry in local.flattened_fqdn_rules :
    idx => entry
  }

  # Keep sorted rules for ip_sets (one per rule, not per FQDN) - using index for naming
  sorted_fqdn_rules = values({
    for k, v in var.fqdn_rules : format("%03d", v.priority) => {
      action      = v.action
      description = k
      fqdns       = v.fqdns
      priority    = v.priority
      source_ip   = v.source_ip
    }
  })

  # Create a map to lookup rule index by priority
  fqdn_rule_priority_to_index = {
    for idx, rule in local.sorted_fqdn_rules : rule.priority => idx
  }

  # Create unique port sets by deduplicating destination_ports combinations
  # Use sorted join of ports as key to ensure consistent ordering
  unique_port_sets = {
    for ports_key, ports in {
      for entry in local.flattened_fqdn_rules :
      join("_", sort(entry.destination_ports)) => entry.destination_ports...
    } : ports_key => ports[0]
  }

  # Map each FQDN entry to its port set key
  fqdn_to_port_set_key = {
    for key, entry in local.fqdn_rules_map :
    key => join("_", sort(entry.destination_ports))
  }

  rules_string = [
    for key, rule in local.fqdn_rules_map : {
      http = format("%s http $src_ip_%d any -> any $dst_prt_%s (http.host;dotprefix;content:\"%s\";endswith;flow:to_server,established;sid:1%d%d2;)", lower(rule.action), local.fqdn_rule_priority_to_index[rule.priority], local.fqdn_to_port_set_key[key], rule.fqdn, local.fqdn_rule_priority_to_index[rule.priority], key)
      tls  = format("%s tls $src_ip_%d any -> any $dst_prt_%s (tls.sni;dotprefix;content:\"%s\";endswith;nocase;flow:to_server,established;sid:1%d%d1;)", lower(rule.action), local.fqdn_rule_priority_to_index[rule.priority], local.fqdn_to_port_set_key[key], rule.fqdn, local.fqdn_rule_priority_to_index[rule.priority], key)
    }
  ]

  sorted_ip_rules = values({
    for k, v in var.ip_rules : format("%03d", v.priority) => {
      action           = v.action
      description      = k
      destination_ip   = v.destination_ip
      destination_port = v.destination_port
      direction        = v.direction
      priority         = v.priority
      protocol         = v.protocol
      source_ip        = v.source_ip
      source_port      = v.source_port
    }
  })
}

data "aws_region" "default" {}

################################################################################
# AWS Network Firewall
################################################################################

resource "aws_networkfirewall_firewall" "default" {
  name                = var.name
  delete_protection   = var.delete_protection
  description         = var.description
  firewall_policy_arn = aws_networkfirewall_firewall_policy.default.arn
  vpc_id              = var.vpc_id
  tags                = var.tags

  encryption_configuration {
    key_id = var.kms_key_arn
    type   = "CUSTOMER_KMS"
  }

  dynamic "subnet_mapping" {
    for_each = var.subnet_ids

    content {
      subnet_id = subnet_mapping.value
    }
  }
}

resource "aws_networkfirewall_firewall_policy" "default" {
  name = "${var.name}-policy"
  tags = var.tags

  encryption_configuration {
    key_id = var.kms_key_arn
    type   = "CUSTOMER_KMS"
  }

  firewall_policy {
    stateless_default_actions          = ["aws:forward_to_sfe"]
    stateless_fragment_default_actions = ["aws:forward_to_sfe"]

    dynamic "policy_variables" {
      for_each = length(var.home_net) > 0 ? { create : true } : {}

      content {
        rule_variables {
          key = "HOME_NET"
          ip_set {
            definition = var.home_net
          }
        }
      }
    }

    stateful_engine_options {
      rule_order = "STRICT_ORDER"
    }

    stateful_default_actions = ["aws:drop_established"]

    dynamic "stateful_rule_group_reference" {
      for_each = { for k, v in var.managed_rule_groups : k => v if v.enabled && v.drop_mode == true }

      content {
        priority     = stateful_rule_group_reference.value.priority
        resource_arn = "arn:aws:network-firewall:${data.aws_region.default.name}:aws-managed:stateful-rulegroup/${stateful_rule_group_reference.key}StrictOrder"
      }
    }


    dynamic "stateful_rule_group_reference" {
      for_each = { for k, v in var.managed_rule_groups : k => v if v.enabled && v.drop_mode == false }

      content {
        priority     = stateful_rule_group_reference.value.priority
        resource_arn = "arn:aws:network-firewall:${data.aws_region.default.name}:aws-managed:stateful-rulegroup/${stateful_rule_group_reference.key}StrictOrder"

        override {
          action = "DROP_TO_ALERT"
        }
      }
    }

    dynamic "stateful_rule_group_reference" {
      for_each = length(local.sorted_fqdn_rules) > 0 ? { create : true } : {}

      content {
        priority     = var.fqdn_rule_group_priority
        resource_arn = aws_networkfirewall_rule_group.fqdn_rules[0].arn
      }
    }

    dynamic "stateful_rule_group_reference" {
      for_each = length(local.sorted_ip_rules) > 0 ? { create : true } : {}

      content {
        priority     = var.ip_rule_group_priority
        resource_arn = aws_networkfirewall_rule_group.ip_rules[0].arn
      }
    }
  }
}

resource "aws_networkfirewall_rule_group" "fqdn_rules" {
  count = length(local.sorted_fqdn_rules) > 0 ? 1 : 0

  capacity = var.fqdn_rules_capacity
  name     = "${var.name}-fqdn-rules"
  type     = "STATEFUL"
  tags     = var.tags

  encryption_configuration {
    key_id = var.kms_key_arn
    type   = "CUSTOMER_KMS"
  }

  rule_group {
    stateful_rule_options {
      rule_order = "STRICT_ORDER"
    }

    rule_variables {
      dynamic "ip_sets" {
        for_each = local.sorted_fqdn_rules

        content {
          key = "src_ip_${ip_sets.key}"

          ip_set {
            definition = ip_sets.value.source_ip
          }
        }
      }

      dynamic "port_sets" {
        for_each = local.unique_port_sets

        content {
          key = "dst_prt_${port_sets.key}"

          port_set {
            definition = port_sets.value
          }
        }
      }
    }

    rules_source {
      rules_string = join("\n", concat([for rule in local.rules_string : rule.tls], [for rule in local.rules_string : rule.http]))
    }
  }
}

resource "aws_networkfirewall_rule_group" "ip_rules" {
  count = length(local.sorted_ip_rules) > 0 ? 1 : 0

  capacity = var.ip_rules_capacity
  name     = "${var.name}-ip-rules"
  type     = "STATEFUL"
  tags     = var.tags

  encryption_configuration {
    key_id = var.kms_key_arn
    type   = "CUSTOMER_KMS"
  }

  rule_group {
    stateful_rule_options {
      rule_order = "STRICT_ORDER"
    }

    rule_variables {
      dynamic "ip_sets" {
        for_each = { for k, v in local.sorted_ip_rules : k => v if length(v.source_ip) > 0 && v.source_ip[0] != "ANY" }

        content {
          key = "src_ip_${ip_sets.value.priority}"

          ip_set {
            definition = ip_sets.value.source_ip
          }
        }
      }

      dynamic "ip_sets" {
        for_each = { for k, v in local.sorted_ip_rules : k => v if length(v.destination_ip) > 0 && v.destination_ip[0] != "ANY" }

        content {
          key = "dst_ip_${ip_sets.value.priority}"

          ip_set {
            definition = ip_sets.value.destination_ip
          }
        }
      }

      dynamic "port_sets" {
        for_each = { for k, v in local.sorted_ip_rules : k => v if length(v.destination_port) > 0 && v.destination_port[0] != "ANY" }

        content {
          key = "dst_prt_${port_sets.value.priority}"

          port_set {
            definition = port_sets.value.destination_port
          }
        }
      }

      dynamic "port_sets" {
        for_each = { for k, v in local.sorted_ip_rules : k => v if length(v.source_port) > 0 && v.source_port[0] != "ANY" }

        content {
          key = "src_prt_${port_sets.value.priority}"

          port_set {
            definition = port_sets.value.source_port
          }
        }
      }
    }

    rules_source {
      dynamic "stateful_rule" {
        for_each = local.sorted_ip_rules

        content {
          action = upper(stateful_rule.value.action)

          header {
            destination      = stateful_rule.value.destination_ip[0] != "ANY" ? "${"$"}dst_ip_${stateful_rule.value.priority}" : "ANY"
            destination_port = stateful_rule.value.destination_port[0] != "ANY" ? "${"$"}dst_prt_${stateful_rule.value.priority}" : "ANY"
            direction        = upper(stateful_rule.value.direction)
            protocol         = upper(stateful_rule.value.protocol)
            source           = stateful_rule.value.source_ip[0] != "ANY" ? "${"$"}src_ip_${stateful_rule.value.priority}" : "ANY"
            source_port      = stateful_rule.value.source_port[0] != "ANY" ? "${"$"}src_prt_${stateful_rule.value.priority}" : "ANY"
          }

          rule_option {
            keyword  = "sid"
            settings = [stateful_rule.value.priority]
          }
        }
      }
    }
  }
}

################################################################################
# AWS Network Firewall Logging
################################################################################

resource "aws_networkfirewall_logging_configuration" "default" {
  count = var.cloudwatch_logging_configuration["alert_logs"].enabled || var.cloudwatch_logging_configuration["flow_logs"].enabled ? 1 : 0

  firewall_arn = aws_networkfirewall_firewall.default.arn

  logging_configuration {

    dynamic "log_destination_config" {
      for_each = { for log_type, log_configuration in var.cloudwatch_logging_configuration : log_type => log_configuration if log_configuration.enabled }

      content {
        log_destination = {
          logGroup = aws_cloudwatch_log_group.default[log_destination_config.key].name
        }
        log_destination_type = "CloudWatchLogs"
        log_type             = upper(split("_", log_destination_config.key)[0])
      }
    }
  }
}

resource "aws_cloudwatch_log_group" "default" {
  for_each = { for log_type, log_configuration in var.cloudwatch_logging_configuration : log_type => log_configuration if log_configuration.enabled }

  name              = "${each.value.log_group_prefix}${var.name}-${split("_", each.key)[0]}-logs"
  kms_key_id        = var.kms_key_arn
  retention_in_days = each.value.retention_in_days
}
