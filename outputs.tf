output "cloudwatch_log_group_arn" {
  description = "Map of CloudWatch log group type and arn when at least one log type is enabled"
  value       = { for log_type, log_configuration in var.cloudwatch_logging_configuration : log_type => aws_cloudwatch_log_group.default[log_type].arn if log_configuration.enabled }
}

output "cloudwatch_log_group_name" {
  description = "Map of CloudWatch log group type and name when at least one log type is enabled"
  value       = { for log_type, log_configuration in var.cloudwatch_logging_configuration : log_type => aws_cloudwatch_log_group.default[log_type].name if log_configuration.enabled }
}

output "firewall_status" {
  description = "Information about the current status of the firewall."
  value       = aws_networkfirewall_firewall.default.firewall_status
}
