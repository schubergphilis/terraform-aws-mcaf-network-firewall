output "firewall_status" {
  description = "Information about the current status of the firewall."
  value       = aws_networkfirewall_firewall.default.firewall_status
}
