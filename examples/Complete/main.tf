provider "aws" {
  region = "eu-west-1"
}

module "network_firewall" {
  source = "../.."

  name        = "egress-firewall"
  home_net    = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  subnet_ids  = aws_subnet.network_firewall[*].id
  vpc_id      = module.vpc.vpc_id
  kms_key_arn = module.kms_key.arn

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

  fqdn_rules = {
    blocked_domains = {
      action    = "DROP"
      priority  = 1
      source_ip = ["10.0.1.0/24", "10.0.2.0/24"]
      fqdns = {
        "icanhazip.com" = {}
        "parrot.live"   = {}
        "www.nu.nl"     = {}
        "tweakers.net"  = {}
      }
    }

    allow_essential_sites = {
      action    = "PASS"
      priority  = 2
      source_ip = ["10.0.0.0/16"]
      fqdns = {
        "parrot.live" = {}
        "www.nu.nl"   = {}
      }
    }

    allow_custom_ports = {
      action    = "PASS"
      priority  = 3
      source_ip = ["10.0.0.0/16"]
      fqdns = {
        "api.example.com"      = { destination_ports = ["8443", "9000"] }
        "webhook.example.com"  = { destination_ports = ["443", "8080"] }
        "standard.example.com" = {} # uses default ports 80, 443
      }
    }
  }

  managed_rule_groups = {
    AbusedLegitBotNetCommandAndControlDomains = { enabled = true }
    MalwareDomains                            = { enabled = true, drop_mode = true }
    ThreatSignaturesBotnetWeb                 = { enabled = true }
  }
}
