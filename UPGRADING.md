# Upgrading Notes

This document captures breaking changes between versions of this module.

## Upgrading to v2.0.0

### Key Changes v2.0.0

This module now requires a minimum AWS provider version of 6.0 to support the region parameter. If you are using multiple AWS provider blocks, please read [migrating from multiple provider configurations](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/guides/enhanced-region-support#migrating-from-multiple-provider-configurations).


## Upgrading to v1.0.0

### Breaking Changes

#### `fqdn_rules` variable structure changed

The `fqdns` attribute within `fqdn_rules` has changed from a `list(string)` to a `map(object)` to support per-FQDN destination ports.

##### Before

```hcl
variable "fqdn_rules" {
  type = map(object({
    action    = string
    fqdns     = list(string)
    priority  = number
    source_ip = list(string)
  }))
}
```

Example usage:

```hcl
fqdn_rules = {
  allow_github = {
    action    = "PASS"
    priority  = 1
    source_ip = ["10.0.0.0/8"]
    fqdns     = [".github.com", ".githubusercontent.com"]
  }
}
```

##### After

```hcl
variable "fqdn_rules" {
  type = map(object({
    action    = string
    fqdns     = map(object({
      destination_ports = optional(list(string), ["80", "443"])
    }))
    priority  = number
    source_ip = list(string)
  }))
}
```

Example usage:

```hcl
fqdn_rules = {
  allow_github = {
    action    = "PASS"
    priority  = 1
    source_ip = ["10.0.0.0/8"]
    fqdns = {
      ".github.com"            = {}                                    # uses default ports 80, 443
      ".githubusercontent.com" = {}                                    # uses default ports 80, 443
    }
  }
}
```

##### New Feature: Per-FQDN Destination Ports

You can now specify custom destination ports for individual FQDNs:

```hcl
fqdn_rules = {
  allow_services = {
    action    = "PASS"
    priority  = 1
    source_ip = ["10.0.0.0/8"]
    fqdns = {
      ".github.com"       = {}                                         # default ports 80, 443
      ".api.example.com"  = { destination_ports = ["8443", "9000"] }   # custom ports
      ".webhook.example.com" = { destination_ports = ["443", "8080"] } # custom ports
    }
  }
}
```

##### Migration Steps

1. Change each FQDN from a list item to a map key
2. Use `{}` for FQDNs that should use default ports (80, 443)
3. Use `{ destination_ports = ["port1", "port2"] }` for FQDNs that need custom ports

**Before:**

```hcl
fqdns = [".github.com", ".api.example.com"]
```

**After:**

```hcl
fqdns = {
  ".github.com"      = {}
  ".api.example.com" = {}
}
```

Or with custom ports:

```hcl
fqdns = {
  ".github.com"      = {}                                    # default 80, 443
  ".api.example.com" = { destination_ports = ["8443"] }      # custom port
}
```
