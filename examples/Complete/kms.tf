data "aws_caller_identity" "default" {}

module "kms_key" {
  source      = "github.com/schubergphilis/terraform-aws-mcaf-kms?ref=v0.2.0"
  name        = "network-firewall"
  description = "KMS key used for encrypting flow and alert logs from network firewall"
  policy      = data.aws_iam_policy_document.kms_key_policy.json
  tags        = {}
}

data "aws_iam_policy_document" "kms_key_policy" {
  statement {
    sid       = "Base Permissions"
    actions   = ["kms:*"]
    effect    = "Allow"
    resources = ["arn:aws:kms:${data.aws_region.default.name}:${data.aws_caller_identity.default.account_id}:key/*"]

    principals {
      type = "AWS"
      identifiers = [
        "arn:aws:iam::${data.aws_caller_identity.default.account_id}:root"
      ]
    }
  }

  statement {
    sid = "Allow all Cloudwatch groups in this account"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:Describe"
    ]
    effect    = "Allow"
    resources = ["arn:aws:kms:${data.aws_region.default.name}:${data.aws_caller_identity.default.account_id}:key/*"]

    principals {
      identifiers = ["logs.${data.aws_region.default.name}.amazonaws.com"]
      type        = "Service"
    }

    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"

      values = [
        "arn:aws:logs:${data.aws_region.default.name}:${data.aws_caller_identity.default.account_id}:*"
      ]
    }
  }

  statement {
    sid = "Allow all Network Firewalls in this account"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:Describe",
      "kms:RetireGrant"
    ]
    effect    = "Allow"
    resources = ["arn:aws:kms:${data.aws_region.default.name}:${data.aws_caller_identity.default.account_id}:key/*"]

    principals {
      identifiers = ["network-firewall.amazonaws.com"]
      type        = "Service"
    }

    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:network-firewall:resource-id"

      values = [
        "arn:aws:network-firewall:${data.aws_region.default.name}:${data.aws_caller_identity.default.account_id}:*"
      ]
    }
  }

}
