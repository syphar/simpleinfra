# Builders reuse the infrastructure account's existing Ubuntu Pro parameters.
# Separate roles prevent staging hosts from reading the production parameter.
locals {
  builder_bootstrap_accounts = {
    staging = "519825364412"
    prod    = "760062276060"
  }
}

resource "aws_iam_role" "builder_bootstrap" {
  for_each = local.builder_bootstrap_accounts
  name     = "docs-rs-builder-bootstrap-${each.key}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = "arn:aws:iam::${each.value}:root" }
      Condition = {
        ArnEquals = { "aws:PrincipalArn" = "arn:aws:iam::${each.value}:role/builder" }
      }
    }]
  })
}

resource "aws_iam_role_policy" "builder_bootstrap" {
  for_each = local.builder_bootstrap_accounts
  name     = "read-ubuntu-pro-token"
  role     = aws_iam_role.builder_bootstrap[each.key].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "ssm:GetParameter"
        Resource = "arn:aws:ssm:us-west-1:890664054962:parameter/${each.key}/ansible/all/ubuntu-pro-token"
      },
      {
        Effect   = "Allow"
        Action   = "kms:Decrypt"
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:ViaService"                      = "ssm.us-west-1.amazonaws.com"
            "kms:EncryptionContext:PARAMETER_ARN" = "arn:aws:ssm:us-west-1:890664054962:parameter/${each.key}/ansible/all/ubuntu-pro-token"
          }
        }
      },
    ]
  })
}
