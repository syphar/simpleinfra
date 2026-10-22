locals {
  builders = {
    for index in range(var.builder_count) : "builder-${index + 1}" => var.builder_config
  }
}

# Preserve the existing builder and its public IP when adopting named builders.
# Keep builder-1 in accounts that already have the singleton in state.
moved {
  from = aws_instance.builder
  to   = aws_instance.builder["builder-1"]
}

moved {
  from = aws_eip.builder
  to   = aws_eip.builder["builder-1"]
}

moved {
  from = aws_eip_association.builder
  to   = aws_eip_association.builder["builder-1"]
}

moved {
  from = aws_route53_record.builder
  to   = aws_route53_record.builder["builder-1"]
}

resource "aws_eip" "builder" {
  for_each = local.builders

  domain = "vpc"

  tags = {
    Name = "docs-rs-${each.key}"
  }
}

resource "aws_instance" "builder" {
  for_each = local.builders

  ami                         = data.aws_ami.ubuntu24.id
  instance_type               = each.value.instance_type
  subnet_id                   = var.cluster_config.subnet_ids[0]
  vpc_security_group_ids      = [aws_security_group.builder.id]
  iam_instance_profile        = aws_iam_instance_profile.builder.name
  associate_public_ip_address = true

  user_data_base64            = base64gzip(local.builder_user_data[each.key])
  user_data_replace_on_change = true

  # Register only after the ECS agent's instance permissions are attached.
  depends_on = [aws_iam_role_policy_attachment.builder_agent, aws_iam_role_policy.builder_bootstrap]

  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    http_protocol_ipv6          = "disabled"
  }

  root_block_device {
    # Size of the volume in GiB.
    volume_size           = each.value.volume_size
    volume_type           = "gp3"
    iops                  = each.value.volume_iops
    throughput            = each.value.volume_throughput
    delete_on_termination = true
  }

  tags = {
    Name = "docs-rs-${each.key}"
  }

  lifecycle {
    # Don't recreate the instance automatically when the AMI changes.
    ignore_changes = [ami]

    precondition {
      condition     = length(base64gzip(local.builder_user_data[each.key])) / 4 * 3 - length(regex("=*$", base64gzip(local.builder_user_data[each.key]))) <= 16384
      error_message = "Builder cloud-init exceeds EC2's 16 KiB user data limit."
    }
  }
}

resource "aws_eip_association" "builder" {
  for_each = local.builders

  instance_id   = aws_instance.builder[each.key].id
  allocation_id = aws_eip.builder[each.key].id
}

# Private address for identifying the builder host.
resource "aws_route53_record" "builder" {
  for_each = local.builders

  zone_id = var.zone_id
  name    = "${each.key}.${var.domain}"
  type    = "A"
  ttl     = 300
  records = [aws_instance.builder[each.key].private_ip]
}

module "builder_ecr" {
  source = "../ecr-repo"
  name   = "docs-rs-build-server"
}

moved {
  from = aws_iam_role_policy_attachment.builder_agent[0]
  to   = aws_iam_role_policy_attachment.builder_agent
}

resource "aws_iam_role_policy_attachment" "builder_agent" {
  role       = aws_iam_role.builder.name
  policy_arn = "arn:${data.aws_partition.builder.partition}:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role"
}

data "aws_ami" "ubuntu24" {
  most_recent = true
  owners      = ["099720109477"] // Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

// Instance permissions are for the ECS agent. Application access uses task roles.

resource "aws_iam_instance_profile" "builder" {
  name = "builder"
  role = aws_iam_role.builder.name
}

resource "aws_iam_role" "builder" {
  name = "builder"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = ["sts:AssumeRole"]
      }
    ]
  })
}

resource "aws_iam_role_policy" "builder_s3" {
  role = aws_iam_role.builder_task.name
  name = "builder_s3"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      // Access to s3
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:ListBucket",
          "s3:AbortMultipartUpload",
          "s3:PutObjectTagging",
          "s3:DeleteObject"
        ]

        Resource = [
          aws_s3_bucket.storage.arn,
          "${aws_s3_bucket.storage.arn}/*"
        ]
      }
    ]
  })
}

// Builders initiate outbound connections and accept no inbound traffic.
resource "aws_security_group" "builder" {
  vpc_id      = var.cluster_config.vpc_id
  name        = "docs-rs-builder"
  description = "Access rules for the docs-rs builder."

  ingress = []

  // Allow outgoing connections

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = -1
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all IPv4 egress traffic."
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = -1
    ipv6_cidr_blocks = ["::/0"]
    description      = "Allow all IPv6 egress traffic."
  }

  tags = {
    Name = "docs-rs-builder"
  }
}

data "aws_partition" "builder" {}

data "aws_region" "builder" {}
