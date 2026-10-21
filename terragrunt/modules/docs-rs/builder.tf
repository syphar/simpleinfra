resource "aws_eip" "builder" {
  domain = "vpc"

  tags = {
    Name = "docs-rs-builder"
  }
}

resource "aws_instance" "builder" {
  ami                         = data.aws_ami.ubuntu24.id
  instance_type               = var.builder_instance_type
  subnet_id                   = element(var.cluster_config.subnet_ids, 0)
  vpc_security_group_ids      = [aws_security_group.builder.id]
  iam_instance_profile        = aws_iam_instance_profile.builder.name
  associate_public_ip_address = true

  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    http_protocol_ipv6          = "disabled"
  }

  root_block_device {
    # Size of the volume in GiB.
    volume_size           = 64
    volume_type           = "gp3"
    iops                  = var.builder_volume_iops
    throughput            = var.builder_volume_throughput
    delete_on_termination = true
  }

  tags = {
    Name = "docs-rs-builder"
  }

  lifecycle {
    # Don't recreate the instance automatically when the AMI changes.
    ignore_changes = [ami]
  }
}

resource "aws_eip_association" "builder" {
  instance_id   = aws_instance.builder.id
  allocation_id = aws_eip.builder.id
}

# SSH through the bastion to this private address.
resource "aws_route53_record" "builder" {
  zone_id = var.zone_id
  name    = "builder.${var.domain}"
  type    = "A"
  ttl     = 300
  records = [aws_instance.builder.private_ip]
}

module "builder_ecr" {
  source = "../ecr-repo"
  name   = "docs-rs-build-server"
}

resource "aws_iam_role_policy_attachment" "builder_ecr_pull" {
  role       = aws_iam_role.builder.name
  policy_arn = module.builder_ecr.policy_pull_arn
}

resource "aws_iam_role_policy" "builder_configuration" {
  name = "builder-configuration"
  role = aws_iam_role.builder.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["ssm:GetParameter"]
      Resource = aws_ssm_parameter.connection_url.arn
    }]
  })
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

// The instance profile the builder will assume when communicating with s3

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
  role = aws_iam_role.builder.name
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

// Security group allowing all egress and ssh ingress from the bastion instance
resource "aws_security_group" "builder" {
  vpc_id      = var.cluster_config.vpc_id
  name        = "docs-rs-builder"
  description = "Access rules for the docs-rs builder."

  // SSH access from the bastion instance
  ingress {
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    description     = "SSH access from bastion"
    security_groups = [var.bastion_security_group_id]
  }

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
