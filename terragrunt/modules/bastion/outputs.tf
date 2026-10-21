output "security_group_id" {
  value       = aws_security_group.bastion.id
  description = "Id of the security group for the bastion instance"
}

output "hostname" {
  description = "Bastion DNS hostname for SSH connections."
  value       = aws_route53_record.bastion.fqdn
}
