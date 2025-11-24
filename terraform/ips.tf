resource "aws_eip" "allocated_ips" {
  count = var.number_of_public_ips
}

output "public_ip_addresses" {
  description = "The list of allocated public IPs"
  value       = [aws_eip.allocated_ips[*].public_ip]
}
