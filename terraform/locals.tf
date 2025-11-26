locals {
  # Map availability zone names to indices
  az_indices = {
    for az in data.aws_availability_zones.available.names : az =>
    index(data.aws_availability_zones.available.names, az)
  }

  # Set of timeboost public subnet IDs
  public_subnet_ids = values(aws_subnet.timeboost_public)[*].id
}
