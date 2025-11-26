# Given some CIDR block we create a pair of public and private subnets for each
# availability zone in the region as set in the provider.
#
# We then create 1 route table with an internet gateway and associate each
# public subnet with that table.
#
# Finally, each private subnet gets its own NAT gateway and routing table
# (commented out for the time being).

resource "aws_vpc" "timeboost" {
  cidr_block = var.vpc_cidr_block
  tags       = { Name = "Timeboost" }
}

data "aws_availability_zones" "available" {
  state = "available"
  filter {
    name   = "zone-type"
    values = ["availability-zone"]
  }
}

# Public subnets get an even octet, e.g. if the CIDR block is 10.0.0.0/16, they
# get 10.0.i.0/24 with i in 0, 2, 4, 6, ...
resource "aws_subnet" "timeboost_public" {
  for_each   = toset(data.aws_availability_zones.available.names)
  vpc_id     = aws_vpc.timeboost.id
  cidr_block = cidrsubnet(aws_vpc.timeboost.cidr_block, 8, local.az_indices[each.value] * 2)
}

# Public subnets get an odd octet, e.g. if the CIDR block is 10.0.0.0/16, they
# get 10.0.i.0/24 with i in 1, 3, 5, 7, ...
resource "aws_subnet" "timeboost_private" {
  for_each   = toset(data.aws_availability_zones.available.names)
  vpc_id     = aws_vpc.timeboost.id
  cidr_block = cidrsubnet(aws_vpc.timeboost.cidr_block, 8, local.az_indices[each.value] * 2 + 1)
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.timeboost.id
}

resource "aws_route_table" "timeboost_public" {
  vpc_id = aws_vpc.timeboost.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
}

resource "aws_route_table_association" "public" {
  for_each       = aws_subnet.timeboost_public
  subnet_id      = each.value.id
  route_table_id = aws_route_table.timeboost_public.id
}


# resource "aws_eip" "nat_eip" {
#   for_each = aws_subnet.timeboost_private
#   domain   = "vpc"
# }

# resource "aws_nat_gateway" "timeboost_nat" {
#   for_each      = aws_subnet.timeboost_private
#   allocation_id = aws_eip.nat_eip[each.value].id
#   subnet_id     = each.value.id
# }

# resource "aws_route_table" "timeboost_private" {
#   for_each = aws_subnet.timeboost_private
#   vpc_id   = aws_vpc.timeboost.id

#   route {
#     cidr_block     = "0.0.0.0/0"
#     nat_gateway_id = aws_nat_gateway.timeboost_nat[each.value].id
#   }
# }

# resource "aws_route_table_association" "private" {
#   for_each       = aws_subnet.timeboost_private
#   subnet_id      = each.value.id
#   route_table_id = aws_route_table.timeboost_private[each.value].id
# }
