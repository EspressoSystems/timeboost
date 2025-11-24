resource "aws_vpc" "timeboost" {
  cidr_block = var.vpc_cidr_block
  tags       = { Name = "Timeboost" }
}

# Public subnet

resource "aws_subnet" "timeboost-public-1" {
  vpc_id     = aws_vpc.timeboost.id
  cidr_block = var.vpc_sub_public_1
  tags       = { Name = "Timeboost-Public-1" }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.timeboost.id
  tags   = { Name = "VPC-Internet-Gateway" }
}

resource "aws_route_table" "timeboost-public" {
  vpc_id = aws_vpc.timeboost.id
  tags   = { Name = "Timeboost-Public" }

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.timeboost-public-1.id
  route_table_id = aws_route_table.timeboost-public.id
}

# Private subnet

resource "aws_subnet" "timeboost-private-1" {
  vpc_id     = aws_vpc.timeboost.id
  cidr_block = var.vpc_sub_private_1
  tags       = { Name = "Timeboost-Private-1" }
}

# resource "aws_eip" "nat_eip" {
#   vpc = true
# }

# resource "aws_nat_gateway" "timeboost-nat" {
#   tags          = { Name = "Timeboost-NAT-gateway" }
#   allocation_id = aws_eip.nat_eip.id
#   subnet_id     = aws_subnet.timeboost-public-1.id
# }

# resource "aws_route_table" "timeboost-private" {
#   tags = { Name = "Timeboost-Private" }
#   vpc_id = aws_vpc.timeboost.id

#   route {
#     cidr_block     = "0.0.0.0/0"
#     nat_gateway_id = aws_nat_gateway.timeboost-nat.id
#   }
# }

# resource "aws_route_table_association" "private" {
#   subnet_id      = aws_subnet.timeboost-private-1.id
#   route_table_id = aws_route_table.timeboost-private.id
# }
