resource "aws_security_group" "timeboost" {
  name   = "timeboost"
  vpc_id = aws_vpc.timeboost.id
  tags   = { Name = "timeboost" }
}

# Allow access to ports:
#
# - 8000 = Sailfish (in/out)
# - 8001 = Decrypt  (in/out)
# - 8002 = Certify  (in/out)
# - 8003 = HTTP     (in)

resource "aws_vpc_security_group_ingress_rule" "timeboost" {
  security_group_id = aws_security_group.timeboost.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 8000
  to_port           = 8002
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "http" {
  security_group_id = aws_security_group.timeboost.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 8003
  to_port           = 8003
  ip_protocol       = "http"
}

resource "aws_vpc_security_group_egress_rule" "timeboost" {
  security_group_id = aws_security_group.timeboost.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 8000
  to_port           = 8002
  ip_protocol       = "tcp"
}

