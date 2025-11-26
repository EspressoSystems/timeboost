terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  backend "s3" {
    bucket       = "xmxxsdnjvltzwxf2wikwvgo"
    key          = "timeboost-tf/terraform.tfstate"
    region       = "eu-central-1"
    encrypt      = true
    use_lockfile = true
  }
}

provider "aws" {
  region = var.region
}

data "aws_caller_identity" "current" {}

data "aws_ami" "timeboost_ami" {
  most_recent = true
  owners      = ["self"]
  filter {
    name   = "name"
    values = ["timeboost-*"]
  }
}

locals {
  public_subnet_ids = values(aws_subnet.timeboost_public)[*].id
}

resource "aws_instance" "timeboost" {
  for_each = {
    for i, config in var.configs : i => config
  }
  tags                        = { Name = "Timeboost-${each.key}" }
  ami                         = data.aws_ami.timeboost_ami.id
  instance_type               = var.instance_type
  key_name                    = var.keypair
  iam_instance_profile        = aws_iam_instance_profile.timeboost_profile.name
  security_groups             = [aws_security_group.timeboost.id]
  associate_public_ip_address = false
  subnet_id                   = local.public_subnet_ids[each.key % length(local.public_subnet_ids)]
  user_data = templatefile("cloud-init.tpl", {
    timeboost_config = base64gzip(each.value.timeboost)
    nitro_config     = base64gzip(each.value.nitro)
    chain_config     = base64gzip(each.value.chain) # TODO: Remove when removing block-maker
  })
}

data "aws_eip" "existing_ip" {
  for_each = {
    for i, config in var.configs : i => config
  }
  public_ip = each.value.ip
}

resource "aws_eip_association" "eip_assoc" {
  for_each = {
    for i, config in var.configs : i => config
  }
  instance_id   = aws_instance.timeboost[each.key].id
  allocation_id = data.aws_eip.existing_ip[each.key].id
}
