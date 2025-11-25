terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  # backend "s3" {
  #   bucket         = var.terraform_bucket
  #   key            = "ec2-instance/terraform.tfstate"
  #   region         = aws.region
  #   dynamodb_table = "Terraform"
  #   encrypt        = true
  # }
}

provider "aws" {
  region = var.region
}

data "aws_ami" "timeboost_ami" {
  most_recent = true
  owners      = ["self"]
  filter {
    name   = "name"
    values = ["timeboost-*"]
  }
}

resource "aws_instance" "timeboost" {
  for_each = {
    for _, config in var.configs : config.ip => config
  }

  tags                        = { Name = "Timeboost" }
  ami                         = data.aws_ami.timeboost_ami.id
  instance_type               = var.instance_type
  key_name                    = var.keypair
  iam_instance_profile        = aws_iam_instance_profile.instance_profile.name
  security_groups             = [aws_security_group.timeboost.id]
  associate_public_ip_address = each.value.ip

  user_data = templatefile("cloud-init.tpl", {
    timeboost_config = base64gzip(each.value.timeboost)
    nitro_config     = base64gzip(each.value.nitro)
    chain_config     = base64gzip(each.value.chain) # TODO: Remove when removing block-maker
  })
}

