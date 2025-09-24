packer {
  required_plugins {
    amazon = {
      version = ">= 1.2.0"
      source  = "github.com/hashicorp/amazon"
    }
  }
}

variable "version" {
  type = string
}

variable "vector-version" {
  type = string
}

variable "overlay-archive" {
  type = string
}

source "amazon-ebs" "al2" {
  ami_name      = "timeboost-${var.version}"
  instance_type = "t3a.micro"
  region        = "eu-central-1"

  source_ami_filter {
    filters = {
      name                = "amzn2-ami-hvm-*-x86_64-gp2"
      root-device-type    = "ebs"
      virtualization-type = "hvm"
    }
    owners      = ["amazon"]
    most_recent = true
  }

  launch_block_device_mappings {
    device_name           = "/dev/xvda"
    volume_size           = 16
    volume_type           = "gp3"
    delete_on_termination = true
  }

  ssh_username         = "ec2-user"
}

build {
  sources = ["source.amazon-ebs.al2"]

  provisioner "shell" {
    inline = [
      "echo upgrading base and installing dependencies ...",
      "sudo yum update -y",
      "sudo rpm -i https://yum.vector.dev/stable/vector-0/x86_64/vector-${var.vector-version}-1.x86_64.rpm"
    ]
  }

  provisioner "file" {
    source      = "${var.overlay-archive}"
    destination = "/tmp/${var.overlay-archive}"
  }

  provisioner "shell" {
    inline = [
      "echo extracting overlay ...",
      "sudo tar xzf /tmp/${var.overlay-archive} -C /",
      "sudo chown -R ec2-user:ec2-user /usr/local/bin/timeboost",
      "sudo rm /tmp/${var.overlay-archive}"
    ]
  }

  provisioner "shell" {
    inline = [
      "sudo systemctl daemon-reload",
      "sudo systemctl enable vector",
      "sudo systemctl enable timeboost"
    ]
  }
}
