packer {
  required_plugins {
    amazon = {
      version = ">= 1.8.0"
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

variable "regions" {
  type = list(string)
}

variable "ssh_user" {
  type = string
}

source "amazon-ebs" "linux" {
  ami_name      = "tx-generator-${var.version}"
  instance_type = "t3a.micro"
  region        = "eu-west-1"
  profile       = "timeboost-dev"
  ami_regions   = var.regions

  source_ami_filter {
    filters = {
      name                = "al2023-ami-*-x86_64"
      root-device-type    = "ebs"
      virtualization-type = "hvm"
    }
    owners      = ["amazon"]
    most_recent = true
  }

  launch_block_device_mappings {
    device_name           = "/dev/xvda"
    volume_size           = 32
    volume_type           = "gp3"
    delete_on_termination = true
  }

  ssh_username = var.ssh_user
}

build {
  sources = ["source.amazon-ebs.linux"]

  provisioner "shell" {
    inline = [
      "echo upgrading base and installing dependencies ...",
      "sudo yum update -y",
      "sudo rpm -i https://yum.vector.dev/stable/vector-0/x86_64/vector-${var.vector-version}-1.x86_64.rpm"
    ]
  }

  provisioner "shell" {
    inline = [
      "echo preparing upload directory ...",
      "sudo mkdir /upload",
      "sudo chmod 0777 /upload"
    ]
  }

  provisioner "file" {
    source      = "${var.overlay-archive}"
    destination = "/upload/${var.overlay-archive}"
  }

  provisioner "shell" {
    inline = [
      "echo extracting overlay ...",
      "sudo tar xzf /upload/${var.overlay-archive} -C /",
      "sudo rm -rf /upload"
    ]
  }
}
