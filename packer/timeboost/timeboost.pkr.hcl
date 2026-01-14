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
  ami_name      = "timeboost-${var.version}"
  instance_type = "t3a.micro"
  region        = "eu-west-2"
  ami_regions   = var.regions

  source_ami_filter {
    filters = {
      name                = "Fedora-Cloud-Base-AmazonEC2.x86_64-43-*"
      architecture        = "x86_64"
      root-device-type    = "ebs"
      virtualization-type = "hvm"
    }
    owners      = ["125523088429"]
    most_recent = true
  }

  launch_block_device_mappings {
    device_name           = "/dev/xvda"
    volume_size           = 32
    volume_type           = "gp3"
    delete_on_termination = true
  }

  ssh_username = var.ssh_user
  temporary_key_pair_type = "ed25519"
}

build {
  sources = ["source.amazon-ebs.linux"]

  provisioner "shell" {
    inline = [
      "echo upgrading base and installing dependencies ...",
      "sudo dnf upgrade -y --refresh",
      "sudo rpm -i https://packages.timber.io/vector/${var.vector-version}/vector-${var.vector-version}-1.x86_64.rpm"
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
