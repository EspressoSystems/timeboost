variable "keypair" {
  description = "SSH keypair name"
  type        = string
}

variable "configs" {
  description = "Per instance config values"
  type = list(object({
    ip : string,
    timeboost : string,
    nitro : string,
    chain : string # TODO: remove when removing block-maker
  }))
}

variable "number_of_public_ips" {
  description = "How many public IPs to allocate"
  type        = number
}

# variables with defaults:

variable "region" {
  description = "AWS region to use"
  type        = string
  default     = "eu-central-1"
}

variable "instance_type" {
  description = "EC2 instance type to use"
  type        = string
  default     = "t3a.micro"
}

variable "vpc_cidr_block" {
  description = "VPC CIDR block"
  type        = string
  default     = "10.0.0.0/16"
}
