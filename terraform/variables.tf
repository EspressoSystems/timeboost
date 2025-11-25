variable "terraform_bucket" {
  description = "The S3 bucket name for terraform state storage"
  type        = string
}

variable "owner" {
  description = "AWS account owner"
  type        = string
}

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

variable "vpc_sub_public_1" {
  description = "VPC public subnet block"
  type        = string
  default     = "10.0.1.0/24"
}

variable "vpc_sub_private_1" {
  description = "VPC private subnet block"
  type        = string
  default     = "10.0.2.0/24"
}

