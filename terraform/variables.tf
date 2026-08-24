variable "db_password" {
  type        = string
  description = "Password for the RDS MySQL instance"
  sensitive   = true
}

variable "aws_region" {
  type        = string
  description = "AWS region for provisioning"
  default     = "ap-south-1"
}
