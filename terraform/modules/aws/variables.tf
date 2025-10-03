variable "environment" { type = string }
variable "project_name" { type = string }
variable "kubernetes_version" { type = string }
variable "node_count" { type = number }
variable "node_instance_type" { type = string }

variable "aws_region" {
  type    = string
  default = "eu-west-3"
}
