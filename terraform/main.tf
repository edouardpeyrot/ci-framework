# terraform/main.tf
terraform {
  required_version = ">= 1.5.7"

  required_providers {
    # azurerm = {
    #   source  = "hashicorp/azurerm"
    #   version = "~> 3.0"
    #}
    # google = {
    #   source  = "hashicorp/google"
    #   version = "~> 5.0"
    # }
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.15.0"
    }
  }

  backend "s3" {
    bucket         = "epe-terraform-state-bucket"
    key            = "prod/terraform.tfstate"
    region         = "eu-west-3"
  }
}

# Variables globales
variable "cloud_provider" {
  description = "Cloud provider to use (azure, gcp, or aws)"
  type        = string
  validation {
    condition     = contains(["azure", "gcp", "aws"], var.cloud_provider)
    error_message = "Cloud provider must be azure, gcp, or aws."
  }
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
}

variable "project_name" {
  description = "Project name"
  type        = string
  default     = "app-stack"
}

variable "kubernetes_version" {
  description = "Kubernetes version"
  type        = string
  default     = "1.33"
}

variable "node_count" {
  description = "Number of worker nodes"
  type        = number
  default     = 3
}

variable "node_vm_size" {
  description = "VM size for nodes"
  type        = map(string)
  default = {
    azure = "Standard_D2s_v3"
    gcp   = "e2-standard-2"
    aws   = "t3.medium"
  }
}


# Déploiement conditionnel par provider
# module "azure_infrastructure" {
#   source = "./modules/azure"
#   count  = var.cloud_provider == "azure" ? 1 : 0
#
#   environment         = var.environment
#   project_name        = var.project_name
#   kubernetes_version  = var.kubernetes_version
#   node_count          = var.node_count
#   node_vm_size        = var.node_vm_size["azure"]
# }
#
# module "gcp_infrastructure" {
#   source = "./modules/gcp"
#   count  = var.cloud_provider == "gcp" ? 1 : 0
#
#   environment         = var.environment
#   project_name        = var.project_name
#   kubernetes_version  = var.kubernetes_version
#   node_count          = var.node_count
#   node_machine_type   = var.node_vm_size["gcp"]
# }

module "aws_infrastructure" {
  source = "./modules/aws"
  count  = var.cloud_provider == "aws" ? 1 : 0

  environment         = var.environment
  project_name        = var.project_name
  kubernetes_version  = var.kubernetes_version
  node_count          = var.node_count
  node_instance_type  = var.node_vm_size["aws"]
}

provider "aws" {
  region = "eu-west-3"
}


# # Outputs
# output "kubernetes_cluster_endpoint" {
#   value = (
#     var.cloud_provider == "azure" ? try(module.azure_infrastructure[0].cluster_endpoint, "") :
#       var.cloud_provider == "gcp" ? try(module.gcp_infrastructure[0].cluster_endpoint, "") :
#       try(module.aws_infrastructure[0].cluster_endpoint, "")
#   )
#   sensitive = true
# }
#
# output "kubernetes_cluster_name" {
#   value = (
#     var.cloud_provider == "azure" ? try(module.azure_infrastructure[0].cluster_name, "") :
#       var.cloud_provider == "gcp" ? try(module.gcp_infrastructure[0].cluster_name, "") :
#       try(module.aws_infrastructure[0].cluster_name, "")
#   )
# }