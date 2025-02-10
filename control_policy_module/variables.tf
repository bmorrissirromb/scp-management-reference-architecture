variable "cp_name" {
  description = "Name to be used for the Control Policy"
  type        = string
}

variable "cp_desc" {
  description = "Description of the Control Policy"
  type        = string
}

variable "cp_policy" {
  description = "Customer managed Control Policy json to be attached"
  type        = string
  validation {
    condition = (
      length(var.cp_policy) < 5120
    )
    error_message = "Your Control Policy would exceed the AWS Quota of 5120 characters. Reduce its size."
  }
}

variable "cp_target_list" {
  description = "A list of Target IDs to which the Control Policy will be attached. It can be the Root OU or individual OUs or individual AWS Account"
  type        = list(string)
  default     = []
}

variable "policy_type" {
  description = "The type of AWS Organizations policy to create a resource for"
  type        = string
  validation {
    condition = (
      var.policy_type == "SERVICE_CONTROL_POLICY" || var.policy_type == "RESOURCE_CONTROL_POLICY"
    )
    error_message = "Only SERVICE_CONTROL_POLICY or RESOURCE_CONTROL_POLICY is supported"
  }
}
