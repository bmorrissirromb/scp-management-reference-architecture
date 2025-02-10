################################################################
# Creating an CP and then attaching it to a Target OU / Account
################################################################

# Resource to create a Control Policy in the Management Account
resource "aws_organizations_policy" "create_cp" {
  name        = var.cp_name
  description = var.cp_desc
  type        = var.policy_type
  content     = var.cp_policy
}

# Resource to attach the above created CP to a specifc Target (that can be Root OU or any individual OU or AWS Account)
resource "aws_organizations_policy_attachment" "attach_cp" {
  for_each  = toset(var.cp_target_list)
  policy_id = aws_organizations_policy.create_cp.id
  target_id = each.key
}
