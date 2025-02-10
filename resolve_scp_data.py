"""
Summary
    This script will walk through the control_policies_ou_structure folder and generate SCP attachments based on its contents

Input
    A directory structure containing folders that match your AWS Organization, with JSON files representing SCP attachments.

Output
    A Terraform file that will create the SCP attachments using the `scp_module` like so:
    module "Service_Baseline_Root" {
        source          = "./scp_module"
        ...
    }
"""

import boto3
import glob
import logging
import os
import json
import re

MAX_CUSTOM_POLICY_ATTACHMENTS = (
    4  # making this a global variable as it may change in future AWS versions
)
MAX_FOLDER_CUSTOM_POLICY_ATTACHMENTS = (
    MAX_CUSTOM_POLICY_ATTACHMENTS - 2
)  # Assumes that Control Tower applies 2 guardrails to each OU
CONTROL_POLICIES_FOLDER = "control_policies_ou_structure"
CHILD_TYPES = ["ORGANIZATIONAL_UNIT", "ACCOUNT"]
ACCOUNT_SUFFIX = "_ACCOUNT"  # Differentiates OU folders vs Account folders
OUTPUT_FILE = "scp_define_attach_auto.tf"
GLOBAL_SCP_NAME_LIST = (
    []
)  # TODO - Implement a check to ensure that same-named policies are not present

logging.basicConfig(level=logging.INFO)


def verify_attachment_counts(
    current_path,
    policy_type,
):
    # Count the number of attachments in the current path
    attachment_count = 0
    if policy_type == "RESOURCE_CONTROL_POLICY":
        short_name = "rcp"
    elif policy_type == "SERVICE_CONTROL_POLICY":
        short_name = "scp"
    else:
        raise Exception(
            f"Policy type {policy_type} is not supported. Only RESOURCE_CONTROL_POLICY and SERVICE_CONTROL_POLICY are supported."
        )
    for each_item in os.listdir(current_path):
        if os.path.isfile(os.path.join(current_path, each_item)) and re.search(
            rf"\.{short_name}(\.shared)?$", each_item
        ):
            attachment_count += 1
        if attachment_count > MAX_CUSTOM_POLICY_ATTACHMENTS:
            raise Exception(
                f"The {current_path} folder has more than {MAX_CUSTOM_POLICY_ATTACHMENTS} {policy_type} attachments, making it invalid. Fix it before continuing."
            )
        if not re.search(r"(ROOT|ACCOUNT)$", current_path) and attachment_count > (
            MAX_CUSTOM_POLICY_ATTACHMENTS - 2
        ):
            raise Exception(
                f"The {current_path} folder is an OU folder with more than 2 custom attachments, making it invalid. Fix it before continuing."
            )
    logging.info(
        f"Successfully validated {policy_type} attachment counts for folder {current_path}."
    )


def get_policy_attachments(
    current_target_id,
    current_path,
    data_dict,
    org_client,
    policy_type,
):
    # Get Shortname
    if policy_type == "RESOURCE_CONTROL_POLICY":
        short_name = "rcp"
    elif policy_type == "SERVICE_CONTROL_POLICY":
        short_name = "scp"
    else:
        raise Exception(
            f"Policy type {policy_type} is not supported. Only RESOURCE_CONTROL_POLICY and SERVICE_CONTROL_POLICY are supported."
        )
    # Count the number of items in the current path and exit if invalid
    logging.info(f"Scanning {current_path} for {policy_type} attachments")
    verify_attachment_counts(
        current_path=current_path,
        policy_type=policy_type,
    )
    # Enumerate directly-attached control policies
    for json in glob.glob(
        os.path.join(current_path, f"*.{short_name}"), recursive=False
    ):
        base_name = os.path.basename(json).replace(f".{short_name}", "")
        data_dict[base_name] = {
            "path": f"{current_path}/{base_name}.{short_name}",
            "targets": [current_target_id],
        }
    # If there are SHARED files in the folder, create Terraform resources that reference their SHARED equivalent.
    for shared_json in glob.glob(os.path.join(current_path, f"*.{short_name}.shared")):
        logging.info(
            f"Pulling policy attachment info for {shared_json} within {current_path}"
        )
        base_name = os.path.basename(shared_json).replace(".{short_name}.shared", "")
        if data_dict.get(base_name, ""):
            data_dict[base_name]["targets"].append(current_target_id)
        else:
            data_dict[base_name] = {
                "path": f"{CONTROL_POLICIES_FOLDER}/SHARED/{base_name}.{short_name}",
                "targets": [current_target_id],
            }
    # Get all child OUs and Accounts
    for child_type in CHILD_TYPES:
        if re.match(r"\d{12}", current_target_id):
            # Don't recurse into accounts
            continue
        children = org_client.list_children(
            ParentId=current_target_id, ChildType=child_type
        )
        while "NextToken" in children:
            children.append(
                org_client.list_children(
                    ParentId=current_target_id,
                    ChildType=child_type,
                    NextToken=children["NextToken"],
                )
            )
        for child in children["Children"]:
            object_id = child["Id"]
            if child_type == "ORGANIZATIONAL_UNIT":
                child_path_name = org_client.describe_organizational_unit(
                    OrganizationalUnitId=object_id
                )["OrganizationalUnit"]["Name"]
            else:
                child_path_name = (
                    org_client.describe_account(AccountId=object_id)["Account"]["Name"]
                    + ACCOUNT_SUFFIX
                )
            # Recursive call for each sub-OU
            try:
                data_dict.update(
                    get_policy_attachments(
                        current_target_id=object_id,
                        current_path=os.path.join(current_path, child_path_name),
                        data_dict=data_dict,
                        org_client=org_client,
                        policy_type=policy_type,
                    )
                )
            except FileNotFoundError:
                raise FileNotFoundError(
                    "The AWS OU structure contains a resource without a matching file/folder in the SCP repo. To resolve this, run the update_scp_ou_structure workflow."
                )

    return data_dict


def get_terraform_resource_string(
    # Name of the Control Policy
    cp_name,
    # Path to the Control Policy JSON file, relative to the CONTROL_POLICIES_FOLDER
    cp_policy_path,
    # List of targets to attach the SCP to
    cp_target_list,
    # The SCP policy type
    cp_type,
):
    """
    This function will return a string that represents a Terraform resource
    """
    cp_policy_path = cp_policy_path.replace("\\", "/")
    cp_target_list_string = ", ".join(f'"{s}"' for s in cp_target_list)
    cp_resource_string = f"""
module "{cp_name}" {{
  source          = "./control_policy_module"
  cp_name        = "{cp_name}"
  cp_desc        = jsondecode(file("./{cp_policy_path}")).description
  cp_policy      = jsonencode(jsondecode(file("./{cp_policy_path}")).policy)
  cp_target_list = [{cp_target_list_string}]
  policy_type    = "{cp_type}"
}}

output "{cp_name}_byte_size" {{
  value = module.{cp_name}.cp_byte_size
}}
"""
    return cp_resource_string


def main():
    org_client = boto3.client("organizations")
    root = org_client.list_roots()["Roots"][0]
    root_id = root["Id"]
    # The data dictionary will keep track of control policy names, source paths, and targets
    data_dict = {}

    # Delete the output file if it exists so that we're starting fresh
    if os.path.exists(OUTPUT_FILE):
        os.remove(OUTPUT_FILE)

    root_path = os.path.join(CONTROL_POLICIES_FOLDER, "ROOT")
    current_target_id = root_id
    current_path = root_path
    policy_list = [
        "SERVICE_CONTROL_POLICY",
        "RESOURCE_CONTROL_POLICY",
    ]
    for current_policy_type in policy_list:
        data_dict = get_policy_attachments(
            current_target_id=current_target_id,
            current_path=current_path,
            data_dict=data_dict,
            org_client=org_client,
            policy_type=current_policy_type,
        )
        # Write the Terraform manifest
        with open(OUTPUT_FILE, "a") as f:
            for cp_entry in data_dict:
                cp_policy_path = data_dict[cp_entry]["path"]
                cp_target_list = data_dict[cp_entry]["targets"]
                f.write(
                    get_terraform_resource_string(
                        cp_name=cp_entry,
                        cp_policy_path=cp_policy_path,
                        cp_target_list=cp_target_list,
                        cp_type=current_policy_type,
                    )
                )


if __name__ == "__main__":
    main()
