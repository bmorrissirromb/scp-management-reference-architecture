"""
Summary
    This script is a useful starting point if you have manually-managed SCPs that you want to migrate to IaC.
    This script will parse the OU structure and create SCP JSONs in a local representation of the OU structure.
    It will also generate import files to be used by Terraform, unless specified otherwise.

    This script can also be used to refresh the OU structure to make it easier to add new SCP attachments.
    To run this script to just refresh the OU structure and not make SCP updates or generate imports, run:
    python generate_scp_ou_structure_and_imports.py --skip-import-creation --skip-customer-scp-refresh
"""

import argparse
import boto3
from collections import Counter
import json
import logging
import os
import re

# Set log level to INFO
logging.basicConfig(level=logging.INFO)

# Initialize AWS Organizations client
org_client = boto3.client(
    "organizations",
)

# Define the local folder where you want to save the structure
OUTPUT_FOLDER = "service_control_policies"
IMPORT_POLICY_ATTACHMENTS_TF = "import_policy_attachments.tf"
# SCP_TERRAFORM_MANIFEST = "scp_define_attach.tf"


def get_all_scp_attachments(
    ou_id: str,
):
    return get_all_policy_attachments(
        ou_id=ou_id,
        policy_type="SERVICE_CONTROL_POLICY",
    )


def get_all_rcp_attachments(
    ou_id: str,
):
    return get_all_policy_attachments(
        ou_id=ou_id,
        policy_type="RESOURCE_CONTROL_POLICY",
    )


def get_all_policy_attachments(
    ou_id: str,
    policy_type: str,
):
    """
    Return a list of all policy attachments, 1 per attachment, to see what should be placed in SHARED.
    """
    list_of_policies_attached = []
    attached_scps = org_client.list_policies_for_target(
        TargetId=ou_id,
        Filter=policy_type,
    )["Policies"]
    for attached_scp in attached_scps:
        list_of_policies_attached.append(attached_scp["Name"])
    # Don't recurse into accounts
    if not re.match(r"\d{12}", ou_id):
        child_ous = org_client.list_organizational_units_for_parent(ParentId=ou_id)
        for child_ou in child_ous["OrganizationalUnits"]:
            child_attachments = get_all_policy_attachments(
                child_ou["Id"],
                policy_type=policy_type,
            )
            for child_attachment in child_attachments:
                list_of_policies_attached.append(child_attachment)
        child_accounts = org_client.list_accounts_for_parent(ParentId=ou_id)
        for child_account in child_accounts["Accounts"]:
            child_attachments = get_all_policy_attachments(
                child_account["Id"],
                policy_type=policy_type,
            )
            for child_attachment in child_attachments:
                list_of_policies_attached.append(child_attachment)
    return list_of_policies_attached


def get_child_ou_and_scps(
    ou_id,
    starting_folder,
    all_attachments_counter,
    skip_import_creation,
    skip_customer_cp_refresh,
    control_policy_type,
    attachment_dict: dict = {},
):
    """
    Walks through each OU/account in the Organization and

    This function will write files to disk in the folder structure within service_control_policies directory.


    Returns a dictionary of SCP attachments with each key representing an SCP (an SCP can be attached to multiple OUs).
    This return value can be used for troubleshooting purposes.
    """
    # Get OU Information -- OU here is root, OU, or account
    # Special case for root
    if re.match(r"r-", ou_id):
        ou_info = {}  # Empty dict to avoid KeyError: 'OrganizationalUnit'
        ou_info["OrganizationalUnit"] = {"Name": "ROOT"}
    # Special case for accounts
    elif re.match(r"\d{12}", ou_id):
        account_name = org_client.describe_account(AccountId=ou_id)["Account"]["Name"]
        ou_info = {}  # Empty dict to avoid KeyError: 'OrganizationalUnit'
        ou_info["OrganizationalUnit"] = {"Name": f"{account_name}_ACCOUNT"}
    else:
        ou_info = org_client.describe_organizational_unit(OrganizationalUnitId=ou_id)
    ou_name = ou_info["OrganizationalUnit"]["Name"]
    ou_path = os.path.join(starting_folder, ou_name)

    # Create a folder for the current OU if necessary
    os.makedirs(
        ou_path,
        exist_ok=True,
    )

    # List attached control policies for the OU
    attached_scps = org_client.list_policies_for_target(
        TargetId=ou_id,
        Filter=control_policy_type,
    )

    # Save attached SCPs as JSON files
    for control_policy in attached_scps["Policies"]:
        # Skip FullAWSAccess SCP and AWS Guardrails SCPs
        if control_policy["Name"] == "FullAWSAccess":
            print(f"Adding Full AWS Access placeholder to {ou_path}")
            with open(os.path.join(ou_path, "FullAWSAccess.placeholder"), "w") as f:
                f.write("# Placeholder for FullAWSAccess")
            continue
        cp_id = control_policy["Id"]
        cp_name = control_policy["Name"]
        # Get description but fall back to name if blank
        cp_description = control_policy["Description"]
        if cp_description == "":
            cp_description = cp_name
        if re.match(r"aws-guardrails", control_policy["Name"]):
            target_path = os.path.join(ou_path, f"{cp_name}.guardrail")
            print(f"Adding Control Tower guardrail placeholder to {target_path}")
            with open(target_path, "w") as f:
                f.write(
                    f"# This is a placeholder for the Control Tower Guardrail SCP {cp_name}"
                )
            continue
        elif (
            cp_name in all_attachments_counter
            and all_attachments_counter[cp_name] > 1
            and not skip_customer_cp_refresh
        ):
            target_path = os.path.join(OUTPUT_FOLDER, "SHARED", f"{cp_name}.json")
            placeholder = os.path.join(ou_path, f"{cp_name}.shared")
            print(f"Adding shared placeholder for {cp_name} to {target_path}")
            with open(placeholder, "w") as f:
                f.write(f"# This is a placeholder for shared Control Policy {cp_name}")
        else:
            target_path = os.path.join(ou_path, f"{cp_name}.json")
        if skip_customer_cp_refresh:
            continue
        scp_document = org_client.describe_policy(PolicyId=cp_id)["Policy"]["Content"]
        scp_document_to_print = {
            "policy": json.loads(scp_document),
            "description": cp_description,
        }
        scp_json = json.dumps(scp_document_to_print, indent=4)
        print(f"Writing Control Policy to {target_path}")
        with open(target_path, "w") as f:
            f.write(scp_json)
        if not skip_import_creation:
            with open(IMPORT_POLICY_ATTACHMENTS_TF, "a") as f:
                if control_policy_type == "SERVICE_CONTROL_POLICY":
                    short_name = "scp"
                elif control_policy_type == "RESOURCE_CONTROL_POLICY":
                    short_name = "rcp"
                else:
                    raise Exception(
                        f"Invalid control policy type: {control_policy_type}"
                    )
                f.write(
                    f"""
import {{
  to = module.{cp_name}.aws_organizations_policy_attachment.attach_{short_name}["{ou_id}"]
  id = "{ou_id}:{cp_id}"
}}
"""
                )
        if attachment_dict.get(cp_name) is None:
            attachment_dict[cp_name] = {}
            attachment_dict[cp_name] = {
                "cp_name": cp_name,
                "cp_desc": cp_description,
                "target_path": target_path,
                "cp_target_list": [ou_id],
            }
        else:
            attachment_dict[cp_name]["scp_target_list"].append(ou_id)

    # Recursively process child OUs and accounts
    if not re.match(r"\d{12}", ou_id):
        child_ous = org_client.list_organizational_units_for_parent(ParentId=ou_id)
        child_accounts = org_client.list_accounts_for_parent(ParentId=ou_id)
        for child in child_ous["OrganizationalUnits"] + child_accounts["Accounts"]:
            attachment_dict.update(
                get_child_ou_and_scps(
                    ou_id=child["Id"],
                    starting_folder=ou_path,
                    all_attachments_counter=all_attachments_counter,
                    skip_import_creation=skip_import_creation,
                    skip_customer_cp_refresh=skip_customer_scp_refresh,
                    attachment_dict=attachment_dict,
                    control_policy_type=control_policy_type,
                )
            )

    return attachment_dict


def write_policy_imports(
    file_io,
    all_policies,
    policy_type,
):
    """
    Given a filestream and list of policies, write imports for the policy to the filestream
    """
    for policy in all_type_policies:
        policy_id = policy["Id"]
        policy_name = policy["Name"]
        module_name = policy_name.replace(" ", "_")
        f.write(
            f"""
import {{
  to = module.{module_name}.aws_organizations_policy.{policy_type}
  id = "{policy_id}"
}}
"""
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate SCP/RCP structure and import manifest"
    )
    parser.add_argument(
        "--skip-customer-scp-refresh",
        help="If specified, will leave customer SCPs alone and only refresh the externally managed (Control Tower guardrails and FullAWSAccess) SCPs",
        action="store_true",
    )
    parser.add_argument(
        "--skip-import-creation",
        help="If specified, will not create any import files during the script execution. Useful for refreshes of CT and FullAWSAccess SCPs",
        action="store_true",
    )
    parser.add_argument(
        "--skip-rcps",
        help="If specified, will skip RCP creation",
        action="store_true",
    )
    args = parser.parse_args()
    skip_customer_scp_refresh = args.skip_customer_scp_refresh
    skip_import_creation = args.skip_import_creation
    skip_rcps = args.skip_rcps
    # Create the output folder
    os.makedirs(OUTPUT_FOLDER, exist_ok=True)
    os.makedirs(os.path.join(OUTPUT_FOLDER, "SHARED"), exist_ok=True)

    if not skip_import_creation:
        with open(IMPORT_POLICY_ATTACHMENTS_TF, "w") as f:
            f.write(
                f"""# This file was automatically generated by {os.path.basename(__file__)} and may require manual review
    """
            )
    # Get a list of all existing SCPs in the Organization
    if skip_rcps:
        policy_list = ["SERVICE_CONTROL_POLICY"]
    else:
        policy_list = [
            "SERVICE_CONTROL_POLICY",
            "RESOURCE_CONTROL_POLICY",
        ]
    for policy_to_query in policy_list:
        response = org_client.list_policies(Filter=policy_to_query)
        all_type_policies = response["Policies"]
        # Loop through responses while there is a NextToken
        while "NextToken" in response:
            response = org_client.list_policies(
                Filter=policy_to_query,
                NextToken=response["NextToken"],
            )
            all_type_policies.extend(response["Policies"])
        # Exclude CT-managed (aws-guardrails) and FullAWSAccess
        all_type_policies = [
            policy
            for policy in all_type_policies
            if (
                policy["Name"] != "FullAWSAccess"
                and not re.match(r"aws-guardrails", policy["Name"])
            )
        ]

        if not skip_import_creation:
            with open("import_policies.tf", "w") as f:
                logging.info("Generating policy import manifest...")
                write_policy_imports(
                    file_io=f,
                    all_policies=all_type_policies,
                    policy_type=policy_to_query,
                )

        all_policy_names = [policy["Name"] for policy in all_type_policies]

        # Get the root of the organization tree
        root_id = org_client.list_roots()["Roots"][0]["Id"]
        all_policy_attachments = get_all_policy_attachments(
            ou_id=root_id,
            policy_type=policy_to_query,
        )
        all_attachments_counter = Counter(all_policy_attachments)

        # Start parsing the organization structure
        all_attachments = get_child_ou_and_scps(
            ou_id=root_id,
            starting_folder=OUTPUT_FOLDER,
            skip_import_creation=skip_import_creation,
            skip_customer_scp_refresh=skip_customer_scp_refresh,
            all_attachments_counter=all_attachments_counter,
            control_policy_type=policy_to_query,
        )

        if not skip_customer_scp_refresh:
            logging.info(
                "Printing attachment details for customer managed control policies..."
            )
            logging.info(all_attachments)
        logging.info(
            f"Organization structure and control policies saved in {OUTPUT_FOLDER}"
        )
