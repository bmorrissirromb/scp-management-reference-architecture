# Service Control Policy (SCP) Management Pipeline

In this example, you will automate AWS SCP pipeline for managing and tracking service control policies (SCPs) across an organization’s multi-account environment. 

![SCP deployment pipeline example archiecture](/static/ref_arch.png "Example Architecture")

### Prerequisites

Before getting started, 
* Make sure that you have a pre-configured [Amazon SNS topic with atleast one verified subscriber](https://docs.aws.amazon.com/sns/latest/dg/sns-create-topic.html).
* You also need organization units in your AWS environment as the SCPs will need target to be attached.

Basic understating of the following can help as this solution uses: 
* Python and [Boto3](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html).
* [CDK environments](https://docs.aws.amazon.com/cdk/v2/guide/environments.html).

## Deploy the infrastructure and set up the pipeline

1. Use the following command to download and unzip the Cloud Development Kit (CDK) project associated with this blog post.

    ```git clone https://github.com/aws-samples/scp-management-reference-architecture```
    
2. Create a virtual Python environment to contain the project dependencies by using the following command.

    ```python3 -m venv .venv```

3. Activate the virtual environment with the following command.

    ```source .venv/bin/activate```

4. Install the project requirements by using the following command.

    ```pip install -r requirements.txt```

5. Use the following command to update the CDK CLI to the latest major version.

    ```npm install -g aws-cdk@2 --force```

6. Before you can deploy the CDK project, use the following command to bootstrap your AWS environment. Bootstrapping is the process of creating resources needed for deploying CDK projects. These resources include an Amazon Simple Storage Service (Amazon S3) bucket for storing files and IAM roles that grant permissions needed to perform deployments.

    ```cdk bootstrap```

7. Finally, use the following command to deploy the pipeline infrastructure. Replace SNS arn of the topic you want to receive alerts for manual approval with your sns arn.

    ```cdk deploy --parameters SNSarn=SNS arn of the topic you want to receive alerts for manual approval``` 

8. The deployment will generate create a CodeCommmit repository with the files in this repository, CodeBuild projects for the different validation steps for the SCP deployment, and a CodePipeline tying all the CodeBuild steps togather.

9. Once the pipeline runs, and if the SCPs specified in the templates pass all the validation steps, a notification will be sent to the subscribed email/mobile address on the SNS topic that was provided during CDK deploy. Once you approve the changes, the pipeline will attempt to deploy SCPs in your AWS Organization if the correct organization structure exists. 

### Cleanup

Use the following command to delete the infrastructure that was provisioned as part of the examples in this blog post.

  ```cdk destroy```


## Repository walk-through

### Repository Structure

```sh

.
├── devtools.py # <-- sets up the development and deployment tools.
├── pipeline.py # <-- defines the CI/CD pipeline stages and how the application is built and deployed.
├── SCP_Management_Pipeline.py  # <-- sets up the main resources required for the SCP pipeline solution.
├── Static
  ├── scp_define_attach.tf     # <-- main terraform file that is executed when you perform <terraform apply>.
  ├── variables.tf             # <-- variable definition file
  ├── terraform.tfvars         # <-- pass values to variables before execution through this file
  ├── service_control_policies # <-- a directory with sub-directories specific to the OUs to which SCPs are directly attached
      ├── Root                      # <-- all SCP policies to be attached directly to Root
      ├── InfrastructureOU          # <-- all SCP policies to be attached directly to Infrastructure OU
      ├── MultiOUs                  # <-- all SCP policies to be attached directly to the list of multiple OUs.
                                    #     To check the list, refer to .tfvars files in terraform directory.
                                    #     Look for variables whose name is similar to the last keyword of the SCP policy
  ├── scp_module               # <-- code for creating SCPs and attaching them to targets
  ├── List-of-SCPs.md          # <-- A file containing overview of all the SCPs enabled in your company.
                              #     Must be updated every time a change is made to any SCP policy
└── README.md                # <-- This file
```

### Scripts in this directory

1. **_`scp_define_attach.tf`_** - this is the main terraform file that is executed. All the SCPs creation and attachement calls are made from this file.
2. **_`variables.tf`_** - this is where you define all the runtime values that you want to pass to the SCP creaion process, which includes account IDs, OU names etc.
3. **_`terraform.tfvars`_** - this is the file where you provide the value for each of the variables defined in `variables.tf` file

### service_control_policies

- this directory contains all the custom SCP policy statements built for your company, categorized based on the Orgaization Unit (OU) to which there are attached. For example, in this directory all the SCP policy files you will see under the `Root` sub-directory are attached directly to the Root OU.
- **scripts in this directory:** All SCP policy files are defined as `.tpl` files. Files with `.tpl` extensions are template files that gives you the privilege to pass user-defined variables at runtime to the file.
- In this directory all the `.tpl` files are in json format

### scp_module

- this directory contains the terraform resources for
  1. creating a SCP in the organization's management account
  2. attaching the above created SCP to a desired target OU or AWS Account as provided by you.
     > NOTE: Benefit of this module directory is defining the SCP creation and attachment resources only once in your repository and call these two resources as many times as required in a modularized approach. Thus maintainig standardized coding and avoid repeated resource definition in code.
- **scripts in this directory:**
  1. **_`main.tf`_** - this is the terraform file where two resources are defined.
     - `resource "aws_organizations_policy"` for creating a SCP
     - `resource "aws_organizations_policy_attachment"` for attaching a SCP. This block is optional and depends on whether you want to attach a SCP to a target. Decision of this resource execution varies on the runtime input value passed to `main.tf` via the `scp_target_list` variable. If you do not pass any value for this variable, this resource block will not be executed
  2. **_`variables.tf`_** - this is where you define all the values that are passed to the `main.tf` file.

## SCP File Naming Convention

> NOTE:
> 1. All SCP files created in this repository are template files (`.tpl` extension)
> 2. Any SCP file you create in this repository should have a suffix of `.json` followed by the extension `.tpl`

### SCP File Names for Root:

- Account_Baseline_Root.json.tpl
- Security_Baseline_Root.json.tpl
- Infrastructure_Baseline_Root.json.tpl
- Data_Baseline_Root.json.tpl

### SCP File Names for Multiple OUs:

- Account_Baseline_*Logical Keyword*.json.tpl
- Security_Baseline_*Logical Keyword*.json.tpl
- Infrastructure_Baseline_*Logical Keyword*.json.tpl
- Data_Baseline_*Logical Keyword*.json.tpl
  > This logical keyword should define the logical grouping of multiple OUs you have planned for applying the SCP statements. **For example**, if you have a set of VPC and EC2 restrictions that you want to put on all non-infrastructure OUs then your SCP file name can be `Infrastructure_Baseline_NonInfraOUs.json.tpl`

### SCP File Names for any specific OU:

- Account*Baseline*_OU Name_.json.tpl
- Security*Baseline*_OU Name_.json.tpl
- Infrastructure*Baseline*_OU Name_.json.tpl
- Data*Baseline*_OU Name_.json.tpl

### SCP File Names for any specific AWS Account:

- Account*Baseline*_Account Name or ID_.json.tpl
- Security*Baseline*_Account Name or ID_.json.tpl
- Infrastructure*Baseline*_Account Name or ID_.json.tpl
- Data*Baseline*_Account Name or ID_.json.tpl

## Steps to follow for Adding New SCPs

1.  First identify the target to which your new SCP statement should be attached.
    - **If you want to attach your SCP policy actions to all OUs**, check the `Root` sub-directory in `service_control_policies` directory
    - **If you want to attach your SCP policy actions to Multiple OUs but not All**, check the `MultiOUs` sub-directory in `service_control_policies` directory
    - **If you want to attach your SCP policy actions to a specific OU or AWS Account**, check under `service_control_policies` directory if a sub-directory exist with a name same as the OU or AWS Account name you want to attach your policy actions.
      - If you find one, then go to the next step to see how to add the policy actions
      - If you DONT find the appropriate sub-directory then create one with a name exactly same as the OU or AWS Account name you want to attach your policy actions, then go to next step.
2.  Based on the target chosen for your SCP navigate to the appropriate sub-directory, next identify under what category does your new SCP policy actions belong out of the below mentioned four catgeories.
    - `account_baseline_scp` - choose this category if yor policy actions are specific to governance or account management services
    - `security_iam_baseline_scp` - choose this category if yor policy actions are specific to security services
    - `infrastructure_baseline_scp` - choose this category if yor policy actions are specific to network services
    - `data_logging_baseline_scp` - choose this category if yor policy actions are specific to storage services
3.  Next, check if an SCP file with a name similar to your above chosen SCP category exist in the sub-directory you have decided as your SCP target.
    - If you find an existing file with a name similar to your above chosen SCP category then edit the identified SCP file, either add your actions to an existing statement or create a new statement in the policy file based on the SCP policy size limit and your requirements. Go to Step 4.
    - If you DONT find an existing file with a name similar to your above chosen SCP category then create a new SCP policy file with your policy actions. The name of this new SCP file must follow the standard naming convention defined in [SCP File Naming Convention](#scp-file-naming-convention)
      - If you created a new SCP file then creating the policy file, next you have to create a module block in the `scp_define_attach.tf` file to create a SCP policy and attach it to the target.
      - In the new module block, you will have to provide the following parameters:
        - source = `"../scp_module"` - this source path should not be changed
        - scp*name = \_a name that follows the SCP naming standards as outlined in this README*
        - scp*desc = \_a short description about the SCP*
        - scp*policy = jsonencode(jsondecode(templatefile("../service_control_policies/\_path of .tpl file*", { _variables to pass to the policy file_})))
        - scp_target_list = [*either a target OU or Account ID or a series of OUs. In any case this should be passed as a list even if the target is just one ID*]
4.  Update the `List-of-SCPs.md` with details of the new SCP policy file added to the service_control_policies directory.
5.  Next, push your code for a PR and after approval the new SCP policy actions will be reflected in your AWS organizations.

> NOTE:
> 1. If you want to pass any specific value to the SCP policy like account ID or a role name etc, you can pass it as an input variable to the `scp_policy`
> 2. If you want to attach the SCP to a list of OUs and no other SCPs are already attached to this target list of OUs, then you can define a variable in the `variables.tf` as a list(string). Define the value of this variable in the `terraform.tfvars` file and enter the name of all of your chosen OUs in it.

### Steps to edit existing SCPs

Either edit policy's Action or Resource or Conditions

1.  First identify where in `service_control_policies` directory the SCP policy is defined
2.  Based on the correct `.tpl file` chosen, next edit the file.
3.  Update the `List-of-SCPs.md` with details of the new policy statement added to an existing SCP in service_control_policies directory.
4.  After file edit, the pipeline will detect the change and run.

## Steps to follow for Denying All Actions from a specific OU

Remove the `FullAWSAccess` policy that is directly attached to the OU to which you want to deny all actions.

> NOTE: The `FullAWSAccess` policy inherited from a parent OU will not allow permissions to a principal (OU or account) until you directly attach the `FullAWSAccess` policy to the principal.

## Security
See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License
This library is licensed under the MIT-0 License. See the LICENSE file.