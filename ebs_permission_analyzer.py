#########################################################################################
#       Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.              #
#                 SPDX-License-Identifier: Apache-2.0                                   #
#                                                                                       #
# Permission is hereby granted, free of charge, to any person obtaining a copy of this  #
# software and associated documentation files (the "Software"), to deal in the Software #
# without restriction, including without limitation the rights to use, copy, modify,    #
# merge, publish, distribute, sublicense, and/or sell copies of the Software, and to    #
# permit persons to whom the Software is furnished to do so.                            #
#                                                                                       #
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,   #
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A         #
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT    #
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION     #
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE        #
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.                                #
#########################################################################################
import json
import logging
import fnmatch
from botocore.exceptions import NoCredentialsError, ClientError
from botocore.config import Config
import boto3

# Configure logging
logging.basicConfig(format='%(message)s')
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG) 

# Verify AWS credentials availability:
def check_aws_credentials():
    try:
        boto3.Session().client('sts').get_caller_identity()
        return True
    except (NoCredentialsError, ClientError):
        return False

# Prompt user to manually enter AWS credentials when script can't find them in env variables.
def get_manual_credentials():
    logger.info("\nAWS credentials not found. Please enter your credentials manually.")
    while True:
        access_key = input("Enter your AWS Access Key ID: ").strip()
        if access_key:
            break
        logger.info("Access Key ID cannot be empty. Please try again.")
    
    while True:
        secret_key = input("Enter your AWS Secret Access Key: ").strip()
        if secret_key:
            break
        logger.info("Secret Access Key cannot be empty. Please try again.")
    
    return access_key, secret_key

# Creating IAM Client using boto3
def create_iam_client(access_key=None, secret_key=None):
    config = Config(
        retries=dict(max_attempts=3),
        max_pool_connections=25
    )

    if access_key and secret_key:
        session = boto3.Session(aws_access_key_id=access_key, aws_secret_access_key=secret_key)
    else:
        session = boto3.Session()
    return session.client('iam', config=config)

# Prompt user to select the API action to scan for.
def select_action():
    while True:
        logger.info("\nSelect the API action to scan for:")
        logger.info("1. ec2:CreateVolume")
        logger.info("2. ec2:CopySnapshot")
        
        choice = input("\nEnter your choice (1 or 2): ").strip()
        
        if choice == '1':
            return "ec2:CreateVolume"
        elif choice == '2':
            return "ec2:CopySnapshot"
        else:
            logger.info("Invalid choice. Please enter 1 or 2.")

def check_policy_for_action(policy_document, action_to_find):
    """
    Analyze policy document for specific IAM action permission.
    Args:
        policy_document (dict or str): IAM policy document to analyze
        action_to_find (str): IAM action to search for
    """
# Analyze policy document for specific IAM action permission.
def check_policy_for_action(policy_document, action_to_find):
    try:
        # 1. Convert string to dictionary if needed
        if isinstance(policy_document, str):
            policy_document = json.loads(policy_document)

        # 2. Get the Statement section and ensure it's a list
        statements = policy_document.get('Statement', [])
        if isinstance(statements, dict):
            statements = [statements]

        # 3. Check each statement in the policy
        for statement in statements:
            # Skip if statement is not in correct format
            if isinstance(statement, str):
                continue

            # 4. Check if this is an "Allow" statement
            if statement.get('Effect', '').lower() != 'allow':
                continue

            # 5. Get Actions and handle both string and list formats
            actions = statement.get('Action', [])
            if isinstance(actions, str):
                actions = [actions]

            # 6. Get NotActions and handle both string and list formats
            not_actions = statement.get('NotAction', [])
            if isinstance(not_actions, str):
                not_actions = [not_actions]

            # 7. Check if action is allowed through Actions
            for allowed_action in actions:
                if (allowed_action == '*' or                   # Allows all actions
                    allowed_action == 'ec2:*' or               # Allows all EC2 actions
                    fnmatch.fnmatch(action_to_find.lower(),    # Matches specific action
                                  allowed_action.lower())):
                    return True

            # 8. Check if action is allowed through NotAction
            if not_actions and action_to_find not in not_actions:
                return True

        return False
    except (json.JSONDecodeError, Exception):
        logger.debug("Failed to parse policy document")
        return False

# Check IAM authorization details to identify policies with specific permissions.
def check_authorization_details(auth_details, action_to_find):
    policies_with_action = []

    # Check all policy types in a single loop
    for item in auth_details.get('Policies', []) + \
                auth_details.get('RoleDetailList', []) + \
                auth_details.get('UserDetailList', []) + \
                auth_details.get('GroupDetailList', []):
        if 'PolicyName' in item:  # Customer Managed Policy
            for version in item.get('PolicyVersionList', []):
                if version.get('IsDefaultVersion') and check_policy_for_action(version['Document'], action_to_find):
                    policies_with_action.append({'type': 'Customer Managed', 'name': item['PolicyName'], 'arn': item['Arn']})
        elif 'RoleName' in item:  # Role Inline Policy
            for policy in item.get('RolePolicyList', []):
                if check_policy_for_action(policy['PolicyDocument'], action_to_find):
                    policies_with_action.append({'type': 'Role Inline', 'role': item['RoleName'], 'policy': policy['PolicyName']})
        elif 'UserName' in item:  # User Inline Policy
            for policy in item.get('UserPolicyList', []):
                if check_policy_for_action(policy['PolicyDocument'], action_to_find):
                    policies_with_action.append({'type': 'User Inline', 'user': item['UserName'], 'policy': policy['PolicyName']})
        elif 'GroupName' in item:  # Group Inline Policy
            for policy in item.get('GroupPolicyList', []):
                if check_policy_for_action(policy['PolicyDocument'], action_to_find):
                    policies_with_action.append({'type': 'Group Inline', 'group': item['GroupName'], 'policy': policy['PolicyName']})

    return policies_with_action

# Retrieve all policies containing the specified action.
def get_policies_with_action(iam, action):
    from concurrent.futures import ThreadPoolExecutor, as_completed # import concurrent.futures

    policies_with_action = []
    try:
        paginator = iam.get_paginator('get_account_authorization_details')
        pages = list(paginator.paginate(
            Filter=['User', 'Role', 'Group', 'LocalManagedPolicy'],
            PaginationConfig={'PageSize': 100}
        ))
        
        max_workers = min(10, len(pages))  # Adjust max_workers based on number of pages
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(check_authorization_details, page, action) for page in pages]
            for future in as_completed(futures):
                policies_with_action.extend(future.result())

    except ClientError as e:
        logger.error("AWS Client Error during policy scanning: %s", str(e))
        raise
    except Exception as e:
        logger.error("Unexpected error during policy scanning: %s", str(e), exc_info=True)
        raise

    return policies_with_action

# Display the scan results grouped by policy type.
def display_results(policies):
    if not policies:
        logger.info("\nNo policies found containing the specified action.")
        return

    # Group policies by type
    customer_managed = []
    role_inline = []
    user_inline = []
    group_inline = []

    for policy in policies:
        if policy['type'] == 'Customer Managed':
            customer_managed.append(policy)
        elif policy['type'] == 'Role Inline':
            role_inline.append(policy)
        elif policy['type'] == 'User Inline':
            user_inline.append(policy)
        elif policy['type'] == 'Group Inline':
            group_inline.append(policy)

    logger.info("\nFound policies:")
    
    # Display Role Inline Policies
    if role_inline:
        logger.info("\nRole Inline Policies:")
        for policy in role_inline:
            logger.info(f"- {policy['policy']} (Role: {policy['role']})")

    # Display User Inline Policies
    if user_inline:
        logger.info("\nUser Inline Policies:")
        for policy in user_inline:
            logger.info(f"- {policy['policy']} (User: {policy['user']})")

    # Display Group Inline Policies
    if group_inline:
        logger.info("\nGroup Inline Policies:")
        for policy in group_inline:
            logger.info(f"- {policy['policy']} (Group: {policy['group']})")

    # Display Customer Managed Policies
    if customer_managed:
        logger.info("\nCustomer Managed Policies:")
        for policy in customer_managed:
            logger.info(f"- {policy['name']}")
            logger.info(f"  ARN: {policy['arn']}")

    logger.info(f"\nTotal policies found: {len(policies)}")

def print_disclaimer(action):
    logger.warning("\nDisclaimer:")
    logger.warning(f"* Please be aware this script list IAM polices that give both implicit and explicit access to {action} action.")
    if action == "ec2:CreateVolume":
        logger.warning("* For more information about changes to CreateVolume API, see - https://aws.amazon.com/blogs/storage/enhancing-resource-level-permission-for-creating-an-amazon-ebs-volume-from-a-snapshot")
    elif action == "ec2:CopySnapshot":
        logger.warning("* For more information about CopySnapshot API permissions, refer to AWS documentation.")
        
def setup_aws_client():
    if not check_aws_credentials():
        access_key, secret_key = get_manual_credentials()
        return create_iam_client(access_key, secret_key)
    else:
        return create_iam_client()

def scan_and_display_policies(iam):
    logger.info("Scannning for IAM policies that permit 'ec2:CreateVolume' action ...")
    policies = get_policies_with_action(iam, "ec2:CreateVolume")
    display_results(policies)

def handle_errors(e):
    if isinstance(e, ClientError):
        logger.error(f"\nError: {e}")
        if e.response['Error']['Code'] == 'AccessDenied':
            logger.error("Please ensure you have the necessary permissions to list and read IAM policies and roles.")
        elif e.response['Error']['Code'] == 'InvalidClientTokenId':
            logger.error("Invalid AWS credentials. Please check your credentials and try again.")
    elif isinstance(e, NoCredentialsError):
        logger.error("\nError: AWS credentials not found or invalid.")
    else:
        logger.error(f"\nUnexpected error: {str(e)}")

def main():
    try:
        # Get user's action selection
        selected_action = select_action()
        
        # Setup AWS client
        iam = setup_aws_client()
        
        # Scan for selected action
        logger.info(f"\nScannning for IAM policies that permit '{selected_action}' action ...")
        policies = get_policies_with_action(iam, selected_action)
        display_results(policies)
        
        # Show disclaimer with selected action
        print_disclaimer(selected_action)
    except Exception as e:
        handle_errors(e)

if __name__ == "__main__":
    main()