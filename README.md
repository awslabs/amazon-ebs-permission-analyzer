# EBS Permission Analyzer

## Description

The EBS Permission Analyzer is an automated tool designed to identify IAM policies within your AWS account that contain the ‘ec2:CreateVolume’ or ‘ec2:CopySnapshot’ actions. This tool is particularly useful for organizations managing EBS volumes and snapshots, assisting in identifying policies that may necessitate review or modification to ensure appropriate access control in accordance with the recent announcement of enhanced resource-level permissions for following actions:

- [CreateVolume action](https://aws.amazon.com/blogs/storage/enhancing-resource-level-permission-for-creating-an-amazon-ebs-volume-from-a-snapshot/)

### Key Features

- Automated scanning of IAM policies across your AWS account.
- Option to scan for 'ec2:CreateVolume' or 'ec2:CopySnapshot' actions.
- Detection of both inline and managed policies across IAM Users, Groups & Roles.
- Comprehensive reporting of policies allowing the selected action explicitly and implicitly.
- Compatible with any CLI environment including AWS CloudShell.
- Simple execution with minimal setup.

## Usage

### Prerequisites

- Python 3.x
- [Boto3](https://boto3.amazonaws.com/v1/documentation/api/latest/guide/quickstart.html) library (`pip install boto3`)
- Configure [AWS credentials](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html) (via AWS CLI or environment variables)
- Required IAM permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["iam:GetAccountAuthorizationDetails"],
      "Resource": "*"
    }
  ]
}
```

### Quick Start

1. Navigate to below URL and download the script:

```bash
https://github.com/awslabs/amazon-ebs-permission-analyzer/blob/main/ebs_permission_analyzer.py
```

2. Make the script executable:

```bash
chmod +x ebs_permission_analyzer.py
```

3. Execute the script:

```bash
python ebs_permission_analyzer.py
```

4. Follow the on-screen prompts to select the action you want to scan for (CreateVolume or CopySnapshot).

## Sample Output

```
Select the API action to scan for:
1. ec2:CreateVolume
2. ec2:CopySnapshot

Enter your choice (1 or 2): 1

Scanning for IAM policies that permit 'ec2:CreateVolume' action...

Found policies:

Role Inline Policies:
- Devops-role-policy (Role: Devops-role)

User Inline Policies:
- EC2-full-access (User: EC2-Admin)

Group Inline Policies:
- Devops-Group-policy (Group: Devops-Group)

Customer Managed Policies:
- production-permission-boundary
  ARN: arn:aws:iam::123456789012:policy/production-permission-boundary

Total policies found: 4

Disclaimer:
Please be aware this script lists IAM policies that give both implicit and explicit access to ec2:CreateVolume action.
For more information about changes to CreateVolume API, see - https://aws.amazon.com/blogs/storage/enhancing-resource-level-permission-for-creating-an-amazon-ebs-volume-from-a-snapshot
```

## Security

This tool requires IAM credentials with specific permissions. Please ensure:

- Use of least privilege principles when configuring IAM permissions.
- No hardcoding of AWS credentials in the code.
- Regular rotation of AWS access keys.
- Execution in a secure environment.

### Best Practices

- Use AWS CloudShell or EC2 instances with appropriate IAM roles
- Review and audit the generated reports in a secure manner
- Ensure AWS credentials are properly configured before execution

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### Support

For support, please create an issue in the GitHub repository or contact the maintainers.

## Authors

- [Tuhin Mukherjee](https://github.com/tuhinmukherjee)
