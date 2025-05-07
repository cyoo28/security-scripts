# Security Scripts
These are scripts to automate workflows within AWS.

## lambda_alarm.py and lambda_lob_filter.py
These scripts offer 2 different methods for monitoring AWS CloudWatch logs for the occurrence of a JiraError in a specified log group. When the error is detected, an SNS message is sent to alert subscribers. One script uses CloudWatch alarms to trigger the alert, while the other leverages a log filter for real-time detection. These scripts help automate error monitoring and provide immediate notifications for faster issue resolution.

## role_trust_check.py
This script scans an AWS account to identify roles that allow cross-account access. It classifies the cross-account access as either internal (within the AWS organization) or external. The tool helps in auditing permissions and improving security by quickly highlighting roles with cross-account access, enabling better control over access management.

## role-checker.sh
This script reads each line from the role-checker.txt file, splits it into individual arguments, and passes those arguments to the Python script role_trust_check.py. This further automates the process of auditing roles and cross-account permissions for more than one account.

## sg_check.py
This script checks if security groups are currently in use within your AWS environment. It is designed to help determine if security groups identified in GuardDuty findings can be safely deleted or disabled before further investigation. The tool streamlines the process of identifying unused security groups, reducing the risk of unnecessary exposures.
