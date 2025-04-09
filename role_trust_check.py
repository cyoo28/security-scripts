#!/usr/bin/env python3
import sys
import boto3

def getRoleInfo(iam, awsPrincipal, role, myAccount, orgAccounts, extRoles, intRoles):
    # Get the name of the role, its creation date, and the date that it was last used
    roleName = role["RoleName"]
    createDate = role["CreateDate"].strftime('%Y-%m-%d %H:%M:%S %Z')
    try:
        lastUseDate = iam.get_role(RoleName=roleName)["Role"]["RoleLastUsed"]["LastUsedDate"].strftime('%Y-%m-%d %H:%M:%S %Z')
    # If the role has never been used then the returned role will not have this value
    except:
        lastUseDate = "No activity"
    # Add the value to the referenced dictionary
    if awsPrincipal.split(":")[4] not in orgAccounts:
        extRoles[roleName] = {"Creation Date":createDate,"Last Used":lastUseDate}
    elif awsPrincipal.split(":")[4] != myAccount:
        intRoles[roleName] = {"Creation Date":createDate,"Last Used":lastUseDate}


def main(iam, sts, org):
    # Get current account ID and account IDs within the organization
    myAccount = sts.get_caller_identity().get('Account')
    orgAccounts = [account["Id"] for account in org.list_accounts()["Accounts"]]
    # Create a new report file
    with open(fileName, "w") as file:
        file.write("Role Cross-Account Access Report\n")
    # Set up the paginator and dictionaries that contain the roles with cross-account access
    paginator = iam.get_paginator('list_roles')
    extRoles = {} # for accounts external to the organization
    intRoles = {} # for accounts internal to the organization
    # Iterate through the paginator
    page_iterator = paginator.paginate()
    for page in page_iterator:
        # Iterate through each role
        for role in page["Roles"]:
            # Iterate through each assume role policy statement (a role could have more than one)
            for statement in role["AssumeRolePolicyDocument"]["Statement"]:
                # Stop iterating through the statements if it has already been confirmed that this role has cross-account access
                if role["RoleName"] in extRoles or role["RoleName"] in intRoles:
                    break
                else:
                    # Check that the statement is for an AWS principal
                    principals = statement.get("Principal",{})
                    if "AWS" in principals:
                        awsPrincipals = principals["AWS"]
                        # If it is a single principal it may be specified as a str
                        if isinstance(awsPrincipals, str):
                            getRoleInfo(iam, awsPrincipals, role, myAccount, orgAccounts, extRoles, intRoles)
                        # If it are multiple principal it may be specified as a dict
                        elif isinstance(awsPrincipals, list):
                            for awsPrincipal in awsPrincipals:
                                getRoleInfo(iam, awsPrincipal, role, myAccount, orgAccounts, extRoles, intRoles)
    #print(extTrustRoles)
    #print(intTrustRoles)
    # Write the results to the file
    with open(fileName, "a") as file:
        file.write("\nRoles with External Cross-Account Access:\n")
        if not extRoles:
            file.write("(None)")
        else:
            for key, value in extRoles.items():
                file.write("Role Name: {}\n  Creation Date: {}\n  Last Used: {}\n".format(key, value["Creation Date"], value["Last Used"]))
        file.write("\n\nRoles with Internal Cross-Account Access:\n")
        if not intRoles:
            file.write("(None)")
        else:
            for key, value in intRoles.items():
                file.write("Role Name: {}\n  Creation Date: {}\n  Last Used: {}\n".format(key, value["Creation Date"], value["Last Used"]))

if __name__ == "__main__":
    # verify that all arguments are used
    if len(sys.argv) < 2:
        print('Not enough arguments have been passed.')
        print("arg: 'profile', 'reportName' (optional)")
        sys.exit(1)
    if len(sys.argv) > 2:
        fileName = sys.argv[2]
    else:
        fileName = "role-trust-report.txt"
    # config profile [str]
    # e.g. "symphony-c9dev"
    profile = sys.argv[1]
    # check that the profile is valid by creating a boto3 session
    try:
        session = boto3.Session(profile_name=profile)
        iam = session.client("iam")
        sts = session.client("sts")
        org = session.client('organizations')
    except:
        print("Unable to create session.\nCheck the profile.")
        print("arg: 'profile', 'reportName' (optional)")
        sys.exit(1)
    main(iam, sts, org)