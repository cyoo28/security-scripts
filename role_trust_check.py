#!/usr/bin/env python3
import sys
import boto3

def getRoleInfo(iam, awsPrincipal, role, myAccount, orgAccounts, extRoles, intRoles, unknownRoles):
    # Get the name of the role, its creation date, and the date that it was last used
    roleName = role["RoleName"]
    createDate = role["CreateDate"].strftime('%Y-%m-%d %H:%M:%S %Z')
    try:
        lastUseDate = iam.get_role(RoleName=roleName)["Role"]["RoleLastUsed"]["LastUsedDate"].strftime('%Y-%m-%d %H:%M:%S %Z')
    # If the role has never been used then the returned role will not have this value
    except:
        lastUseDate = "No activity"
    # Add the value to the referenced dictionary
    if ":" in awsPrincipal:
        if awsPrincipal.split(":")[4] not in orgAccounts:
            extRoles[roleName] = {"Creation Date":createDate,"Last Used":lastUseDate}
        elif awsPrincipal.split(":")[4] != myAccount:
            intRoles[roleName] = {"Creation Date":createDate,"Last Used":lastUseDate}
    else:
        unknownRoles[roleName] = {"Creation Date":createDate,"Last Used":lastUseDate}

def main(iam, sts, org):
    # Set up the paginators
    iamPaginator = iam.get_paginator('list_roles')
    orgPaginator = org.get_paginator('list_accounts')
    # Get current account ID and account IDs within the organization
    myAccount = sts.get_caller_identity().get('Account')
    orgAccounts = []
    # Iterate through the paginator
    orgIterator = orgPaginator.paginate()
    for page in orgIterator:
        for account in page["Accounts"]:
            orgAccounts.append(account["Id"])
    # Create a new report file
    with open(fileName, "w") as file:
        file.write("Type, Role Name, Creation Date, Last Used\n")
    # Set up the dictionaries that contain the roles with cross-account access
    extRoles = {} # for roles with trust to accounts external to the organization
    intRoles = {} # for roles with trust to accounts internal to the organization
    unknownRoles = {} # for roles with trust to an entity that may no longer exist

    # Iterate through the paginator
    iamIterator = iamPaginator.paginate()
    for page in iamIterator:
        # Iterate through each role
        for role in page["Roles"]:
            # Print role name
            #print(role["RoleName"])
            # Iterate through each assume role policy statement (a role could have more than one)
            for statement in role["AssumeRolePolicyDocument"]["Statement"]:
                # Stop iterating through the statements if it has already been confirmed that this role has cross-account access
                if role["RoleName"] in extRoles or role["RoleName"] in intRoles or role["RoleName"] in unknownRoles:
                    break
                else:
                    # Check that the statement is for an AWS principal
                    principals = statement.get("Principal",{})
                    if "AWS" in principals:
                        awsPrincipals = principals["AWS"]
                        if isinstance(awsPrincipals, str):
                            awsPrincipals = [awsPrincipals]
                        for awsPrincipal in awsPrincipals:
                            getRoleInfo(iam, awsPrincipal, role, myAccount, orgAccounts, extRoles, intRoles, unknownRoles)
    # Write the results to the file
    with open(fileName, "a") as file:
        if not extRoles:
            print("No External Roles (that allow access to accounts outside the org)")
        else:
            for key, value in extRoles.items():
                file.write("{},{},{},{}\n".format("External", key, value["Creation Date"], value["Last Used"]))
        if not intRoles:
            print("No Internal Roles (that allow access to accounts inside the org)")
        else:
            for key, value in intRoles.items():
                file.write("{},{},{},{}\n".format("Internal", key, value["Creation Date"], value["Last Used"]))
        if unknownRoles:
            for key, value in intRoles.items():
                file.write("{},{},{},{}\n".format("Unknown", key, value["Creation Date"], value["Last Used"]))

if __name__ == "__main__":
    # verify that all arguments are used
    if len(sys.argv) < 3:
        print('Not enough arguments have been passed.')
        print("arg: 'account-profile', 'org-admin-profile', 'reportName' (optional)")
        sys.exit(1)
    if len(sys.argv) > 3:
        fileName = sys.argv[3]
    else:
        fileName = "role-cross-account-report.csv"
    # config profile [str]
    # e.g. "symphony-c9dev"
    accProfile = sys.argv[1]
    orgProfile = sys.argv[2]
    # check that the profile is valid by creating a boto3 session
    try:
        accSession = boto3.Session(profile_name=accProfile)
        orgSession = boto3.Session(profile_name=orgProfile)
        iam = accSession.client("iam")
        sts = accSession.client("sts")
        org = orgSession.client('organizations')
    except:
        print("Unable to create session.\nCheck the profile.")
        print("arg: 'profile', 'reportName' (optional)")
        sys.exit(1)
    main(iam, sts, org)