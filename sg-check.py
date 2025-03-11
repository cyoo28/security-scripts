#!/usr/bin/env python3

import sys
import ast
import boto3

def checkSgUsage(client, check_sg_ids):
    # list all network interfaces
    paginator = client.get_paginator('describe_network_interfaces')
    page_iterator = paginator.paginate()
    # look at the security groups that are being used with the network interfaces
    usedSgs = set()
    for enis in page_iterator:
        for eni in enis["NetworkInterfaces"]:
            for group in eni["Groups"]:
                # if the security group is in the list of groups you're looking for,
                if group["GroupId"] in check_sg_ids:
                    # then add it to the list of used security groups
                    usedSgs.add(group["GroupId"])
    # return the security groups that are being used
    return usedSgs

def main(client, checkSgs):
    # return security groups that are in use
    usedSgs = checkSgUsage(client, checkSgs)
    if usedSgs:
        print("The following security groups are in use:")
        print("  {}".format(usedSgs))
    else:
        print("None of the security groups are in use")

if __name__ == "__main__":
    # verify that all arguments are used
    if len(sys.argv) < 4:
        print('Not enough arguments have been passed.')
        print("arg: 'profile', 'region', ['sg-1', 'sg-2', ...]")
        sys.exit(1)

    # config profile [str]
    # e.g. "symphony-c9dev"
    profile = sys.argv[1]
    # check that the profile is valid by creating a boto3 session
    try:
        session = boto3.Session(profile_name=profile)
    except:
        print("Unable to create session.\nCheck the profile.")
        print("arg: 'profile', 'region', ['sg-1', 'sg-2', ...]")
        sys.exit(1)

    # region to search in [str]
    # e.g. "us-east-1"
    region = sys.argv[2]
    # check that the region is valid
    validRegions = session.get_available_regions('ec2')
    if region not in validRegions:
        print("Not a valid region.\nCheck that the region is spelled correctly.")
        print("arg: 'profile', 'region', ['sg-1', 'sg-2', ...]")
        sys.exit(1)

    # recreate the session specifying the valid region
    session = boto3.Session(profile_name=profile, region_name=region)
    client = session.client("ec2")

    # security groups to look up [list or str]
    # e.g. "['sg-089c5df23b33ac8b5', 'sg-05816c13731074c0d']"
    checkSgs = ast.literal_eval(sys.argv[3])
    # check to see if the security groups exist
    paginator = client.get_paginator('describe_security_groups')
    page_iterator = paginator.paginate()
    # look at the security groups that are being used with the network interfaces
    existingSgs = set()
    for page in page_iterator:
        for sg in page["SecurityGroups"]:
            existingSgs.add(sg["GroupId"])
    errorSgs = list(set(checkSgs).difference(existingSgs))
    if errorSgs:
        print("The following security groups do not exist:\n")
        for errorSg in errorSgs:
            print(errorSg+"\n")
        print("Check that these security groups are spelled correctly and that you are looking in the correct account/region.")
        sys.exit(1)

    # if all checks are passed, run the rest of the code
    main(client, checkSgs)