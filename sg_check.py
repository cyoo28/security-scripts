#!/usr/bin/env python3
import sys
import ast
import boto3
import argparse

def checkSgUsage(ec2, checkSGs):
    # List all network interfaces
    paginator = ec2.get_paginator('describe_network_interfaces')
    page_iterator = paginator.paginate()
    # Look at the security groups that are being used with the network interfaces
    usedSGs = set()
    for enis in page_iterator:
        for eni in enis["NetworkInterfaces"]:
            for group in eni["Groups"]:
                # If the security group is in the list of groups you're looking for,
                if group["GroupId"] in checkSGs:
                    # Then add it to the list of used security groups
                    usedSGs.add(group["GroupId"])
    unusedSGs = list(set(checkSGs).difference(set(usedSGs)))
    # Return the security groups that are being used
    return usedSGs, unusedSGs

def main():
    # Create an ArgumentParser object
    parser = argparse.ArgumentParser(description="Use this script to check whether or not security groups are in use")
    # Create arguments
    parser.add_argument("profile", metavar="profile", type=str, help="The account profile that you would like to search within")
    parser.add_argument("region", metavar="region", type=str, help="The region that you would like to search within")
    parser.add_argument("checkSGs", metavar="checkSGs", nargs="+", type=str, help="The security groups you would like to search for")
    parser.add_argument("--fileName", dest="fileName", type=str, default="sg-usage-report.csv", help="Name of your file (\"sg-usage-report.csv\" if not specified)")
    parser.add_argument("--debug", dest="debug", action="store_true", help="Enable debug mode")
    # Parse the command-line arguments
    args = parser.parse_args(sys.argv[1:])
    # Create the session
    try:
        session = boto3.Session(profile_name=args.profile, region_name=args.region)
        ec2 = session.client("ec2")
    except:
        if args.debug:
            print("Unable to create session.\nCheck the profile/region.")
        sys.exit(1)
    # Create a new report file
    with open(args.fileName, "w") as file:
            file.write("Security Group Name, Status\n")
    # Set up the paginator
    paginator = ec2.get_paginator('describe_security_groups')
    # Check which security groups exist and which do not
    page_iterator = paginator.paginate()
    allSGs = set()
    for page in page_iterator:
        for sg in page["SecurityGroups"]:
            allSGs.add(sg["GroupId"])
    nonExistSGs = list(set(args.checkSGs).difference(allSGs))
    existSGs = list(set(args.checkSGs).intersection(allSGs))
    # Check whether or not existing security groups are in use
    usedSGs, unusedSGs = checkSgUsage(ec2, existSGs)
    # Write the results to the file
    with open(args.fileName, "a") as file:
        if args.debug and not usedSGs and not unusedSGs and nonExistSGs:
            print("None of the security groups exist (check the names of the security groups and if you're looking in the correct account/region)")
            sys.exit(1)
        else:
            if args.debug and not usedSGs:
                print("None of the security groups are in use")
            else:
                for usedSG in usedSGs:
                    file.write("{},{}\n".format(usedSG, "In Use"))
            if args.debug and not unusedSGs:
                print("All of the security groups are in use")
            else:
                for unusedSG in unusedSGs:
                    file.write("{},{}\n".format(unusedSG, "Not In Use"))
            if nonExistSGs:
                for nonExistSG in nonExistSGs:
                    file.write("{},{}\n".format(nonExistSG, "Does Not Exist"))

if __name__ == "__main__":
    main()
