#!/usr/bin/python
# coding: UTF-8

import boto.ec2
import argparse
import sys

def main():
    try:
        conn = boto.ec2.connect_to_region(args.region,aws_access_key_id=args.aws_access_key_id,aws_secret_access_key=args.aws_secret_access_key,profile_name=args.profile)
    except:
        print "UNKNOWN: Unable to connect to reqion %s" % args.region
        sys.exit(3)

    try:    
        groups=conn.get_all_security_groups(group_ids=args.sgids)
    except:
        print "UNKNOWN: Not match AWS Security Group ID %s" % args.sgids
        sys.exit(3)

    group=groups[0]
    for rule in group.rules:
        for ip in rule.grants:
            if ip.cidr_ip == args.checkip:
                print "CRITICAL:Match IP %s" % ip.cidr_ip
                sys.exit(2)
            else:
                print ip.cidr_ip
    print "Check OK"
    sys.exit(0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Check IP of security group')
    
    parser.add_argument('-a', '--aws-access-key-id', required=False, dest='aws_access_key_id', help='AWS Access Key')
    parser.add_argument('-s', '--aws-secret-access-key', required=False, dest='aws_secret_access_key', help='AWS Secret Access Key')
    parser.add_argument('--profile', required=False, dest='profile', help=' Profile name of AWS shared credential file entry.')
    parser.add_argument('-r', '--region', required=True, dest='region', help='AWS Region')
    parser.add_argument('-g', '--sgid', required=True, dest='sgids', help='AWS Security Group ID')
    parser.add_argument('-i', '--ip', required=True, dest='checkip', help='IP Adress')
    
    args = parser.parse_args()

    main()
