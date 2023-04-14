 #! /usr/bin/env python
from __future__ import print_function
from getpass import getpass
import argparse
         
def main():
    """ main function """
    parser = argparse.ArgumentParser(description='this is to get IP address for lynis audit only')
    parser.add_argument('-aip', '--audit_ip', help='The IP for which lynis Audit needs to be done .... by default tries root/Administrator if username not provided')
    parser.add_argument('-u', '--user_name', help='The username of the user to be logged in,for a specific user')
    parser.add_argument('-pem', '--pem_file', help='The pem file to access to AWS instance')
    parser.add_argument('-p', '--password', action='store_true', dest='password', help='hidden password prompt')
    parser.add_argument('-env', '--environment', help='The cloud on which the test-suite is to be run', choices=['aws', 'gcp', 'azure'], required=True)
    parser.add_argument('-pId', '--project_name', help='Project Name for which GCP Audit needs to be run')
    args = parser.parse_args()
    if args.password:
        password = getpass()


    if args.environment == 'gcp':
        from modules import gcpaudit
        if not args.project_name:
            print ("Please pass project name for the GCP Audit")
            print ("Exiting !!!")
            exit(0)
        else:
            gcpaudit.gcp_audit(args.project_name)



    elif args.environment == 'aws':
        from modules import awsaudit
        from modules import merger
        from modules import localaudit
        if args.audit_ip:
            if not(args.user_name):
                args.user_name = None
            if not(args.pem_file):
                args.pem_file = None
            if not(args.password):
                password = None
            localaudit.local_audit(args.audit_ip, args.user_name, args.pem_file, password)
        else:
            awsaudit.aws_audit()
            merger.merge()
        exit(0)
    elif args.environment == 'azure':
        from modules import azureaudit
        azureaudit.azure_audit()


if __name__ == '__main__':
    main()
