#!/usr/bin/env python3
# MIT License

# Copyright (c) 2020 Chris Farris based on works
# Copyright (c) 2019 Jeremy Baker (https://gist.github.com/jbaker10/4d03616910b86a5f7e24bbc0dab37023)

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import os
import re
import csv
import json
import boto3
import keyring
import getpass
from botocore.exceptions import ClientError
from ldap3 import Server, ServerPool, Connection, ALL, MODIFY_REPLACE, ALL_ATTRIBUTES, SUBTREE, FIRST
from ldap3.core.exceptions import *
from ldap3.extend.microsoft.addMembersToGroups import ad_add_members_to_groups as addUsersInGroups

from LDAP import LDAP
from xkcdpass import xkcd_password as xp

import logging
logger = logging.getLogger()
logger.setLevel(getattr(logging, os.getenv('LOG_LEVEL', default='INFO')))
logging.getLogger('botocore').setLevel(logging.WARNING)
logging.getLogger('boto3').setLevel(logging.WARNING)
logging.getLogger('urllib3').setLevel(logging.WARNING)
logging.getLogger('keyring').setLevel(logging.WARNING)

CC_ADDRESS="FIXME"
VPN_PORTAL="FIXME"
BUNDLE="wsb-FIXME"

# Init XKCD
wordfile = xp.locate_wordfile()
mywords = xp.generate_wordlist(wordfile=wordfile, min_length=5, max_length=8)

def get_password(username):
    '''prompt user for their AD Password '''
    keyring_user = username.replace('\\', '-')
    try:
        import keyring
        password = keyring.get_password('seccdc-admin', keyring_user)
        HAS_KEYRING=True
    except:
        HAS_KEYRING=False
        password = None
    if not password:
        password = getpass.getpass("{} password: ".format(username))
        if HAS_KEYRING:
            keyring.set_password('seccdc-admin', keyring_user, password)
    return password

def get_ssm_param(param_name):
    try:
        client = boto3.client('ssm')
        response = client.get_parameter(Name=param_name)
        config = json.loads(response['Parameter']['Value'])  # config gets passed to the next conditional.
        return(config)
    except Exception as e:
        logger.critical(f"Failed to get AD Config from SSM Parameter Store: {e}")
        exit(1)

def main(args):

    # Go fetch the IP Address end points from SSM
    ad_config = get_ssm_param(args.ad_param_name)
    logger.debug(ad_config)
    AD_OU = ad_config['UserOU']

    dc_ips = ad_config['SimpleADDnsIpAddresses']
    ## create the LDAP object
    ldap = LDAP(dc_ips)

    ad_username = f"{ad_config['Domain']}\\{args.username}"
    ad_password = get_password(ad_username)

    logger.debug(f"Using username {ad_username} and {ad_password}")

    ## bind to the domain controllers
    ldap.bind(ad_username, ad_password)

    try:
        current_ad_users = ldap.list_users(ou=AD_OU)
        current_ad_groups = ldap.list_groups(ou=AD_OU)

    except Exception as e:
        logger.critical(f"Caught Exception getting existing users and groups: {e}")
        exit(1)

    password_fh = open(args.password_file, "a")

    # parse csv
    with open(args.users_to_add, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for user in reader:
            logger.debug(json.dumps(user, indent=2))

            # Things to do
            # 3. Configure forced reset or not?

            username = user['username']

            if username not in current_ad_users:
                password = f"{xp.generate_xkcdpassword(mywords, delimiter='.', numwords=3)}99"
                user['password'] = password
                logger.info(f"{username}: {password}")
                password_fh.write(f"{username}: {password}\n")

                try:
                    ldap.create_user(user=user, password=password, ou=AD_OU)
                    logger.info("Successfully created {} in {}".format(username, AD_OU))
                except Exception as e:
                    logger.error(f"An error occurred while trying to create {username}. The error was: {e}")
                    raise
                    exit(1)
            else:
                logger.info(f"{username} is already in AD")

            # Now process group memberships
            if user['team'] == "Build Team":
                # Build Team gets Domain Admin (as does Red Team if they're good)
                ldap.add_user_to_group(f"{user['first_name']} {user['last_name']}", "Domain Admins", AD_OU)

            # Add User to Group based on their Team. But first make sure it exists
            if user['team'] not in current_ad_groups:
                logger.info(f"Group {user['team']} doesn't exist. attempting to create it")
                ldap.create_group(group_name=user['team'], ou=AD_OU)
                current_ad_groups = ldap.list_groups(ou=AD_OU)

            try:
                logger.info(f"Adding {username} to {user['team']}")
                ldap.add_user_to_group(f"{user['first_name']} {user['last_name']}", user['team'], AD_OU)
            except Exception as e:
                logger.error(f"Failed to add {username} to AD Group {user['team']}: {e}")
                pass

            # Create the user's workspace
            if user['workspace'] == "TRUE":
                workspace_id, reg_code = create_workspace(user)
            else:
                workspace_id = None
                reg_code = None

            # Send the user a welcome email
            send_user_welcome(args.from_addr, user, workspace_id, reg_code)

    password_fh.close()


def send_user_welcome(from_addr, user, workspace_id, reg_code):
    logger.info(f"Sending welcome email to {user['email']}")

    ses_client = boto3.client('sesv2')

    if 'password' in user:
        password_line = f"is {user['password']}"
    else:
        password_line = "(emailed to you previously, or sent under separate cover)"


    if user['workspace'] == "TRUE":
        workspace = f"""
As a result of the pandemic, the competition will be held remotely. In order to replicate the experience of previous years, we have moved the competition environment into Amazon Web Services. Your competition workstation will leverage AWS Workspaces - a managed virtual desktop environment from AWS. You will need to login to your personal AWS Workspace for the entire competition.

You will need to install the AWS Workspaces Client from Amazon. You can download the client here: https://clients.amazonworkspaces.com/
Please allow thirty-minutes from receiving this email before attempting to log in.

The Registration Code is: {reg_code}
        """
        if workspace_id is not None:
            workspace += f"Your Workspace ID is: {workspace_id}\n"
    else:
        workspace = ""

    if user['VPN'] == "TRUE":
        vpn = f"You also have been granted VPN access into the competition environment. In order to access the VPN, please go to {VPN_PORTAL} to download the VPN Client and VPN Configuration file. You will use the username and password above to authenticate to the portal and to the VPN. "
    else:
        vpn = ""

    email_body = f"""
Hello {user['first_name']} and welcome to the SECCDC.

Please keep this email, as it contains important information you will need for the competition.

Your username and password are:
Username: {user['username']}
Password: {password_line}.

You are {user['title']} on team {user['team']}
{workspace}
{vpn}

Welcome to SECCDC, you can reach out to your team coach if you have additional questions.

SECCDC Organizers

--end of auto-generated message--
    """

    response = ses_client.send_email(
        FromEmailAddress=from_addr,
        Destination={
            'ToAddresses': [ user['email'] ],
            'CcAddresses': [ from_addr ],
            'BccAddresses': [ CC_ADDRESS ],
        },
        ReplyToAddresses=[ from_addr ],
        # FeedbackForwardingEmailAddress='string',
        # FeedbackForwardingEmailAddressIdentityArn='string',
        Content={
            'Simple': {
                'Subject': {'Data': 'Your SECCDC Account Information'},
                'Body': {'Text': {'Data': email_body } }
            }
        }
    )

    return(True)

def create_workspace(user):
    logger.info(f"Creating workspace for {user['username']}")

    client = boto3.client('workspaces')

    response = client.describe_workspace_directories()
    if len(response['Directories']) != 1:
        logger.critical(f"Too many or too few Workspace Directories. Cannot create workspaces. Aborting...")
        exit(1)

    directory = response['Directories'][0]

    response = client.create_workspaces(
        Workspaces=[
            {
                'DirectoryId': directory['DirectoryId'],
                'UserName': user['username'],
                'BundleId': BUNDLE,
                'WorkspaceProperties': {
                    'RunningMode': 'AUTO_STOP',
                    'RunningModeAutoStopTimeoutInMinutes': 60,
                    'RootVolumeSizeGib': 80,
                    'UserVolumeSizeGib': 10,
                    'ComputeTypeName': 'STANDARD'
                },
                'Tags': [
                    {'Key': 'Team', 'Value': user['team'] },
                    {'Key': 'Username', 'Value': user['username'] },
                    {'Key': 'Email', 'Value': user['email'] },
                    {'Key': 'Title', 'Value': user['title'] },
                    {'Key': 'Full Name', 'Value': f"{user['first_name']} {user['last_name']}" }
                ]
            }
        ]
    )

    logger.debug(f"Workspace Response: {response}")

    if len(response['FailedRequests']) > 0:
        if response['FailedRequests'][0]['ErrorCode'] == "ResourceExists.WorkSpace":
            logger.warning(f"Workspace already exists for {user['username']}")
            return(None, directory['RegistrationCode'])
        else:
            logger.error(f"Got an error creating workspace for {user['username']}. ErrorMessage: {response['FailedRequests'][0]['ErrorMessage']}")
            exit(1)
            return(False)
    else:
        logger.info(f"Workspace ID {response['PendingRequests'][0]['WorkspaceId']} is pending for {user['username']}")
        return(response['PendingRequests'][0]['WorkspaceId'], directory['RegistrationCode'])


if __name__ == '__main__':

    # Process Arguments
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", help="print debugging info", action='store_true')
    parser.add_argument("--error", help="print error info only", action='store_true')
    parser.add_argument("--users-to-add", help="List of users to add", required=True)
    parser.add_argument("--from-addr", help="Send User Welcome email and passwords via SES from this address", required=True)
    parser.add_argument("--username", help="AD Username", default='Administrator')
    parser.add_argument("--ad-param-name", help="AD StackName", default="Corp-SimpleAD")
    parser.add_argument("--password-file", help="Save Generated Passwords here", default="passwords.txt")
    args = parser.parse_args()

    # Logging idea stolen from: https://docs.python.org/3/howto/logging.html#configuring-logging
    # create console handler and set level to debug
    ch = logging.StreamHandler()
    if args.debug:
        logger.setLevel(logging.DEBUG)
    elif args.error:
        logger.setLevel(logging.ERROR)
    else:
        logger.setLevel(logging.INFO)
    # create formatter
    # formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    formatter = logging.Formatter('%(name)s - %(levelname)s - %(message)s')
    # add formatter to ch
    ch.setFormatter(formatter)
    # add ch to logger
    logger.addHandler(ch)

    # Wrap in a handler for Ctrl-C
    try:
        exit(main(args))
    except KeyboardInterrupt:
        exit(1)