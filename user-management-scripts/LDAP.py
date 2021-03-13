
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
from ldap3 import Server, ServerPool, Connection, ALL, MODIFY_REPLACE, ALL_ATTRIBUTES, SUBTREE, FIRST
from ldap3.core.exceptions import *
from ldap3.extend.microsoft.addMembersToGroups import ad_add_members_to_groups as addUsersInGroups

import logging
logger = logging.getLogger('LDAP')
logger.setLevel(getattr(logging, os.getenv('LOG_LEVEL', default='INFO')))
logging.getLogger('urllib3').setLevel(logging.WARNING)

class LDAP:
    def __init__(self, domain_controllers):
        self.domain_controllers = domain_controllers
        pass

    def bind(self, ad_username, ad_password):
        """
        Function that can be called to bind to a list of domain controllers as a pool
        """
        logger.debug("Trying to connect to domain controllers: {}".format(self.domain_controllers))
        server_pool_list = []
        for dc in self.domain_controllers:
            server_pool_list.append(Server(host=dc, get_info=ALL, port=636, use_ssl=True, connect_timeout=120))
        server_pool = ServerPool(server_pool_list, FIRST, active=True, exhaust=120)
        try:
            self.conn = Connection(
                server_pool, auto_bind=True, user=ad_username, password=ad_password, raise_exceptions=True
            )
            self.conn.bind()
        except LDAPTimeLimitExceededResult as e:
            logger.critical("Unable to establish a connection with the LDAP server, timed out after 60 seconds")
            exit(1)
        except Exception as e:
            logger.critical("Unable to create an LDAP connection to provision users in Active Directory. The error was: {}".format(str(e) ) )
            raise
            exit(1)

    def list_groups(self, ou, attributes=ALL_ATTRIBUTES):

        if not attributes == ALL_ATTRIBUTES and not "sAMAccountName" in attributes:
            raise Exception("The attribute 'sAMAccountName' must be included in the attributes list passed")
        ad_groups = {}
        try:
            groups = self.conn.extend.standard.paged_search(
                search_base=ou,
                search_filter="(objectClass=Group)",
                search_scope=SUBTREE,
                attributes=attributes,
                paged_size=100,
                generator=False,
            )
        except Exception as e:
            raise Exception("Unable to list groups in AD. The error was: {}".format(str(e)))
        if not self.conn.result.get("description") == "success":
            raise Exception("Unable to list users in AD. The error was: {}".format(self.conn.result))
        elif len(groups) == 0:
            logger.info("No groups were found in Active Directory, but got a good response. Proceeding.")
            return {}

        for group in groups:
            # print(json.dumps(group, indent=2, sort_keys=True, default=str))
            try:
                ad_groups[group.get("attributes", {}).get("cn", "")] = dict(group.get("attributes", {}))
            except Exception as e:
                logger.warning("Unable to add group {} to ad_groups list. The error was: {}".format(group.get("cn", ""), e))
        return ad_groups

    def list_users(self, ou, attributes=ALL_ATTRIBUTES):
        """
        List all users in a given OU or CN
        :param ou: The DN path where you want the listing to occur
        :param attributes: a list of attributes that you would like returned in the query (must contain at least userPrincipalName), defaults to ALL
        :return: a dictionary of returned objects from the specified search DN with the key set to the user's UPN and value their AD record
        """
        if not attributes == ALL_ATTRIBUTES and not "sAMAccountName" in attributes:
            raise Exception("The attribute 'sAMAccountName' must be included in the attributes list passed")
        ad_users = {}
        try:
            users = self.conn.extend.standard.paged_search(
                search_base=ou,
                search_filter="(objectClass=User)",
                search_scope=SUBTREE,
                attributes=attributes,
                paged_size=100,
                generator=False,
            )
        except Exception as e:
            raise Exception("Unable to list users in AD. The error was: {}".format(str(e)))
        if not self.conn.result.get("description") == "success":
            raise Exception("Unable to list users in AD. The error was: {}".format(self.conn.result))
        elif len(users) == 0:
            logger.info("No users were found in Active Directory, but got a good response. Proceeding.")
            return {}

        for user in users:
            # print(json.dumps(user, indent=2, sort_keys=True, default=str))
            try:
                # we append each user to a dictionary and set the value to the user record
                # we are primarily using this as a lookup reference to know if the user was already in AD or not
                ad_users[user.get("attributes", {}).get("sAMAccountName", "")] = dict(user.get("attributes", {}))
            except Exception as e:
                logger.warning("Unable to add user {} to ad_users list. The error was: {}".format(user.get("dn", ""), e))
        return ad_users

    def create_user(self, user, password, ou):
        """
        Create a new user in Active Directory with default attributes
        (including a generated secure password, and account enablement)
        :param ou: the path in AD for the user to be created
        :param ldap_user_attributes: the JSON formatted user record
        :return: bool status of whether the creation succeeded or not
        """
        ldap_user_attributes = {
            "objectClass": ["top", "person", "organizationalPerson", "user"],
            "cn": [f"{user['first_name']} {user['last_name']}"],
            "sAMAccountName": [user['username'][:20]],  # we need to strip the sAMAccountName to 20 chars
            "displayName": [f"{user['first_name']} {user['last_name']}"],
            "mail": [user['email']],
            "userPrincipalName": [user['email']],
            # mind the extra set of quotes in the uncodePWd value, this is required, do not change
            # this is very specific to MS AD, so this needs be the encoding
            "unicodePwd": f'"{password}"'.encode("utf-16-le"),
            "userAccountControl": "66048",  # userAccountControl mappings: https://vaportech.wordpress.com/2007/12/06/useraccountcontrol/
            "department": user['team'],
            "givenName": user['first_name'],
            "sn": user['last_name'],
            "title": user['title'],
            "description": f"{user['title']} for {user['team']}"
        }


        try:
            username = ldap_user_attributes.get("cn", {})[0]  # sAMAccountName is a list, we need the first entry
        except IndexError as e:
            logger.error("Unable to retrieve the sAMAccountName for record {}".format(ldap_user_attributes))
            return False
        logger.debug("Attempting to create AD user {}".format(username))
        dn = "CN={},{}".format(username, ou)
        logger.debug("The DN will be set to {}".format(dn))
        logger.debug(f"The ldap_user_attributes will be: {json.dumps(ldap_user_attributes, default=str)}")
        try:
            resp = self.conn.add(dn, attributes=ldap_user_attributes)
        except LDAPEntryAlreadyExistsResult as e:
            logger.warning("The user {} already exists in Active Directory, skipping".format(username))
            ## we return True here since the user does already exist in the domain
            exit(1)
            return True
        except LDAPConstraintViolationResult as e:
            logger.error("Unable to update account {} due to a Contstraint Violation".format(username))
            return False
        except Exception as e:
            logger.error(
                "An unexpected error occurred while trying to create user {}. The error was: {}".format(
                    ldap_user_attributes.get("userPrincipalName", [])[0], str(e)
                )
            )
            return False
        if not resp:
            logger.error(
                "Unable to create user {}. The error was: {}".format(
                    ldap_user_attributes.get("userPrincipalName", ""), self.conn.result
                )
            )
            return False
        return True

    def dump_stuff(self, search_base):
        total_entries = 0

        self.conn.search(search_base = search_base,
         search_filter = '(objectClass=OrganizationalUnit)',
         search_scope = SUBTREE,
         paged_size = 5)

        total_entries += len(self.conn.response)

        for entry in self.conn.response:
            print(entry)

        print('Total entries retrieved:', total_entries)

    def add_user_to_group(self, user, group_name, AD_OU):
        rndUser = f"CN={user},{AD_OU}"
        rndGroup = f"CN={group_name},{AD_OU}"

        addUsersInGroups(self.conn, rndUser, rndGroup)

    def create_group(self, group_name, ou):
        """
        Create a new user in Active Directory with default attributes
        (including a generated secure password, and account enablement)
        :param ou: the path in AD for the user to be created
        :param ldap_user_attributes: the JSON formatted user record
        :return: bool status of whether the creation succeeded or not
        """
        ldap_group_attributes = {
            "objectClass": ["top", "group"],
            "cn": [group_name],
            "sAMAccountName": [group_name[:20]],  # we need to strip the sAMAccountName to 20 chars
            "name": [group_name],
        }


        logger.debug("Attempting to create AD group {}".format(group_name))
        dn = "CN={},{}".format(group_name, ou)
        logger.debug("The DN will be set to {}".format(dn))
        logger.debug(f"The ldap_group_attributes will be: {json.dumps(ldap_group_attributes, default=str)}")
        try:
            resp = self.conn.add(dn, attributes=ldap_group_attributes)
        except LDAPEntryAlreadyExistsResult as e:
            logger.warning("The group {} already exists in Active Directory, skipping".format(group_name))
            return True
        except LDAPConstraintViolationResult as e:
            logger.error("Unable to update account {} due to a Contstraint Violation".format(group_name))
            return False
        except Exception as e:
            logger.error(
                "An unexpected error occurred while trying to create group {}. The error was: {}".format(
                    ldap_user_attributes.get("userPrincipalName", [])[0], str(e)
                )
            )
            return False
        if not resp:
            logger.error(f"Unable to create group {group_name}. The error was: {self.conn.result}")
            return False
        return True
