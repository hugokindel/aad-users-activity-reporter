#!/usr/bin/env python3
# coding: utf-8

import base64
import os
import msal
import json
import logging
import argparse
import requests
from datetime import date, datetime, timedelta


def load_attachment(file_path):
    if not os.path.exists(file_path):
        logging.error('Could not open file')
        return None

    with open(file_path, 'rb') as file:
        content = base64.b64encode(file.read())

    data = {
        '@odata.type': '#microsoft.graph.fileAttachment',
        'contentBytes': content.decode('utf-8'),
        'name': os.path.basename(file_path)
    }

    return data


def fatal_permissions_missing(r=None):
    if r:
        logging.critical(r.json())
        logging.critical("The application needs the applicative permissions `AuditLog.Read.All`, `Directory.Read.All` and `Mail.Send`.")
    return 1


def main():
    parser = argparse.ArgumentParser(description='''tool to search for inactive users throughout an Active Directory
    
you need to define multiple values through environment variables or a JSON config file:
- UAR_CLIENT_ID:            the azure application\'s client id
- UAR_CLIENT_SECRET:        the azure application\'s client secret
- UAR_TENAND_ID:            the azure environment tenant id
- UAR_MAIL_USER_ID:              the azure user id (or a shared mailbox) through which notification emails will be sent
- UAR_NOTIFICATION_TARGETS: the targets (mail addresses) to which notifications emails will be sent
- UAR_USER_EXCLUSIONS:      the list of user emails to ignore when going through the analysis
    
you can take a look at the examples folder to see how the environment variables or the config values are defined''', formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-c', '--config', help='path to the config file containing client\'s secrets')
    parser.add_argument('--no-mail', help='deactivates the mail sending feature', action='store_true')
    args = parser.parse_args()

    logging.getLogger().setLevel(logging.INFO)

    client_id = os.environ.get("UAR_CLIENT_ID", "")
    client_secret = os.environ.get("UAR_CLIENT_SECRET", "")
    tenant_id = os.environ.get("UAR_TENAND_ID", "")
    user_id = os.environ.get("UAR_MAIL_USER_ID", "")
    notification_targets = os.environ.get("UAR_NOTIFICATION_TARGETS", "").split(",")
    user_exclusions = os.environ.get("UAR_USER_EXCLUSIONS", "").split(",")
    actions = {}
    for key_value in os.environ.get("UAR_USER_ACTIONS", "").split(","):
        if key_value:
            vals = key_value.split(":")
            actions += {vals[0]: vals[1]}

    if args.config:
        config_file = open(args.config, "r", encoding="utf-8-sig")
        config_json = json.load(config_file)
        config_file.close()

        if "UAR_CLIENT_ID" in config_json:
            client_id = config_json["UAR_CLIENT_ID"]
        if "UAR_CLIENT_SECRET" in config_json:
            client_secret = config_json["UAR_CLIENT_SECRET"]
        if "UAR_TENAND_ID" in config_json:
            tenant_id = config_json["UAR_TENAND_ID"]
        if "UAR_MAIL_USER_ID" in config_json:
            user_id = config_json["UAR_MAIL_USER_ID"]
        if "UAR_NOTIFICATION_TARGETS" in config_json:
            notification_targets = config_json["UAR_NOTIFICATION_TARGETS"]
        if "UAR_USER_EXCLUSIONS" in config_json:
            user_exclusions = config_json["UAR_USER_EXCLUSIONS"]
        if "UAR_USER_ACTIONS" in config_json:
            actions = config_json["UAR_USER_ACTIONS"]

    if not client_id or not client_secret or not tenant_id:
        logging.critical("You need to specify a client ID (UAR_CLIENT_ID), client secret (UAR_CLIENT_SECRET) and tenant ID (UAR_TENAND_ID) to connect to Azure AD through an application.")
        return fatal_permissions_missing()
    if not user_id or not notification_targets:
        logging.warning("You need to provide a user ID (UAR_MAIL_USER_ID) in order to send a notification e-mail and notification target(s) (UAR_NOTIFICATION_TARGETS) as receivers.")
    if not user_exclusions:
        logging.info("You can define a user exclusion list (UAR_USER_EXCLUSIONS) to exclude some users from the report.")
    if not client_id or not client_secret or not tenant_id or not user_id or not notification_targets or not user_exclusions:
        logging.info("Those variables can be defined either through environment variables or a JSON config file that you can pass using the `-c` parameter. Look at the examples folder.")

    logging.info("The results can change from time to time as the beta Graph API for sign-in dates does not always return the same values.")

    authority = f"https://login.microsoftonline.com/{tenant_id}"
    scopes = ["https://graph.microsoft.com/.default"]
    graph_url = "https://graph.microsoft.com/v1.0"
    graph_beta_url = "https://graph.microsoft.com/beta"

    # Connects to MSAL API.
    app = msal.ConfidentialClientApplication(client_id=client_id, client_credential=client_secret, authority=authority)

    # Check for a suitable token in cache.
    token_request = app.acquire_token_silent(scopes, account=None)

    # If there is no suitable token in cache, tries to get a new one from AAD.
    if not token_request:
        token_request = app.acquire_token_for_client(scopes=scopes)

    # If we did not successfully get a suitable token, prints the error and exits.
    if "access_token" not in token_request:
        logging.critical(token_request.get("error"))
        logging.critical(token_request.get("error_description"))
        logging.critical(token_request.get("correlation_id"))
        return 1

    # The token in a request header JSON format to use in every GET/POST.
    token = {'Authorization': 'Bearer ' + token_request['access_token']}

    # Make a request to get the mail and sign-in activity of all the users that have never signed in and for which the account is older than 30 days.
    user_exp_date_str = (date.today() - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    r = requests.get(
        f'{graph_beta_url}/users?$select=id,mail,accountEnabled,signInActivity,createdDateTime&$top=120&$filter=createdDateTime le {user_exp_date_str}',
        headers=token)
    if not r.ok:
        return fatal_permissions_missing(r)
    exp_users_list = [x for x in r.json()["value"] if "mail" in x and x["mail"] not in user_exclusions and x["accountEnabled"] and "signInActivity" not in x]

    # Make a request to get the mail and sign-in activity of all the users that haven`t attempted to sign-in for more than 30 days.
    r = requests.get(
        f'{graph_beta_url}/users?$select=id,mail,accountEnabled,signInActivity&$top=120&$filter=signInActivity/lastSignInDateTime le {user_exp_date_str}',
        headers=token)
    # If the request did not work, prints the error and exits.
    if not r.ok:
        return fatal_permissions_missing(r)
    exp_users_list += [x for x in r.json()["value"] if "mail" in x and x["mail"] not in user_exclusions and x["accountEnabled"]]

    # Get the list of groups of each user
    for exp_user in exp_users_list:
        r = requests.get(
            f'{graph_beta_url}/users/{exp_user["id"]}/memberOf',
            headers=token)
        # If the request did not work, prints the error and exits.
        if not r.ok:
            return fatal_permissions_missing(r)
        for group in r.json()["value"]:
            if group["@odata.type"] == "#microsoft.graph.group":
                if "groups" not in exp_user:
                    exp_user["groups"] = []
                exp_user["groups"].append(group["displayName"])

    # Prepare message
    if len(exp_users_list) == 0:
        message = "Congratulations!\n\nYou have 0 inactive user(s) in your Azure Active Directory."
    else:
        # Sort expired users list by date from oldest to newest.
        exp_users_list.sort(key=lambda i: datetime.strptime(i["signInActivity"]["lastSignInDateTime"], "%Y-%m-%dT%H:%M:%SZ") if "signInActivity" in i else datetime(1970, 1, 1))

        # Prepares a string containing the list of expired users.
        exp_users_list_str = ""
        for exp_user in exp_users_list:
            if "signInActivity" not in exp_user:
                exp_users_list_str += f'\n• {exp_user["mail"]}'
            else:
                exp_users_list_str += f'\n• {exp_user["mail"]} since {exp_user["signInActivity"]["lastSignInDateTime"][:10].replace("-", "/")}'

        message = f"You have {len(exp_users_list)} inactive user(s) in your Azure Active Directory:\n{exp_users_list_str}"

    logging.info(message)

    # Prepare csv file
    file_path = f'users-activity-report_{date.today().strftime("%Y-%m-%d")}.csv'
    file = open(file_path, "w", encoding="utf-8-sig")
    file.write("User Mail;Last Sign In Date Time;Groups;Actions\n")
    for exp_user in exp_users_list:
        exp_user_sign_in_activity = exp_user["signInActivity"]["lastSignInDateTime"][:10].replace("-", "/") if "signInActivity" in exp_user else ""
        exp_user_groups = ','.join(exp_user["groups"]) if "groups" in exp_user else ""
        exp_user_actions = actions[exp_user["mail"]] if exp_user["mail"] in actions else ""
        file.write(f'{exp_user["mail"]};{exp_user_sign_in_activity};{exp_user_groups};{exp_user_actions}\n')
    file.close()

    logging.info(f'A CSV file called `{file_path}` has been generated for further analysis.')

    if not args.no_mail and user_id and notification_targets:
        email_msg = {
            'Message': {
                'ToRecipients': [{'EmailAddress': {'Address': x}} for x in notification_targets],
                'Subject': 'Users Activity Report for Azure AD',
                'Body': {
                    'ContentType': 'Text',
                    'Content': f"{message}"
                },
                'Importance': 'Normal',
                'Attachments': [
                    load_attachment(file_path)
                ]
            },
            'SaveToSentItems': 'true'
        }

        r = requests.post(f'{graph_url}/users/{user_id}/sendMail', headers=token, json=email_msg)

        if not r.ok:
            return fatal_permissions_missing(r)

    return 0


if __name__ == '__main__':
    exit(main())
