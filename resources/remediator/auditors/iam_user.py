import json
from shared import get_session_for_account, fetch_all_accounts, send_notification, UTC

from datetime import tzinfo, timedelta, datetime
import boto3


def audit(resource, remediate=False):
    MAX_INACTIVE_PASSWORD_DAYS = 90
    MAX_INACTIVE_ACCESS_KEY_DAYS = 90

    is_compliant = True
    if resource["type"] != "iam_user":
        raise Exception(
            "Mismatched type. Expected {} but received {}".format(
                "iam_user", resource["type"]
            )
        )

    # Get a session in the account where this resource is
    iam = get_session_for_account(resource["account"], resource["region"], "iam")

    description = ""

    user = iam.get_user(UserName=resource["id"])["User"]
    create_date = user["CreateDate"]

    utc = UTC()

    t_minus_1_days = datetime.now(utc) - timedelta(days=1)
    login_create_date = False

    # If there is a login profile, then this user has a console login (ie. a password)
    try:
        login_profile = iam.get_login_profile(UserName=resource["id"])
        login_create_date = login_profile.get("LoginProfile", {}).get(
            "CreateDate", False
        )
    except iam.exceptions.NoSuchEntityException:
        # No login profile
        print("No login profile found")
        pass

    if login_create_date:
        # User has a password login

        # Ensure they have an MFA
        user_mfa = iam.list_mfa_devices(UserName=resource["id"])
        if (
            len(user_mfa["MFADevices"]) == 0
            and login_profile
            and login_create_date < t_minus_1_days
        ):
            # User has no MFA device, but does have a password login, and their password login was created more than 1 day ago
            is_compliant = False
            issue = "IAM user {} in account {} has a password login but no MFA".format(
                resource["id"], resource["account"]
            )
            print(issue)

            if remediate:
                if not remediation_remove_password(iam, resource, "lack of MFA"):
                    issue += " - Not remediated"
            send_notification(issue, description, resource)

        # Ensure they've logged in within MAX_INACTIVE_PASSWORD_DAYS
        last_login = user.get("PasswordLastUsed", None)
        t_minus_max_inactive_password_days = datetime.now(utc) - timedelta(
            days=MAX_INACTIVE_PASSWORD_DAYS
        )

        if last_login is None:
            # User has never logged in. Check how old this user is.
            if login_create_date < t_minus_max_inactive_password_days:
                is_compliant = False
                issue = "IAM user {} in account {} has not logged in ever, and their user was created more than {} days ago".format(
                    resource["id"], resource["account"], MAX_INACTIVE_PASSWORD_DAYS
                )
                print(issue)

                if remediate:
                    if not remediation_remove_password(
                        iam,
                        resource,
                        "password inactive for over {} days".format(
                            MAX_INACTIVE_PASSWORD_DAYS
                        ),
                    ):
                        issue += " - Not remediated"
                send_notification(issue, description, resource)
        else:
            # User has logged in. Check long ago it was.
            if last_login < t_minus_max_inactive_password_days:
                # User has not logged in for more than MAX_INACTIVE_PASSWORD_DAYS
                is_compliant = False
                issue = "IAM user {} in account {} has a password, but has not logged in for over {} days".format(
                    resource["id"], resource["account"], MAX_INACTIVE_PASSWORD_DAYS
                )

                if remediate:
                    if not remediation_remove_password(
                        iam,
                        resource,
                        "password inactive for over {} days".format(
                            MAX_INACTIVE_PASSWORD_DAYS
                        ),
                    ):
                        issue += " - Not remediated"
                send_notification(issue, description, resource)

    # Get access keys for the user
    keys = iam.list_access_keys(UserName=resource["id"])

    t_minus_max_inactive_key_days = datetime.now(utc) - timedelta(
        days=MAX_INACTIVE_ACCESS_KEY_DAYS
    )

    for k in keys["AccessKeyMetadata"]:
        last_used_response = iam.get_access_key_last_used(AccessKeyId=k["AccessKeyId"])
        last_used_date = last_used_response["AccessKeyLastUsed"].get(
            "LastUsedDate", None
        )
        if last_used_date is None:
            if k["CreateDate"] < t_minus_max_inactive_key_days:
                # Access key is old and unused
                is_compliant = False
                issue = "IAM user {} in account {} has an access key that has not been used for over {} days".format(
                    resource["id"], resource["account"], MAX_INACTIVE_ACCESS_KEY_DAYS
                )

                if remediate:
                    if not remediation_remove_access_key(
                        iam, resource, k["AccessKeyId"]
                    ):
                        issue += " - Not remediated"
                send_notification(issue, description, resource)

        elif last_used_date < t_minus_max_inactive_key_days:
            # Access key has not been used for over 100 days
            is_compliant = False
            issue = "IAM user {} in account {} has an access key that has not been used for over {} days".format(
                resource["id"], resource["account"], MAX_INACTIVE_ACCESS_KEY_DAYS
            )

            if remediate:
                if not remediation_remove_access_key(iam, resource, k["AccessKeyId"]):
                    issue += " - Not remediated"
            send_notification(issue, description, resource)

    return is_compliant


def remediation_remove_password(iam, resource, reason):
    print("Remediating: {}".format(resource["id"]))

    try:
        print("Disabling console password for user: {}".format(resource["id"]))
        iam.delete_login_profile(UserName=resource["id"])
    except Exception as e:
        print(e)
        return False

    return True


def remediation_remove_access_key(iam, resource, access_key_id):
    print("Remediating: {}".format(resource["id"]))

    try:
        print(
            "Removing access key {} for user: {}".format(access_key_id, resource["id"])
        )
        iam.delete_access_key(AccessKeyId=access_key_id)
    except Exception as e:
        print(e)
        return False

    return True
