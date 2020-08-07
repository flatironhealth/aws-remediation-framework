import json
import boto3

from shared import get_session_for_account, fetch_all_accounts, send_notification, UTC

from policyuniverse.policy import Policy
from policyuniverse.statement import Statement


def audit(resource, remediate=False):
    is_compliant = True
    if resource["type"] != "iam_role":
        raise Exception(
            "Mismatched type. Expected {} but received {}".format(
                "iam_role", resource["type"]
            )
        )

    # Get a session in the account where this resource is
    iam = get_session_for_account(resource["account"], resource["region"], "iam")
    role_is_permissive = False

    try:
        role = iam.get_role(RoleName=resource["id"])["Role"]
        policy = role["AssumeRolePolicyDocument"]
        policy = Policy(policy)
        role_is_permissive = policy.is_internet_accessible()

    except Exception as e:
        print(e)
        print("No role policy: {}".format(resource["id"]))

    if role_is_permissive:
        is_compliant = False
        issue = "IAM role {} is publicly exposed".format(resource["id"])

        if remediate:
            if not remediation_make_role_restricted(resource, iam):
                issue += " - Not remediated"

        send_notification(issue, "", resource)

    if is_compliant:
        print("Role is compliant: {}".format(resource["id"]))

    return is_compliant


def remediation_make_role_restricted(resource, iam):
    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyAll",
                "Effect": "Deny",
                "Principal": {
                    "AWS": "*"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }

    try:
        iam.update_assume_role_policy(RoleName=resource["id"], PolicyDocument=json.dumps(deny_policy))
    except Exception as e:
        print(e)
        return False

    return True
