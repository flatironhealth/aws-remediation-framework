import json
from shared import get_session_for_account, fetch_all_accounts, send_notification

from policyuniverse.policy import Policy
from policyuniverse.statement import Statement


def audit(resource, remediate=False):
    is_compliant = True
    if resource["type"] != "lambda_function":
        raise Exception(
            "Mismatched type. Expected {} but received {}".format(
                "lambda_function", resource["type"]
            )
        )

    # Get a session in the account where this resource is
    lambda_ = get_session_for_account(resource["account"], resource["region"], "lambda")

    lambda_is_public = False
    try:
        response_policy = lambda_.get_policy(FunctionName=resource["id"])
        policy = json.loads(response_policy["Policy"])
        policy = Policy(policy)
        lambda_is_public = policy.is_internet_accessible()

    except Exception as e:
        print(e)
        print("No lambda policy: {}".format(resource["id"]))

    if lambda_is_public:
        is_compliant = False

        issue = "Lambda {} is public via resource policy".format(resource["id"])
        if remediate:
            for statement in policy.statements:
                if '*' in statement.principals:
                    if not remediation_make_lambda_private(resource, lambda_, statement.statement["Sid"]):
                        issue += " - Not remediated"
        send_notification(issue, "", resource)

    if is_compliant:
        print("lambda is private: {}".format(resource["id"]))

    return is_compliant


def remediation_make_lambda_private(resource, lambda_, sid):
    try:
        lambda_.remove_permission(FunctionName=resource["id"], StatementId=sid)
    except Exception as e:
        print(e)
        return False
    return True
