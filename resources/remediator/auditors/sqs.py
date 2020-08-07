import json
from shared import get_session_for_account, send_notification
from policyuniverse.policy import Policy


def audit(resource, remediate=False):
    is_compliant = True
    if resource["type"] != "sqs":
        raise Exception(
            "Mismatched type. Expected {} but received {}".format(
                "sqs", resource["type"]
            )
        )

    # Get a session in the account where this resource is
    sqs = get_session_for_account(resource["account"], resource["region"], "sqs")

    # Get the policy
    policy_string = sqs.get_queue_attributes(
        QueueUrl=resource["id"], AttributeNames=["Policy"]
    )
    if policy_string is None:
        return is_compliant
    policy_string = policy_string.get("Attributes", {}).get("Policy", {})
    if len(policy_string) == 0:
        # Policy is empty or not present
        return is_compliant

    policy = json.loads(policy_string)

    description = "Policy " + policy_string

    # Check if it is public
    policy = Policy(policy)
    if policy.is_internet_accessible():
        is_compliant = False
        issue = "SQS {} is public".format(resource["id"])
        if remediate:
            if not remediation_make_private(sqs, resource):
                issue += " - Not remediated"
        send_notification(issue, description, resource)

    # TODO Check for unknown accounts being allowed access

    return is_compliant


def remediation_make_private(sqs, resource):
    print("Remediating: Making {} private".format(resource["id"]))
    sqs.set_queue_attributes(QueueUrl=resource["id"], Attributes={"Policy": ""})
    return True
