import json
from shared import get_session_for_account, fetch_all_accounts, send_notification

from policyuniverse.policy import Policy
from policyuniverse.statement import Statement


def audit(resource, remediate=False):
    is_compliant = True
    if resource["type"] != "kms_key":
        raise Exception(
            "Mismatched type. Expected {} but received {}".format(
                "kms_key", resource["type"]
            )
        )

    # Get a session in the account where this resource is

    kms = get_session_for_account(resource["account"], resource["region"], "kms")

    # Remediation for Key Policy
    key_policy_is_non_compliant = False
    try:
        bad_policies = find_bad_policies(resource, kms)

        if bad_policies:
            key_policy_is_non_compliant = True


    except Exception as e:
        print(e)
        print("No KMS Keys: {}".format(resource["id"]))


    if key_policy_is_non_compliant:
        is_compliant =  False
        issue = "KMS Key: {} - has a non restrictive key policy".format(resource["id"])
        if remediate:
            for policy in bad_policies:
                is_compliant = remediation_kms_policy(resource,kms, policy)
            if not is_compliant:
                issue += " - Not remediated"

        send_notification(issue, "", resource)

    if is_compliant:
        print("KMS Key is compliant: {}".format(resource["id"]))

    return is_compliant




## Returns a list of "Bad" Policies
## Takes Resource & KMS objects as arguments
def find_bad_policies(resource, kms):
    try:
        key_policies = kms.list_key_policies(
            KeyId = resource["id"]
        )["PolicyNames"]

        policies_to_update = []
        for key_policy in key_policies:
            policy = kms.get_key_policy(
                KeyId = resource["id"],
                PolicyName = key_policy
            )

            policy_document =  json.loads(policy["Policy"])

            policy_object = Policy(policy_document)
            if policy_object.is_internet_accessible():
                policies_to_update.append(key_policy)

        return policies_to_update

    except Exception as e:
        print(e)
        print("No non-compliant Key Policies found")
        return []



## Corrects the over permissive key policy
def remediation_kms_policy(resource, kms, policy_name):
    try:
        ## First get the Key Policy
        old_policy = json.loads(kms.get_key_policy(
            KeyId = resource["id"],
            PolicyName = policy_name
        )["Policy"])

        key_meta_data = kms.describe_key(
            KeyId = resource["id"]
        )["KeyMetadata"]
        account_number = key_meta_data["AWSAccountId"]
        owner_root = "arn:aws:iam::{}:root".format(account_number)

        ## Find the overpermissive statment in the policy and then make the KeyOwner root user, the principal
        index = 0
        for statement in old_policy["Statement"]:
            if "*" in statement["Principal"]["AWS"]:
                old_policy["Statement"][index]["Principal"]["AWS"] = owner_root
            index += 1

        ## We now update the policy using the modified "old_policy" (which is actually the new policy)
        kms.put_key_policy(
            KeyId=resource["id"],
            PolicyName = policy_name,
            Policy = json.dumps(old_policy)
        )
    except Exception as e:
        print(e)
        return False
    return True
