import json
from shared import get_session_for_account, fetch_all_accounts, send_notification

from policyuniverse.policy import Policy


def audit(resource, remediate=False):
    is_compliant = True
    if resource["type"] != "ami":
        raise Exception(
            "Mismatched type. Expected {} but received {}".format(
                "ami", resource["type"]
            )
        )

    # Get a session in the account where this resource is
    ec2 = get_session_for_account(resource["account"], resource["region"], "ec2")

    image_attribute = ec2.describe_image_attribute(
        Attribute="launchPermission", ImageId=resource["id"]
    )

    # Get the accounts in the org
    all_account_in_org = fetch_all_accounts()


    description = (
        "image_attribute:" + str(image_attribute)
    )

    # Check the permissions
    launchpermission = image_attribute["LaunchPermissions"]
    # Check if it is shared publicly
    if "all" in str(launchpermission):
        is_compliant = False

        issue = "EC2 AMI %s in account %s is public" % (
            resource["id"],
            resource["account"],
        )

        if remediate:
            if not remediation_remove_all(ec2, resource):
                issue += " - Not remediated"
        send_notification(issue, description, resource)

    # Check if it is shared with any accounts that are not in the org
    if "UserId" in str(launchpermission):
        for userid in launchpermission:
            if userid["UserId"] not in str(all_account_in_org):
                is_compliant = False

                issue = "AMI %s in account %s is shared with unknown account %s" % (
                    resource["id"],
                    resource["account"],
                    userid["UserId"],
                )

                if remediate:
                    if not remediation_remove_userid(ec2, resource, userid):
                        issue += " - Not remediated"
                send_notification(issue, description, resource)

    return is_compliant


def remediation_remove_all(ec2, resource):
    print("Remediating: {}".format(resource["id"]))

    try:
        mod_image = ec2.modify_image_attribute(
            Attribute="launchPermission",
            LaunchPermission={"Remove": [{"Group": "all"}]},
            ImageId=resource["id"],
        )
        print(mod_image)
    except Exception as e:
        print(e)
        return False

    return True


def remediation_remove_userid(ec2, resource, userid):
    print("Remediating: {}".format(resource["id"]))

    try:
        mod_image = ec2.modify_image_attribute(
            Attribute="launchPermission",
            LaunchPermission={"Remove": [{"UserId": userid["UserId"]}]},
            ImageId=resource["id"],
        )

        print(mod_image)
    except Exception as e:
        print(e)
        return False

    return True
