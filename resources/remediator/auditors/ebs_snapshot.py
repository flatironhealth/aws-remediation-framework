import json
from shared import get_session_for_account, fetch_all_accounts, send_notification

from policyuniverse.policy import Policy


def audit(resource, remediate=False):
    is_compliant = True
    if resource["type"] != "ebs_snapshot":
        raise Exception(
            "Mismatched type. Expected {} but received {}".format(
                "ebs_snapshot", resource["type"]
            )
        )

    # Get a session in the account where this resource is
    ec2 = get_session_for_account(resource["account"], resource["region"], "ec2")

    snap_attribute = ec2.describe_snapshot_attribute(
        Attribute="createVolumePermission", SnapshotId=resource["id"],
    )

    # Get the accounts in the org
    all_account_in_org = fetch_all_accounts()


    description = (
        "snapshot_attribute:"
        + str(snap_attribute)
    )

    # Check the permissions
    volumepermission = snap_attribute["CreateVolumePermissions"]
    if "all" in str(volumepermission):
        is_compliant = False

        issue = "EBS snapshot %s in account %s is public" % (
            resource["id"],
            resource["account"],
        )

        if remediate:
            if not remediation_remove_all(ec2, resource):
                issue += " - Not remediated"
        send_notification(issue, description, resource)

    if "UserId" in str(volumepermission):
        for userid in volumepermission:
            if userid["UserId"] not in str(all_account_in_org):
                is_compliant = False

                issue = (
                    "EBS snapshot %s in account %s is shared with unknown account %s"
                    % (resource["id"], resource["account"], userid["UserId"])
                )

                if remediate:
                    if not remediation_remove_userid(ec2, resource, userid):
                        issue += " - Not remediated"
                send_notification(issue, description, resource)

    return is_compliant


def remediation_remove_all(ec2, resource):
    print("Remediating: {}".format(resource["id"]))

    try:
        mod_snap = ec2.modify_snapshot_attribute(
            Attribute="createVolumePermission",
            CreateVolumePermission={"Remove": [{"Group": "all"},]},
            SnapshotId=resource["id"],
        )
        print(mod_snap)
    except Exception as e:
        print(e)
        return False

    return True


def remediation_remove_userid(ec2, resource, userid):
    print("Remediating: {}".format(resource["id"]))

    try:
        mod_snap = ec2.modify_snapshot_attribute(
            Attribute="createVolumePermission",
            CreateVolumePermission={"Remove": [{"UserId": userid["UserId"]},]},
            SnapshotId=resource["id"],
        )
        print(mod_snap)
    except Exception as e:
        print(e)
        return False

    return True
