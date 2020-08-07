import json
from shared import UTC, get_session_for_account, fetch_all_accounts, send_notification
from policyuniverse.policy import Policy
import os
from datetime import tzinfo, timedelta, datetime


def audit(resource, remediate=False):
    is_compliant = True
    if resource["type"] != "rds_snapshot":
        raise Exception(
            "Mismatched type. Expected {} but received {}".format(
                "rds_snapshot", resource["type"]
            )
        )

    # Get a session in the account where this resource is
    rds = get_session_for_account(resource["account"], resource["region"], "rds")
    snapshot = rds.describe_db_snapshot_attributes(DBSnapshotIdentifier=resource["id"])
    if not snapshot:
        print("Resource {} not found".format(resource["id"]))
        return True

    attributes = snapshot.get("DBSnapshotAttributesResult", {}).get(
        "DBSnapshotAttributes", {}
    )
    description = (
        "db_snapshot_details:"
        + str(snapshot)
        + "\n\n"
        + "snapshot_attribute:"
        + str(attributes)
    )

    all_account_in_org = fetch_all_accounts()

    # Look at the attributes to see if this snapshot is shared publicly or with unknown accounts
    for attribute in attributes:
        if attribute["AttributeName"] != "restore":
            continue

        for shared_id in attribute["AttributeValues"]:
            if shared_id == "all":
                is_compliant = False
                issue = "RDS DB snapshot %s in account %s is public" % (
                    resource["id"],
                    resource["account"],
                )

                if remediate:
                    if not remediation_remove_all(rds, resource):
                        issue += " - Not remediated"
                send_notification(issue, description, resource)
            elif shared_id not in str(all_account_in_org):
                is_compliant = False
                issue = (
                    "RDS DB snapshot %s in account %s is shared with unknown account"
                    % (resource["id"], resource["account"])
                )

                if remediate:
                    if not remediation_remove_shared(rds, resource, shared_id):
                        issue += " - Not remediated"
                send_notification(issue, description, resource)

    return is_compliant


def remediation_remove_all(rds, resource):
    try:
        remove_all = rds.modify_db_snapshot_attribute(
            DBSnapshotIdentifier=resource["id"],
            AttributeName="restore",
            ValuesToRemove=["all"],
        )
        print(remove_all)
    except Exception as e:
        print(e)
        return False
    return True


def remediation_remove_shared(rds, resource, shared_id):
    try:
        remove_unknown_account = rds.modify_db_snapshot_attribute(
            DBSnapshotIdentifier=resource["id"],
            AttributeName="restore",
            ValuesToRemove=[shared_id],
        )
        print(remove_unknown_account)
    except Exception as e:
        print(e)
        return False
    return True
