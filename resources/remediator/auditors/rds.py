import json
from shared import (
    UTC,
    get_session_for_account,
    send_notification,
    is_missing_tags,
    get_required_tags,
    repeat_invocation,
)
from policyuniverse.policy import Policy
import os
from datetime import tzinfo, timedelta, datetime


def audit(resource, remediate=False):
    is_compliant = True
    if resource["type"] != "rds":
        raise Exception(
            "Mismatched type. Expected {} but received {}".format(
                "rds", resource["type"]
            )
        )

    # Get a session in the account where this resource is
    rds = get_session_for_account(resource["account"], resource["region"], "rds")
    instance = rds.describe_db_instances(DBInstanceIdentifier=resource["id"])
    if not instance:
        print("Resource {} not found".format(resource["id"]))
        return True

    instance = instance["DBInstances"][0]

    encrypted = instance["StorageEncrypted"]
    public_access = instance["PubliclyAccessible"]
    dbstatus = instance["DBInstanceStatus"]

    # Only check databases that were started within the past 60 minutes
    time_difference = int(os.environ.get("db_check_time", 60))
    utc = UTC()
    threshold_check = datetime.now(utc) - timedelta(minutes=time_difference)

    # Ignore instances that are not running
    if dbstatus in ["stopped"]:
        return True
    if dbstatus not in ["available"]:
        # For databases that are still starting we should check again
        repeat_invocation(resource)
        return True

    if "InstanceCreateTime" in instance:
        db_create_time = instance["InstanceCreateTime"]

        if db_create_time <= threshold_check:
            if not encrypted:
                is_compliant = False
                issue = "RDS {} not compliant - Storage not Encrypted".format(
                    resource["id"]
                )

                if remediate:
                    if not remediation_stop_instance(rds, resource, instance):
                        issue += " - Not remediated"
                send_notification(issue, "", resource)

    if public_access:
        is_compliant = False
        issue = "RDS {} not compliant - PubliclyAccessible".format(resource["id"])
        if remediate:
            if not remediation_make_private(rds, resource):
                issue += " - Not remediated"
        send_notification(issue, "", resource)

    # Get tags for database
    assigned_tags = rds.list_tags_for_resource(ResourceName=instance["DBInstanceArn"])[
        "TagList"
    ]
    if is_missing_tags(assigned_tags):
        is_compliant = False
        issue = "RDS {} not compliant - Missing required tags".format(resource["id"])
        #only notify if rds has no tags, uncomment to stop instances with no tag
        if remediate:
            if not remediation_stop_instance(rds, resource, instance):
                issue += " - Not remediated"
        send_notification(
            issue, "Required tags: {}".format(", ".join(get_required_tags())), resource
        )

    return is_compliant


def remediation_stop_instance(rds, resource, instance):

    print("Remediating: Stopping RDS instance {}".format(resource["id"]))
    if "DBClusterIdentifier" in instance:
        db_identifier = instance["DBClusterIdentifier"]
        try:
            mod_resp = rds.stop_db_cluster(DBClusterIdentifier=db_identifier)
            print(mod_resp)
        except Exception as e:
            print(e)
            return False
    else:
        try:
            db_identifier = instance["DBInstanceIdentifier"]
            mod_resp = rds.stop_db_instance(DBInstanceIdentifier=db_identifier)
            print(mod_resp)
        except Exception as e:
            print(e)
            return False

    return True


def remediation_make_private(rds, resource):
    try:
        mod_resp = rds.modify_db_instance(
            DBInstanceIdentifier=resource["id"],
            PubliclyAccessible=False,
            ApplyImmediately=True,
        )
        print(mod_resp)
    except Exception as e:
        print(e)
        return False
    return True
