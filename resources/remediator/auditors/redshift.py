import json
from shared import (
    get_session_for_account,
    send_notification,
    is_missing_tags,
    get_required_tags,
    repeat_invocation,
)
from policyuniverse.policy import Policy


def audit(resource, remediate=False):
    is_compliant = True
    if resource["type"] != "redshift":
        raise Exception(
            "Mismatched type. Expected {} but received {}".format(
                "redshift", resource["type"]
            )
        )

    # Get a session in the account where this resource is
    redshift = get_session_for_account(
        resource["account"], resource["region"], "redshift"
    )

    cluster = redshift.describe_clusters(ClusterIdentifier=resource["id"])["Clusters"][
        0
    ]

    if cluster["ClusterStatus"] != "available" or "ClusterCreateTime" not in cluster:
        # For clusters that are still starting we should check again
        repeat_invocation(resource)
        return True

    if cluster["PubliclyAccessible"]:
        is_compliant = False

        issue = "Redshift {} is not compliant - Is public".format(resource["id"])
        if remediate:
            if not remediation_make_private(redshift, resource):
                issue += " - Not remediated"
        send_notification(issue, "", resource)

    if not cluster["Encrypted"]:
        is_compliant = False

        issue = "Redshift {} is not compliant - Not encrypted".format(resource["id"])
        if remediate:
            if not remediation_make_encrypted(redshift, resource):
                issue += " - Not remediated"
        send_notification(issue, "", resource)

    if is_missing_tags(cluster["Tags"]):
        is_compliant = False
        issue = "Redshift {} not compliant - Missing required tags - Not remediated".format(
            resource["id"]
        )
        # You cannot stop a redshift cluster, so we just file the issue
        send_notification(
            issue, "Required tags: {}".format(", ".join(get_required_tags())), resource
        )

    # Check that access requires TLS
    requires_tls = False
    for param_group in cluster["ClusterParameterGroups"]:
        # You can have multiple parameter groups applied to a redshift cluster that have different settings.
        # I believe if one requires TLS then that must win, so I just ensure that at least one of the active
        # parameters groups has this setting.

        # Only look at parameter groups that are in-sync
        if param_group["ParameterApplyStatus"] != "in-sync":
            continue

        # Look through the parameters for require_ssl and ensure it is set to "true"
        parameters = redshift.describe_cluster_parameters(
            ParameterGroupName=param_group["ParameterGroupName"]
        )["Parameters"]
        for parameter in parameters:
            if (
                parameter["ParameterName"] == "require_ssl"
                and parameter["ParameterValue"] == "true"
            ):
                requires_tls = True

    if not requires_tls:
        is_compliant = False
        issue = "Redshift {} not compliant - Not enforcing TLS - Not remediated".format(
            resource["id"]
        )
        # You cannot stop a redshift cluster, so we just file the issue
        send_notification(issue, "", resource)

    return is_compliant


def remediation_make_private(redshift, resource):
    try:
        mod_resp = redshift.modify_cluster(
            ClusterIdentifier=resource["id"], PubliclyAccessible=False
        )
    except Exception as e:
        print(e)
        return False
    return True


def remediation_make_encrypted(redshift, resource):
    try:
        mod_resp = redshift.modify_cluster(
            ClusterIdentifier=resource["id"], Encrypted=True
        )
    except Exception as e:
        print(e)
        return False
    return True
