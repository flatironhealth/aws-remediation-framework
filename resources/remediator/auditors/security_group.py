import json
from shared import (
    UTC,
    get_session_for_account,
    send_notification,
    is_missing_tags,
    get_required_tags,
)
from policyuniverse.policy import Policy
import os
from datetime import tzinfo, timedelta, datetime


def audit(resource, remediate=False):
    is_compliant = True
    if resource["type"] != "security_group":
        raise Exception(
            "Mismatched type. Expected {} but received {}".format(
                "security_group", resource["type"]
            )
        )

    # Get a session in the account where this resource is
    ec2 = get_session_for_account(resource["account"], resource["region"], "ec2")
    security_group = ec2.describe_security_groups(GroupIds=[resource["id"]])
    security_group = security_group["SecurityGroups"][0]

    # Check if this allows ingress from 0.0.0.0/0 or the IPv6 equivalent ::/0
    allows_public_ingress = False
    for permission in security_group.get("IpPermissions", []):
        for ip_range in permission.get("IpRanges", []):
            if "/0" in ip_range.get("CidrIp", "") or "/0" in ip_range.get(
                "CidrIpv6", ""
            ):
                allows_public_ingress = True
                print("Security Group allows public ingress: {}".format(permission))

    if allows_public_ingress:
        is_compliant = False
        issue = "Security Group {} not compliant - Allows public ingress - Not remediated".format(
            resource["id"]
        )
        send_notification(issue, "", resource)

    return is_compliant
