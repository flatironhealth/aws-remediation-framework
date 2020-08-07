import json
from shared import UTC, get_session_for_account, send_notification
from policyuniverse.policy import Policy
import os
from datetime import tzinfo, timedelta, datetime
import logging


GUARDDUTY_MASTER_ACCOUNT = os.environ.get("GUARDDUTY_MASTER_ACCOUNT", "")

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def audit(resource, remediate=False):
    is_compliant = True
    if resource["type"] != "region":
        raise Exception(
            "Mismatched type. Expected {} but received {}".format(
                "region", resource["type"]
            )
        )

    issues = []
    if not is_guardduty_enabled(resource):
        issues.append("GuardDuty not enabled")
        is_compliant = False
    if not is_config_enabled(resource):
        issues.append("Config is not enabled")
        is_compliant = False
    if not is_cloudtrail_enabled(resource):
        issues.append("CloudTrail is not enabled")
        is_compliant = False
    if not is_flow_logs_enabled(resource):
        issues.append("VPC Flow Logs are not enabled everywhere")
        is_compliant = False

    if resource["region"] == "us-east-1":
        if not root_has_mfa(resource):
            issues.append("Root user does not have MFA")
            is_compliant = False
        if not has_compliant_password_policy(resource):
            issues.append("Password policy is not compliant")
            is_compliant = False

    if not is_compliant:
        # No remediations are peformed for these issues
        send_notification(", ".join(issues), "", resource)

    return is_compliant


def is_guardduty_enabled(resource):
    guardduty = get_session_for_account(
        resource["account"], resource["region"], "guardduty"
    )
    detectors_list = guardduty.list_detectors()["DetectorIds"]

    if len(detectors_list) == 0:
        print("No detectors found, please enable GuardDuty for this account")
        return False

    for d in detectors_list:
        master_account = guardduty.get_master_account(DetectorId=d)

        if (
            "Master" in master_account.keys()
            and master_account["Master"]["RelationshipStatus"] == "Enabled"
            and master_account["Master"]["AccountId"] == GUARDDUTY_MASTER_ACCOUNT
        ):
            print("GuardDuty is enabled")
            return True
        else:
            if account == GUARDDUTY_MASTER_ACCOUNT:
                print("This is the GuardDuty master account")
                return True
            else:
                print("GuardDuty is not connected with the master account")
    return False


def is_config_enabled(resource):
    config = get_session_for_account(resource["account"], resource["region"], "config")
    delivery_channels = config.describe_delivery_channels()["DeliveryChannels"]
    if len(delivery_channels) == 0:
        print("No delivery channels configured for Config Service")
        return False

    logger.debug("Delivery Channels configured:")
    for c in delivery_channels:
        logger.debug(json.dumps(c, sort_keys=True, indent=4))

    print("Config Service has Delivery Channels configured")
    return True


def is_cloudtrail_enabled(resource):
    cloudtrail = get_session_for_account(
        resource["account"], resource["region"], "cloudtrail"
    )
    trails = cloudtrail.describe_trails()["trailList"]

    if len(trails) == 0:
        print("No CloudTrail trails configured in this region")
        return False

    logger.debug("CloudTrail trails configured in this region:")
    for t in trails:
        logger.debug(json.dumps(t, sort_keys=True, indent=4))

    print("CloudTrail trails are configured in this region")

    return True


def is_flow_logs_enabled(resource):
    ec2 = get_session_for_account(resource["account"], resource["region"], "ec2")
    vpc_ids = [item["VpcId"] for item in ec2.describe_vpcs()["Vpcs"]]
    flowlog_vpcs = [item["ResourceId"] for item in ec2.describe_flow_logs()["FlowLogs"]]

    """
    the full list of VPC IDs should be present in the flow logs list, but there could be more
    flow logs, since ResourceId is not limited to a VPC
    """
    diff = list(set(vpc_ids).difference(set(flowlog_vpcs)))
    if len(diff) == 0:
        print("All VPCs have Flow Logs enabled")
        return True

    logger.debug("VPCs that do not have Flow Logs associated with them:")
    logger.debug(json.dumps(diff))

    print("Not all VPC have Flow logs associated with them")

    return False


def root_has_mfa(resource):
    iam = get_session_for_account(resource["account"], resource["region"], "iam")
    summary = iam.get_account_summary()
    if summary["SummaryMap"]["AccountMFAEnabled"] != 1:
        # Root user does not have MFA
        return False

    return True


def has_compliant_password_policy(resource):
    iam = get_session_for_account(resource["account"], resource["region"], "iam")
    is_compliant = True

    try:
        policy = iam.get_account_password_policy()
        policy = policy["PasswordPolicy"]
        if policy.get("MinimumPasswordLength", 0) < 8:
            print("Password policy does not have the minimum number of characters")
            is_compliant = False
        if not policy.get("RequireNumbers", False):
            print("Password policy does not require numbers")
            is_compliant = False
        if not policy.get("RequireSymbols", False):
            print("Password policy does not require symbols")
            is_compliant = False
        if not policy.get("RequireLowercaseCharacters", False):
            print("Password policy does not require lowercase characters")
            is_compliant = False
        if not policy.get("RequireUppercaseCharacters", False):
            print("Password policy does not require uppercase characters")
            is_compliant = False
    except iam.exceptions.NoSuchEntityException:
        print("No password policy set")
        return False
    except Exception as e:
        print("Exception: {}".format(e))
        return False

    return is_compliant
