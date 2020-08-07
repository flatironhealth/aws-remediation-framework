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
    if resource["type"] != "ec2":
        raise Exception(
            "Mismatched type. Expected {} but received {}".format(
                "ec2", resource["type"]
            )
        )
    # get list of dev account(s) - keep it as list to add staging and future dev accounts
    if os.environ.get("DEV_ACCOUNTS", None) is not None:
        dev_accounts = os.environ["DEV_ACCOUNTS"].split(",")
    else:
        dev_accounts = None
    if os.environ.get("EC2_INSTANCE_IGNORE_LIST", None) is not None:
        EC2_INSTANCE_IGNORE_LIST = os.environ["EC2_INSTANCE_IGNORE_LIST"].split(",")
    else:
        EC2_INSTANCE_IGNORE_LIST = None

    # Get a session in the account where this resource is
    ec2 = get_session_for_account(resource["account"], resource["region"], "ec2")
    instances = ec2.describe_instances(InstanceIds=[resource["id"]])
    # We looked for a specific instance id, so ensure it has been returned.
    if (
        len(instances["Reservations"]) != 1
        or len(instances["Reservations"][0]["Instances"]) != 1
    ):
        print("Resource {} not found".format(resource["id"]))
        return True

    instance = instances["Reservations"][0]["Instances"][0]

    # check for dev instances and include the whitelist for ec2
    if resource["account"] in dev_accounts and resource["id"] not in EC2_INSTANCE_IGNORE_LIST:
        is_compliant = dev_public_ec2_remediation(ec2, resource, remediate)

    if instance["State"]["Name"] != "running":
        # Instance is stopped, or still starting
        # TODO If the instance is still starting, we should recheck it later.
        return True

    # Check if IMDSv2 is enforced
    if (
        instance["MetadataOptions"]["HttpEndpoint"] == "enabled"
        and instance["MetadataOptions"]["HttpTokens"] != "required"
    ):
        # IMDS v1 is still allowed

        is_compliant = False
        issue = "EC2 {} not compliant - IMDSv1 still allowed".format(resource["id"])
        if remediate:
            if not remediation_enforce_IMDSv2(ec2, resource):
                issue += " - Not remediated"
        send_notification(issue, "", resource)

    # Check the required tags have been set
    assigned_tags = instance.get("Tags", [])
    if is_missing_tags(assigned_tags):
        is_compliant = False
        issue = "EC2 {} not compliant - Missing required tags".format(resource["id"])
        if remediate:
            if not remediation_stop_instance(ec2, resource):
                issue += " - Not remediated"
        send_notification(
            issue, "Required tags: {}".format(", ".join(get_required_tags())), resource
        )

    return is_compliant


def remediation_enforce_IMDSv2(ec2, resource):

    try:
        response = ec2.modify_instance_metadata_options(
            InstanceId=resource["id"], HttpTokens="required", HttpEndpoint="enabled"
        )
        print(response)
    except Exception as e:
        print(e)
        return False
    return True


def remediation_stop_instance(ec2, resource):
    
    try:
        response = ec2.stop_instances(InstanceIds=[resource["id"]])
        print(response)
    except Exception as e:
        print(e)
        return False
    return True


# add remediation for dev public assets by removing eip
def remediation_private_dev_instance(ec2, resource, association_id):
    try:
        response = ec2.disassociate_address(AssociationId=association_id, DryRun=True)
        print(response)
    except Exception as e:
        print(e)
        return False
    return True


# add remediation for terminating instnaces with primary public ip.
def remediation_terminate_ec2(ec2, resource, dryrun):
    try:
        response = ec2.terminate_instances(InstanceIds=[resource["id"]], DryRun=dryrun)
        print(response)
    except Exception as e:
        print(e)
        return False
    return True


def dev_public_ec2_remediation(ec2, resource, remediate):
    filters = [
        {"Name": "instance-id", "Values": [resource["id"],]},
    ]
    addresses = ec2.describe_addresses(Filters=filters).get("Addresses")
    if addresses:
        is_compliant = False
        for address in addresses:
            association_id = address.get("AssociationId")
            issue = "Dev EC2 {} is Public - via elastic ip".format(resource["id"])
            if remediate:
                if not remediation_private_dev_instance(ec2, resource, association_id):
                    issue += " - Not remediated"
            send_notification(issue, "", resource)

    filters_iface = [
        {"Name": "attachment.instance-id", "Values": [resource["id"],]},
    ]
    network_ifaces = ec2.describe_network_interfaces(Filters=filters_iface,)
    for network_iface in network_ifaces["NetworkInterfaces"]:
        if "AssociationId" not in str(network_iface) and "PublicIp" in str(
            network_iface
        ):
            is_compliant = False
            issue = "Dev EC2 {} is public via primary interface".format(resource["id"])
            if remediate:
                if not remediation_terminate_ec2(ec2, resource, False):
                    issue += " - Not remediated"
            send_notification(issue, "", resource)

    return is_compliant
