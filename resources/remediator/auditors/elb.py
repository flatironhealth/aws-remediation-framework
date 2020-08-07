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
    if resource["type"] != "elb":
        raise Exception(
            "Mismatched type. Expected {} but received {}".format(
                "elb", resource["type"]
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
    elb = get_session_for_account(resource["account"], resource["region"], "elb")
    load_balancer = elb.describe_load_balancers(LoadBalancerNames=[resource["id"]])[
        "LoadBalancerDescriptions"
    ][0]
    load_balancer_scheme = load_balancer["Scheme"]

    # Add check for public facing dev ec2 instances
    if (
        load_balancer_scheme == "internet-facing"
        and resource["account"] in dev_accounts
    ):
        is_compliant = check_public_dev_elb(
            load_balancer, elb, EC2_INSTANCE_IGNORE_LIST, resource, remediate
        )

    # Check all required tags have been set
    assigned_tags = elb.describe_tags(LoadBalancerNames=[resource["id"]])[
        "TagDescriptions"
    ][0].get("Tags", [])

    if is_missing_tags(assigned_tags):
        is_compliant = False
        issue = "ELB {} not compliant - Missing required tags - Not remediated".format(
            resource["id"]
        )
        send_notification(
            issue, "Required tags: {}".format(", ".join(get_required_tags())), resource
        )

    return is_compliant


def check_public_dev_elb(loadbalancer, elb, EC2_INSTANCE_IGNORE_LIST, resource, remediate):
    # enumerate instances, enumeration can be skipped if we can change how we do event translation
    # by adding few moer fields in resource[] which is sent to remeditor
    is_compliant = True
    loadbalancer_name = loadbalancer["LoadBalancerName"]
    for instance in loadbalancer["Instances"]:

        instanceid = instance["InstanceId"]
        instance_elb_info = {
            "Id": instanceid,
            "loadbalancer": loadbalancer_name,
            "type": "classic",
        }

        if instanceid not in str(EC2_INSTANCE_IGNORE_LIST):
            is_compliant = False
            issue = "Dev EC2 {} is Public - via elbv1 {}".format(
                instanceid, loadbalancer_name
            )
            if remediate:
                if not remediate_instance(loadbalancer_name, instanceid, elb):
                    issue += " - Not remediated"
            send_notification(
                issue,
                "Instance ELB Information: {}".format(", ".join(instance_elb_info)),
                resource,
            )

    return is_compliant


def remediate_instance(loadbalancer_name, instanceid, elb):
    try:

        response = elb.deregister_instances_from_load_balancer(
            LoadBalancerName=loadbalancer_name, Instances=[{"InstanceId": instanceid},],
        )
        print(response)
    except Exception as e:
        print(e)
        return False
    return True
