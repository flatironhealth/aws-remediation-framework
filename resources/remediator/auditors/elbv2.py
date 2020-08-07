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
    if resource["type"] != "elbv2":
        raise Exception(
            "Mismatched type. Expected {} but received {}".format(
                "elbv2", resource["type"]
            )
        )

    # Get a session in the account where this resource is
    elbv2 = get_session_for_account(resource["account"], resource["region"], "elbv2")
    # polling based is easy - you just enumerate all loadbalancers and their attached target groups with instances.
    # making it event driven for elbv2 is complicated (as for some cases multiple api calls would make it public) than expected - we would need to address below cases.
    # 1. creating/updating a new elb listener with target group(new or existing with or without instance)
    # 2. updating already existing(attached to elb listener) target group with new instances, without modifying elb listener
    # 3. creating a new target group (not attached) with instances AND then attaching to elb listener

    if ":loadbalancer/" in resource["id"]:
        loadbalancer_arn = resource["id"]
        is_compliant = enumerate_instances(elbv2, loadbalancer_arn, resource, remediate)
    if ":targetgroup/" in resource["id"]:
        load_balancers = elbv2.describe_target_groups(TargetGroupArns=[resource["id"]])[
            "TargetGroups"
        ][0]["LoadBalancerArns"]
        for loadbalancer_arn in load_balancers:
            is_compliant = enumerate_instances(
                elbv2, loadbalancer_arn, resource, remediate
            )

    return is_compliant


def enumerate_instances(elbv2, loadbalancer_arn, resource, remediate):
    is_compliant = True
    # get list of dev account(s) - keep it as list to add more dev accounts
    if os.environ.get("DEV_ACCOUNTS", None) is not None:
        dev_accounts = os.environ["DEV_ACCOUNTS"].split(",")
    else:
        dev_accounts = None
    if os.environ.get("EC2_INSTANCE_IGNORE_LIST", None) is not None:
        EC2_INSTANCE_IGNORE_LIST = os.environ["EC2_INSTANCE_IGNORE_LIST"].split(",")
    else:
        EC2_INSTANCE_IGNORE_LIST = None

    load_balancer = elbv2.describe_load_balancers(LoadBalancerArns=[loadbalancer_arn])[
        "LoadBalancers"
    ][0]
    loadbalancer_name = load_balancer["LoadBalancerName"]
    loadbalncer_type = load_balancer["Type"]
    loadbalancer_arn = load_balancer["LoadBalancerArn"]
    loadbalancer_scheme = load_balancer["Scheme"]
    if loadbalancer_scheme == "internet-facing" and resource["account"] in dev_accounts:

        target_attribute = elbv2.describe_target_groups(
            LoadBalancerArn=loadbalancer_arn
        )

        for target_group in target_attribute["TargetGroups"]:
            target_group_arn = target_group["TargetGroupArn"]

            target_group_health = elbv2.describe_target_health(
                TargetGroupArn=target_group_arn
            )

            for target in target_group_health["TargetHealthDescriptions"]:
                target_id = target["Target"].get("Id")
                if target_id.startswith("i-"):

                    instance_elb_info = {
                        "Id": target_id,
                        "loadbalancer": loadbalancer_arn,
                        "type": loadbalncer_type,
                        "targetgroup": target_group_arn,
                    }
                    # check if instance is not whitelisted
                    if target_id not in str(EC2_INSTANCE_IGNORE_LIST):
                        is_compliant = False
                        issue = "Dev EC2 {} is Public - via elbv2 {}".format(
                            target_id, loadbalancer_name
                        )
                        if remediate:
                            if not deregister_targets(
                                elbv2, target_group_arn, target_id
                            ):
                                issue += " - Not remediated"
                        send_notification(
                            issue,
                            "Instance ELB Information: {}".format(
                                ", ".join(instance_elb_info)
                            ),
                            resource,
                        )

    return is_compliant


def deregister_targets(elbv2, target_group_arn, target_id):
    try:
        response = elbv2.deregister_targets(
            TargetGroupArn=target_group_arn, Targets=[{"Id": target_id,},],
        )
        print(response)
    except Exception as e:
        print(e)
        return False
    return True
