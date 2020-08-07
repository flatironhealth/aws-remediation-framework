#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import boto3
import json
import os
import logging
import botocore

# Copied from the remediator codebase
def get_session_for_account(
    account, region, service, role="member_remediator", custom_session_name=None
):
    logging.getLogger("botocore").setLevel(logging.CRITICAL)
    logging.getLogger("urllib3").setLevel(logging.CRITICAL)
    client = boto3.client("sts")

    role_session_name = "security-{}-remediator-{}".format(service, account)
    if custom_session_name:
        role_session_name = custom_session_name

    creds = client.assume_role(
        RoleArn="arn:aws:iam::" + account + ":role/" + role,
        RoleSessionName=role_session_name,
    )
    session = boto3.Session(
        aws_access_key_id=creds["Credentials"]["AccessKeyId"],
        aws_secret_access_key=creds["Credentials"]["SecretAccessKey"],
        aws_session_token=creds["Credentials"]["SessionToken"],
    )
    # Set retry account higher than the default 3
    config = botocore.config.Config(retries={"max_attempts": 8})
    client = session.client(service, region, config=config)
    return client


def paginate_call(handler, method_to_call, parameters):
    data = None
    if handler.can_paginate(method_to_call):
        paginator = handler.get_paginator(method_to_call)
        page_iterator = paginator.paginate(**parameters)

        for response in page_iterator:
            if not data:
                data = response
            else:
                for k in data:
                    if isinstance(data[k], list):
                        data[k].extend(response[k])
    else:
        function = getattr(handler, method_to_call)
        data = function(**parameters)

    return data


class Resource:
    def __init__(self, account, region, resource_type, identifier):
        self.account = account
        self.region = region
        self.resource_type = resource_type
        self.identifier = identifier

    def __repr__(self):
        return {
            "account": self.account,
            "region": self.region,
            "type": self.resource_type,
            "id": self.identifier,
        }

    def __str__(self):
        return json.dumps(self.__repr__())


def output_resource(sqs_for_output, sqs_output, resource):
    """ Print the resource and send to the SQS if it exists"""
    print(resource)
    if sqs_output is not None:
        sqs_for_output.send_message(
            QueueUrl=sqs_output, DelaySeconds=0, MessageBody=str(resource)
        )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--sqs",
        help="The SQS URL to send resources to (ex. https://sqs.us-east-1.amazonaws.com/000000000000/remediator-resource-queue), or use the environment variable POLLER_SQS",
        type=str,
    )
    parser.add_argument(
        "--regions",
        help="Comma separated list of regions to poll (ex. us-east-1,us-west-2), or use the environment variable REGIONS",
        type=str,
    )
    parser.add_argument(
        "--accounts",
        help="Comma separated list of accounts to poll (ex. 000000000000,000000000001), or use the environment variable ACCOUNTS",
        type=str,
    )
    parser.add_argument(
        "--stdout",
        help="Write the results to stdout as opposed to the sqs",
        default=False,
        action="store_true",
    )
    parser.add_argument(
        "--only_use_test_resources",
        help="Only use the resource created by remediation_maker, or use the environment variable ONLY_USE_TEST_RESOURCES",
        default=False,
        action="store_true",
    )
    args = parser.parse_args()

    # Determine output
    sqs_output = None
    if args.sqs:
        sqs_output = args.sqs
    elif os.environ.get("POLLER_SQS", "") != "":
        sqs_output = os.environ["POLLER_SQS"]

    # Output the resource
    sqs_for_output = None
    if sqs_output is not None:
        session = boto3.Session()
        sqs_for_output = session.client("sqs", region_name="us-east-1")

    # Determine regions
    regions = []
    if args.regions:
        regions = args.regions.split(",")
    elif os.environ.get("REGIONS", None) is not None:
        regions = os.environ["REGIONS"].split(",")
    else:
        regions = ["us-east-1", "us-west-2"]

    # Determine accounts
    accounts = []
    if args.accounts:
        accounts = args.accounts.split(",")
    elif os.environ.get("ACCOUNTS", None) is not None:
        accounts = os.environ["ACCOUNTS"].split(",")
    else:
        # If no account is given, look at current account
        session = boto3.Session()
        sts = session.client("sts", region_name="us-east-1")
        accounts = [sts.get_caller_identity()["Account"]]

    # Determine if only test resources should be used
    only_use_test_resources = args.only_use_test_resources
    if os.environ.get("ONLY_USE_TEST_RESOURCES", "false") == "true":
        only_use_test_resources = True

    for account_id in accounts:
        for region in regions:

            # Look at IAM Roles
            iam = get_session_for_account(account_id, region, "iam")
            all_roles = paginate_call(iam, "list_roles", {}).get("Roles", [])

            for role in all_roles:
                if only_use_test_resources:
                    if role["RoleName"] == "misconfiguration_maker":
                        output_resource(
                            sqs_for_output,
                            sqs_output,
                            Resource(
                                account_id, region, "iam_role", role["RoleName"]
                            ),
                        )
                else:
                    output_resource(
                        sqs_for_output,
                        sqs_output,
                        Resource(account_id, region, "iam_role", role["RoleName"]),
                    )

            # Look at queues
            sqs = get_session_for_account(account_id, region, "sqs")
            queues = paginate_call(sqs, "list_queues", {})
            for q in queues.get("QueueUrls", []):
                if only_use_test_resources and "misconfiguration_maker" not in q:
                    continue
                output_resource(
                    sqs_for_output, sqs_output, Resource(account_id, region, "sqs", q)
                )

            # Look at Lambdas
            lambdas = get_session_for_account(account_id, region, "lambda")
            all_lambdas = paginate_call(lambdas, "list_functions", {})

            for lambda_ in all_lambdas.get("Functions", []):
                if only_use_test_resources:
                    if lambda_["FunctionName"] == "misconfiguration_maker":
                        output_resource(
                            sqs_for_output,
                            sqs_output,
                            Resource(
                                account_id, region, "lambda_function", lambda_["FunctionName"]
                            ),
                        )
                else:
                    output_resource(
                        sqs_for_output,
                        sqs_output,
                        Resource(account_id, region, "lambda_function", lambda_["FunctionName"]),
                    )

            # Look at EBS snapshots
            ec2 = get_session_for_account(account_id, region, "ec2")
            all_snapshots = paginate_call(
                ec2, "describe_snapshots", {"OwnerIds": [account_id]}
            )

            for snap in all_snapshots.get("Snapshots", []):
                snapshot_id = snap["SnapshotId"]
                if only_use_test_resources:
                    for tag in snap.get("Tags", []):
                        if (
                            tag["Key"] == "Name"
                            and tag["Value"] == "misconfiguration_maker"
                        ):
                            output_resource(
                                sqs_for_output,
                                sqs_output,
                                Resource(
                                    account_id, region, "ebs_snapshot", snapshot_id
                                ),
                            )
                else:
                    output_resource(
                        sqs_for_output,
                        sqs_output,
                        Resource(account_id, region, "ebs_snapshot", snapshot_id),
                    )

            # Look at AMIs
            ec2 = get_session_for_account(account_id, region, "ec2")
            all_images = paginate_call(ec2, "describe_images", {"Owners": [account_id]})

            for image in all_images.get("Images", []):
                image_id = image["ImageId"]
                if only_use_test_resources:
                    for tag in image.get("Tags", []):
                        if (
                            tag["Key"] == "Name"
                            and tag["Value"] == "misconfiguration_maker"
                        ):
                            output_resource(
                                sqs_for_output,
                                sqs_output,
                                Resource(account_id, region, "ami", image_id),
                            )
                else:
                    output_resource(
                        sqs_for_output,
                        sqs_output,
                        Resource(account_id, region, "ami", image_id),
                    )

            # Look at IAM users
            if region == "us-east-1":
                iam = get_session_for_account(account_id, region, "iam")
                all_users = paginate_call(iam, "list_users", {}).get("Users", [])
                for user in all_users:
                    if only_use_test_resources:
                        if user["UserName"] == "misconfiguration_maker":
                            output_resource(
                                sqs_for_output,
                                sqs_output,
                                Resource(
                                    account_id, region, "iam_user", user["UserName"]
                                ),
                            )
                    else:
                        output_resource(
                            sqs_for_output,
                            sqs_output,
                            Resource(account_id, region, "iam_user", user["UserName"]),
                        )

            # Look at RDS instances
            rds = get_session_for_account(account_id, region, "rds")
            instances = paginate_call(rds, "describe_db_instances", {})
            for instance in instances.get("DBInstances", []):
                if only_use_test_resources:
                    if instance.get("DBName", "") == "misconfiguration_maker":
                        output_resource(
                            sqs_for_output,
                            sqs_output,
                            Resource(
                                account_id,
                                region,
                                "rds",
                                instance["DBInstanceIdentifier"],
                            ),
                        )
                else:
                    output_resource(
                        sqs_for_output,
                        sqs_output,
                        Resource(
                            account_id, region, "rds", instance["DBInstanceIdentifier"],
                        ),
                    )

            # Look at RDS snapshots
            rds = get_session_for_account(account_id, region, "rds")
            snapshots = paginate_call(
                rds, "describe_db_snapshots", {"SnapshotType": "manual"}
            )
            snapshots = snapshots.get("DBSnapshots", [])
            for snapshot in snapshots:
                if only_use_test_resources:
                    if (
                        snapshot["DBSnapshotIdentifier"] == "misconfiguration-maker"
                    ):  # Forced to use a dash instead of underscore
                        output_resource(
                            sqs_for_output,
                            sqs_output,
                            Resource(
                                account_id,
                                region,
                                "rds_snapshot",
                                snapshot["DBSnapshotIdentifier"],
                            ),
                        )
                else:
                    output_resource(
                        sqs_for_output,
                        sqs_output,
                        Resource(
                            account_id,
                            region,
                            "rds_snapshot",
                            snapshot["DBSnapshotIdentifier"],
                        ),
                    )

            # Look at S3 buckets
            # S3 buckets are local to specific regions, but their namespace is global, so we only list them in one region
            # to avoid re-checking the same S3 buckets multiple times.
            if region == "us-east-1":
                s3 = get_session_for_account(account_id, region, "s3")
                buckets = paginate_call(s3, "list_buckets", {}).get("Buckets", [])
                for bucket in buckets:
                    if only_use_test_resources:
                        if "misconfig-maker" in bucket["Name"]:
                            output_resource(
                                sqs_for_output,
                                sqs_output,
                                Resource(
                                    account_id, region, "s3_bucket", bucket["Name"]
                                ),
                            )
                    else:
                        output_resource(
                            sqs_for_output,
                            sqs_output,
                            Resource(account_id, region, "s3_bucket", bucket["Name"]),
                        )

            # Look at Redshift
            redshift = get_session_for_account(account_id, region, "redshift")
            clusters = paginate_call(redshift, "describe_clusters", {})
            for cluster in clusters.get("Clusters", []):
                if only_use_test_resources:
                    if "misconfig-maker" in cluster["ClusterIdentifier"]:
                        output_resource(
                            sqs_for_output,
                            sqs_output,
                            Resource(
                                account_id,
                                region,
                                "redshift",
                                cluster["ClusterIdentifier"],
                            ),
                        )
                else:
                    output_resource(
                        sqs_for_output,
                        sqs_output,
                        Resource(
                            account_id, region, "redshift", cluster["ClusterIdentifier"]
                        ),
                    )

            # Look at EC2 instances
            ec2 = get_session_for_account(account_id, region, "ec2")
            instances = paginate_call(ec2, "describe_instances", {})

            for reservation in instances.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    if only_use_test_resources:
                        for tag in instance.get("Tags", []):
                            if (
                                tag["Key"] == "Name"
                                and tag["Value"] == "misconfiguration_maker"
                            ):
                                output_resource(
                                    sqs_for_output,
                                    sqs_output,
                                    Resource(
                                        account_id,
                                        region,
                                        "ec2",
                                        instance["InstanceId"],
                                    ),
                                )
                    else:
                        output_resource(
                            sqs_for_output,
                            sqs_output,
                            Resource(
                                account_id, region, "ec2", instance["InstanceId"],
                            ),
                        )

            # Look at Security Groups
            ec2 = get_session_for_account(account_id, region, "ec2")
            security_groups = paginate_call(ec2, "describe_security_groups", {})
            for security_group in security_groups.get("SecurityGroups", []):
                if only_use_test_resources:
                    if "misconfiguration_maker" in security_group["GroupName"]:
                        output_resource(
                            sqs_for_output,
                            sqs_output,
                            Resource(
                                account_id,
                                region,
                                "security_group",
                                security_group["GroupId"],
                            ),
                        )
                else:
                    output_resource(
                        sqs_for_output,
                        sqs_output,
                        Resource(
                            account_id,
                            region,
                            "security_group",
                            security_group["GroupId"],
                        ),
                    )

            # Look at Load Balancers
            elb = get_session_for_account(account_id, region, "elb")
            load_balancers = paginate_call(elb, "describe_load_balancers", {})
            for load_balancer in load_balancers.get("LoadBalancerDescriptions", []):
                if only_use_test_resources:
                    if "misconfig" in load_balancer["LoadBalancerName"]:
                        output_resource(
                            sqs_for_output,
                            sqs_output,
                            Resource(
                                account_id,
                                region,
                                "elb",
                                load_balancer["LoadBalancerName"],
                            ),
                        )
                else:
                    output_resource(
                        sqs_for_output,
                        sqs_output,
                        Resource(
                            account_id,
                            region,
                            "elb",
                            load_balancer["LoadBalancerName"],
                        ),
                    )

            # Look at Region
            output_resource(
                sqs_for_output, sqs_output, Resource(account_id, region, "region", ""),
            )


def handler(event, context):
    main()


if __name__ == "__main__":
    main()
