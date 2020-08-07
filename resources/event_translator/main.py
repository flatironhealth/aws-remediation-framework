#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import boto3
import json
import os


def handler(event, context):
    # Determine if we should send the message to the SQS, or just print it to stdout.
    sqs_output = None
    if os.environ.get("SQS", "") != "":
        sqs_output = os.environ["SQS"]

    print(event)

    # If the event indicates it has an error in it then we shouldn't need to check the resource, because that means the resource
    # was not created or changed.
    # Also, if the error was due to our remediator itself for some reason, I don't want us to enter an infinite loop of attempting to fix
    # something, getting an error, and then attempting to fix it again.
    if "errorCode" in event:
        return False

    resources = translate_event(event)

    # Output the resource
    if sqs_output is not None:
        session = boto3.Session()
        sqs = session.client("sqs", region_name="us-east-1")
        for r in resources:
            resource = json.dumps(r)
            print(resource)
            sqs.send_message(
                QueueUrl=sqs_output,
                DelaySeconds=r.get("delay", 0),
                MessageBody=str(resource),
            )

    return True


def translate_event(event):
    # Given an event, translate it into the resources that should be checked.
    # In most cases, this is a single resource in the array, but ec2:RunInstances can potentially return multiple resources
    resource = {
        "account": event["detail"]["userIdentity"]["accountId"],
        "region": event["detail"].get("awsRegion", "us-east-1"),
        "type": "",
        "id": "",
    }

    eventName = event["detail"].get("eventName", "")
    eventSource = event["detail"].get("eventSource", "")

    # SQS
    if eventName == "CreateQueue":
        resource["type"] = "sqs"
        resource["id"] = event["detail"]["responseElements"]["queueUrl"]
        return [resource]
    elif eventName == "SetQueueAttributes":
        resource["type"] = "sqs"
        resource["id"] = event["detail"]["requestParameters"]["queueUrl"]
        return [resource]
    elif eventName == "AddPermission":
        resource["type"] = "sqs"
        resource["id"] = event["detail"]["requestParameters"]["queueUrl"]
        return [resource]

    # AMI
    elif eventName == "ModifyImageAttribute":
        resource["type"] = "ami"
        resource["id"] = event["detail"]["requestParameters"]["imageId"]
        return [resource]

    # EBS Snapshot
    elif eventName == "ModifySnapshotAttribute":
        resource["type"] = "ebs_snapshot"
        resource["id"] = event["detail"]["requestParameters"]["snapshotId"]
        return [resource]

    # RDS Snapshot
    elif eventName == "ModifyDBSnapshotAttribute":
        resource["type"] = "rds_snapshot"
        resource["id"] = event["detail"]["requestParameters"]["dBSnapshotIdentifier"]
        return [resource]

    # RDS
    elif eventName == "ModifyDBInstance":
        resource["type"] = "rds"
        resource["id"] = event["detail"]["requestParameters"][
            "dBInstanceIdentifier"
        ]# This is the correct capitalization as seen in CloudTrail
        resource["delay"] = 120
        return [resource]
    elif eventName == "CreateDBInstanceReadReplica":
        resource["type"] = "rds"
        resource["id"] = event["detail"]["responseElements"]["dBInstanceIdentifier"]
        resource["delay"] = 900
        return [resource]
    elif eventName == "CreateDBInstance":
        resource["type"] = "rds"
        resource["id"] = event["detail"]["responseElements"]["dBInstanceIdentifier"]
        resource["delay"] = 900
        return [resource]

    # Redshift
    elif eventName == "ModifyCluster":
        if eventSource == "redshift.amazonaws.com":
            resource["type"] = "redshift"
            resource["id"] = event["detail"]["requestParameters"]["clusterIdentifier"]
            resource["delay"] = 900
            return [resource]
        else:
            return []
    elif eventName == "CreateCluster":
        if eventSource == "redshift.amazonaws.com":
            resource["type"] = "redshift"
            resource["id"] = event["detail"]["responseElements"]["clusterIdentifier"]
            resource["delay"] = 900
            return [resource]
        else:
            return []

    # S3
    elif eventName == "PutBucketPolicy":
        resource["type"] = "s3_bucket"
        resource["id"] = event["detail"]["requestParameters"]["bucketName"]
        return [resource]
    elif eventName == "PutBucketAcl":
        resource["type"] = "s3_bucket"
        resource["id"] = event["detail"]["requestParameters"]["bucketName"]
        return [resource]
    elif eventName == "CreateBucket":
        resource["type"] = "s3_bucket"
        resource["id"] = event["detail"]["requestParameters"]["bucketName"]
        return [resource]

    # EC2
    elif eventName == "RunInstances":
        resource["type"] = "ec2"
        resources = []
        for r in event["detail"]["responseElements"]["instancesSet"]["items"]:
            resource["id"] = r["instanceId"]
            resources.append(resource)
        return resources
    elif eventName == "ModifyInstanceMetadataOptions":
        resource["type"] = "ec2"
        resource["id"] = event["detail"]["requestParameters"][
            "ModifyInstanceMetadataOptionsRequest"
        ]["InstanceId"]
        return [resource]
    # Add triger for Associate Address - for dev ec2 remediation
    elif eventName == "AssociateAddress":
        resource["type"] = "ec2"
        resources = []
        # easiest way here is to put allocation-id in id, but to re-use the ec2.py remediation, let's keep instance-id as id.
        resource["id"] = event["detail"]["requestParameters"]["instanceId"]
        resources.append(resource)
        return resources

    # Security Group
    elif eventName == "CreateSecurityGroup":
        resource["type"] = "security_group"
        resource["id"] = event["detail"]["responseElements"]["groupId"]
        return [resource]
    elif eventName == "AuthorizeSecurityGroupIngress":
        resource["type"] = "security_group"
        resource["id"] = event["detail"]["requestParameters"]["groupId"]
        return [resource]

    # ELB
    elif eventName == "RegisterInstancesWithLoadBalancer":
        resource["type"] = "elb"
        resource["id"] = event["detail"]["requestParameters"]["loadBalancerName"]
        return [resource]

    # ELBv2
    elif eventName == "RegisterTargets":
        resource["type"] = "elbv2"
        resource["id"] = event["detail"]["requestParameters"]["targetGroupArn"]
        return [resource]

    elif eventName == "CreateListener":
        resource["type"] = "elbv2"
        resource["id"] = event["detail"]["requestParameters"]["loadBalancerArn"]
        return [resource]

    elif eventName == "ModifyListener":
        resource["type"] = "elbv2"
        resource["id"] = event["detail"]["requestParameters"]["loadBalancerArn"]
        return [resource]

    # IAM Role
    elif eventName == "CreateRole":
        resource["type"] = "iam_role"
        resource["id"] = event["detail"]["requestParameters"]["roleName"]
        return [resource]

    elif eventName == "UpdateAssumeRolePolicy":
        resource["type"] = "iam_role"
        resource["id"] = event["detail"]["requestParameters"]["roleName"]
        return [resource]

    # Lambda
    elif eventName == "AddPermission20150331v2":
        resource["type"] = "lambda_function"
        resource["id"] = event["detail"]["requestParameters"]["functionName"]
        return [resource]

    elif eventName == "CreateFunction20150331":
        resource["type"] = "lambda_function"
        resource["id"] = event["detail"]["requestParameters"]["functionName"]
        return [resource]

    else:
        raise Exception("Unexpected event: {}".format(eventName))

    return None


if __name__ == "__main__":
    # When called from the command-line (as opposed to being called as a Lambda),
    # read json lines from stdin and convert them to look like they were received from an SQS trigger
    # for the Lambda handler.
    import sys

    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--remediate", help="Remediate the issues found", default=None,
    )
    args = parser.parse_args()

    for line in sys.stdin:
        event = line

        handler(event, None)
