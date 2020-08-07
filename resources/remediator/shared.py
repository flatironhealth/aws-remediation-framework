import logging
import boto3
import json
import botocore
from datetime import tzinfo, timedelta, datetime
import os

ZERO = timedelta(0)


class UTC(tzinfo):
    def utcoffset(self, dt):
        return ZERO

    def tzname(self, dt):
        return "UTC"

    def dst(self, dt):
        return ZERO


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


def depaginate_accounts(boto_handle):
    paginator = boto_handle.get_paginator("list_accounts")
    response_iterator = paginator.paginate()

    results = []
    for response in response_iterator:
        results = results + response["Accounts"]

    return results


def fetch_all_accounts():
    # Assume a role into the Org master, and then list all the accounts in the Org.
    # If we do not have access to the Org master, then only return the known accounts.
    try:
        aws_org_account = os.environ["ORGANIZATION_ACCOUNT"]
        org = get_session_for_account(
            aws_org_account, # Organization root account
            "us-east-1",
            "organizations",
            role="member_remediator",
            custom_session_name="fetch-accounts-" + aws_org_account,
        )
        response = depaginate_accounts(org)
        return response
    except Exception as e:
        print(f'Unable to list accounts: {e}')
        return os.environ["KNOWN_ACCOUNTS"]


def send_notification(summary, description, resource):
    print("Sending SNS Notification")
    region = os.environ["REMEDIATOR_REGION"]
    topic = os.environ["NOTIFICATION_TOPIC"]
    message = description + '\n\n' + json.dumps(resource)
    sns = boto3.client("sns",region)

    description = "Account:{}\nRegion:{}\nResource type:{}\nIdentifier:{}\n\n{}".format(
        resource["account"],
        resource["region"],
        resource["type"],
        resource["id"],
        description,
    )
    try:
        ticket_id = sns.publish(TopicArn=topic, Message=description,Subject=summary)
        print(f'Notification Sent: {summary}')
        return True
    except Exception as e:
        print(f'Unable to send notification: {e}')
        return False


def is_missing_tags(assigned_tags):
    # Check if it has all required tags
    # For each required tag, if no match is found, add it to the missing_tags array
    for required_tag in get_required_tags():
        match_found = False
        for tag in assigned_tags:
            if tag["Key"].lower() == required_tag.lower():
                match_found = True
                break
        if not match_found:
            return True
    return False


def get_required_tags():
    if os.environ.get("REQUIRED_TAGS", None) is not None:
        tags = os.environ["REQUIRED_TAGS"].split(",")
    else:
        tags = None
    return tags

def repeat_invocation(resource):
    sqs_queue = os.environ["SQS_QUEUE"]
    parts = sqs_queue.split(":")
    sqs_queue_url = "https://queue.amazonaws.com/{}/{}".format(parts[4], parts[5])
    sqs = boto3.client("sqs")
    r = json.dumps(resource)
    try:
        sqs.send_message(
            QueueUrl=sqs_queue_url, DelaySeconds=300, MessageBody=str(r),
        )
    except Exception as e:
        print(e)
