#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import boto3
import os
import traceback
import auditors


def get_queue_url(queue_arn):
    # Given a queue_arn like "arn:aws:sqs:us-east-1:123456789012:remediator-queue"
    # returns "https://queue.amazonaws.com/123456789012/remediator-queue"
    parts = queue_arn.split(":")
    return "https://queue.amazonaws.com/{}/{}".format(parts[4], parts[5])


def handler(event, context, remediate=False):
    sqs = boto3.client("sqs")

    # Get environment variable for whether we should remediate
    if os.environ.get("REMEDIATE", "") != "":
        if os.environ["REMEDIATE"].lower() == "true":
            remediate = True

    remediation_resource_exception = (os.environ.get("REMEDIATION_RESOURCE_EXCEPTION", "")).split(',')
    print("custom resource exception: {}".format(remediation_resource_exception))
    custom_module_exception = os.environ.get("REMEDIATION_MODULE_EXCEPTION", "")
    print("custom module exception: {}".format(custom_module_exception))
    custom_module_exception = json.loads(custom_module_exception)


    for record in event["Records"]:
        # Records will look like this:
        # {
        #   "messageId": "059f36b4-87a3-44ab-83d2-661975830a7d",
        #   "receiptHandle": "AQEB6UZhSlv+DHpVqtgx7MX1TxYbAmqEfY95cC6vRuX0fSmuO+cKE5rYRzposEaQHyh/FFoXwhOGCjGQJPNYTjMu8sHRC8RqtEV1zv9AIXaMIjz1mpsVv3Kvg/NjDdgZH+Ve83L27zG30iMUI6P/dEl7HYz/YTREeu1Em++rk2f601RSylgnJEjtFHEYv+0jYL26VExwGDCraVRmBmkxUS823IFrzELSDu69B8km35+Koy52e0hlTU0CjbdZwEilrzws7hENGAAmIODbcrBNp9+Xceiif9toyYhCySbVZEkAHT6/fumbu6a2ryAq4QB9LQ+bKctogK3VrgDrML5AXHyjmSlzlgWIHslfOx1c9p6ynwprVWHv8D4QZgScXrB3TdkJZb0rOtecj4prMqnxBp+kFA==",
        #   "body": "{\"account\": \"123456789012\", \"region\": \"us-east-1\", \"type\": \"sqs\", \"id\": \"https://sqs.us-east-1.amazonaws.com/123456789012/remediator-queue\"}",
        #   "attributes": {
        #     "ApproximateReceiveCount": "6",
        #     "SentTimestamp": "1576514933843",
        #     "SenderId": "AIDAEXAMPLE:event_translator",
        #     "ApproximateFirstReceiveTimestamp": "1576514933843"
        #   },
        #   "messageAttributes":
        # {}
        # ,
        #   "md5OfBody": "284dc368c8caf5174468424aceaf88be",
        #   "eventSource": "aws:sqs",
        #   "eventSourceARN": "arn:aws:sqs:us-east-1:123456789012:remediator-queue",
        #   "awsRegion": "us-east-1"
        # }

        # Delete the message from the queue so we don't keep rereading it
        # This strategy does mean if there are errors in remediating, we won't retry
        if "receiptHandle" in record:
            receipt_handle = record["receiptHandle"]
            queue_url = get_queue_url(record["eventSourceARN"])
            # Delete received message from queue
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=receipt_handle)

        resource = json.loads(record["body"])

        print("Checking {}".format(resource))
        # Get the module based on the type passed in the message
        resource_module = getattr(auditors, resource["type"])
        try:

            # Call the auditor and check if custom whitelisting is present
            if (resource["account"] in custom_module_exception.keys() and resource[
                "type"
            ] in custom_module_exception.get(resource["account"])) or (resource["id"] in remediation_resource_exception):

                remediate = False
                resource_module.audit(resource, remediate)
            else:
                resource_module.audit(resource, remediate)
        except Exception as e:
            print(e)
            traceback.print_exc()
            continue
    return True


if __name__ == "__main__":
    # When called from the command-line (as opposed to being called as a Lambda),
    # read json lines from stdin and convert them to look like they were received from an SQS trigger
    # for the Lambda handler.
    import sys

    import argparse

    parser = argparse.ArgumentParser(
        description="""
    To test manually, create a test file with contents:

    {"account": "123456789012", "region": "us-east-1", "type": "sqs", "id": "https://sqs.us-east-1.amazonaws.com/123456789012/misconfiguration_maker-bad"}
    Then run:
    cat test.json  | python resources/remediator/main.py
    """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--remediate", help="Remediate the issues found", default=None,
    )
    args = parser.parse_args()

    for line in sys.stdin:
        event = {
            "Records": [
                {
                    "messageId": "0",
                    "body": line,
                    "attributes": {
                        "ApproximateReceiveCount": "1",
                        "SentTimestamp": "0",
                        "SenderId": "",
                        "ApproximateFirstReceiveTimestamp": "0",
                    },
                    "messageAttributes": {},
                    "md5OfBody": "",
                    "eventSource": "aws:sqs",
                    "eventSourceARN": "arn:aws:sqs:us-east-1:000000000000:remediator-queue",
                    "awsRegion": "us-east-1",
                }
            ]
        }

        handler(event, None, remediate=args.remediate)
