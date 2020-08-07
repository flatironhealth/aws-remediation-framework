import sys
import os
from importlib import reload

from nose.tools import assert_equal, assert_true, assert_false
from unittest import TestCase, mock
from unittest.mock import MagicMock

from resources.event_translator.main import translate_event


class TestTranslator(TestCase):
    def test_sqs_SetQueueAttributes_translation(self):
        event = {
            "version": "0",
            "id": "c2a207fb-cb90-7068-d4a9-6240d2cdd127",
            "detail-type": "AWS API Call via CloudTrail",
            "source": "aws.sqs",
            "account": "123456789012",
            "time": "2019-12-16T17:29:19Z",
            "region": "us-east-1",
            "resources": [],
            "detail": {
                "eventVersion": "1.05",
                "userIdentity": {
                    "type": "AssumedRole",
                    "principalId": "ABCDEFGHIJKLMNOPQRSTU:abc@xyz.com",
                    "arn": "arn:aws:sts::123456789012:assumed-role/role-name/abc@xyz.com",
                    "accountId": "123456789012",
                    "accessKeyId": "ABCDEFGHIJKLMNOPQRST",
                    "sessionContext": {
                        "attributes": {
                            "mfaAuthenticated": "true",
                            "creationDate": "2019-12-16T16:31:30Z",
                        },
                        "sessionIssuer": {
                            "type": "Role",
                            "principalId": "ABCDEFGHIJKLMNOPQRSTU",
                            "arn": "arn:aws:iam::123456789012:role/role-name",
                            "accountId": "123456789012",
                            "userName": "role-name",
                        },
                    },
                },
                "eventTime": "2019-12-16T17:29:19Z",
                "eventSource": "sqs.amazonaws.com",
                "eventName": "SetQueueAttributes",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "1.1.1.1",
                "userAgent": "console.amazonaws.com",
                "requestParameters": {
                    "attributes": {
                        "Policy": '{"Version":"2012-10-17", "Id":"sqspolicy", "Statement":[{"Sid":"Sid1576516421540", "Effect":"Allow", "Principal":"*", "Action":"SQS:SendMessage", "Resource":"arn:aws:sqs:us-east-1:123456789012:misconfiguration_maker-bad"}]}'
                    },
                    "queueUrl": "https://sqs.us-east-1.amazonaws.com/123456789012/misconfiguration_maker-bad",
                },
                "responseElements": None,
                "requestID": "8ab5b156-9e4f-5a82-91d4-e7275f60cd55",
                "eventID": "9b5808a9-7a05-429e-be70-6256b9a745af",
                "eventType": "AwsApiCall",
            },
        }
        assert_equal(
            translate_event(event),
            [
                {
                    "account": "123456789012",
                    "id": "https://sqs.us-east-1.amazonaws.com/123456789012/misconfiguration_maker-bad",
                    "region": "us-east-1",
                    "type": "sqs",
                }
            ],
        )

    def test_sqs_CreateQueue_translation(self):
        event = {
            "version": "0",
            "id": "c2a207fb-cb90-7068-d4a9-6240d2cdd127",
            "detail-type": "AWS API Call via CloudTrail",
            "source": "aws.sqs",
            "account": "123456789012",
            "time": "2019-12-16T17:29:19Z",
            "region": "us-east-1",
            "resources": [],
            "detail": {
                "eventVersion": "1.05",
                "userIdentity": {
                    "type": "AssumedRole",
                    "principalId": "ABCDEFGHIJKLMNOPQRSTU:1576513574938242000",
                    "arn": "arn:aws:sts::123456789012:assumed-role/role-name/1576513574938242000",
                    "accountId": "123456789012",
                    "accessKeyId": "ABCDEFGHIJKLMNOPQRST",
                    "sessionContext": {
                        "attributes": {
                            "mfaAuthenticated": "true",
                            "creationDate": "2019-12-16T16:26:14Z",
                        },
                        "sessionIssuer": {
                            "type": "Role",
                            "principalId": "ABCDEFGHIJKLMNOPQRSTU",
                            "arn": "arn:aws:iam::123456789012:role/role-name",
                            "accountId": "123456789012",
                            "userName": "role-name",
                        },
                    },
                },
                "eventTime": "2019-12-16T16:47:50Z",
                "eventSource": "sqs.amazonaws.com",
                "eventName": "CreateQueue",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "1.1.1.1",
                "userAgent": "aws-sdk-go/1.25.36 (go1.13.3; darwin; amd64) APN/1.0 HashiCorp/1.0 Terraform/0.12.16 (+https://www.terraform.io)",
                "requestParameters": {
                    "queueName": "remediator-resource-queue",
                    "tags": {
                        "App": "remediator",
                        "system": "aws-remediation",
                        "team": "security",
                    },
                    "attribute": {
                        "ReceiveMessageWaitTimeSeconds": "10",
                        "DelaySeconds": "90",
                        "MessageRetentionPeriod": "86400",
                        "MaximumMessageSize": "2048",
                        "VisibilityTimeout": "30",
                    },
                },
                "responseElements": {
                    "queueUrl": "https://sqs.us-east-1.amazonaws.com/123456789012/remediator-resource-queue"
                },
                "requestID": "80c37425-0ef7-587d-ab6e-2254b981ad47",
                "eventID": "13c8a1f5-4b23-470b-9dfb-51479473287c",
                "eventType": "AwsApiCall",
                "recipientAccountId": "123456789012",
            },
        }
        assert_equal(
            translate_event(event),
            [
                {
                    "account": "123456789012",
                    "id": "https://sqs.us-east-1.amazonaws.com/123456789012/remediator-resource-queue",
                    "region": "us-east-1",
                    "type": "sqs",
                }
            ],
        )

    def test_sqs_AddPermission_translation(self):
        event = {
            "version": "0",
            "id": "c2a207fb-cb90-7068-d4a9-6240d2cdd127",
            "detail-type": "AWS API Call via CloudTrail",
            "source": "aws.sqs",
            "account": "123456789012",
            "time": "2019-12-16T17:29:19Z",
            "region": "us-east-1",
            "resources": [],
            "detail": {
                "eventVersion": "1.05",
                "userIdentity": {
                    "type": "AssumedRole",
                    "principalId": "ABCDEFGHIJKLMNOPQRSTU:1576522229953466000",
                    "arn": "arn:aws:sts::123456789012:assumed-role/role-name/1576522229953466000",
                    "accountId": "123456789012",
                    "accessKeyId": "ABCDEFGHIJKLMNOPQRST",
                    "sessionContext": {
                        "attributes": {
                            "mfaAuthenticated": "true",
                            "creationDate": "2019-12-16T18:50:30Z",
                        },
                        "sessionIssuer": {
                            "type": "Role",
                            "principalId": "ABCDEFGHIJKLMNOPQRSTU",
                            "arn": "arn:aws:iam::123456789012:role/role-name",
                            "accountId": "123456789012",
                            "userName": "role-name",
                        },
                    },
                },
                "eventTime": "2019-12-16T18:51:15Z",
                "eventSource": "sqs.amazonaws.com",
                "eventName": "AddPermission",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "1.1.1.1",
                "userAgent": "aws-cli/1.16.286 Python/3.7.5 Darwin/18.7.0 botocore/1.13.25",
                "requestParameters": {
                    "actions": ["SendMessage"],
                    "aWSAccountIds": ["123456789012"],
                    "label": "0",
                    "queueUrl": "https://sqs.us-east-1.amazonaws.com/123456789012/misconfiguration_maker-bad",
                },
                "responseElements": None,
                "requestID": "e1ede60f-0cd7-52f2-9520-b07ed8b4b30c",
                "eventID": "a8bdb7fb-66b0-45ed-a5e4-d13f1e91d26b",
                "eventType": "AwsApiCall",
                "recipientAccountId": "123456789012",
            },
        }
        assert_equal(
            translate_event(event),
            [
                {
                    "account": "123456789012",
                    "id": "https://sqs.us-east-1.amazonaws.com/123456789012/misconfiguration_maker-bad",
                    "region": "us-east-1",
                    "type": "sqs",
                }
            ],
        )

    def test_s3_PutBucketPolicy_translation(self):
        event = {
            "version": "0",
            "id": "c2a207fb-cb90-7068-d4a9-6240d2cdd127",
            "detail-type": "AWS API Call via CloudTrail",
            "source": "aws.sqs",
            "account": "123456789012",
            "time": "2019-12-16T17:29:19Z",
            "region": "us-east-1",
            "resources": [],
            "detail": {
                "eventVersion": "1.05",
                "userIdentity": {
                    "type": "AssumedRole",
                    "principalId": "ABCDEFGHIJKLMNOPQRSTU:1575572476274064000",
                    "arn": "arn:aws:sts::123456789012:assumed-role/role-name/1575572476274064000",
                    "accountId": "123456789012",
                    "accessKeyId": "ABCDEFGHIJKLMNOPQRST",
                    "sessionContext": {
                        "attributes": {
                            "mfaAuthenticated": "true",
                            "creationDate": "2019-12-05T19:01:16Z",
                        },
                        "sessionIssuer": {
                            "type": "Role",
                            "principalId": "ABCDEFGHIJKLMNOPQRSTU",
                            "arn": "arn:aws:iam::123456789012:role/role-name",
                            "accountId": "123456789012",
                            "userName": "role-name",
                        },
                    },
                },
                "eventTime": "2019-12-05T19:02:08Z",
                "eventSource": "s3.amazonaws.com",
                "eventName": "PutBucketPolicy",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "1.1.1.1",
                "userAgent": "[aws-sdk-go/1.25.38 (go1.13.4; darwin; amd64) APN/1.0 HashiCorp/1.0 Terraform/0.12.16 (+https://www.terraform.io)]",
                "requestParameters": {
                    "bucketName": "wkykdxpwwr67imj4-misconfig-maker",
                    "bucketPolicy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Principal": "*",
                                "Action": ["s3:GetObjectAcl"],
                                "Effect": "Allow",
                                "Resource": [
                                    "arn:aws:s3:::wkykdxpwwr67imj4-misconfig-maker/*"
                                ],
                            }
                        ],
                    },
                    "host": ["wkykdxpwwr67imj4-misconfig-maker.s3.amazonaws.com"],
                    "policy": [""],
                },
                "responseElements": None,
                "additionalEventData": {
                    "SignatureVersion": "SigV4",
                    "CipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
                    "AuthenticationMethod": "AuthHeader",
                },
                "requestID": "0E1152F10A561447",
                "eventID": "bc81ed34-b1d0-4a6c-987f-59f584db2173",
                "eventType": "AwsApiCall",
                "recipientAccountId": "123456789012",
            },
        }

        assert_equal(
            translate_event(event),
            [
                {
                    "account": "123456789012",
                    "id": "wkykdxpwwr67imj4-misconfig-maker",
                    "region": "us-east-1",
                    "type": "s3_bucket",
                }
            ],
        )

    def test_s3_PutBucketAcl_translation(self):
        event = {
            "version": "0",
            "id": "c2a207fb-cb90-7068-d4a9-6240d2cdd127",
            "detail-type": "AWS API Call via CloudTrail",
            "source": "aws.sqs",
            "account": "123456789012",
            "time": "2019-12-16T17:29:19Z",
            "region": "us-east-1",
            "resources": [],
            "detail": {
                "eventVersion": "1.05",
                "userIdentity": {
                    "type": "AssumedRole",
                    "principalId": "ABCDEFGHIJKLMNOPQRSTU:user-a",
                    "arn": "arn:aws:sts::123456789012:assumed-role/role-name/user-a",
                    "accountId": "123456789012",
                    "accessKeyId": "ABCDEFGHIJKLMNOPQRST",
                    "sessionContext": {
                        "attributes": {
                            "mfaAuthenticated": "false",
                            "creationDate": "2019-12-09T16:18:23Z",
                        },
                        "sessionIssuer": {
                            "type": "Role",
                            "principalId": "ABCDEFGHIJKLMNOPQRSTU",
                            "arn": "arn:aws:iam::123456789012:role/role-name",
                            "accountId": "123456789012",
                            "userName": "role-name",
                        },
                    },
                },
                "eventTime": "2019-12-09T16:26:47Z",
                "eventSource": "s3.amazonaws.com",
                "eventName": "PutBucketAcl",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "1.1.1.1",
                "userAgent": "[S3Console/0.4, aws-internal/3 aws-sdk-java/1.11.666 Linux/4.9.184-0.1.ac.235.83.329.metal1.x86_64 OpenJDK_64-Bit_Server_VM/25.232-b09 java/1.8.0_232 vendor/Oracle_Corporation]",
                "requestParameters": {
                    "bucketName": "bucket-name",
                    "AccessControlPolicy": {
                        "AccessControlList": {
                            "Grant": [
                                {
                                    "Grantee": {
                                        "xsi:type": "CanonicalUser",
                                        "DisplayName": "aws+account-name",
                                        "xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance",
                                        "ID": "abcdefghijklmnop1234567890",
                                    },
                                    "Permission": "FULL_CONTROL",
                                },
                                {
                                    "Grantee": {
                                        "xsi:type": "Group",
                                        "xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance",
                                        "URI": "http://acs.amazonaws.com/groups/s3/LogDelivery",
                                    },
                                    "Permission": "READ_ACP",
                                },
                                {
                                    "Grantee": {
                                        "xsi:type": "Group",
                                        "xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance",
                                        "URI": "http://acs.amazonaws.com/groups/s3/LogDelivery",
                                    },
                                    "Permission": "WRITE",
                                },
                            ]
                        },
                        "xmlns": "http://s3.amazonaws.com/doc/2006-03-01/",
                        "Owner": {
                            "DisplayName": "aws+account-name",
                            "ID": "abcdefghijklmnop1234567890",
                        },
                    },
                    "host": ["s3.amazonaws.com"],
                    "acl": [""],
                },
                "responseElements": None,
                "additionalEventData": {
                    "SignatureVersion": "SigV4",
                    "CipherSuite": "ECDHE-RSA-AES128-SHA",
                    "AuthenticationMethod": "AuthHeader",
                    "vpcEndpointId": "vpce-example",
                },
                "requestID": "9C9E4CB44162228C",
                "eventID": "0655c8f0-0130-4659-acc0-e29a65aca2e5",
                "eventType": "AwsApiCall",
                "recipientAccountId": "123456789012",
                "vpcEndpointId": "vpce-example",
            },
        }
        assert_equal(
            translate_event(event),
            [
                {
                    "account": "123456789012",
                    "id": "bucket-name",
                    "region": "us-east-1",
                    "type": "s3_bucket",
                }
            ],
        )

    def test_s3_CreateBucket_translation(self):
        event = {
            "version": "0",
            "id": "c2a207fb-cb90-7068-d4a9-6240d2cdd127",
            "detail-type": "AWS API Call via CloudTrail",
            "source": "aws.sqs",
            "account": "123456789012",
            "time": "2019-12-16T17:29:19Z",
            "region": "us-east-1",
            "resources": [],
            "detail": {
                "eventVersion": "1.05",
                "userIdentity": {
                    "type": "AssumedRole",
                    "principalId": "ABCDEFGHIJKLMNOPQRSTU:1577212321281084000",
                    "arn": "arn:aws:sts::123456789012:assumed-role/role-name/1577212321281084000",
                    "accountId": "123456789012",
                    "accessKeyId": "ABCDEFGHIJKLMNOPQRST",
                    "sessionContext": {
                        "attributes": {
                            "mfaAuthenticated": "true",
                            "creationDate": "2019-12-24T18:32:01Z",
                        },
                        "sessionIssuer": {
                            "type": "Role",
                            "principalId": "ABCDEFGHIJKLMNOPQRSTU",
                            "arn": "arn:aws:iam::123456789012:role/role-name",
                            "accountId": "123456789012",
                            "userName": "role-name",
                        },
                    },
                },
                "eventTime": "2019-12-24T18:32:23Z",
                "eventSource": "s3.amazonaws.com",
                "eventName": "CreateBucket",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "1.1.1.1",
                "userAgent": "[aws-sdk-go/1.25.38 (go1.13.4; darwin; amd64) APN/1.0 HashiCorp/1.0 Terraform/0.12.16 (+https://www.terraform.io)]",
                "requestParameters": {
                    "x-amz-acl": ["private"],
                    "host": ["o3hxotcqp2u9mbtl-misconfig-maker.s3.amazonaws.com"],
                    "bucketName": "o3hxotcqp2u9mbtl-misconfig-maker",
                },
                "responseElements": None,
                "additionalEventData": {
                    "SignatureVersion": "SigV4",
                    "CipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
                    "AuthenticationMethod": "AuthHeader",
                },
                "requestID": "85C95550E930607C",
                "eventID": "5cc82958-1953-4945-aab5-bc114e920c33",
                "eventType": "AwsApiCall",
                "recipientAccountId": "123456789012",
            },
        }
        assert_equal(
            translate_event(event),
            [
                {
                    "account": "123456789012",
                    "id": "o3hxotcqp2u9mbtl-misconfig-maker",
                    "region": "us-east-1",
                    "type": "s3_bucket",
                }
            ],
        )

    def test_ec2_ModifyImageAttribute_translation(self):
        event = {
            "version": "0",
            "id": "c2a207fb-cb90-7068-d4a9-6240d2cdd127",
            "detail-type": "AWS API Call via CloudTrail",
            "source": "aws.sqs",
            "account": "123456789012",
            "time": "2019-12-16T17:29:19Z",
            "region": "us-east-1",
            "resources": [],
            "detail": {
                "eventVersion": "1.05",
                "userIdentity": {
                    "type": "AssumedRole",
                    "principalId": "ABCDEFGHIJKLMNOPQRSTU:1234567890123456789",
                    "arn": "arn:aws:sts::123456789012:assumed-role/role-name/1234567890123456789",
                    "accountId": "123456789012",
                    "accessKeyId": "ABCDEFGHIJKLMNOPQRST",
                    "sessionContext": {
                        "sessionIssuer": {
                            "type": "Role",
                            "principalId": "ABCDEFGHIJKLMNOPQRSTU",
                            "arn": "arn:aws:iam::123456789012:role/role-name",
                            "accountId": "123456789012",
                            "userName": "role-name",
                        },
                        "webIdFederationData": {},
                        "attributes": {
                            "mfaAuthenticated": "true",
                            "creationDate": "2019-12-05T23:00:31Z",
                        },
                    },
                },
                "eventTime": "2019-12-05T23:05:15Z",
                "eventSource": "ec2.amazonaws.com",
                "eventName": "ModifyImageAttribute",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "1.1.1.1",
                "userAgent": "aws-sdk-go/1.25.38 (go1.13.4; darwin; amd64) APN/1.0 HashiCorp/1.0 Terraform/0.12.16 (+https://www.terraform.io)",
                "requestParameters": {
                    "imageId": "ami-1234a",
                    "launchPermission": {
                        "remove": {"items": [{"userId": "000000000000"}]}
                    },
                    "attributeType": "launchPermission",
                },
                "responseElements": {"_return": True},
                "requestID": "88cf05ef-c844-4f75-8456-391c388cade0",
                "eventID": "b4469d10-a068-41eb-8d3f-ca36e5e8d06b",
                "eventType": "AwsApiCall",
                "recipientAccountId": "123456789012",
            },
        }

        assert_equal(
            translate_event(event),
            [
                {
                    "account": "123456789012",
                    "id": "ami-1234a",
                    "region": "us-east-1",
                    "type": "ami",
                }
            ],
        )

    def test_ec2_ModifySnapshotAttribute_translation(self):
        event = {
            "version": "0",
            "id": "c2a207fb-cb90-7068-d4a9-6240d2cdd127",
            "detail-type": "AWS API Call via CloudTrail",
            "source": "aws.sqs",
            "account": "123456789012",
            "time": "2019-12-16T17:29:19Z",
            "region": "us-east-1",
            "resources": [],
            "detail": {
                "eventVersion": "1.05",
                "userIdentity": {
                    "type": "AssumedRole",
                    "principalId": "ABCDEFGHIJKLMNOPQRSTU:1234567890123456789",
                    "arn": "arn:aws:sts::123456789012:assumed-role/role-name/1234567890123456789",
                    "accountId": "123456789012",
                    "accessKeyId": "ABCDEFGHIJKLMNOPQRST",
                    "sessionContext": {
                        "sessionIssuer": {
                            "type": "Role",
                            "principalId": "ABCDEFGHIJKLMNOPQRSTU",
                            "arn": "arn:aws:iam::123456789012:role/role-name",
                            "accountId": "123456789012",
                            "userName": "role-name",
                        },
                        "webIdFederationData": {},
                        "attributes": {
                            "mfaAuthenticated": "true",
                            "creationDate": "2019-12-05T23:00:31Z",
                        },
                    },
                },
                "eventTime": "2019-12-05T23:05:15Z",
                "eventSource": "ec2.amazonaws.com",
                "eventName": "ModifySnapshotAttribute",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "1.1.1.1",
                "userAgent": "aws-sdk-go/1.25.38 (go1.13.4; darwin; amd64) APN/1.0 HashiCorp/1.0 Terraform/0.12.16 (+https://www.terraform.io)",
                "requestParameters": {
                    "snapshotId": "snap-abc123",
                    "createVolumePermission": {
                        "remove": {"items": [{"userId": "000000000000"}]}
                    },
                    "attributeType": "CREATE_VOLUME_PERMISSION",
                },
                "responseElements": {
                    "requestId": "8009c9ff-d63e-4e0d-9d71-cd23c35cb649",
                    "_return": True,
                },
                "requestID": "8009c9ff-d63e-4e0d-9d71-cd23c35cb649",
                "eventID": "19e65b1e-2667-42da-82ff-84e8e032c41a",
                "eventType": "AwsApiCall",
                "recipientAccountId": "123456789012",
            },
        }

        assert_equal(
            translate_event(event),
            [
                {
                    "account": "123456789012",
                    "id": "snap-abc123",
                    "region": "us-east-1",
                    "type": "ebs_snapshot",
                }
            ],
        )

    def test_rds_ModifyDBSnapshotAttribute_translation(self):
        event = {
            "version": "0",
            "id": "c2a207fb-cb90-7068-d4a9-6240d2cdd127",
            "detail-type": "AWS API Call via CloudTrail",
            "source": "aws.sqs",
            "account": "123456789012",
            "time": "2019-12-16T17:29:19Z",
            "region": "us-east-1",
            "resources": [],
            "detail": {
                "eventVersion": "1.05",
                "userIdentity": {
                    "type": "AssumedRole",
                    "principalId": "ABCDEFGHIJKLMNOPQRSTU:abc@xyz.com",
                    "arn": "arn:aws:sts::123456789012:assumed-role/role-name/abc@xyz.com",
                    "accountId": "123456789012",
                    "accessKeyId": "ABCDEFGHIJKLMNOPQRST",
                    "sessionContext": {
                        "attributes": {
                            "mfaAuthenticated": "true",
                            "creationDate": "2019-12-04T21:52:47Z",
                        },
                        "sessionIssuer": {
                            "type": "Role",
                            "principalId": "ABCDEFGHIJKLMNOPQRSTU",
                            "arn": "arn:aws:iam::123456789012:role/role-name",
                            "accountId": "123456789012",
                            "userName": "role-name",
                        },
                    },
                },
                "eventTime": "2019-12-04T22:27:29Z",
                "eventSource": "rds.amazonaws.com",
                "eventName": "ModifyDBSnapshotAttribute",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "1.1.1.1",
                "userAgent": "console.amazonaws.com",
                "requestParameters": {
                    "dBSnapshotIdentifier": "misconfiguration-maker",
                    "attributeName": "restore",
                    "valuesToAdd": ["000000000000"],
                },
                "responseElements": {
                    "dBSnapshotIdentifier": "misconfiguration-maker",
                    "dBSnapshotAttributes": [
                        {
                            "attributeName": "restore",
                            "attributeValues": ["000000000000"],
                        }
                    ],
                },
                "requestID": "4e2915f3-c8c9-47d1-a0c5-ac1d3d709753",
                "eventID": "19f5a1b0-c17e-4d1e-af69-bc42628dcde9",
                "eventType": "AwsApiCall",
                "recipientAccountId": "123456789012",
            },
        }

        assert_equal(
            translate_event(event),
            [
                {
                    "account": "123456789012",
                    "id": "misconfiguration-maker",
                    "region": "us-east-1",
                    "type": "rds_snapshot",
                }
            ],
        )

    def test_rds_ModifyDBInstance_translation(self):
        event = {
            "version": "0",
            "id": "c2a207fb-cb90-7068-d4a9-6240d2cdd127",
            "detail-type": "AWS API Call via CloudTrail",
            "source": "aws.sqs",
            "account": "123456789012",
            "time": "2019-12-16T17:29:19Z",
            "region": "us-east-1",
            "resources": [],
            "detail": {
                "eventVersion": "1.05",
                "userIdentity": {
                    "type": "AssumedRole",
                    "principalId": "ABCDEFGHIJKLMNOPQRSTU:role-name",
                    "arn": "arn:aws:sts::123456789012:assumed-role/role-name/role-name",
                    "accountId": "123456789012",
                    "accessKeyId": "ABCDEFGHIJKLMNOPQRST",
                    "sessionContext": {
                        "attributes": {
                            "mfaAuthenticated": "false",
                            "creationDate": "2019-11-14T04:59:24Z",
                        },
                        "sessionIssuer": {
                            "type": "Role",
                            "principalId": "ABCDEFGHIJKLMNOPQRSTU",
                            "arn": "arn:aws:iam::123456789012:role/role-name",
                            "accountId": "123456789012",
                            "userName": "role-name",
                        },
                    },
                },
                "eventTime": "2019-11-14T04:59:26Z",
                "eventSource": "rds.amazonaws.com",
                "eventName": "ModifyDBInstance",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "18.206.194.39",
                "userAgent": "Boto3/1.9.221 Python/3.6.9 Linux/4.14.138-99.102.amzn2.x86_64 exec-env/AWS_Lambda_python3.6 Botocore/1.12.221",
                "requestParameters": {
                    "allowMajorVersionUpgrade": False,
                    "applyImmediately": True,
                    "publiclyAccessible": False,
                    "dBInstanceIdentifier": "dbname",
                },
                "responseElements": {
                    "dBInstanceArn": "arn:aws:rds:us-east-1:123456789012:db:dbname",
                    "storageEncrypted": False,
                    "preferredBackupWindow": "04:27-04:57",
                    "preferredMaintenanceWindow": "sat:09:34-sat:10:04",
                    "backupRetentionPeriod": 7,
                    "allocatedStorage": 20,
                    "storageType": "gp2",
                    "engineVersion": "5.7.22",
                    "dbInstancePort": 0,
                    "associatedRoles": [],
                    "optionGroupMemberships": [
                        {"status": "in-sync", "optionGroupName": "default:mysql-5-7"}
                    ],
                    "dBParameterGroups": [
                        {
                            "dBParameterGroupName": "default.mysql5.7",
                            "parameterApplyStatus": "in-sync",
                        }
                    ],
                    "instanceCreateTime": "Jul 17, 2019 7:31:39 PM",
                    "maxAllocatedStorage": 1000,
                    "monitoringInterval": 0,
                    "dBInstanceClass": "db.t2.micro",
                    "readReplicaDBInstanceIdentifiers": [],
                    "dBSubnetGroup": {
                        "dBSubnetGroupName": "default",
                        "dBSubnetGroupDescription": "default",
                        "subnets": [
                            {
                                "subnetAvailabilityZone": {"name": "us-east-1b"},
                                "subnetIdentifier": "subnet-abcd",
                                "subnetStatus": "Active",
                            },
                            {
                                "subnetAvailabilityZone": {"name": "us-east-1a"},
                                "subnetIdentifier": "subnet-abcd",
                                "subnetStatus": "Active",
                            },
                            {
                                "subnetAvailabilityZone": {"name": "us-east-1c"},
                                "subnetIdentifier": "subnet-abcd",
                                "subnetStatus": "Active",
                            },
                            {
                                "subnetAvailabilityZone": {"name": "us-east-1f"},
                                "subnetIdentifier": "subnet-abcd",
                                "subnetStatus": "Active",
                            },
                            {
                                "subnetAvailabilityZone": {"name": "us-east-1d"},
                                "subnetIdentifier": "subnet-abcd",
                                "subnetStatus": "Active",
                            },
                            {
                                "subnetAvailabilityZone": {"name": "us-east-1e"},
                                "subnetIdentifier": "subnet-abcd",
                                "subnetStatus": "Active",
                            },
                        ],
                        "vpcId": "vpc-abcd",
                        "subnetGroupStatus": "Complete",
                    },
                    "masterUsername": "admin",
                    "multiAZ": False,
                    "autoMinorVersionUpgrade": True,
                    "latestRestorableTime": "Nov 14, 2019 4:55:00 AM",
                    "engine": "mysql",
                    "httpEndpointEnabled": False,
                    "cACertificateIdentifier": "rds-ca-2015",
                    "dbiResourceId": "db-abcd",
                    "deletionProtection": False,
                    "endpoint": {
                        "address": "dbname.xyz.us-east-1.rds.amazonaws.com",
                        "port": 3306,
                        "hostedZoneId": "ABCDEFGHIJKLMN",
                    },
                    "dBSecurityGroups": [],
                    "pendingModifiedValues": {},
                    "dBInstanceStatus": "available",
                    "publiclyAccessible": True,
                    "domainMemberships": [],
                    "copyTagsToSnapshot": True,
                    "dBInstanceIdentifier": "dbname",
                    "licenseModel": "general-public-license",
                    "iAMDatabaseAuthenticationEnabled": False,
                    "performanceInsightsEnabled": False,
                    "vpcSecurityGroups": [
                        {"status": "active", "vpcSecurityGroupId": "sg-abcd"}
                    ],
                    "dbname.xyz.us-east-1.rds.amazonaws.com"dbname",
                    "availabilityZone": "us-east-1d",
                },
                "requestID": "3ae00dda-20a9-45c7-b464-bf5b46ac97e7",
                "eventID": "f15b2ee4-6a74-425a-8629-e91f9e6fcc3a",
                "eventType": "AwsApiCall",
                "recipientAccountId": "123456789012",
            },
        }
        assert_equal(
            translate_event(event),
            [
                {
                    "account": "123456789012",
                    "id": "dbname",
                    "region": "us-east-1",
                    "type": "rds",
                }
            ],
        )

    def test_rds_CreateDBInstance_translation(self):
        event = {
            "version": "0",
            "id": "c2a207fb-cb90-7068-d4a9-6240d2cdd127",
            "detail-type": "AWS API Call via CloudTrail",
            "source": "aws.sqs",
            "account": "123456789012",
            "time": "2019-12-16T17:29:19Z",
            "region": "us-east-1",
            "resources": [],
            "detail": {
                "eventVersion": "1.05",
                "userIdentity": {
                    "type": "AssumedRole",
                    "principalId": "ABCDEFGHIJKLMNOPQRSTU:1575491847268719000",
                    "arn": "arn:aws:sts::123456789012:assumed-role/role-name/1575491847268719000",
                    "accountId": "123456789012",
                    "accessKeyId": "ABCDEFGHIJKLMNOPQRST",
                    "sessionContext": {
                        "attributes": {
                            "mfaAuthenticated": "true",
                            "creationDate": "2019-12-04T20:37:27Z",
                        },
                        "sessionIssuer": {
                            "type": "Role",
                            "principalId": "ABCDEFGHIJKLMNOPQRSTU",
                            "arn": "arn:aws:iam::123456789012:role/role-name",
                            "accountId": "123456789012",
                            "userName": "role-name",
                        },
                    },
                },
                "eventTime": "2019-12-04T21:14:11Z",
                "eventSource": "rds.amazonaws.com",
                "eventName": "CreateDBInstance",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "1.1.1.1",
                "userAgent": "aws-sdk-go/1.25.38 (go1.13.4; darwin; amd64) APN/1.0 HashiCorp/1.0 Terraform/0.12.16 (+https://www.terraform.io)",
                "requestParameters": {
                    "dbname.xyz.us-east-1.rds.amazonaws.com",
                    "dBInstanceIdentifier": "dbname",
                    "allocatedStorage": 5,
                    "dBInstanceClass": "db.t2.micro",
                    "engine": "mysql",
                    "masterUsername": "foo",
                    "masterUserPassword": "****",
                    "dBParameterGroupName": "default.mysql5.7",
                    "backupRetentionPeriod": 0,
                    "engineVersion": "5.7",
                    "autoMinorVersionUpgrade": True,
                    "publiclyAccessible": False,
                    "tags": [
                        {"key": "team", "value": "security"},
                        {"key": "Name", "value": "misconfiguration_maker"},
                        {"key": "App", "value": "misconfiguration_maker"},
                        {"key": "system", "value": "aws-remediation"},
                    ],
                    "storageEncrypted": False,
                    "copyTagsToSnapshot": False,
                    "deletionProtection": False,
                },
                "responseElements": {
                    "dBInstanceIdentifier": "dbname",
                    "dBInstanceClass": "db.t2.micro",
                    "engine": "mysql",
                    "dBInstanceStatus": "creating",
                    "masterUsername": "foo",
                    "dbname.xyz.us-east-1.rds.amazonaws.com",
                    "allocatedStorage": 5,
                    "preferredBackupWindow": "04:37-05:07",
                    "backupRetentionPeriod": 0,
                    "dBSecurityGroups": [],
                    "vpcSecurityGroups": [
                        {"vpcSecurityGroupId": "sg-abcd", "status": "active"}
                    ],
                    "dBParameterGroups": [
                        {
                            "dBParameterGroupName": "default.mysql5.7",
                            "parameterApplyStatus": "in-sync",
                        }
                    ],
                    "dBSubnetGroup": {
                        "dBSubnetGroupName": "default",
                        "dBSubnetGroupDescription": "default",
                        "vpcId": "vpc-abcd",
                        "subnetGroupStatus": "Complete",
                        "subnets": [
                            {
                                "subnetIdentifier": "subnet-abcd",
                                "subnetAvailabilityZone": {"name": "us-east-1b"},
                                "subnetOutpost": {},
                                "subnetStatus": "Active",
                            },
                            {
                                "subnetIdentifier": "subnet-abcd",
                                "subnetAvailabilityZone": {"name": "us-east-1a"},
                                "subnetOutpost": {},
                                "subnetStatus": "Active",
                            },
                            {
                                "subnetIdentifier": "subnet-abcd",
                                "subnetAvailabilityZone": {"name": "us-east-1c"},
                                "subnetOutpost": {},
                                "subnetStatus": "Active",
                            },
                            {
                                "subnetIdentifier": "subnet-abcd",
                                "subnetAvailabilityZone": {"name": "us-east-1f"},
                                "subnetOutpost": {},
                                "subnetStatus": "Active",
                            },
                            {
                                "subnetIdentifier": "subnet-abcd",
                                "subnetAvailabilityZone": {"name": "us-east-1d"},
                                "subnetOutpost": {},
                                "subnetStatus": "Active",
                            },
                            {
                                "subnetIdentifier": "subnet-abcd",
                                "subnetAvailabilityZone": {"name": "us-east-1e"},
                                "subnetOutpost": {},
                                "subnetStatus": "Active",
                            },
                        ],
                    },
                    "preferredMaintenanceWindow": "mon:08:13-mon:08:43",
                    "pendingModifiedValues": {"masterUserPassword": "****"},
                    "multiAZ": False,
                    "engineVersion": "5.7.22",
                    "autoMinorVersionUpgrade": True,
                    "readReplicaDBInstanceIdentifiers": [],
                    "licenseModel": "general-public-license",
                    "optionGroupMemberships": [
                        {"optionGroupName": "default:mysql-5-7", "status": "in-sync"}
                    ],
                    "publiclyAccessible": False,
                    "storageType": "gp2",
                    "dbInstancePort": 0,
                    "storageEncrypted": False,
                    "dbiResourceId": "db-abcd",
                    "cACertificateIdentifier": "rds-ca-2015",
                    "domainMemberships": [],
                    "copyTagsToSnapshot": False,
                    "monitoringInterval": 0,
                    "dBInstanceArn": "arn:aws:rds:us-east-1:123456789012:db:dbname",
                    "iAMDatabaseAuthenticationEnabled": False,
                    "performanceInsightsEnabled": False,
                    "deletionProtection": False,
                    "associatedRoles": [],
                    "httpEndpointEnabled": False,
                },
                "requestID": "5243cd91-8200-4f75-bfdf-73b0838cfe70",
                "eventID": "9899c3f4-5f18-4e91-8bbf-6748f1f0be67",
                "eventType": "AwsApiCall",
                "recipientAccountId": "123456789012",
            },
        }

        assert_equal(
            translate_event(event),
            [
                {
                    "account": "123456789012",
                    "id": "dbname",
                    "delay": 900,
                    "region": "us-east-1",
                    "type": "rds",
                }
            ],
        )

    def test_redshift_ModifyCluster_translation(self):
        event = {
            "version": "0",
            "id": "c2a207fb-cb90-7068-d4a9-6240d2cdd127",
            "detail-type": "AWS API Call via CloudTrail",
            "source": "aws.sqs",
            "account": "123456789012",
            "time": "2019-12-16T17:29:19Z",
            "region": "us-east-1",
            "resources": [],
            "detail": {
                "eventVersion": "1.05",
                "userIdentity": {
                    "type": "AssumedRole",
                    "principalId": "ABCDEFGHIJKLMNOPQRSTU:role-name-123456789012",
                    "arn": "arn:aws:sts::123456789012:assumed-role/local_remediator/role-name-123456789012",
                    "accountId": "123456789012",
                    "accessKeyId": "ABCDEFGHIJKLMNOPQRST",
                    "sessionContext": {
                        "attributes": {
                            "mfaAuthenticated": "true",
                            "creationDate": "2019-12-05T20:46:09Z",
                        },
                        "sessionIssuer": {
                            "type": "Role",
                            "principalId": "ABCDEFGHIJKLMNOPQRSTU",
                            "arn": "arn:aws:iam::123456789012:role/local_remediator",
                            "accountId": "123456789012",
                            "userName": "local_remediator",
                        },
                    },
                },
                "eventTime": "2019-12-05T20:46:13Z",
                "eventSource": "redshift.amazonaws.com",
                "eventName": "ModifyCluster",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "1.1.1.1",
                "userAgent": "Boto3/1.10.25 Python/3.7.5 Darwin/18.7.0 Botocore/1.13.25",
                "requestParameters": {
                    "clusterIdentifier": "misconfig-maker",
                    "masterUserPassword": "****",
                    "encrypted": True,
                },
                "responseElements": None,
                "requestID": "469e7fef-17a0-11ea-9532-f3c8251db4e6",
                "eventID": "754f30bf-a02c-49ab-9523-14c40d872979",
                "eventType": "AwsApiCall",
                "recipientAccountId": "123456789012",
            },
        }

        assert_equal(
            translate_event(event),
            [
                {
                    "account": "123456789012",
                    "id": "misconfig-maker",
                    "delay": 900,
                    "region": "us-east-1",
                    "type": "redshift",
                }
            ],
        )

    def test_redshift_CreateCluster_translation(self):
        event = {
            "version": "0",
            "id": "c2a207fb-cb90-7068-d4a9-6240d2cdd127",
            "detail-type": "AWS API Call via CloudTrail",
            "source": "aws.sqs",
            "account": "123456789012",
            "time": "2019-12-16T17:29:19Z",
            "region": "us-east-1",
            "resources": [],
            "detail": {
                "eventVersion": "1.05",
                "userIdentity": {
                    "type": "AssumedRole",
                    "principalId": "ABCDEFGHIJKLMNOPQRSTU:1577208946667274000",
                    "arn": "arn:aws:sts::123456789012:assumed-role/role-name/1577208946667274000",
                    "accountId": "123456789012",
                    "accessKeyId": "ABCDEFGHIJKLMNOPQRST",
                    "sessionContext": {
                        "attributes": {
                            "mfaAuthenticated": "true",
                            "creationDate": "2019-12-24T17:35:47Z",
                        },
                        "sessionIssuer": {
                            "type": "Role",
                            "principalId": "ABCDEFGHIJKLMNOPQRSTU",
                            "arn": "arn:aws:iam::123456789012:role/role-name",
                            "accountId": "123456789012",
                            "userName": "role-name",
                        },
                    },
                },
                "eventTime": "2019-12-24T17:36:59Z",
                "eventSource": "redshift.amazonaws.com",
                "eventName": "CreateCluster",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "1.1.1.1",
                "userAgent": "aws-sdk-go/1.25.38 (go1.13.4; darwin; amd64) APN/1.0 HashiCorp/1.0 Terraform/0.12.16 (+https://www.terraform.io)",
                "requestParameters": {
                    "clusterIdentifier": "misconfig-maker",
                    "allowVersionUpgrade": True,
                    "clusterVersion": "1.0",
                    "tags": [
                        {"value": "misconfiguration_maker", "key": "App"},
                        {"value": "security", "key": "team"},
                        {"value": "misconfiguration_maker", "key": "Name"},
                        {"value": "aws-remediation", "key": "system"},
                    ],
                    "masterUsername": "foo",
                    "masterUserPassword": "****",
                    "automatedSnapshotRetentionPeriod": 1,
                    "port": 5439,
                    "dbname.xyz.us-east-1.rds.amazonaws.com",
                    "clusterType": "single-node",
                    "nodeType": "dc1.large",
                    "publiclyAccessible": True,
                },
                "responseElements": {
                    "nextMaintenanceWindowStartTime": "Dec 28, 2019 8:00:00 AM",
                    "nodeType": "dc1.large",
                    "clusterAvailabilityStatus": "Modifying",
                    "preferredMaintenanceWindow": "sat:08:00-sat:08:30",
                    "manualSnapshotRetentionPeriod": -1,
                    "clusterStatus": "creating",
                    "deferredMaintenanceWindows": [],
                    "vpcId": "vpc-abcd",
                    "enhancedVpcRouting": False,
                    "masterUsername": "foo",
                    "clusterSecurityGroups": [],
                    "pendingModifiedValues": {"masterUserPassword": "****"},
                    "maintenanceTrackName": "current",
                    "dbname.xyz.us-east-1.rds.amazonaws.com",
                    "clusterVersion": "1.0",
                    "encrypted": False,
                    "publiclyAccessible": True,
                    "tags": [
                        {"value": "misconfiguration_maker", "key": "App"},
                        {"value": "aws-remediation", "key": "system"},
                        {"value": "security", "key": "team"},
                        {"value": "misconfiguration_maker", "key": "Name"},
                    ],
                    "clusterParameterGroups": [
                        {
                            "parameterGroupName": "default.redshift-1.0",
                            "parameterApplyStatus": "in-sync",
                        }
                    ],
                    "allowVersionUpgrade": True,
                    "automatedSnapshotRetentionPeriod": 1,
                    "numberOfNodes": 1,
                    "vpcSecurityGroups": [
                        {"status": "active", "vpcSecurityGroupId": "sg-abcd"}
                    ],
                    "iamRoles": [],
                    "clusterIdentifier": "misconfig-maker",
                    "clusterSubnetGroupName": "default",
                },
                "requestID": "fc2e9ff2-2673-11ea-9caa-c956bec1ce87",
                "eventID": "8357728a-3df4-4604-aa5f-6ec57ead3371",
                "eventType": "AwsApiCall",
                "recipientAccountId": "123456789012",
            },
        }

        assert_equal(
            translate_event(event),
            [
                {
                    "account": "123456789012",
                    "id": "misconfig-maker",
                    "delay": 900,
                    "region": "us-east-1",
                    "type": "redshift",
                }
            ],
        )

    def test_ec2_RunInstances_translation(self):
        event = {
            "version": "0",
            "id": "c2a207fb-cb90-7068-d4a9-6240d2cdd127",
            "detail-type": "AWS API Call via CloudTrail",
            "source": "aws.sqs",
            "account": "123456789012",
            "time": "2019-12-16T17:29:19Z",
            "region": "us-east-1",
            "resources": [],
            "detail": {
                "eventVersion": "1.05",
                "userIdentity": {
                    "type": "AssumedRole",
                    "principalId": "ABCDEFGHIJKLMNOPQRSTU:1234567890123456789",
                    "arn": "arn:aws:sts::123456789012:assumed-role/role-name/1234567890123456789",
                    "accountId": "123456789012",
                    "accessKeyId": "ABCDEFGHIJKLMNOPQRST",
                    "sessionContext": {
                        "sessionIssuer": {
                            "type": "Role",
                            "principalId": "ABCDEFGHIJKLMNOPQRSTU",
                            "arn": "arn:aws:iam::123456789012:role/role-name",
                            "accountId": "123456789012",
                            "userName": "role-name",
                        },
                        "webIdFederationData": {},
                        "attributes": {
                            "mfaAuthenticated": "true",
                            "creationDate": "2019-12-19T15:22:58Z",
                        },
                    },
                },
                "eventTime": "2019-12-19T15:37:58Z",
                "eventSource": "ec2.amazonaws.com",
                "eventName": "RunInstances",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "1.1.1.1",
                "userAgent": "aws-sdk-go/1.25.38 (go1.13.4; darwin; amd64) APN/1.0 HashiCorp/1.0 Terraform/0.12.16 (+https://www.terraform.io)",
                "requestParameters": {
                    "instancesSet": {
                        "items": [
                            {
                                "imageId": "ami-1234",
                                "minCount": 1,
                                "maxCount": 1,
                            }
                        ]
                    },
                    "instanceType": "t2.micro",
                    "blockDeviceMapping": {},
                    "monitoring": {"enabled": False},
                    "disableApiTermination": False,
                    "iamInstanceProfile": {},
                    "ebsOptimized": False,
                    "tagSpecificationSet": {
                        "items": [
                            {
                                "resourceType": "instance",
                                "tags": [
                                    {"key": "App", "value": "misconfiguration_maker"},
                                    {"key": "Name", "value": "misconfiguration_maker"},
                                    {"key": "system", "value": "aws-remediation"},
                                    {"key": "team", "value": "security"},
                                ],
                            }
                        ]
                    },
                },
                "responseElements": {
                    "requestId": "da2549b5-1cfa-4312-a9c5-2343cf561dd9",
                    "reservationId": "r-abcd",
                    "ownerId": "123456789012",
                    "groupSet": {},
                    "instancesSet": {
                        "items": [
                            {
                                "instanceId": "i-abcd",
                                "imageId": "ami-1234",
                                "instanceState": {"code": 0, "name": "pending"},
                                "privateDnsName": "ip-192-168-1-1.ec2.internal",
                                "amiLaunchIndex": 0,
                                "productCodes": {},
                                "instanceType": "t2.micro",
                                "launchTime": 1576769878000,
                                "placement": {
                                    "availabilityZone": "us-east-1d",
                                    "tenancy": "default",
                                },
                                "monitoring": {"state": "disabled"},
                                "subnetId": "subnet-abcd",
                                "vpcId": "vpc-abcd",
                                "privateIpAddress": "19.168.1.1",
                                "stateReason": {
                                    "code": "pending",
                                    "message": "pending",
                                },
                                "architecture": "x86_64",
                                "rootDeviceType": "ebs",
                                "rootDeviceName": "/dev/sda1",
                                "blockDeviceMapping": {},
                                "virtualizationType": "hvm",
                                "hypervisor": "xen",
                                "tagSet": {
                                    "items": [
                                        {"key": "team", "value": "security"},
                                        {
                                            "key": "Name",
                                            "value": "misconfiguration_maker",
                                        },
                                        {"key": "system", "value": "aws-remediation"},
                                        {
                                            "key": "App",
                                            "value": "misconfiguration_maker",
                                        },
                                    ]
                                },
                                "groupSet": {
                                    "items": [
                                        {
                                            "groupId": "sg-abcd",
                                            "groupName": "default",
                                        }
                                    ]
                                },
                                "sourceDestCheck": True,
                                "networkInterfaceSet": {
                                    "items": [
                                        {
                                            "networkInterfaceId": "eni-abcd",
                                            "subnetId": "subnet-abcd",
                                            "vpcId": "vpc-abcd",
                                            "ownerId": "123456789012",
                                            "status": "in-use",
                                            "macAddress": "0e:89:82:29:40:d9",
                                            "privateIpAddress": "19.168.1.1",
                                            "privateDnsName": "ip-192-168-1-1.ec2.internal",
                                            "sourceDestCheck": True,
                                            "interfaceType": "interface",
                                            "groupSet": {
                                                "items": [
                                                    {
                                                        "groupId": "sg-abcd",
                                                        "groupName": "default",
                                                    }
                                                ]
                                            },
                                            "attachment": {
                                                "attachmentId": "eni-abcd",
                                                "deviceIndex": 0,
                                                "status": "attaching",
                                                "attachTime": 1576769878000,
                                                "deleteOnTermination": True,
                                            },
                                            "privateIpAddressesSet": {
                                                "item": [
                                                    {
                                                        "privateIpAddress": "19.168.1.1",
                                                        "privateDnsName": "ip-192-168-1-1.ec2.internal",
                                                        "primary": True,
                                                    }
                                                ]
                                            },
                                            "ipv6AddressesSet": {},
                                            "tagSet": {},
                                        }
                                    ]
                                },
                                "ebsOptimized": False,
                                "cpuOptions": {"coreCount": 1, "threadsPerCore": 1},
                                "capacityReservationSpecification": {
                                    "capacityReservationPreference": "open"
                                },
                                "enclaveOptions": {"enabled": False},
                                "metadataOptions": {
                                    "state": "pending",
                                    "httpTokens": "optional",
                                    "httpPutResponseHopLimit": 1,
                                    "httpEndpoint": "enabled",
                                },
                            }
                        ]
                    },
                },
                "requestID": "da2549b5-1cfa-4312-a9c5-2343cf561dd9",
                "eventID": "4fb65f01-3889-4ecf-8a79-65fda2efe348",
                "eventType": "AwsApiCall",
                "recipientAccountId": "123456789012",
            },
        }

        assert_equal(
            translate_event(event),
            [
                {
                    "account": "123456789012",
                    "id": "i-abcd",
                    "region": "us-east-1",
                    "type": "ec2",
                }
            ],
        )

    def test_ec2_ModifyInstanceMetadataOptions_translation(self):
        event = {
            "version": "0",
            "id": "c2a207fb-cb90-7068-d4a9-6240d2cdd127",
            "detail-type": "AWS API Call via CloudTrail",
            "source": "aws.sqs",
            "account": "123456789012",
            "time": "2019-12-16T17:29:19Z",
            "region": "us-east-1",
            "resources": [],
            "detail": {
                "eventVersion": "1.05",
                "userIdentity": {
                    "type": "AssumedRole",
                    "principalId": "ABCDEFGHIJKLMNOPQRSTU:role-name",
                    "arn": "arn:aws:sts::123456789012:assumed-role/local_remediator/role-name",
                    "accountId": "123456789012",
                    "accessKeyId": "ABCDEFGHIJKLMNOPQRST",
                    "sessionContext": {
                        "sessionIssuer": {
                            "type": "Role",
                            "principalId": "ABCDEFGHIJKLMNOPQRSTU",
                            "arn": "arn:aws:iam::123456789012:role/local_remediator",
                            "accountId": "123456789012",
                            "userName": "local_remediator",
                        },
                        "webIdFederationData": {},
                        "attributes": {
                            "mfaAuthenticated": "true",
                            "creationDate": "2019-12-19T18:17:30Z",
                        },
                    },
                },
                "eventTime": "2019-12-19T18:17:30Z",
                "eventSource": "ec2.amazonaws.com",
                "eventName": "ModifyInstanceMetadataOptions",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "1.1.1.1",
                "userAgent": "Boto3/1.10.25 Python/3.7.5 Darwin/18.7.0 Botocore/1.13.25",
                "errorCode": "Client.InvalidParameterValue",
                "errorMessage": "The HttpEndpoint is not set to 'enabled' in this request. To specify a value for HttpTokens, set HttpEndpoint to 'enabled'.",
                "requestParameters": {
                    "ModifyInstanceMetadataOptionsRequest": {
                        "HttpTokens": "required",
                        "InstanceId": "i-abcd",
                    }
                },
                "responseElements": None,
                "requestID": "9ed413bf-ff0d-485a-a245-a7a5f5b86627",
                "eventID": "c844317a-ba80-465e-aec9-65246f16062a",
                "eventType": "AwsApiCall",
                "recipientAccountId": "123456789012",
            },
        }

        assert_equal(
            translate_event(event),
            [
                {
                    "account": "123456789012",
                    "id": "i-abcd",
                    "region": "us-east-1",
                    "type": "ec2",
                }
            ],
        )

    def test_ec2_CreateSecurityGroup_translation(self):
        event = {
            "version": "0",
            "id": "c2a207fb-cb90-7068-d4a9-6240d2cdd127",
            "detail-type": "AWS API Call via CloudTrail",
            "source": "aws.sqs",
            "account": "123456789012",
            "time": "2019-12-16T17:29:19Z",
            "region": "us-east-1",
            "resources": [],
            "detail": {
                "eventVersion": "1.05",
                "userIdentity": {
                    "type": "AssumedRole",
                    "principalId": "ABCDEFGHIJKLMNOPQRSTU:1577212321281084000",
                    "arn": "arn:aws:sts::123456789012:assumed-role/role-name/1577212321281084000",
                    "accountId": "123456789012",
                    "accessKeyId": "ABCDEFGHIJKLMNOPQRST",
                    "sessionContext": {
                        "sessionIssuer": {
                            "type": "Role",
                            "principalId": "ABCDEFGHIJKLMNOPQRSTU",
                            "arn": "arn:aws:iam::123456789012:role/role-name",
                            "accountId": "123456789012",
                            "userName": "role-name",
                        },
                        "webIdFederationData": {},
                        "attributes": {
                            "mfaAuthenticated": "true",
                            "creationDate": "2019-12-24T18:32:01Z",
                        },
                    },
                },
                "eventTime": "2019-12-24T19:12:56Z",
                "eventSource": "ec2.amazonaws.com",
                "eventName": "CreateSecurityGroup",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "1.1.1.1",
                "userAgent": "aws-sdk-go/1.25.38 (go1.13.4; darwin; amd64) APN/1.0 HashiCorp/1.0 Terraform/0.12.16 (+https://www.terraform.io)",
                "requestParameters": {
                    "groupName": "misconfiguration_maker",
                    "groupDescription": "Created by misconfiguration maker for testing",
                },
                "responseElements": {
                    "requestId": "04b3590c-9bd0-438d-ac08-fc051183fc7a",
                    "_return": True,
                    "groupId": "sg-abcd",
                },
                "requestID": "04b3590c-9bd0-438d-ac08-fc051183fc7a",
                "eventID": "fb84b07f-d850-47bd-8845-416d70417cc5",
                "eventType": "AwsApiCall",
                "recipientAccountId": "123456789012",
            },
        }

        assert_equal(
            translate_event(event),
            [
                {
                    "account": "123456789012",
                    "id": "sg-abcd",
                    "region": "us-east-1",
                    "type": "security_group",
                }
            ],
        )

    def test_ec2_AuthorizeSecurityGroupIngress_translation(self):
        event = {
            "version": "0",
            "id": "c2a207fb-cb90-7068-d4a9-6240d2cdd127",
            "detail-type": "AWS API Call via CloudTrail",
            "source": "aws.sqs",
            "account": "123456789012",
            "time": "2019-12-16T17:29:19Z",
            "region": "us-east-1",
            "resources": [],
            "detail": {
                "eventVersion": "1.05",
                "userIdentity": {
                    "type": "AssumedRole",
                    "principalId": "ABCDEFGHIJKLMNOPQRSTU:1577212321281084000",
                    "arn": "arn:aws:sts::123456789012:assumed-role/role-name/1577212321281084000",
                    "accountId": "123456789012",
                    "accessKeyId": "ABCDEFGHIJKLMNOPQRST",
                    "sessionContext": {
                        "sessionIssuer": {
                            "type": "Role",
                            "principalId": "ABCDEFGHIJKLMNOPQRSTU",
                            "arn": "arn:aws:iam::123456789012:role/role-name",
                            "accountId": "123456789012",
                            "userName": "role-name",
                        },
                        "webIdFederationData": {},
                        "attributes": {
                            "mfaAuthenticated": "true",
                            "creationDate": "2019-12-24T18:32:01Z",
                        },
                    },
                },
                "eventTime": "2019-12-24T19:12:59Z",
                "eventSource": "ec2.amazonaws.com",
                "eventName": "AuthorizeSecurityGroupIngress",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "1.1.1.1",
                "userAgent": "aws-sdk-go/1.25.38 (go1.13.4; darwin; amd64) APN/1.0 HashiCorp/1.0 Terraform/0.12.16 (+https://www.terraform.io)",
                "requestParameters": {
                    "groupId": "sg-abcd",
                    "ipPermissions": {
                        "items": [
                            {
                                "ipProtocol": "tcp",
                                "fromPort": 443,
                                "toPort": 443,
                                "groups": {},
                                "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]},
                                "ipv6Ranges": {},
                                "prefixListIds": {},
                            }
                        ]
                    },
                },
                "responseElements": {
                    "requestId": "3deb0532-605a-4b45-89cc-03ffa8362e41",
                    "_return": True,
                },
                "requestID": "3deb0532-605a-4b45-89cc-03ffa8362e41",
                "eventID": "717b1b7e-e94f-4283-adff-e822c1b2e153",
                "eventType": "AwsApiCall",
                "recipientAccountId": "123456789012",
            },
        }

        assert_equal(
            translate_event(event),
            [
                {
                    "account": "123456789012",
                    "id": "sg-abcd",
                    "region": "us-east-1",
                    "type": "security_group",
                }
            ],
        )

    def test_elb_RegisterInstancesWithLoadBalancer_translation(self):
        event = {
            "version": "0",
            "id": "c2a207fb-cb90-7068-d4a9-6240d2cdd127",
            "detail-type": "AWS API Call via CloudTrail",
            "source": "aws.sqs",
            "account": "123456789012",
            "time": "2019-12-16T17:29:19Z",
            "region": "us-east-1",
            "resources": [],
            "detail": {
                "eventVersion": "1.05",
                "userIdentity": {
                    "type": "AssumedRole",
                    "principalId": "ABCDEFGHIJKLMNOPQRSTU:1577386646470489000",
                    "arn": "arn:aws:sts::123456789012:assumed-role/role-name/1577386646470489000",
                    "accountId": "123456789012",
                    "accessKeyId": "ABCDEFGHIJKLMNOPQRST",
                    "sessionContext": {
                        "sessionIssuer": {
                            "type": "Role",
                            "principalId": "ABCDEFGHIJKLMNOPQRSTU",
                            "arn": "arn:aws:iam::123456789012:role/role-name",
                            "accountId": "123456789012",
                            "userName": "role-name",
                        },
                        "webIdFederationData": {},
                        "attributes": {
                            "mfaAuthenticated": "true",
                            "creationDate": "2019-12-26T18:57:26Z",
                        },
                    },
                },
                "eventTime": "2019-12-26T19:45:07Z",
                "eventSource": "elasticloadbalancing.amazonaws.com",
                "eventName": "RegisterInstancesWithLoadBalancer",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "1.1.1.1",
                "userAgent": "aws-sdk-go/1.25.38 (go1.13.4; darwin; amd64) APN/1.0 HashiCorp/1.0 Terraform/0.12.16 (+https://www.terraform.io)",
                "requestParameters": {
                    "loadBalancerName": "misconfiguration-maker",
                    "instances": [{"instanceId": "i-abcd"}],
                },
                "responseElements": {
                    "instances": [{"instanceId": "i-abcd"}]
                },
                "requestID": "a896a473-55d0-4ece-b002-bfd4d60854e6",
                "eventID": "403f2d60-bc4f-4748-8738-1874f1d5d4a9",
                "eventType": "AwsApiCall",
                "apiVersion": "2012-06-01",
                "recipientAccountId": "123456789012",
            },
        }

        assert_equal(
            translate_event(event),
            [
                {
                    "account": "123456789012",
                    "id": "misconfiguration-maker",
                    "region": "us-east-1",
                    "type": "elb",
                }
            ],
        )
