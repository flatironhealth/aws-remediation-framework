import sys
import os
from importlib import reload

from nose.tools import assert_equal, assert_true, assert_false
from unittest import TestCase, mock
from unittest.mock import MagicMock
import datetime
import pytz
import json


class TestAuditors(TestCase):
    def setUp(self):
        def mocked_get_session_for_account_side_effect(account, region, service):
            utc = pytz.UTC

            class Ec2:
                # AMIs
                def describe_image_attribute(self, Attribute, ImageId):
                    if ImageId == "ami-ok":
                        return {
                            "ImageId": "ami-ok",
                            "LaunchPermissions": [],
                        }

                    elif ImageId == "ami-shared":
                        return {
                            "ImageId": "ami-shared",
                            "LaunchPermissions": [{"UserId": "000000000000"}],
                        }
                    elif ImageId == "ami-public":
                        return {
                            "ImageId": "ami-public",
                            "LaunchPermissions": [{"Group": "all"}],
                        }
                    else:
                        raise Exception("Unexpected image id {}".format(ImageId))

                def modify_image_attribute(Attribute, LaunchPermission, ImageId):
                    return True

                # EBS snapshots
                def describe_snapshot_attribute(self, Attribute, SnapshotId):
                    if SnapshotId == "snap-ok":
                        return {"SnapshotId": "snap-ok", "CreateVolumePermissions": []}
                    elif SnapshotId == "snap-shared":
                        return {
                            "CreateVolumePermissions": [{"UserId": "000000000000"}],
                            "SnapshotId": "snap-066877671789bd71b",
                        }
                    elif SnapshotId == "snap-public":
                        return {
                            "CreateVolumePermissions": [{"Group": "all"}],
                            "SnapshotId": "snap-066877671789bd71b",
                        }
                    else:
                        raise Exception("Unexpected snapshot id {}".format(SnapshotId))

                def modify_snapshot_attribute(
                        self, Attribute, CreateVolumePermission, SnapshotId
                ):
                    return True

                # EC2
                def describe_instances(self, InstanceIds):
                    if InstanceIds[0] == "i-ok":
                        return {
                            "Reservations": [
                                {
                                    "Instances": [
                                        {
                                            "InstanceId": "i-ok",
                                            "MetadataOptions": {
                                                "HttpTokens": "required",
                                                "HttpEndpoint": "enabled",
                                            },
                                            "Tags": [
                                                {"Key": "department", "Value": "example"},
                                                {
                                                    "Key": "Name",
                                                    "Value": "example",
                                                },
                                                {"Key": "application", "Value": "example"},
                                            ],
                                            "State": {"Code": 16, "Name": "running"},
                                        }
                                    ]
                                }
                            ]
                        }

                    elif InstanceIds[0] == "i-bad":
                        return {
                            "Reservations": [
                                {
                                    "Instances": [
                                        {
                                            "InstanceId": "i-bad",
                                            "MetadataOptions": {
                                                "HttpTokens": "optional",
                                                "HttpEndpoint": "enabled",
                                            },
                                            "Tags": [
                                                {"Key": "application", "Value": "example"}
                                            ],
                                            "State": {"Code": 16, "Name": "running"},
                                        }
                                    ]
                                }
                            ]
                        }
                    else:
                        raise Exception("Unexpected instance id {}".format(InstanceIds))

                def modify_instance_metadata_options(
                        self, InstanceId, HttpTokens, HttpEndpoint
                ):
                    return True

                def stop_instances(self, InstanceIds):
                    return True

                # VPC Flow Logs for Region check
                def describe_vpcs(self):
                    return {
                        "Vpcs": [
                            {
                                "CidrBlock": "10.0.0.0/24",
                                "DhcpOptionsId": "dopt-d9070ebb",
                                "State": "available",
                                "VpcId": "vpc-a01106c2",
                                "OwnerId": "123456789012",
                                "InstanceTenancy": "default",
                                "CidrBlockAssociationSet": [
                                    {
                                        "AssociationId": "vpc-cidr-assoc-062c64cfafEXAMPLE",
                                        "CidrBlock": "10.0.0.0/24",
                                        "CidrBlockState": {"State": "associated"},
                                    }
                                ],
                                "IsDefault": True,
                                "Tags": [],
                            }
                        ]
                    }

                def describe_flow_logs(self):
                    if region == "us-east-1":
                        return {
                            "FlowLogs": [
                                {
                                    "CreationTime": "2015-06-25T16:51:24Z",
                                    "DeliverLogsPermissionArn": "arn:aws:iam::123456789012:role/SandboxFlowLogs",
                                    "DeliverLogsStatus": "SUCCESS",
                                    "FlowLogId": "fl-a89673c1",
                                    "FlowLogStatus": "ACTIVE",
                                    "LogGroupName": "SandboxNetworkFlow",
                                    "ResourceId": "vpc-a01106c2",
                                    "TrafficType": "ALL",
                                    "LogDestinationType": "cloud-watch-logs",
                                    "LogFormat": "${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status}",
                                }
                            ]
                        }
                    else:
                        return {"FlowLogs": []}

                def terminate_instances(self, InstanceIds, dryrun):
                    return True
                def describe_security_groups(self, GroupIds):
                    if "sg-ok" in GroupIds:
                        return {
                            "SecurityGroups": [
                                {
                                    "Description": "Created by misconfiguration maker for testing",
                                    "GroupName": "misconfiguration_maker",
                                    "IpPermissions": [],
                                    "OwnerId": "123456789012",
                                    "GroupId": "sg-903004f8",
                                    "IpPermissionsEgress": [],
                                    "Tags": [
                                        {"Key": "department", "Value": "security"},
                                        {"Key": "application", "Value": "remediation-framework"},
                                        {
                                            "Key": "Name",
                                            "Value": "misconfiguration_maker",
                                        },
                                        {
                                            "Key": "App",
                                            "Value": "misconfiguration_maker",
                                        },
                                    ],
                                    "VpcId": "vpc-a01106c2",
                                }
                            ]
                        }
                    else:
                        return {
                            "SecurityGroups": [
                                {
                                    "Description": "Created by misconfiguration maker for testing",
                                    "GroupName": "misconfiguration_maker",
                                    "IpPermissions": [
                                        {
                                            "FromPort": 443,
                                            "IpProtocol": "tcp",
                                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                                            "Ipv6Ranges": [],
                                            "PrefixListIds": [],
                                            "ToPort": 443,
                                            "UserIdGroupPairs": [],
                                        }
                                    ],
                                    "OwnerId": "123456789012",
                                    "GroupId": "sg-903004f8",
                                    "IpPermissionsEgress": [],
                                    "Tags": [
                                        {"Key": "department", "Value": "security"},
                                        {"Key": "application", "Value": "remediation-framework"},
                                        {
                                            "Key": "Name",
                                            "Value": "misconfiguration_maker",
                                        },
                                        {
                                            "Key": "App",
                                            "Value": "misconfiguration_maker",
                                        },
                                    ],
                                    "VpcId": "vpc-a01106c2",
                                }
                            ]
                        }


            class Sqs:
                def get_queue_attributes(self, QueueUrl, AttributeNames):
                    if QueueUrl == "https://queue.amazonaws.com/123456789012/ok":
                        # Return private policy
                        return {
                            "Attributes": {
                                "Policy": '{"Version":"2012-10-17","Id":"sqspolicy","Statement":[{"Effect":"Allow","Principal":"arn:aws:iam::123456789012:role/assumed-admin","Action":"sqs:SendMessage","Resource":"arn:aws:sqs:us-east-1:123456789012:ok"}]}'
                            }
                        }
                    elif QueueUrl == "https://queue.amazonaws.com/123456789012/empty":
                        # Return private policy
                        return {"Attributes": {}}
                    elif (
                            QueueUrl
                            == "https://queue.amazonaws.com/123456789012/misconfiguration_maker-bad"
                    ):
                        # Return public policy
                        return {
                            "Attributes": {
                                "Policy": '{"Version":"2012-10-17","Id":"sqspolicy","Statement":[{"Effect":"Allow","Principal":"*","Action":"sqs:SendMessage","Resource":"arn:aws:sqs:us-east-1:000000000000:misconfiguration_maker-bad"}]}'
                            }
                        }
                    else:
                        raise Exception("Unknown QueueUrl: {}".format(QueueUrl))

                def set_queue_attributes(self, QueueUrl, Attributes):
                    return True

                def delete_message(self, QueueUrl, ReceiptHandle):
                    return True

            class Iam:
                def get_user(self, UserName):
                    if UserName == "never_logged_in":
                        return {
                            "User": {
                                "Path": "/",
                                "UserName": "misconfiguration_maker",
                                "UserId": "AIDARVZZW3RWGXPMMHOW4",
                                "Arn": "arn:aws:iam::123456789012:user/misconfiguration_maker",
                                "CreateDate": utc.localize(
                                    datetime.datetime.strptime(
                                        "2010-12-04T03:00:02Z", "%Y-%m-%dT%H:%M:%SZ"
                                    )
                                ),
                            }
                        }
                    elif UserName == "logged_in_long_ago":
                        return {
                            "User": {
                                "Path": "/",
                                "UserName": "misconfiguration_maker",
                                "UserId": "AIDARVZZW3RWGXPMMHOW4",
                                "Arn": "arn:aws:iam::123456789012:user/misconfiguration_maker",
                                "CreateDate": utc.localize(
                                    datetime.datetime.strptime(
                                        "2010-12-04T03:00:02Z", "%Y-%m-%dT%H:%M:%SZ"
                                    )
                                ),
                                "PasswordLastUsed": utc.localize(
                                    datetime.datetime.strptime(
                                        "2010-12-04T03:00:02Z", "%Y-%m-%dT%H:%M:%SZ"
                                    )
                                ),
                            }
                        }
                    else:
                        return {
                            "User": {
                                "Path": "/",
                                "UserName": "good",
                                "UserId": "AIDARVZZW3RWGXPMMHOW4",
                                "Arn": "arn:aws:iam::123456789012:user/good",
                                "CreateDate": utc.localize(
                                    datetime.datetime.strptime(
                                        "2010-12-04T03:00:02Z", "%Y-%m-%dT%H:%M:%SZ"
                                    )
                                ),
                                "PasswordLastUsed": utc.localize(
                                    datetime.datetime.now()
                                ),
                            }
                        }

                def get_login_profile(self, UserName):
                    return {
                        "LoginProfile": {
                            "UserName": "misconfiguration_maker",
                            "CreateDate": utc.localize(
                                datetime.datetime.strptime(
                                    "2010-12-04T03:00:02Z", "%Y-%m-%dT%H:%M:%SZ"
                                )
                            ),
                            "PasswordResetRequired": True,
                        }
                    }

                def list_mfa_devices(self, UserName):
                    if UserName == "no_mfa":
                        return {"MFADevices": []}
                    else:
                        return {
                            "MFADevices": [
                                {
                                    "UserName": "user1@xyz.com",
                                    "SerialNumber": "arn:aws:iam::123456789012:mfa/user1@xyz.com",
                                    "EnableDate": "2015-04-30T17:10:37Z",
                                }
                            ]
                        }

                def delete_login_profile(self, UserName):
                    return

                def get_account_password_policy(self):
                    if account == "bad_password_policy":
                        return {"PasswordPolicy": {}}
                    elif account == "no_password_policy":
                        raise self.exceptions.NoSuchEntityException
                    else:
                        return {
                            "PasswordPolicy": {
                                "MinimumPasswordLength": 32,
                                "RequireNumbers": True,
                                "RequireSymbols": True,
                                "RequireLowercaseCharacters": True,
                                "RequireUppercaseCharacters": True,
                            }
                        }

                def get_account_summary(self):
                    if account == "no_password_policy":
                        return {"SummaryMap": {"AccountMFAEnabled": 0}}
                    else:
                        return {"SummaryMap": {"AccountMFAEnabled": 1}}

                def list_access_keys(self, UserName):
                    if UserName == "has_access_key":
                        return {
                            "AccessKeyMetadata": [
                                {
                                    "UserName": "has_access_key",
                                    "AccessKeyId": "AKIA_good",
                                    "Status": "Active",
                                    "CreateDate": utc.localize(
                                        datetime.datetime.strptime(
                                            "2010-12-04T03:00:02Z", "%Y-%m-%dT%H:%M:%SZ"
                                        )
                                    ),
                                }
                            ]
                        }
                    elif UserName == "old_access_key":
                        return {
                            "AccessKeyMetadata": [
                                {
                                    "UserName": "old_access_key",
                                    "AccessKeyId": "AKIA_old",
                                    "Status": "Active",
                                    "CreateDate": utc.localize(
                                        datetime.datetime.strptime(
                                            "2010-12-04T03:00:02Z", "%Y-%m-%dT%H:%M:%SZ"
                                        )
                                    ),
                                }
                            ]
                        }
                    elif UserName == "access_key_never_used":
                        return {
                            "AccessKeyMetadata": [
                                {
                                    "UserName": "old_access_key",
                                    "AccessKeyId": "AKIA_never_used",
                                    "Status": "Active",
                                    "CreateDate": utc.localize(
                                        datetime.datetime.strptime(
                                            "2010-12-04T03:00:02Z", "%Y-%m-%dT%H:%M:%SZ"
                                        )
                                    ),
                                }
                            ]
                        }
                    return {"AccessKeyMetadata": []}

                def get_access_key_last_used(self, AccessKeyId):
                    if AccessKeyId == "AKIA_good":
                        return {
                            "UserName": ".",
                            "AccessKeyLastUsed": {
                                "LastUsedDate": utc.localize(datetime.datetime.now()),
                                "ServiceName": "cloudformation",
                                "Region": "us-east-1",
                            },
                        }
                    elif AccessKeyId == "AKIA_never_used":
                        return {
                            "UserName": ".",
                            "AccessKeyLastUsed": {
                                "ServiceName": "N/A",
                                "Region": "N/A",
                            },
                        }
                    elif AccessKeyId == "AKIA_old":
                        return {
                            "UserName": ".",
                            "AccessKeyLastUsed": {
                                "LastUsedDate": utc.localize(
                                    datetime.datetime.strptime(
                                        "2010-12-04T03:00:02Z", "%Y-%m-%dT%H:%M:%SZ"
                                    )
                                ),
                                "ServiceName": "cloudformation",
                                "Region": "us-east-1",
                            },
                        }

                def delete_access_key(self, AccessKeyId):
                    return True

                def get_role(self, RoleName):

                    if RoleName == "restricted":
                        return {
                            "Role": {
                                "Path": "/",
                                "RoleName": "restricted",
                                "RoleId": "AROARVZZW3RWCNVIYDBCN",
                                "Arn": "arn:aws:iam::123456789012:role/restricted",
                                "CreateDate": datetime.datetime(2015, 1, 1),
                                "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [
                                    {"Sid": "Restricted", "Effect": "Allow",
                                     "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]},
                                "Description": "Restricted IAM role",
                                "MaxSessionDuration": 3600,
                                "RoleLastUsed": {}
                            }

                        }

                    if RoleName == "overpermissive":
                        return {
                            "Role": {
                                "Path": "/",
                                "RoleName": "overpermissive",
                                "RoleId": "AROARVZZW3RWCNVIYDBCN",
                                "Arn": "arn:aws:iam::123456789012:role/overpermissive",
                                "CreateDate": datetime.datetime(2015, 1, 1),
                                "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [
                                    {"Sid": "overpermissive", "Effect": "Allow",
                                     "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}]},
                                "Description": "Over permissive IAM role",
                                "MaxSessionDuration": 3600,
                                "RoleLastUsed": {}
                            }
                        }

                def update_assume_role_policy(self, RoleName, PolicyDocument):
                    return True

                # Define the exception iam.exceptions.NoSuchEntityException used for checking the password policy
                class exceptions:
                    class NoSuchEntityException(BaseException):
                        pass

            class Rds:
                def describe_db_instances(self, DBInstanceIdentifier):
                    if DBInstanceIdentifier == "ok":
                        return {
                            "DBInstances": [
                                {
                                    "DBInstanceIdentifier": "terraform-20191204183405150900000001",
                                    "DBName": "misconfiguration_maker",
                                    "DBInstanceStatus": "available",
                                    "StorageEncrypted": True,
                                    "PubliclyAccessible": False,
                                    "InstanceCreateTime": utc.localize(
                                        datetime.datetime.strptime(
                                            "2010-12-04T03:00:02Z", "%Y-%m-%dT%H:%M:%SZ"
                                        )
                                    ),
                                    "DBInstanceArn": "arn:aws:rds:us-east-1:123456789012:db:terraform-20191224155042513500000001",
                                }
                            ]
                        }
                    else:
                        return {
                            "DBInstances": [
                                {
                                    "DBInstanceIdentifier": "terraform-20191204183405150900000001",
                                    "DBName": "misconfiguration_maker",
                                    "DBInstanceStatus": "available",
                                    "StorageEncrypted": False,
                                    "PubliclyAccessible": True,
                                    "InstanceCreateTime": utc.localize(
                                        datetime.datetime.strptime(
                                            "2010-12-04T03:00:02Z", "%Y-%m-%dT%H:%M:%SZ"
                                        )
                                    ),
                                    "DBInstanceArn": "arn:aws:rds:us-east-1:123456789012:db:bad",
                                }
                            ]
                        }

                def list_tags_for_resource(self, ResourceName):
                    if ResourceName == "arn:aws:rds:us-east-1:123456789012:db:bad":
                        return {"TagList": []}
                    else:
                        return {
                            "TagList": [
                                {"Key": "App", "Value": "misconfiguration_maker"},
                                {"Key": "application", "Value": "remediation-framework"},
                                {"Key": "department", "Value": "security"},
                                {"Key": "Name", "Value": "misconfiguration_maker"},
                            ]
                        }

                def stop_db_instance(self, DBInstanceIdentifier):
                    return True

                def modify_db_instance(
                        self, DBInstanceIdentifier, PubliclyAccessible, ApplyImmediately
                ):
                    return True

                def describe_db_snapshot_attributes(self, DBSnapshotIdentifier):
                    return {
                        "DBSnapshotAttributesResult": {
                            "DBSnapshotIdentifier": "misconfiguration-maker",
                            "DBSnapshotAttributes": [
                                {
                                    "AttributeName": "restore",
                                    "AttributeValues": ["000000000000"],
                                }
                            ],
                        }
                    }

                def modify_db_snapshot_attribute(
                        self, DBSnapshotIdentifier, AttributeName, ValuesToRemove
                ):
                    return True

            class S3:
                def get_bucket_policy_status(self, Bucket):
                    if Bucket == "good":
                        return {"PolicyStatus": {"IsPublic": False}}
                    else:
                        return {"PolicyStatus": {"IsPublic": True}}

                def get_bucket_acl(self, Bucket):
                    return {
                        "Owner": {
                            "DisplayName": "CustomersName@amazon.com",
                            "ID": "75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a",
                        },
                        "Grants": [
                            {
                                "Grantee": {
                                    "DisplayName": "CustomersName@amazon.com",
                                    "ID": "75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a",
                                    "Type": "CanonicalUser",
                                },
                                "Permission": "FULL_CONTROL",
                            }
                        ],
                    }

                def put_bucket_policy(self, Bucket, Policy):
                    return True

                def get_bucket_tagging(self, Bucket):
                    if Bucket == "good":
                        return {
                            "TagSet": [
                                {"Key": "App", "Value": "misconfiguration_maker"},
                                {"Key": "application", "Value": "remediation-framework"},
                                {"Key": "department", "Value": "security"},
                                {"Key": "Name", "Value": "misconfiguration_maker"},
                            ]
                        }
                    else:
                        return {"TagSet": []}

                def get_bucket_policy(self, Bucket):
                    return {
                        "Policy": '{"Version":"2012-10-17","Statement":[{"Sid":"DenyUnsecureConnections","Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"arn:aws:s3:::slwqi00wh16sfmof-misconfig-maker/*","Condition":{"Bool":{"aws:SecureTransport":"false"}}},{"Sid":"DenyUnencryptedObjectUploads","Effect":"Deny","Principal":"*","Action":"s3:PutObject","Resource":"arn:aws:s3:::slwqi00wh16sfmof-misconfig-maker/*","Condition":{"StringNotEquals":{"s3:x-amz-server-side-encryption":["AES256","aws:kms"]}}}]}'
                    }

            class Redshift:
                def describe_clusters(self, ClusterIdentifier):
                    return {
                        "Clusters": [
                            {
                                "ClusterIdentifier": "misconfig-maker",
                                "NodeType": "dc1.large",
                                "ClusterStatus": "available",
                                "ClusterCreateTime": utc.localize(
                                    datetime.datetime.strptime(
                                        "2010-12-04T03:00:02Z", "%Y-%m-%dT%H:%M:%SZ"
                                    )
                                ),
                                "PubliclyAccessible": True,
                                "Encrypted": False,
                                "Tags": [
                                    {"Key": "App", "Value": "misconfiguration_maker"}
                                ],
                                "ClusterParameterGroups": [
                                    {
                                        "ParameterGroupName": "default.redshift-1.0",
                                        "ParameterApplyStatus": "in-sync",
                                    }
                                ],
                            }
                        ]
                    }

                def modify_cluster(
                        self, ClusterIdentifier, PubliclyAccessible=None, Encrypted=None
                ):
                    return True

                def describe_cluster_parameters(self, ParameterGroupName):
                    return {
                        "Parameters": [
                            {
                                "ParameterName": "auto_analyze",
                                "ParameterValue": "true",
                                "Description": "Use auto analyze",
                                "Source": "engine-default",
                                "DataType": "boolean",
                                "AllowedValues": "true,false",
                                "ApplyType": "static",
                                "IsModifiable": True,
                            },
                            {
                                "ParameterName": "datestyle",
                                "ParameterValue": "ISO, MDY",
                                "Description": "Sets the display format for date and time values.",
                                "Source": "engine-default",
                                "DataType": "string",
                                "ApplyType": "static",
                                "IsModifiable": True,
                            },
                            {
                                "ParameterName": "require_ssl",
                                "ParameterValue": "false",
                                "Description": "require ssl for all databaseconnections",
                                "Source": "engine-default",
                                "DataType": "boolean",
                                "AllowedValues": "true,false",
                                "ApplyType": "static",
                                "IsModifiable": True,
                            },
                        ]
                    }

            class Elb:
                def describe_load_balancers(self, LoadBalancerNames):
                    return {
                        "LoadBalancerDescriptions": [
                            {
                                "LoadBalancerName": "misconfiguration-maker",
                                "DNSName": "misconfiguration-maker-391066998.us-east-1.elb.amazonaws.com",
                                "CanonicalHostedZoneName": "misconfiguration-maker-391066998.us-east-1.elb.amazonaws.com",
                                "CanonicalHostedZoneNameID": "Z35SXDOTRQ7X7K",
                                "ListenerDescriptions": [
                                    {
                                        "Listener": {
                                            "Protocol": "HTTP",
                                            "LoadBalancerPort": 8000,
                                            "InstanceProtocol": "HTTP",
                                            "InstancePort": 8000,
                                        },
                                        "PolicyNames": [],
                                    }
                                ],
                                "Policies": {
                                    "AppCookieStickinessPolicies": [],
                                    "LBCookieStickinessPolicies": [],
                                    "OtherPolicies": [],
                                },
                                "BackendServerDescriptions": [],
                                "AvailabilityZones": ["us-east-1a", "us-east-1b"],
                                "Subnets": ["subnet-5bac2c70", "subnet-8c820ae9"],
                                "VPCId": "vpc-a01106c2",
                                "Instances": [{"InstanceId": "i-ok"}],
                                "HealthCheck": {
                                    "Target": "HTTP:8000/",
                                    "Interval": 30,
                                    "Timeout": 3,
                                    "UnhealthyThreshold": 2,
                                    "HealthyThreshold": 2,
                                },
                                "SourceSecurityGroup": {
                                    "OwnerAlias": "123456789012",
                                    "GroupName": "default_elb_52d611ed-5eb9-3bd9-af0d-11b512735546",
                                },
                                "SecurityGroups": ["sg-04a33d6495f4c157a"],
                                "CreatedTime": "2019-12-26T19:45:06.390Z",
                                "Scheme": "internet-facing",
                            }
                        ]
                    }

                def describe_tags(self, LoadBalancerNames):
                    if LoadBalancerNames[0] == "good":
                        return {
                            "TagDescriptions": [
                                {
                                    "LoadBalancerName": "misconfiguration-maker",
                                    "Tags": [
                                        {
                                            "Key": "App",
                                            "Value": "misconfiguration_maker",
                                        },
                                        {"Key": "application", "Value": "example"},
                                        {"Key": "department", "Value": "example"},
                                        {
                                            "Key": "Name",
                                            "Value": "misconfiguration_maker",
                                        },
                                    ],
                                }
                            ]
                        }
                    else:
                        return {
                            "TagDescriptions": [
                                {
                                    "LoadBalancerName": "misconfiguration-maker",
                                    "Tags": [
                                        {
                                            "Key": "App",
                                            "Value": "misconfiguration_maker",
                                        },
                                        {"Key": "application", "Value": "example"},
                                        {"Key": "department", "Value": "example-bad"},
                                        {
                                            "Key": "Name",
                                            "Value": "misconfiguration_maker",
                                        },
                                    ],
                                }
                            ]
                        }

            class Elbv2:
                def describe_load_balancers(self, LoadBalancerNames):
                    return {'LoadBalancers': [{'LoadBalancerArn': 'arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/dummy-lb/abcdefg012345678', 'DNSName': 'dummy-lb-704041262.us-east-1.elb.amazonaws.com', 'CanonicalHostedZoneId': 'Z35SXDOTRQ7X7K', 'CreatedTime': datetime.datetime(2020, 3, 19, 16, 17, 37, 550000, tzinfo=tzutc()), 'LoadBalancerName': 'dummy-lb', 'Scheme': 'internet-facing', 'VpcId': 'vpc-3aba925f', 'State': {'Code': 'active'}, 'Type': 'application', 'AvailabilityZones': [{'ZoneName': 'us-east-1b', 'SubnetId': 'subnet-5bac2c70', 'LoadBalancerAddresses': []}, {'ZoneName': 'us-east-1d', 'SubnetId': 'subnet-1234567', 'LoadBalancerAddresses': []}, {'ZoneName': 'us-east-1a', 'SubnetId': 'subnet-1234567', 'LoadBalancerAddresses': []}], 'SecurityGroups': ['sg-abc123'], 'IpAddressType': 'ipv4'}], 'ResponseMetadata': {'RequestId': '3daa02db-e964-49c5-9bf1-3ac34a22a6c8', 'HTTPStatusCode': 200, 'HTTPHeaders': {'x-amzn-requestid': '3daa02db-e964-49c5-9bf1-3ac34a22a6c8', 'content-type': 'text/xml', 'content-length': '1717', 'date': 'Wed, 05 Aug 2020 15:20:25 GMT'}, 'RetryAttempts': 0}}

                def describe_target_groups(self, LoadBalancerNames):
                    return {'TargetGroups': [{'TargetGroupArn': 'arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/abc/7f895d339258b7ce', 'TargetGroupName': 'abc', 'Protocol': 'HTTP', 'Port': 80, 'VpcId': 'vpc-abc123', 'HealthCheckProtocol': 'HTTP', 'HealthCheckPort': 'traffic-port', 'HealthCheckEnabled': True, 'HealthCheckIntervalSeconds': 30, 'HealthCheckTimeoutSeconds': 5, 'HealthyThresholdCount': 5, 'UnhealthyThresholdCount': 2, 'HealthCheckPath': '/', 'Matcher': {'HttpCode': '200'}, 'LoadBalancerArns': ['arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/dummy-alb/81315df077712965'], 'TargetType': 'instance'}, {'TargetGroupArn': 'arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/dummy/1234abcdef', 'TargetGroupName': 'dummy', 'Protocol': 'HTTP', 'Port': 80, 'VpcId': 'vpc-abc123', 'HealthCheckProtocol': 'HTTP', 'HealthCheckPort': 'traffic-port', 'HealthCheckEnabled': True, 'HealthCheckIntervalSeconds': 30, 'HealthCheckTimeoutSeconds': 5, 'HealthyThresholdCount': 5, 'UnhealthyThresholdCount': 2, 'HealthCheckPath': '/', 'Matcher': {'HttpCode': '200'}, 'LoadBalancerArns': ['arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/dummy-alb/81315df077712965'], 'TargetType': 'instance'}, {'TargetGroupArn': 'arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/dummy-alb/6a5570e2c3c31fa2', 'TargetGroupName': 'dummy-alb', 'Protocol': 'HTTP', 'Port': 80, 'VpcId': 'vpc-abc123', 'HealthCheckProtocol': 'HTTP', 'HealthCheckPort': 'traffic-port', 'HealthCheckEnabled': True, 'HealthCheckIntervalSeconds': 30, 'HealthCheckTimeoutSeconds': 5, 'HealthyThresholdCount': 5, 'UnhealthyThresholdCount': 2, 'HealthCheckPath': '/', 'Matcher': {'HttpCode': '200'}, 'LoadBalancerArns': ['arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/dummy-alb/81315df077712965'], 'TargetType': 'instance'}], 'ResponseMetadata': {'RequestId': '332e451e-d501-4bda-8270-f55e481f3269', 'HTTPStatusCode': 200, 'HTTPHeaders': {'x-amzn-requestid': '332e451e-d501-4bda-8270-f55e481f3269', 'content-type': 'text/xml', 'content-length': '3563', 'vary': 'accept-encoding', 'date': 'Wed, 05 Aug 2020 15:36:41 GMT'}, 'RetryAttempts': 0}}


            class Guardduty:
                self.account = '123456789012'
                def list_detectors(self):
                    if region == "us-east-1":
                        return {"DetectorIds": ["12abc34d567e8fa901bc2d34eexample"]}
                    else:
                        return {"DetectorIds": []}

                def get_master_account(self, DetectorId):
                    return {
                        "Master": {
                            "AccountId": "123456789012",
                            "InvitationId": "04b94d9704854a73f94e061e8example",
                            "RelationshipStatus": "Enabled",
                            "InvitedAt": "2019-09-27T19:09:33.045Z",
                        }
                    }

            class Config:
                def describe_delivery_channels(self):
                    if region == "us-east-1":
                        return {
                            "DeliveryChannels": [
                                {
                                    "name": "default",
                                    "s3BucketName": "123456789012-awsconfig",
                                    "snsTopicARN": "arn:aws:sns:us-east-1:123456789012:awsconfig-topic",
                                }
                            ]
                        }
                    else:
                        return {"DeliveryChannels": []}

            class Cloudtrail:
                def describe_trails(self):
                    if region == "us-east-1":
                        return {
                            "trailList": [
                                {
                                    "Name": "123456789012-us-east-1",
                                    "S3BucketName": "123456789012-cloudtrail",
                                    "SnsTopicName": "123456789012-us-east-1",
                                    "SnsTopicARN": "arn:aws:sns:us-east-1:123456789012:123456789012-us-east-1",
                                    "IncludeGlobalServiceEvents": True,
                                    "IsMultiRegionTrail": False,
                                    "HomeRegion": "us-east-1",
                                    "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/123456789012-us-east-1",
                                    "LogFileValidationEnabled": False,
                                    "CloudWatchLogsLogGroupArn": "arn:aws:logs:us-east-1:123456789012:log-group:CloudTrail/ingestion-test-stream:*",
                                    "CloudWatchLogsRoleArn": "arn:aws:iam::123456789012:role/CloudTrail_CloudWatchLogs_Role",
                                    "HasCustomEventSelectors": False,
                                    "HasInsightSelectors": False,
                                    "IsOrganizationTrail": False,
                                }
                            ]
                        }
                    else:
                        return {"trailList": []}

            class Lambda:
                def get_policy(self, FunctionName):
                    if FunctionName == "bad":
                        policy = {
                            "Version": "2012-10-17",
                            "Id": "default",
                            "Statement": [
                                {
                                    "Sid": "lambda-eb02b5c6-0855-4a1e-be62-b6093776a838",
                                    "Effect": "Allow",
                                    "Principal": {
                                        "Service": "apigateway.amazonaws.com"
                                    },
                                    "Action": "lambda:InvokeFunction",
                                    "Resource": "arn:aws:lambda:us-east-1:123456789012:function:misconfig-maker-lambda",
                                    "Condition": {
                                        "ArnLike": {
                                            "AWS:SourceArn": "arn:aws:execute-api:us-east-1:123456789012:abcxpaoxyz/*/*/misconfig-maker-lambda"
                                        }
                                    }
                                },
                                {
                                    "Sid": "si34",
                                    "Effect": "Allow",
                                    "Principal": "*",
                                    "Action": "lambda:InvokeFunction",
                                    "Resource": "arn:aws:lambda:us-east-1:123456789012:function:misconfig-maker-lambda"
                                }
                            ]
                        }
                        return {"Policy": json.dumps(policy)}

                    else:
                        policy = {
                            "Version": "2012-10-17",
                            "Id": "default",
                            "Statement": [
                                {
                                    "Sid": "lambda-eb02b5c6-0855-4a1e-be62-b6093776a838",
                                    "Effect": "Allow",
                                    "Principal": {
                                        "Service": "apigateway.amazonaws.com"
                                    },
                                    "Action": "lambda:InvokeFunction",
                                    "Resource": "arn:aws:lambda:us-east-1:123456789012:function:misconfig-maker-lambda",
                                    "Condition": {
                                        "ArnLike": {
                                            "AWS:SourceArn": "arn:aws:execute-api:us-east-1:123456789012:abcxpaoxyz/*/*/misconfig-maker-lambda"
                                        }
                                    }
                                }
                            ]
                        }
                        return {"Policy": json.dumps(policy)}

                def remove_permission(self, FunctionName, StatementId):
                    return True

            if service == "ec2":
                return Ec2()
            elif service == "sqs":
                return Sqs()
            elif service == "iam":
                return Iam()
            elif service == "rds":
                return Rds()
            elif service == "s3":
                return S3()
            elif service == "redshift":
                return Redshift()
            elif service == "elb":
                return Elb()
            elif service == 'elbv2':
                return Elbv2()
            elif service == "guardduty":
                return Guardduty()
            elif service == "config":
                return Config()
            elif service == "cloudtrail":
                return Cloudtrail()
            elif service == "lambda":
                return Lambda()
            else:
                raise Exception("Unknown service: {}".format(service))

        def mocked_send_notification_side_effect(issue, description, resource):
            print(issue)
            return True

        # Set our sys.path so modules load from the correct place
        sys.path.append(os.path.join(*[os.getcwd(), "resources", "remediator"]))

        # Clear cached module so we can mock stuff
        if "resources.remediator.shared" in sys.modules:
            del sys.modules["resources.remediator.shared"]

        self.mocked_get_session_for_account = mock.patch(
            "shared.get_session_for_account"
        ).__enter__()
        self.mocked_get_session_for_account.side_effect = (
            mocked_get_session_for_account_side_effect
        )

        self.mocked_send_notification = mock.patch("shared.send_notification").__enter__()
        self.mocked_send_notification.side_effect = mocked_send_notification_side_effect

        self.mocked_boto3_client = mock.patch("boto3.client").__enter__()

        self.os_environ = mock.patch("os.environ").__enter__()

    def tearDown(self):
        self.mocked_get_session_for_account.__exit__()
        self.mocked_send_notification.__exit__()
        self.mocked_boto3_client.__exit__()
        self.os_environ.__exit__()

    def test_ami(self):
        # Import the module to test
        from resources.remediator.auditors import ami

        resource_message = {
            "account": "123456789012",
            "region": "us-east-1",
            "type": "ami",
            "id": "ami-ok",
        }
        assert_true(ami.audit(resource_message, remediate=True))

        resource_message["id"] = "ami-shared"
        assert_false(ami.audit(resource_message, remediate=True))
        resource_message["id"] = "ami-public"
        assert_false(ami.audit(resource_message, remediate=True))

    def test_sqs(self):
        # Import the module to test
        from resources.remediator.auditors import sqs

        resource_message = {
            "account": "123456789012",
            "region": "us-east-1",
            "type": "sqs",
            "id": "https://queue.amazonaws.com/123456789012/misconfiguration_maker-bad",
        }
        assert_false(sqs.audit(resource_message, remediate=True))

        resource_message["id"] = "https://queue.amazonaws.com/123456789012/ok"
        assert_true(sqs.audit(resource_message))

        resource_message["id"] = "https://queue.amazonaws.com/123456789012/empty"
        assert_true(sqs.audit(resource_message))

    def test_ebs_snapshot(self):
        # Import the module to test
        from resources.remediator.auditors import ebs_snapshot

        resource_message = {
            "account": "123456789012",
            "region": "us-east-1",
            "type": "ebs_snapshot",
            "id": "snap-ok",
        }
        assert_true(ebs_snapshot.audit(resource_message, remediate=True))

        resource_message["id"] = "snap-shared"
        assert_false(ebs_snapshot.audit(resource_message, remediate=True))

        resource_message["id"] = "snap-public"
        assert_false(ebs_snapshot.audit(resource_message, remediate=True))

    def test_iam_user(self):
        # Import the module to test
        from resources.remediator.auditors import iam_user

        resource_message = {
            "account": "123456789012",
            "region": "us-east-1",
            "type": "iam_user",
            "id": "good",
        }
        assert_true(iam_user.audit(resource_message, remediate=True))

        resource_message["id"] = "never_logged_in"
        assert_false(iam_user.audit(resource_message, remediate=True))

        resource_message["id"] = "logged_in_long_ago"
        assert_false(iam_user.audit(resource_message, remediate=True))

        resource_message["id"] = "no_mfa"
        assert_false(iam_user.audit(resource_message, remediate=True))

        # User with access key that was used recently
        resource_message["id"] = "has_access_key"
        assert_true(iam_user.audit(resource_message, remediate=True))

        # Old access key that should be removed
        resource_message["id"] = "old_access_key"
        assert_false(iam_user.audit(resource_message, remediate=True))

        # Access key that has never been used, but is older than 100 days
        resource_message["id"] = "access_key_never_used"
        assert_false(iam_user.audit(resource_message, remediate=True))

    def test_iam_role(self):
        from resources.remediator.auditors import iam_role

        resource_message = {
            "account": "123456789012",
            "region": "us-east-1",
            "type": "iam_role",
            "id": "restricted",
        }

        assert_true(iam_role.audit(resource_message, remediate=True))

        resource_message["id"] = "overpermissive"
        assert_false(iam_role.audit(resource_message, remediate=True))

    def test_rds(self):
        # Import the module to test
        from resources.remediator.auditors import rds

        resource_message = {
            "account": "123456789012",
            "region": "us-east-1",
            "type": "rds",
            "id": "ok",
        }
        assert_true(rds.audit(resource_message, remediate=True))

        resource_message["id"] = "bad"
        assert_false(rds.audit(resource_message, remediate=True))

    def test_rds_snapshot(self):
        # Import the module to test
        from resources.remediator.auditors import rds_snapshot

        resource_message = {
            "account": "123456789012",
            "region": "us-east-1",
            "type": "rds_snapshot",
            "id": "misconfiguration-maker",
        }
        assert_false(rds_snapshot.audit(resource_message, remediate=True))

    def test_s3_bucket(self):
        # Import the module to test
        from resources.remediator.auditors import s3_bucket

        resource_message = {
            "account": "123456789012",
            "region": "us-east-1",
            "type": "s3_bucket",
            "id": "good",
        }
        assert_true(s3_bucket.audit(resource_message, remediate=True))

        resource_message["id"] = "misconfiguration-maker"
        assert_false(s3_bucket.audit(resource_message, remediate=True))

    def test_s3_policy_checkers(self):
        from resources.remediator.auditors import s3_bucket

        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "DenyUnsecureConnections",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:*",
                    "Resource": "arn:aws:s3:::slwqi00wh16sfmof-misconfig-maker/*",
                    "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                },
                {
                    "Sid": "DenyUnencryptedObjectUploads",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:PutObject",
                    "Resource": "arn:aws:s3:::slwqi00wh16sfmof-misconfig-maker/*",
                    "Condition": {
                        "StringNotEquals": {
                            "s3:x-amz-server-side-encryption": ["AES256", "aws:kms"]
                        }
                    },
                },
            ],
        }

        assert_false(s3_bucket.grants_allow(policy))
        assert_true(s3_bucket.denies_unencrypted_uploads(policy))
        assert_true(s3_bucket.denies_lack_of_tls(policy))

        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:*",
                    "Resource": "arn:aws:s3:::slwqi00wh16sfmof-misconfig-maker/*",
                    "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                }
            ],
        }

        assert_true(s3_bucket.grants_allow(policy))
        assert_false(s3_bucket.denies_unencrypted_uploads(policy))
        assert_false(s3_bucket.denies_lack_of_tls(policy))

        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:*",
                    "Resource": "arn:aws:s3:::slwqi00wh16sfmof-misconfig-maker/*",
                    "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                }
            ],
        }

        assert_false(s3_bucket.grants_allow(policy))
        assert_false(s3_bucket.denies_unencrypted_uploads(policy))
        assert_true(s3_bucket.denies_lack_of_tls(policy))

        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::slwqi00wh16sfmof-misconfig-maker/*",
                    "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                }
            ],
        }

        assert_false(s3_bucket.grants_allow(policy))
        assert_false(s3_bucket.denies_unencrypted_uploads(policy))
        assert_false(s3_bucket.denies_lack_of_tls(policy))

    def test_redshift(self):
        # Import the module to test
        from resources.remediator.auditors import redshift

        resource_message = {
            "account": "123456789012",
            "region": "us-east-1",
            "type": "redshift",
            "id": "misconfig-maker",
        }
        assert_false(redshift.audit(resource_message, remediate=True))

    def test_ec2(self):
        # Import the module to test
        from resources.remediator.auditors import ec2

        resource_message = {
            "account": "123456789012",
            "region": "us-east-1",
            "type": "ec2",
            "id": "i-ok",
        }
        assert_true(ec2.audit(resource_message, remediate=True))

        resource_message["id"] = "i-bad"
        assert_false(ec2.audit(resource_message, remediate=True))

    def test_region(self):
        # Import the module to test
        from resources.remediator.auditors import region

        resource_message = {
            "account": "123456789012",
            "region": "us-east-1",
            "type": "region",
            "id": "",
        }
        assert_true(region.audit(resource_message, remediate=True))

        resource_message["region"] = "bad"
        assert_false(region.audit(resource_message, remediate=True))

        resource_message["region"] = "us-east-1"
        resource_message["account"] = "bad_password_policy"
        assert_false(region.audit(resource_message, remediate=True))

        resource_message["account"] = "no_password_policy"
        assert_false(region.audit(resource_message, remediate=True))

    def test_security_group(self):
        # Import the module to test
        from resources.remediator.auditors import security_group

        resource_message = {
            "account": "123456789012",
            "region": "us-east-1",
            "type": "security_group",
            "id": "sg-ok",
        }
        assert_true(security_group.audit(resource_message, remediate=True))

        resource_message["id"] = "sg-bad"
        assert_false(security_group.audit(resource_message, remediate=True))

    def test_elb(self):
        # Import the module to test
        from resources.remediator.auditors import elb

        resource_message = {
            "account": "123456789012",
            "region": "us-east-1",
            "type": "elb",
            "id": "good",
        }
        assert_true(elb.audit(resource_message, remediate=True))

        resource_message["id"] = "bad"
        assert_false(elb.audit(resource_message, remediate=True))

    def test_elbv2(self):
        # Import the module to test
        from resources.remediator.auditors import elbv2

        resource_message = {
            "account": "123456789012",
            "region": "us-east-1",
            "type": "elbv2",
            "id": "good",
        }
        assert_true(elbv2.audit(resource_message, remediate=True))

        resource_message["id"] = "bad"
        assert_false(elbv2.audit(resource_message, remediate=True))


    def test_handler(self):
        from resources.remediator.main import handler

        event = {
            "Records": [
                {
                    "messageId": "0",
                    "body": '{"account": "123456789012", "region": "us-east-1", "type": "ec2", "id": "i-ok"}',
                    "attributes": {
                        "ApproximateReceiveCount": "1",
                        "SentTimestamp": "0",
                        "SenderId": "",
                        "ApproximateFirstReceiveTimestamp": "0",
                    },
                    "receiptHandle": "ABC",
                    "messageAttributes": {},
                    "md5OfBody": "",
                    "eventSource": "aws:sqs",
                    "eventSourceARN": "arn:aws:sqs:us-east-1:000000000000:remediator-resource-queue",
                    "awsRegion": "us-east-1",
                }
            ]
        }

        assert_true(handler(event, None, remediate=False))

    def test_lambda_function(self):
        # Import the module to test
        from resources.remediator.auditors import lambda_function

        resource_message = {
            "account": "123456789012",
            "region": "us-east-1",
            "type": "lambda_function",
            "id": "good",
        }
        assert_true(lambda_function.audit(resource_message, remediate=True))

        resource_message["id"] = "bad"
        assert_false(lambda_function.audit(resource_message, remediate=True))
        return True
