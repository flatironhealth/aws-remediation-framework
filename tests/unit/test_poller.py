import sys
import os
from importlib import reload

from nose.tools import assert_equal, assert_true, assert_false
from unittest import TestCase, mock
from unittest.mock import MagicMock

from resources.poller.main import main


class TestPoller(TestCase):
    def setUp(self):
        def mocked_get_session_for_account_side_effect(account, region, service):
            class Sqs:
                def list_queues(self, *arg, **kwargs):
                    return {"QueueUrls": []}

                def can_paginate(self, method):
                    return False

            class Ec2:
                def describe_snapshots(self, *arg, **kwargs):
                    return {"Snapshots": []}

                def describe_images(self, *arg, **kwargs):
                    return {"Images": []}

                def describe_instances(self, *arg, **kwargs):
                    return {"Reservations": []}

                def describe_security_groups(self, *arg, **kwargs):
                    return {"SecurityGroups": []}

                def can_paginate(self, method):
                    return False

            class Iam:
                def list_users(self, *arg, **kwargs):
                    return {"Users": []}

                def list_roles(self, *arg, **kwargs):
                    return {"Roles": []}

                def can_paginate(self, method):
                    return False

            class Rds:
                def describe_db_instances(self, *arg, **kwargs):
                    return {"DBInstances": []}

                def describe_db_snapshots(self, *arg, **kwargs):
                    return {"DBSnapshots": []}

                def can_paginate(self, method):
                    return False

            class S3:
                def list_buckets(self, *arg, **kwargs):
                    return {"Buckets": []}

                def can_paginate(self, method):
                    return False

            class Redshift:
                def describe_clusters(self, *arg, **kwargs):
                    return {"Clusters": []}

                def can_paginate(self, method):
                    return False

            class Elb:
                def describe_load_balancers(self, *arg, **kwargs):
                    return {"LoadBalancerDescriptions": []}

                def can_paginate(self, method):
                    return False

            class Lambda:
                def list_functions(self, *arg, **kwargs):
                    return {"Functions": []}

                def can_paginate(self, method):
                    return False

            class Ecs:
                def describe_services(self, *arg, **kwargs):
                    return {"Services": []}

                def describe_tasks(self, *arg, **kwargs):
                    return {"Task": []}

                def list_tasks(self, *arg, **kwargs):
                    return {"TasksArns": []}

                def list_clusters(self, *arg, **kwargs):
                    return {"ClusterArns": []}

                def describe_task_sets(self, *arg, **kwargs):
                    return {"TaskSets": []}

                def can_paginate(self, method):
                    return False

            class Kms:
                def list_keys(self, **kwargs):
                    return {"Keys": []}
                def get_key_policy(self, **kwargs):
                    return {"KeyPolicy": []}

                def list_key_policies(self, **kwargs):
                    return {"KeyPolicies": []}

                def describe_key(self, **kwargs):
                    return {"Key": []}

                def can_paginate(self, method):
                    return False

            if service == "sqs":
                return Sqs()
            elif service == "ec2":
                return Ec2()
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
            elif service == "lambda":
                return Lambda()
            elif service == "ecs":
                return Ecs()
            elif service == "kms":
                return Kms()
            else:
                raise Exception("Unknown service: {}".format(service))

        self.mocked_get_session_for_account = mock.patch(
            "resources.poller.main.get_session_for_account"
        ).__enter__()
        self.mocked_get_session_for_account.side_effect = (
            mocked_get_session_for_account_side_effect
        )

        def mocked_argparser_side_effect():
            class MockedArgParse:
                def add_argument(self, *arg, **kwargs):
                    return

                def parse_args(self):
                    class Args:
                        sqs = None
                        regions = "us-east-1"
                        accounts = "000000000000"
                        only_use_test_resources = False
                        stdout = True

                    return Args()

            return MockedArgParse()

        self.mocked_argparser = mock.patch("argparse.ArgumentParser").__enter__()
        self.mocked_argparser.side_effect = mocked_argparser_side_effect

        def mocked_os_environ_side_effect(value, default):
            return default

        self.mocked_os_environ = mock.patch("os.environ.get").__enter__()
        self.mocked_os_environ.side_effect = mocked_os_environ_side_effect

        self.mocked_boto3_client = mock.patch("boto3.client").__enter__()

    def tearDown(self):

        self.mocked_get_session_for_account.__exit__()
        self.mocked_os_environ.__exit__()
        self.mocked_argparser.__exit__()
        self.mocked_boto3_client.__exit__()

    def test_main(self):

        assert_equal(main(), None)
