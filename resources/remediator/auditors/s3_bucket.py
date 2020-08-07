import json
import os
from shared import (
    get_session_for_account,
    send_notification,
    is_missing_tags,
    get_required_tags,
)
from policyuniverse.policy import Policy


def audit(resource, remediate=False):
    is_compliant = True
    if resource["type"] != "s3_bucket":
        raise Exception(
            "Mismatched type. Expected {} but received {}".format(
                "s3_bucket", resource["type"]
            )
        )

    buckets_to_ignore = os.environ.get("S3_BUCKET_IGNORE_LIST", "")
    if resource["id"] in buckets_to_ignore.split(","):
        return True

    # Get a session in the account where this resource is
    s3 = get_session_for_account(resource["account"], resource["region"], "s3")

    policy_is_public = False
    try:
        status = s3.get_bucket_policy_status(Bucket=resource["id"])
        policy_is_public = status["PolicyStatus"]["IsPublic"]
    except Exception as e:
        print(e)
        print("No bucket policy: {}".format(resource["id"]))

    if policy_is_public:
        is_compliant = False

        issue = "S3 bucket {} is public".format(resource["id"])
        if remediate:
            if not remediation_make_policy_private(s3, resource):
                issue += " - Not remediated"
        send_notification(issue, "", resource)

    acl_is_public = False
    acl = s3.get_bucket_acl(Bucket=resource["id"])
    for i in range(len(acl["Grants"])):
        grantee_id = acl["Grants"][i]["Grantee"]
        if "http://acs.amazonaws.com/groups/global/AllUsers" in str(
            grantee_id
        ) or "http://acs.amazonaws.com/groups/global/AuthenticatedUsers" in str(
            grantee_id
        ):
            acl_is_public = True
            break

    if acl_is_public:
        is_compliant = False

        issue = "S3 bucket {} is public".format(resource["id"])
        if remediate:
            if not remediation_make_acl_private(s3, resource):
                issue += " - Not remediated"
        send_notification(issue, "", resource)

    if is_compliant:
        print("bucket is private: {}".format(resource["id"]))

    # Ensure required tags exist
    assigned_tags = []
    try:
        assigned_tags = s3.get_bucket_tagging(Bucket=resource["id"])["TagSet"]
    except Exception as e:
        # If no tags exist, we get an exception that doesn't appear to be defined to catch, so we generically
        # catch the exception and look for the key phrase to indicate this problem, and if we can't find it, we re-raise it
        if "NoSuchTagSet" not in str(e):
            raise e

    if is_missing_tags(assigned_tags):
        is_compliant = False
        issue = "S3 bucket {} not compliant - Missing required tags - Not remediated".format(
            resource["id"]
        )
        send_notification(
            issue, "Required tags: {}".format(", ".join(get_required_tags())), resource
        )

    # Check the bucket policy for some things
    policy = None

    try:
        policy_string = s3.get_bucket_policy(Bucket=resource["id"])["Policy"]
        policy = json.loads(policy_string)
    except Exception as e:
        if "NoSuchBucketPolicy" in str(e):
            print("No bucket policy for {}".format(resource["id"]))
        else:
            print(e)
            raise e

    if not denies_unencrypted_uploads(policy):
        #To-Do add a check for bucket encryption setting
        is_compliant = False

        return False
        issue = "S3 bucket {} not compliant - Does not deny unencrypted uploads".format(
            resource["id"]
        )
        if remediate:
            if not remediation_make_policy_private(s3, resource):
                issue += " - Not remediated"
        send_notification(issue, "", resource)

    if not denies_lack_of_tls(policy):
        is_compliant = False
        #To-Do add a check for bucket encryption setting
        return False
        issue = "S3 bucket {} not compliant - Does not deny non-TLS communications".format(
            resource["id"]
        )
        if remediate:
            if not remediation_make_policy_private(s3, resource):
                issue += " - Not remediated"
        send_notification(issue, "", resource)

    return is_compliant


def grants_allow(policy):
    if policy is None:
        # The bucket does not have a policy
        return False

    statements = []
    statements.extend(policy["Statement"])
    for stmt in statements:
        if stmt["Effect"] == "Allow":
            return True

    return False


def denies_unencrypted_uploads(policy):
    if policy is None:
        return False

    # We want to ensure we have a statement that looks like:
    # {
    #     "Sid": "DenyUnencryptedObjectUploads",
    #     "Effect": "Deny",
    #     "Principal": "*",
    #     "Action": "s3:PutObject",
    #     "Resource": "arn:aws:s3:::my-bucket/*",
    #     "Condition": {
    #         "StringNotEquals": {
    #             "s3:x-amz-server-side-encryption": ["AES256", "aws:kms"]
    #         }
    #     },
    # }

    statements = []
    statements.extend(policy["Statement"])
    for stmt in statements:
        if stmt["Effect"] != "Deny":
            continue
        if stmt.get("Principal", "") != "*":
            continue

        if (
            stmt.get("Action", "") == "*"
            or stmt.get("Action", "") == "s3:*"
            or stmt.get("Action", "") == "s3:PutObject"
        ):
            # The resource should be "arn:aws:s3:::my_bucket/*", "*", or "arn:aws:s3:::my_bucket*"
            # I'm cheating a bit and only checking if it has a "*"
            if "*" in stmt.get("Resource", ""):
                encryption_options = (
                    stmt.get("Condition", {})
                    .get("StringNotEquals", {})
                    .get("s3:x-amz-server-side-encryption", [])
                )
                if "aws:kms" in encryption_options:
                    return True
    return False


def denies_lack_of_tls(policy):
    if policy is None:
        return False

    # We want to ensure we have a statement that looks like:
    # {
    #     "Sid": "DenyUnsecureConnections",
    #     "Effect": "Deny",
    #     "Principal": "*",
    #     "Action": "s3:*",
    #     "Resource": "arn:aws:s3:::my_bucket/*",
    #     "Condition": {"Bool": {"aws:SecureTransport": "false"}},
    # }

    statements = []
    statements.extend(policy["Statement"])
    for stmt in statements:
        if stmt["Effect"] != "Deny":
            continue
        if stmt.get("Principal", "") != "*":
            continue

        if stmt.get("Action", "") == "*" or stmt.get("Action", "") == "s3:*":
            # The resource should be "arn:aws:s3:::my_bucket/*", "*", or "arn:aws:s3:::my_bucket*"
            # I'm cheating a bit and only checking if it has a "*"
            if "*" in stmt.get("Resource", ""):
                if (
                    stmt.get("Condition", {})
                    .get("Bool", {})
                    .get("aws:SecureTransport", "")
                    == "false"
                ):
                    return True
    return False


def remediation_make_policy_private(s3, resource):
    try:
        policy = json.dumps(generate_bucket_policy(resource["id"]))
        s3.put_bucket_policy(Bucket=resource["id"], Policy=policy)
    except Exception as e:
        print(e)
        return False
    return True


def remediation_make_acl_private(s3, resource):
    try:
        s3.put_bucket_acl(Bucket=resource["id"], ACL="private")
    except Exception as e:
        print(e)
        return False
    return True


def generate_bucket_policy(bucket):
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyUnsecureConnections",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": "arn:aws:s3:::" + bucket + "/*",
                "Condition": {"Bool": {"aws:SecureTransport": "false"}},
            },
            {
                "Sid": "DenyUnencryptedObjectUploads",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:PutObject",
                "Resource": "arn:aws:s3:::" + bucket + "/*",
                "Condition": {
                    "StringNotEquals": {
                        "s3:x-amz-server-side-encryption": ["AES256", "aws:kms"]
                    }
                },
            },
        ],
    }

    return policy
