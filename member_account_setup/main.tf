# This sets up the member account

variable "master" {
  type        = string
  description = <<EOT
    Master account id. This is expected to be set to the account where remediator is deployed
  EOT
}

provider "aws" {
  profile = "default"
  region  = "us-east-1"
}

# Member remediator, used for polling and for the remediator
resource "aws_iam_role" "member_remediator" {
  name = "member_remediator"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
	    "AWS": ["arn:aws:iam::${var.master}:role/remediator", "arn:aws:iam::${var.master}:role/poller"]
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF

  tags = {
    App    = "remediator"
    team   = "security"
    system = "aws-remediation"
  }
}


data "aws_iam_policy_document" "member_remediator_policy_document" {
  statement {
    actions = [
      # Actions required for the poller
      "ec2:DescribeRegions",
      "sqs:ListQueues",
      "ec2:DescribeSnapshots",
      "ec2:DescribeImages",
      "iam:ListUsers",
      "rds:DescribeDbInstances",
      "rds:DescribeDbSnapshots",
      "s3:ListAllMyBuckets",
      "redshift:DescribeClusters",
      "ec2:DescribeInstances",
      "ec2:DescribeSecurityGroups",
      "elb:DescribeLoadBalancers",

      # SQS
      "sqs:GetQueueAttributes",
      "sqs:SetQueueAttributes",

      # EBS Snapshot
      "ec2:DescribeSnapshotAttribute",
      "ec2:ModifySnapshotAttribute",

      # AMI
      "ec2:DescribeImageAttribute",
      "ec2:ModifyImageAttribute",

      # IAM user MFA
      "iam:GetUser",
      "iam:GetLoginProfile",
      "iam:ListMfaDevices",
      "iam:DeleteLoginProfile",
      "iam:ListAccessKeys",
      "iam:GetAccessKeyLastUsed",
      "iam:DeleteAccessKey",

      # IAM roles
      "iam:ListRoles",
      "iam:GetRole",
      "iam:UpdateAssumeRolePolicy",

      # RDS no encryption or public
      "rds:DescribeDbInstances",
      "rds:StopDbCluster",
      "rds:StopDbInstance",
      "rds:ModifyDbInstance",
      # RDS has required tags
      "rds:ListTagsForResource",

      # RDS Snapshot
      "rds:DescribeDbSnapshotAttributes",
      "rds:ModifyDbSnapshotAttribute",

      # S3 Bucket
      "s3:GetBucketPolicyStatus",
      "s3:GetBucketAcl",
      "s3:PutBucketPolicy",
      "s3:PutBucketAcl",
      "s3:GetBucketTagging",
      "s3:GetBucketPolicy",

      # Redshift
      "redshift:DescribeClusters",
      "redshift:ModifyCluster",
      "redshift:DescribeClusterParameters",

      # Region checks
      "guardduty:ListDetectors",
      "guardduty:GetMasterAccount",
      "config:DescribeDeliveryChannels",
      "cloudtrail:DescribeTrails",
      "ec2:DescribeVpcs",
      "ec2:DescribeFlowLogs",
      "iam:GetAccountPasswordPolicy",
      "iam:GetAccountSummary",

      # EC2
      "ec2:DescribeInstances",
      "ec2:ModifyInstanceMetadataOptions",
      "ec2:DescribeAddresses",
      "ec2:DisassociateAddress",
      "ec2:DescribeNetworkInterfaces",
      "ec2:TerminateInstances",

      # Security Group
      "ec2:DescribeSecurityGroups",

      # ELB
      "elasticloadbalancing:DescribeLoadBalancers",
      "elasticloadbalancing:DescribeTags",
      "elasticloadbalancing:DeregisterInstancesFromLoadBalancer",
      "elasticloadbalancing:DescribeTargetGroups",
      "elasticloadbalancing:DeregisterTargets",

      # Lambda
      "lambda:ListFunctions",
      "lambda:GetPolicy",
      "lambda:RemovePermission",

      # organizations
      "organizations:ListAccounts",

      # ECS
      "ecs:ListClusters",
      "ecs:ListServices",
      "ecs:ListTasks",
      "ecs:DescribeServices",
      "ecs:DescribeClusters",
      "ecs:DescribeTasks",
      "ecs:DescribeTaskSet",
      "ecs:UpdateTaskSet",
      "ecs:DeleteTaskSet",
      "ecs:UpdateService",
      "ecs:CreateService",
      "ecs:CreateCluster",
      "ecs:PutAttributes",
      "ecs:StopTask"

    ]
    resources = [
      "*",
    ]
  }
}

# Create the policy for the role
resource "aws_iam_policy" "member_remediator" {
  name   = "member_remediator"
  path   = "/"
  policy = data.aws_iam_policy_document.member_remediator_policy_document.json
}

# Attach the policy to the role
resource "aws_iam_role_policy_attachment" "member_remediator" {
  role       = aws_iam_role.member_remediator.name
  policy_arn = aws_iam_policy.member_remediator.arn
}

#role for allowing event forward to bus
resource "aws_iam_role" "event_forward" {
  name = "event_forward"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "events.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF

  tags = {
    App    = "remediator"
    team   = "security"
    system = "aws-remediation"
  }
}

resource "aws_iam_role_policy" "event_bus_policy" {
  name = "event_bus_policy"
  role = aws_iam_role.event_forward.id

  policy = <<-EOF
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Action": [
          "events:PutEvents"
        ],
        "Effect": "Allow",
        "Resource": [
          "arn:aws:events:*:${var.master}:event-bus/default"
          ]
      }
    ]
  }
  EOF
}

# Setup the event forwarders in each region
# Terraform doesn't support count or for_each in modules, revisit after terraform 0.13 release
module "event-fowarder-us-east-1" {
  source = "./event_forwarder"
  region = "us-east-1"
  master = var.master
  role_arn = aws_iam_role.event_forward.arn
}

module "event-forwarder-us-east-2" {
  source = "./event_forwarder"
  region = "us-east-2"
  master = var.master
  role_arn = aws_iam_role.event_forward.arn
}

module "event-forwarder-us-west-1" {
  source = "./event_forwarder"
  region = "us-west-1"
  master = var.master
  role_arn = aws_iam_role.event_forward.arn
}

module "event-forwarder-us-west-2" {
  source = "./event_forwarder"
  region = "us-west-2"
  master = var.master
  role_arn = aws_iam_role.event_forward.arn
}
