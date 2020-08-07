provider "aws" {
  profile = "default"
  region  = "us-east-1"
}

variable "function_name" {
  default = "misconfiguration_maker"
}

# Over permissive AssumeRole policy that anyone can assume that.
resource "aws_iam_role" "misconfiguration_maker" {
  name = "misconfiguration_maker"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "OverPermissive",
      "Effect": "Allow",
      "Principal": {
        "AWS": "*"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

}

# Public SQS that anyone can send messages to
resource "aws_sqs_queue" "bad" {
  name = "${var.function_name}-bad"
  tags = {
    App    = var.function_name
    team   = "security"
    system = "aws-remediation"
  }
}

resource "aws_sqs_queue_policy" "bad" {
  queue_url = aws_sqs_queue.bad.id

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Id": "sqspolicy",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "sqs:SendMessage",
      "Resource": "${aws_sqs_queue.bad.arn}"
    }
  ]
}
POLICY
}

# EBS volume that is accessible from a non-white-listed account
resource "aws_ebs_volume" "bad" {
  availability_zone = "us-east-1a"
  size              = 1

  tags = {
    Name   = var.function_name
    App    = var.function_name
    team   = "security"
    system = "aws-remediation"
  }
}

resource "aws_ebs_snapshot" "bad" {
  volume_id   = aws_ebs_volume.bad.id
  description = "For remediation testing, made accessible from account 000000000000"

  tags = {
    Name   = var.function_name
    App    = var.function_name
    team   = "security"
    system = "aws-remediation"
  }
}

resource "aws_snapshot_create_volume_permission" "bad" {
  snapshot_id = aws_ebs_snapshot.bad.id
  account_id  = "000000000000"
}

# AMI: Shared with 000000000000
resource "aws_ami" "bad" {
  name             = var.function_name
  root_device_name = "/dev/xvda"

  ebs_block_device {
    device_name = "/dev/xvda"
    snapshot_id = aws_ebs_snapshot.bad.id
    volume_size = 1
  }

  tags = {
    Name   = var.function_name
    App    = var.function_name
    team   = "security"
    system = "aws-remediation"
  }
}

resource "aws_ami_launch_permission" "bad" {
  image_id   = aws_ami.bad.id
  account_id = "000000000000"
}

# IAM user: No MFA
resource "aws_iam_user" "bad" {
  name          = var.function_name
  path          = "/"
  force_destroy = true

  tags = {
    Name   = var.function_name
    App    = var.function_name
    team   = "security"
    system = "aws-remediation"
  }
}

resource "aws_iam_user_login_profile" "bad" {
  user    = aws_iam_user.bad.name
  pgp_key = "<DUMMY_PUBLIC_PGP_KEY_GOES_HERE>"
  # a public pgp key is required by terraform.

}


# RDS: Not encrypted
resource "aws_db_instance" "bad" {
  allocated_storage    = 5
  engine               = "mysql"
  engine_version       = "5.7"
  instance_class       = "db.t2.micro"
  name                 = var.function_name
  username             = "foo"
  password             = "foobarbaz"
  parameter_group_name = "default.mysql5.7"

  # AWS wants to create a snapshot before the RDS is deleted. We don't need that.
  skip_final_snapshot = true

  # Misconfigure this RDS by not encrypting it
  storage_encrypted = false

  tags = {
    Name   = var.function_name
    App    = var.function_name
    team   = "security"
    system = "aws-remediation"
  }
}

# RDS Snapshot: Nothing wrong because terraform doesn't have a way of misconfiguring it
resource "aws_db_snapshot" "bad" {
  db_instance_identifier = aws_db_instance.bad.id
  db_snapshot_identifier = "misconfiguration-maker"

  # Looks like terraform does not have the abiliy to share RDS snapshots with other accounts
  # There is an issue to do this here: https://github.com/terraform-providers/terraform-provider-aws/issues/3860

  tags = {
    Name   = var.function_name
    App    = var.function_name
    team   = "security"
    system = "aws-remediation"
  }
}

# S3 Bucket: Create bucket with public access to s3:GetObjectAcl
# Use a random suffix because bucket deletion and creation requires a large delay (an hour+) if you use the same name
resource "random_string" "random" {
  length  = 16
  special = false
  upper   = false
}

resource "aws_s3_bucket" "bad" {
  bucket = "${random_string.random.result}-misconfig-maker"
  acl    = "private"

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Principal": "*",
      "Action": [
        "s3:GetObjectAcl"
      ],
      "Effect": "Allow",
      "Resource": [
        "arn:aws:s3:::${random_string.random.result}-misconfig-maker/*"
      ]
    }
  ]
}
POLICY

  tags = {
    Name   = var.function_name
    App    = var.function_name
    team   = "security"
    system = "aws-remediation"
  }
}

# Redshift: Not encrypted
resource "aws_redshift_cluster" "bad" {
  cluster_identifier = "misconfig-maker"
  database_name      = "misconfig"
  master_username    = "foo"
  master_password    = "Mustbe8characters"
  # The smallest type available is dc1.large for $0.25/hr
  node_type    = "dc1.large"
  cluster_type = "single-node"

  # Allow this to be deleted easily
  skip_final_snapshot = true

  # Don't encrypt at rest
  encrypted = false

  tags = {
    Name   = var.function_name
    App    = var.function_name
    team   = "security"
    system = "aws-remediation"
  }
}

# EC2: Does not enforce IMDS v2
# First get a reference to an AMI to use
data "aws_ami" "ubuntu" {
  most_recent = true

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-trusty-14.04-amd64-server-*"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
  owners = ["099720109477"] # Canonical
}

resource "aws_instance" "bad" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t2.micro"

  tags = {
    Name   = var.function_name
    App    = var.function_name
    team   = "security"
    system = "aws-remediation"
  }
}

resource "aws_security_group" "bad" {
  name        = var.function_name
  description = "Created by misconfiguration maker for testing"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name   = var.function_name
    App    = var.function_name
    team   = "security"
    system = "aws-remediation"
  }
}

# Create a new load balancer with a different tag than the EC2 it is connected to
resource "aws_elb" "bad" {
  name               = "misconfiguration-maker"
  availability_zones = ["us-east-1a", "us-east-1b"]

  listener {
    instance_port     = 8000
    instance_protocol = "http"
    lb_port           = 8000
    lb_protocol       = "http"
  }

  health_check {
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 3
    target              = "HTTP:8000/"
    interval            = 30
  }

  instances = [aws_instance.bad.id]

  tags = {
    Name   = var.function_name
    App    = var.function_name
    team   = "security"
    system = "aws-remediation-2"
  }
}

# Lambda: Public to all
data "archive_file" "lambda_sourcecode" {
  type        = "zip"
  output_path = "${path.module}/lambda_function_payload.zip"
  source {
    content = <<SOURCE
{
import json
def lambda_handler(event, context):
    # TODO implement
    return {
        'statusCode': 200,
        'body': json.dumps('Hello from Lambda!')
    }
}
SOURCE
    filename = "lambda_function.py"
  }
}

resource "aws_lambda_permission" "public_lambda_resource_policy" {
  statement_id  = "PublicLambda"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.bad.function_name
  principal     = "*"
}

resource "aws_lambda_permission" "private_lambda_resource_policy" {
  statement_id  = "PrivateLambda"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.bad.function_name
  principal     = "events.amazonaws.com"
}

resource "aws_iam_role" "lambda_iam_role" {
  name               = "lambda_iam_role"
  path               = "/"
  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
POLICY
}

resource "aws_lambda_function" "bad" {
  filename      = data.archive_file.lambda_sourcecode.output_path
  function_name = "misconfig-public-lambda"
  handler       = "lambda_function.lambda_handler"
  role          = aws_iam_role.lambda_iam_role.arn
  runtime       = "python3.8"

}
