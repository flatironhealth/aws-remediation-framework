# This file creates the following:
# - SQS that receives information about resources.
# - SNS for alarms. Also creates the alarms for the SQS.
# - IAM role the event_translator, and also initalizes the event_translator into specified regions in variables.tf .

provider "aws" {
  profile = "default"
  region  = var.master_region
}

variable "function_name" {
  default = "remediator"
}

variable "lambda_bucket" {
}

# Be able to get the account ID
data "aws_caller_identity" "current" {}

# SNS for alarms to go to
resource "aws_sns_topic" "alarms" {
  name = "remediator_alarms"

  tags = {
    App    = var.function_name
    department   = "security"
    application = "remediation-framework"
  }
}

# Create the SQS that sends messages to the remediator about resources
resource "aws_sqs_queue" "resource_queue" {
  name = "remediator-resource-queue"

  # We want a delay to help reduce the problems of infinite loops
  delay_seconds              = 90
  max_message_size           = 2048
  message_retention_seconds  = 86400
  receive_wait_time_seconds  = 10
  visibility_timeout_seconds = 60
  //  redrive_policy            = "{\"deadLetterTargetArn\":\"${aws_sqs_queue.terraform_queue_deadletter.arn}\",\"maxReceiveCount\":4}"
  tags = {
    App    = var.function_name
    department   = "security"
    application = "remediation-framework"
  }
}

resource "aws_cloudwatch_metric_alarm" "too_many_messages_received" {
  alarm_name          = "remediator-too_many_messages"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "2"
  metric_name         = "NumberOfMessagesSent"
  namespace           = "AWS/SQS"
  period              = "120"
  statistic           = "Average"
  threshold           = "100"
  alarm_description   = "Detect when a large number of messages have been sent into the SQS. This could mean something has gotten out of control."
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alarms.arn]

  dimensions = {
    QueueName = aws_sqs_queue.resource_queue.name
  }

  tags = {
    App    = var.function_name
    department   = "security"
    application = "remediation-framework"
  }
}

resource "aws_cloudwatch_metric_alarm" "backed_up" {
  alarm_name          = "remediator-backed_up"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "2"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = "120"
  statistic           = "Average"
  threshold           = "100"
  alarm_description   = "Detect when too many messages are in the SQS that the remediator learns about resources from. This could mean the remediator is not pulling off resources fast enough or that something is sending too many resources to the queue"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alarms.arn]

  dimensions = {
    QueueName = aws_sqs_queue.resource_queue.name
  }

  tags = {
    App    = var.function_name
    department   = "security"
    application = "remediation-framework"
  }
}


# Setup the event translator IAM role
resource "aws_iam_role" "event_translator" {
  name = "event_translator"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF

  tags = {
    App    = "event_translator"
    department   = "security"
    application = "remediation-framework"
  }
}

data "aws_iam_policy_document" "event_translator_policy_document" {
  statement {
    actions = [
      "logs:CreateLogGroup",
    ]
    resources = [
      "*",
    ]
  }
  statement {
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = [
      "arn:aws:logs:*:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/event_translator",
      "arn:aws:logs:*:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/event_translator:*",
    ]
  }
  statement {
    actions = [
      "sqs:SendMessage",
    ]
    resources = [
      aws_sqs_queue.resource_queue.arn
    ]
  }
}

resource "aws_iam_policy" "event_translator" {
  name   = "event_translator"
  path   = "/"
  policy = data.aws_iam_policy_document.event_translator_policy_document.json
}

resource "aws_iam_role_policy_attachment" "event_translator" {
  role       = aws_iam_role.event_translator.name
  policy_arn = aws_iam_policy.event_translator.arn
}

# Setup the event translators in each region
# terraform doesn't support count or for_each in modules, revisit after terraform 0.13 release
module "events-us-east-1" {
  source        = "./event_translator"
  region        = "us-east-1"
  lambda_bucket = var.lambda_bucket
  function_name = var.function_name
  sqs           = aws_sqs_queue.resource_queue
  iam_role      = aws_iam_role.event_translator.arn
}

module "events-us-east-2" {
  source        = "./event_translator"
  region        = "us-east-2"
  lambda_bucket = var.lambda_bucket
  function_name = var.function_name
  sqs           = aws_sqs_queue.resource_queue
  iam_role      = aws_iam_role.event_translator.arn
}

module "events-us-west-1" {
  source        = "./event_translator"
  region        = "us-west-1"
  lambda_bucket = var.lambda_bucket
  function_name = var.function_name
  sqs           = aws_sqs_queue.resource_queue
  iam_role      = aws_iam_role.event_translator.arn
}

module "events-us-west-2" {
  source        = "./event_translator"
  region        = "us-west-2"
  lambda_bucket = var.lambda_bucket
  function_name = var.function_name
  sqs           = aws_sqs_queue.resource_queue
  iam_role      = aws_iam_role.event_translator.arn
}
