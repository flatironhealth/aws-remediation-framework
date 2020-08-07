resource "aws_sns_topic" "remediator-notifications" {
  name = "remediator_notifications"
}

resource "aws_cloudwatch_log_group" "remediator" {
  name              = "/aws/lambda/${var.function_name}"
  retention_in_days = 14
  tags = {
    App    = var.function_name
    department   = "security"
    application = "remediation-framework"
  }
}

resource "aws_iam_role" "remediator" {
  name = var.function_name

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
    App    = var.function_name
    department   = "security"
    application = "remediation-framework"
  }
}


data "aws_iam_policy_document" "remediator_policy_document" {
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
      "arn:aws:logs:${var.master_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/remediator",
      "arn:aws:logs:${var.master_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/remediator:*",
    ]
  }
  statement {
    actions = [
      "sqs:ReceiveMessage",
      "sqs:DeleteMessage",
      "sqs:GetQueueAttributes",
      "sqs:ChangeMessageVisibility",
      "sqs:SendMessage"
    ]
    resources = [
      aws_sqs_queue.resource_queue.arn
    ]
  }
  statement {
    actions = [
      "sns:Publish",
    ]
    resources = [
      aws_sns_topic.remediator-notifications.arn
    ]
  }
  statement {
    actions = [
      "ses:SendEmail",
    ]
    resources = [
      "*"
    ]
  }
  statement {
    actions = [
      "sts:AssumeRole"
    ]
    resources = [
      "arn:aws:iam::*:role/member_remediator"
    ]
  }
}

resource "aws_iam_policy" "remediator" {
  name   = "remediator"
  path   = "/"
  policy = data.aws_iam_policy_document.remediator_policy_document.json
}

resource "aws_iam_role_policy_attachment" "remediator" {
  role       = aws_iam_role.remediator.name
  policy_arn = aws_iam_policy.remediator.arn
}

resource "aws_lambda_function" "remediator" {
  function_name    = "remediator"
  description      = "Receives info about resources from an SQS, then assumes into the account where this resource is, checks them for compliance, and then potentially remediates them."
  s3_bucket        = "${var.lambda_bucket}-${var.master_region}"
  s3_key           = "remediator.zip"
  role             = aws_iam_role.remediator.arn
  handler          = "main.handler"
  runtime          = "python3.7"
  timeout          = 60 # 1 minute
  source_code_hash = filebase64sha256("cache/remediator.zip")

  environment {
    variables = {
      REMEDIATE = var.remediate
      S3_BUCKET_IGNORE_LIST = var.s3_bucket_ignore_list
      ORGANIZATION_ACCOUNT = var.org_account
      KNOWN_ACCOUNTS = var.accounts
      DEV_ACCOUNTS = var.dev_accounts
      EC2_INSTANCE_IGNORE_LIST = var.ec2_ignore_list
      GUARDDUTY_MASTER_ACCOUNT = var.guardduty_master_account
      REMEDIATION_MODULE_EXCEPTION = jsonencode(var.remediation_module_exception)
      NOTIFICATION_TOPIC = aws_sns_topic.remediator-notifications.arn
      REMEDIATOR_REGION = var.master_region
      REQUIRED_TAGS = var.required_tags
      SQS_QUEUE = aws_sqs_queue.resource_queue.arn
      REMEDIATION_RESOURCE_EXCEPTION = var.remediation_resource_exception
    }
  }

  tags = {
    App    = var.function_name
    department   = "security"
    application = "remediation-framework"
  }
}

resource "aws_lambda_event_source_mapping" "remediator" {
  event_source_arn = aws_sqs_queue.resource_queue.arn
  function_name    = aws_lambda_function.remediator.arn
}

resource "aws_cloudwatch_metric_alarm" "remediator_errors" {
  alarm_name          = "remediator-lambda_errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = "60"
  statistic           = "Sum"
  threshold           = "0"
  alarm_description   = "Detect when the remediator lambda has errors"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alarms.arn]

  dimensions = {
    FunctionName = "remediator"
  }

  tags = {
    App    = var.function_name
    department   = "security"
    application = "remediation-framework"
  }
}

resource "aws_cloudwatch_metric_alarm" "remediator_called_too_often" {
  alarm_name          = "remediator-lambda_called_too_often"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "Invocations"
  namespace           = "AWS/Lambda"
  period              = "60"
  statistic           = "Sum"
  threshold           = "100"
  alarm_description   = "The remediator lambda is being called a large number of times. It may be stuck in a loop."
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alarms.arn]

  dimensions = {
    FunctionName = "remediator"
  }

  tags = {
    App    = var.function_name
    department   = "security"
    application = "remediation-framework"
  }
}
