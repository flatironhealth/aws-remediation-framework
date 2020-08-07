# Poller
resource "aws_cloudwatch_log_group" "poller" {
  name              = "/aws/lambda/poller"
  retention_in_days = 14
  tags = {
    App    = "poller"
    department   = "security"
    application = "remediation-framework"
  }
}

resource "aws_iam_role" "poller" {
  name = "poller"

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
    App    = "poller"
    department   = "security"
    application = "remediation-framework"
  }
}


data "aws_iam_policy_document" "poller_policy_document" {
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
      "arn:aws:logs:${var.master_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/poller",
      "arn:aws:logs:${var.master_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/poller:*",
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
  statement {
    actions = [
      "sts:AssumeRole"
    ]
    resources = [
      "arn:aws:iam::*:role/member_remediator"
    ]
  }
}

resource "aws_iam_policy" "poller" {
  name   = "poller"
  path   = "/"
  policy = data.aws_iam_policy_document.poller_policy_document.json
}

resource "aws_iam_role_policy_attachment" "poller" {
  role       = aws_iam_role.poller.name
  policy_arn = aws_iam_policy.poller.arn
}

resource "aws_lambda_function" "poller" {
  function_name    = "poller"
  description      = "Scans an account for all resources and tells the remediator about them"
  s3_bucket        = "${var.lambda_bucket}-${var.master_region}"
  s3_key           = "poller.zip"
  role             = aws_iam_role.poller.arn
  handler          = "main.handler"
  runtime          = "python3.7"
  timeout          = 900 # 15 minutes
  source_code_hash = filebase64sha256("cache/poller.zip")

  environment {
    variables = {
      POLLER_SQS              = aws_sqs_queue.resource_queue.id
      ONLY_USE_TEST_RESOURCES = "false"
      REGIONS                 = var.regions
      ACCOUNTS                = var.accounts
    }
  }

  tags = {
    App    = "poller"
    department   = "security"
    application = "remediation-framework"
  }
}


resource "aws_cloudwatch_event_rule" "poller" {
  name        = "aws-remediation-poller"
  description = "Execute the remediation poller"

  schedule_expression = "cron(0 8 * * ? *)"

  tags = {
    App    = "poller"
    department   = "security"
    application = "remediation-framework"
  }
}

# Connect the CloudWatch Rule to the Lambda so it runs every day
resource "aws_cloudwatch_event_target" "poller" {
  target_id = "poller"
  rule      = aws_cloudwatch_event_rule.poller.name
  arn       = aws_lambda_function.poller.arn
}

resource "aws_lambda_permission" "poller" {
  statement_id  = "poller"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.poller.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.poller.arn
}

resource "aws_cloudwatch_metric_alarm" "poller_errors" {
  alarm_name          = "remediator-lambda_poller_errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = "60"
  statistic           = "Sum"
  threshold           = "0"
  alarm_description   = "Detect when the poller lambda has errors"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alarms.arn]

  dimensions = {
    FunctionName = "poller"
  }

  tags = {
    App    = var.function_name
    department   = "security"
    application = "remediation-framework"
  }
}
