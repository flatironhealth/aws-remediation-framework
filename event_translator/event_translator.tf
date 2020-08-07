variable "region" {}
variable "sqs" {}
variable "lambda_bucket" {}
variable "function_name" {}
variable "iam_role" {}

provider "aws" {
  profile = "default"
  region  = var.region
}

# Event translator
resource "aws_cloudwatch_log_group" "event_translator" {
  name              = "/aws/lambda/event_translator"
  retention_in_days = 14
  tags = {
    App    = "event_translator"
    department   = "security"
    application = "remediation-framework"
  }
}

resource "aws_lambda_function" "event_translator" {
  function_name = "event_translator"
  description   = "Identifies resources created or modified via CloudWatch Events and then tells the remediator about these"
  # If this is us-east-1, use the bucket for that region.
  s3_bucket        = "${var.lambda_bucket}-${var.region}"
  s3_key           = "event_translator.zip"
  role             = var.iam_role
  handler          = "main.handler"
  runtime          = "python3.7"
  timeout          = 300
  source_code_hash = filebase64sha256("cache/event_translator.zip")

  environment {
    variables = {
      SQS = var.sqs.id
    }
  }

  tags = {
    App    = "event_translator"
    department   = "security"
    application = "remediation-framework"
  }
}

# Open the event bus so any account in the org can send events to it
data "aws_organizations_organization" "org" {}

resource "aws_cloudwatch_event_permission" "OrganizationAccess" {
  principal    = "*"
  statement_id = "OrganizationAccess"

  condition {
    key   = "aws:PrincipalOrgID"
    type  = "StringEquals"
    value = data.aws_organizations_organization.org.id
  }
}


resource "aws_cloudwatch_event_rule" "event_translator" {
  name        = "aws-remediation-event_translator"
  description = "Receives and translates events for potential remediation"

  # List of events that should be translated so the remediator can check the resource that was changed
  event_pattern = file("${path.module}/../member_account_setup/events_to_watch.json")

  tags = {
    App    = "event_translator"
    department   = "security"
    application = "remediation-framework"
  }
}

# Connect rule to Lambda
resource "aws_cloudwatch_event_target" "event_translator" {
  target_id = "event_translator"
  rule      = aws_cloudwatch_event_rule.event_translator.name
  arn       = aws_lambda_function.event_translator.arn
}

resource "aws_lambda_permission" "event_translator" {
  statement_id  = "event_translator"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.event_translator.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.event_translator.arn
}


# SNS for alarms to go to
resource "aws_sns_topic" "alarms" {
  name = "remediator_event_translator_alarms"

  tags = {
    App    = var.function_name
    department   = "security"
    application = "remediation-framework"
  }
}

resource "aws_cloudwatch_metric_alarm" "translator_errors" {
  alarm_name          = "remediator-lambda_event_translator_errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = "60"
  statistic           = "Sum"
  threshold           = "0"
  alarm_description   = "Detect when the event_translator lambda has errors"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alarms.arn]

  dimensions = {
    FunctionName = "event_translator"
  }

  tags = {
    App    = var.function_name
    department   = "security"
    application = "remediation-framework"
  }
}
