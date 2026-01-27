# AWS Serverless E-commerce Order Processing Pipeline
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# S3 Bucket for order data
resource "aws_s3_bucket" "order_data" {
  bucket = "ecommerce-order-data-${random_string.suffix.result}"
}

resource "aws_s3_bucket_versioning" "order_data_versioning" {
  bucket = aws_s3_bucket.order_data.id
  versioning_configuration {
    status = "Enabled"
  }
}

# DynamoDB table for orders
resource "aws_dynamodb_table" "orders" {
  name           = "Orders"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "OrderId"
  
  attribute {
    name = "OrderId"
    type = "S"
  }
  
  attribute {
    name = "CustomerId"
    type = "S"
  }
  
  global_secondary_index {
    name     = "CustomerIndex"
    hash_key = "CustomerId"
  }
}

# SNS topic for notifications
resource "aws_sns_topic" "order_notifications" {
  name = "order-notifications"
}

# Lambda function for order processing
resource "aws_lambda_function" "order_processor" {
  function_name = "order-processor"
  role         = aws_iam_role.lambda_execution.arn
  handler      = "index.handler"
  runtime      = "python3.11"
  timeout      = 30
  
  filename         = "order_processor.zip"
  source_code_hash = filebase64sha256("order_processor.zip")
  
  environment {
    variables = {
      ORDERS_TABLE = aws_dynamodb_table.orders.name
      DATA_BUCKET  = aws_s3_bucket.order_data.bucket
      SNS_TOPIC    = aws_sns_topic.order_notifications.arn
    }
  }
}

# Lambda function for payment processing
resource "aws_lambda_function" "payment_processor" {
  function_name = "payment-processor"
  role         = aws_iam_role.lambda_execution.arn
  handler      = "payment.handler"
  runtime      = "python3.11"
  timeout      = 30
  
  filename         = "payment_processor.zip"
  source_code_hash = filebase64sha256("payment_processor.zip")
  
  environment {
    variables = {
      ORDERS_TABLE = aws_dynamodb_table.orders.name
    }
  }
}

# IAM role for Lambda execution (overprivileged - to be optimized by AdaPol)
resource "aws_iam_role" "lambda_execution" {
  name = "lambda-execution-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

# Overprivileged policy (AdaPol will optimize this)
resource "aws_iam_role_policy" "lambda_policy" {
  name = "lambda-execution-policy"
  role = aws_iam_role.lambda_execution.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "s3:*",
          "dynamodb:*",
          "sns:*",
          "lambda:InvokeFunction"
        ]
        Resource = "*"
      }
    ]
  })
}

# API Gateway for triggering functions
resource "aws_api_gateway_rest_api" "order_api" {
  name        = "order-processing-api"
  description = "API for order processing"
}

resource "aws_api_gateway_resource" "orders" {
  rest_api_id = aws_api_gateway_rest_api.order_api.id
  parent_id   = aws_api_gateway_rest_api.order_api.root_resource_id
  path_part   = "orders"
}

resource "aws_api_gateway_method" "post_order" {
  rest_api_id   = aws_api_gateway_rest_api.order_api.id
  resource_id   = aws_api_gateway_resource.orders.id
  http_method   = "POST"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "lambda_integration" {
  rest_api_id = aws_api_gateway_rest_api.order_api.id
  resource_id = aws_api_gateway_method.post_order.resource_id
  http_method = aws_api_gateway_method.post_order.http_method
  
  integration_http_method = "POST"
  type                   = "AWS_PROXY"
  uri                    = aws_lambda_function.order_processor.invoke_arn
}

resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}
