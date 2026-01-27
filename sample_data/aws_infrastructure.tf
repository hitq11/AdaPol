
# Sample AWS Serverless Application
resource "aws_lambda_function" "order_processor" {
  function_name = "order-processor"
  role         = aws_iam_role.lambda_role.arn
  handler      = "index.handler"
  runtime      = "python3.9"
  
  environment {
    variables = {
      BUCKET_NAME = aws_s3_bucket.data_bucket.bucket
      TABLE_NAME  = aws_dynamodb_table.orders.name
    }
  }
}

resource "aws_lambda_function" "payment_handler" {
  function_name = "payment-handler"
  role         = aws_iam_role.lambda_role.arn
  handler      = "payment.handler"
  runtime      = "python3.9"
}

resource "aws_s3_bucket" "data_bucket" {
  bucket = "my-serverless-data-bucket"
}

resource "aws_dynamodb_table" "orders" {
  name           = "Orders"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "OrderId"
  
  attribute {
    name = "OrderId"
    type = "S"
  }
}

resource "aws_sns_topic" "notifications" {
  name = "order-notifications"
}
