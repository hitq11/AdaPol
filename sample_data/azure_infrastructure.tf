resource "aws_dynamodb_table" "orders" {
  name         = "Orders"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "orderId"

  attribute {
    name = "orderId"
    type = "S"
  }
}

resource "aws_lambda_function" "order_handler" {
  function_name = "order-handler"
  role          = aws_iam_role.lambda_exec.arn
  handler       = "index.handler"
  runtime       = "python3.12"
}

resource "aws_iam_role" "lambda_exec" {
  name = "lambda-dynamo-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

# ❌ Narrow: only allows GetItem
resource "aws_iam_role_policy" "lambda_policy" {
  name = "dynamo-get-only"
  role = aws_iam_role.lambda_exec.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Allow",
        Action   = ["dynamodb:GetItem"],
        Resource = [aws_dynamodb_table.orders.arn]
      }
    ]
  })
}

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}
