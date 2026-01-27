resource "aws_iam_policy" "order_processor_least_privilege_policy" {
  name        = "order-processor-least-privilege-policy"
  description = "AdaPol generated least-privilege policy for order-processor"
  
  policy = jsonencode({
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb.amazonaws.com"
      ],
      "Resource": [
        "Query:arn:aws:dynamodb:us-east-1:123456789012:table/Orders",
        "GetItem:arn:aws:dynamodb:us-east-1:123456789012:table/Orders",
        "PutItem:arn:aws:dynamodb:us-east-1:123456789012:table/Orders"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3.amazonaws.com"
      ],
      "Resource": [
        "GetObject:arn:aws:s3:::my-bucket/data-14.json",
        "GetObject:arn:aws:s3:::my-bucket/data-1.json"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "logs.amazonaws.com"
      ],
      "Resource": [
        "PutLogEvents:arn:aws:lambda:us-east-1:123456789012:function:order-processor",
        "CreateLogStream:arn:aws:lambda:us-east-1:123456789012:function:order-processor"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "lambda.amazonaws.com"
      ],
      "Resource": [
        "InvokeFunction:arn:aws:lambda:us-east-1:123456789012:function:order-processor"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "lambda.amazonaws.com:InvokeFunction"
      ],
      "Resource": [
        "aws_s3_bucket.data_bucket.bucket",
        "aws_dynamodb_table.orders.name",
        "aws_iam_role.lambda_role.arn"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb.amazonaws.com:PutItem"
      ],
      "Resource": [
        "aws_s3_bucket.data_bucket.bucket",
        "aws_dynamodb_table.orders.name",
        "aws_iam_role.lambda_role.arn"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "logs.amazonaws.com:PutLogEvents"
      ],
      "Resource": [
        "aws_s3_bucket.data_bucket.bucket",
        "aws_dynamodb_table.orders.name",
        "aws_iam_role.lambda_role.arn"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3.amazonaws.com:GetObject"
      ],
      "Resource": [
        "aws_s3_bucket.data_bucket.bucket",
        "aws_dynamodb_table.orders.name",
        "aws_iam_role.lambda_role.arn"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb.amazonaws.com:Query"
      ],
      "Resource": [
        "aws_s3_bucket.data_bucket.bucket",
        "aws_dynamodb_table.orders.name",
        "aws_iam_role.lambda_role.arn"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "logs.amazonaws.com:CreateLogStream"
      ],
      "Resource": [
        "aws_s3_bucket.data_bucket.bucket",
        "aws_dynamodb_table.orders.name",
        "aws_iam_role.lambda_role.arn"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb.amazonaws.com:GetItem"
      ],
      "Resource": [
        "aws_s3_bucket.data_bucket.bucket",
        "aws_dynamodb_table.orders.name",
        "aws_iam_role.lambda_role.arn"
      ]
    }
  ]
})
  
  tags = {
    GeneratedBy = "AdaPol"
    Function    = "order-processor"
    RiskReduction = "0.0%"
  }
}

resource "aws_iam_role_policy_attachment" "order_processor_policy_attachment" {
  policy_arn = aws_iam_policy.order_processor_least_privilege_policy.arn
  role       = aws_iam_role.order_processor_execution_role.name
}