resource "aws_iam_policy" "lambda_dynamo_role_least_privilege_policy" {
  name        = "lambda-dynamo-role-least-privilege-policy"
  description = "AdaPol generated least-privilege policy for lambda-dynamo-role"
  
  policy = jsonencode({
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb.amazonaws.com"
      ],
      "Resource": [
        "PutItem:arn:aws:dynamodb:us-east-1:123456789012:table/Orders",
        "GetItem:arn:aws:dynamodb:us-east-1:123456789012:table/Orders"
      ]
    }
  ]
})
  
  tags = {
    GeneratedBy = "AdaPol"
    Function    = "lambda-dynamo-role"
    RiskReduction = "95.0%"
  }
}

resource "aws_iam_role_policy_attachment" "lambda_dynamo_role_policy_attachment" {
  policy_arn = aws_iam_policy.lambda_dynamo_role_least_privilege_policy.arn
  role       = aws_iam_role.lambda_dynamo_role_execution_role.name
}