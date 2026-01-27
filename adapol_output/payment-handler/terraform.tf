resource "aws_iam_policy" "payment_handler_least_privilege_policy" {
  name        = "payment-handler-least-privilege-policy"
  description = "AdaPol generated least-privilege policy for payment-handler"
  
  policy = jsonencode({
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "logs.amazonaws.com"
      ],
      "Resource": [
        "CreateLogStream:arn:aws:lambda:us-east-1:123456789012:function:payment-handler"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "logs.amazonaws.com:CreateLogStream"
      ],
      "Resource": [
        "aws_iam_role.lambda_role.arn"
      ]
    }
  ]
})
  
  tags = {
    GeneratedBy = "AdaPol"
    Function    = "payment-handler"
    RiskReduction = "95.0%"
  }
}

resource "aws_iam_role_policy_attachment" "payment_handler_policy_attachment" {
  policy_arn = aws_iam_policy.payment_handler_least_privilege_policy.arn
  role       = aws_iam_role.payment_handler_execution_role.name
}