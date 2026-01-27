resource "aws_iam_policy" "notification_service_least_privilege_policy" {
  name        = "notification-service-least-privilege-policy"
  description = "AdaPol generated least-privilege policy for notification-service"
  
  policy = jsonencode({
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "logs.amazonaws.com"
      ],
      "Resource": [
        "CreateLogStream:arn:aws:lambda:us-east-1:123456789012:function:notification-service"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "sns.amazonaws.com"
      ],
      "Resource": [
        "Publish:arn:aws:sns:us-east-1:123456789012:order-notifications"
      ]
    }
  ]
})
  
  tags = {
    GeneratedBy = "AdaPol"
    Function    = "notification-service"
    RiskReduction = "95.0%"
  }
}

resource "aws_iam_role_policy_attachment" "notification_service_policy_attachment" {
  policy_arn = aws_iam_policy.notification_service_least_privilege_policy.arn
  role       = aws_iam_role.notification_service_execution_role.name
}