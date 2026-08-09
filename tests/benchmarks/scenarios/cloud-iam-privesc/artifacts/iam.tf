# IAM for the developer role. Developers deploy Lambda functions and manage their
# own application policies. Attached to the "developers" group (~40 engineers).

resource "aws_iam_policy" "developer_policy" {
  name = "developer-self-service"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "LambdaDeploy"
        Effect = "Allow"
        Action = [
          "lambda:CreateFunction",
          "lambda:UpdateFunctionCode",
          "lambda:InvokeFunction"
        ]
        Resource = "*"
      },
      {
        # Devs "need to tweak their own managed policies", so this was added.
        Sid    = "ManagePolicies"
        Effect = "Allow"
        Action = [
          "iam:CreatePolicyVersion",
          "iam:SetDefaultPolicyVersion",
          "iam:ListPolicies",
          "iam:GetPolicy"
        ]
        Resource = "*"
      },
      {
        # Lambda execution roles are passed at deploy time.
        Sid    = "PassExecRole"
        Effect = "Allow"
        Action = "iam:PassRole"
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_group_policy_attachment" "dev_attach" {
  group      = "developers"
  policy_arn = aws_iam_policy.developer_policy.arn
}
