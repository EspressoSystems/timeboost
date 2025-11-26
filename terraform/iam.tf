resource "aws_iam_policy" "timeboost_policy" {
  name = "TimeboostLogs"
  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Effect" : "Allow",
        "Action" : [
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ],
        "Resource" : "*"
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],
        "Resource" : [
          "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:timeboost",
          "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:timeboost:log-stream:*"
        ]
      },
    ]
  })
}

resource "aws_iam_role" "timeboost_role" {
  name = "Timeboost"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = "sts:AssumeRole",
        Effect = "Allow",
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "attach_policy" {
  role       = aws_iam_role.timeboost_role.name
  policy_arn = aws_iam_policy.timeboost_policy.arn
}

resource "aws_iam_instance_profile" "timeboost_profile" {
  name = "TimeboostInstanceProfile"
  role = aws_iam_role.timeboost_role.name
}


