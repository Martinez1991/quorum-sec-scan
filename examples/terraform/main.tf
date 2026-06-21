# Intentionally insecure Terraform for demoing quorum's IaC consensus.
# Trivy + Checkov + KICS should all flag the public, unencrypted S3 bucket.

resource "aws_s3_bucket" "data" {
  bucket = "quorum-demo-public-bucket"
  acl    = "public-read" # public access — flagged by all engines
}

resource "aws_iam_policy" "admin" {
  name = "quorum-demo-admin"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*" # wildcard action — flagged
      Resource = "*"
    }]
  })
}
