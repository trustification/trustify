# IAM user

resource "aws_iam_user" "storage" {
  name = "storage-${var.environment}"
  tags = {
    Environment = var.environment
  }
}

resource "aws_iam_access_key" "storage" {
  user = aws_iam_user.storage.name
}

resource "kubernetes_secret" "storage-credentials" {
  metadata {
    name      = "storage-credentials"
    namespace = var.namespace
  }

  data = {
    aws_access_key_id     = aws_iam_access_key.storage.id
    aws_secret_access_key = aws_iam_access_key.storage.secret
  }

  type = "Opaque"
}

data "aws_iam_policy_document" "storage" {
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket", "s3:ListAllMyBuckets"]
    resources = ["arn:aws:s3:::trustify-${var.environment}"]
  }
}

resource "aws_iam_policy" "storage" {
  name        = "storage-policy-${var.environment}"
  description = "Policies for storage access"
  policy      = data.aws_iam_policy_document.storage.json
  tags        = {
    Environment = var.environment
  }
}

resource "aws_iam_user_policy_attachment" "storage-attach" {
  user       = aws_iam_user.storage.name
  policy_arn = aws_iam_policy.storage.arn
}

# S3 buckets

resource "aws_s3_bucket" "bucket" {
  bucket        = "trustify-${var.environment}"
  force_destroy = true
  tags          = {
    Environment = var.environment
  }
}

data "aws_iam_policy_document" "bucket_policy" {
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket"]
    resources = [
      "arn:aws:s3:::trustify-${var.environment}/*",
      "arn:aws:s3:::trustify-${var.environment}",
    ]
    principals {
      type        = "AWS"
      identifiers = [aws_iam_user.storage.arn]
    }
  }
}

resource "aws_s3_bucket_policy" "storage-bucket-policy" {
  bucket = aws_s3_bucket.bucket.id
  policy = data.aws_iam_policy_document.bucket_policy.json
}

resource "kubernetes_config_map" "aws-storage" {
  metadata {
    name      = "aws-storage"
    namespace = var.namespace
  }

  data = {
    region = data.aws_region.current.name
  }
}
