terraform {
  required_version = ">= 1.4.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

resource "aws_kms_key" "vault" {
  description             = "SecureVault data key encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true
}

resource "aws_s3_bucket" "vault" {
  bucket        = var.bucket_name
  force_destroy = true
}

resource "aws_s3_bucket_versioning" "vault" {
  bucket = aws_s3_bucket.vault.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "vault" {
  bucket = aws_s3_bucket.vault.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.vault.key_id
    }
  }
}

resource "aws_iam_role" "ec2_role" {
  name = "securevault-ec2-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action = "sts:AssumeRole",
      Effect = "Allow",
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "ec2_policy" {
  name = "securevault-ec2-policy"
  role = aws_iam_role.ec2_role.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = ["s3:GetObject","s3:PutObject","s3:ListBucket"],
        Resource = [aws_s3_bucket.vault.arn, "${aws_s3_bucket.vault.arn}/*"]
      },
      {
        Effect = "Allow",
        Action = ["kms:GenerateDataKey","kms:Decrypt"],
        Resource = [aws_kms_key.vault.arn]
      },
      {
        Effect = "Allow",
        Action = ["cloudtrail:LookupEvents"],
        Resource = ["*"]
      }
    ]
  })
}

resource "aws_iam_instance_profile" "ec2_profile" {
  name = "securevault-ec2-profile"
  role = aws_iam_role.ec2_role.name
}

resource "aws_cloudtrail" "trail" {
  name                          = "securevault-trail"
  s3_bucket_name                = aws_s3_bucket.vault.id
  s3_key_prefix                 = "cloudtrail"
  include_global_service_events = true
  is_multi_region_trail         = true
}

output "s3_bucket" { value = aws_s3_bucket.vault.id }
output "kms_key_id" { value = aws_kms_key.vault.key_id }