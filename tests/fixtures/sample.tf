# sample.tf – Terraform-Fixtures für NHI Discovery IaC-Scanner Tests
# Dieses File enthält ABSICHTLICH Sicherheitsprobleme zum Testen.

# =====================================================================
# PROBLEM 1: Overprivileged IAM Policy (Wildcard Action) → CRITICAL
# =====================================================================
resource "aws_iam_policy" "wildcard_policy" {
  name = "overprivileged-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

# =====================================================================
# PROBLEM 2: Hardcodierter AWS Access Key → CRITICAL
# =====================================================================
resource "aws_iam_access_key" "legacy_key" {
  user = aws_iam_user.service_account.name
}

# Simulated hardcoded key in a variable (for testing regex detection)
locals {
  # DO NOT DO THIS IN PRODUCTION
  legacy_access_key = "AKIAIOSFODNN7EXAMPLE"
  legacy_password   = "my-super-secret-password123"
}

# =====================================================================
# PROBLEM 3: IAM Role mit Principal * (Trust-Policy-Wildcard) → CRITICAL
# =====================================================================
resource "aws_iam_role" "overly_trusted_role" {
  name = "overly-trusted"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = "*"
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

# =====================================================================
# PROBLEM 4: Resource * mit Schreibrechten → HIGH
# =====================================================================
resource "aws_iam_policy" "s3_write_all" {
  name = "s3-write-all-buckets"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:PutBucketPolicy"
        ]
        Resource = "*"
      }
    ]
  })
}

# =====================================================================
# PROBLEM 5: Sensitive Action ohne Condition → MEDIUM
# =====================================================================
resource "aws_iam_policy" "iam_no_condition" {
  name = "iam-actions-no-condition"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["iam:CreateUser", "iam:AttachUserPolicy"]
        Resource = "arn:aws:iam::123456789012:user/*"
        # Kein Condition-Block!
      }
    ]
  })
}

# =====================================================================
# KORREKT: Gut konfigurierte Lambda-Role (soll KEINE Findings erzeugen)
# =====================================================================
resource "aws_iam_role" "lambda_processor" {
  name = "lambda-processor-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = "123456789012"
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda_processor.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# =====================================================================
# IAM User (für Discovery-Tests)
# =====================================================================
resource "aws_iam_user" "service_account" {
  name = "svc-terraform-managed"
  tags = {
    Environment = "production"
    ManagedBy   = "terraform"
  }
}
