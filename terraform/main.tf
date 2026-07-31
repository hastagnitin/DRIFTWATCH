provider "aws" {
  region = "ap-south-1" 
}

resource "aws_instance" "web_servers" {
  count         = 3
  ami           = "ami-0c2af51e265bd5e0e"
  instance_type = "t3.micro"
  
  tags = {
    Name = "DriftWatch-Test-${count.index + 1}"
  }
}

resource "aws_s3_bucket" "drift_test_bucket" {
  bucket = "driftwatch-test-bucket-27072026-xyz"

  tags = {
     Name        = "DriftWatch-S3-Test"
     Environment = "Dev"
  }
}

resource "aws_security_group" "drift_test_sg" {
  name        = "driftwatch-test-sg"
  description = "Security group for DriftWatch testing"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "DriftWatch-SG-Test"
    Environment = "Dev"
  }
}

resource "aws_db_instance" "driftwatch_rds" {
  identifier           = "driftwatch-test-db"
  allocated_storage    = 20
  engine               = "mysql"
  engine_version       = "8.0"
  instance_class       = "db.t3.micro"
  username             = "admin"
  password             = "DriftWatch"
  skip_final_snapshot  = true
  publicly_accessible  = false
}

resource "aws_iam_role" "lambda_exec_role" {
  name = "driftwatch_lambda_role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

data "archive_file" "lambda_zip" {
  type        = "zip"
  output_path = "lambda_function.zip"
  source {
    content  = "def lambda_handler(event, context):\n    return 'Hello DriftWatch!'"
    filename = "index.py"
  }
}

resource "aws_lambda_function" "driftwatch_lambda" {
  function_name    = "driftwatch-test-function"
  role             = aws_iam_role.lambda_exec_role.arn
  handler          = "index.lambda_handler"
  runtime          = "python3.9"
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
}
resource "aws_security_group" "driftwatch_managed_test" {
    name        = "driftwatch-managed-test-sg"
    description = "Testing DriftWatch Auto Remediation"

    ingress {
        from_port   = 443
        to_port     = 443
        protocol    = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
    }
}