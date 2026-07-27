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