provider "aws" {
  region = "ap-south-1" 
}

resource "aws_instance" "drift_test" {
  ami           = "ami-09d88f7c4c272b0c5" 
  instance_type = "t3.micro"

  tags = {
    Name = "DriftWatch-Sandbox"
  }
}