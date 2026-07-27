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