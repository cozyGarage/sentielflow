resource "aws_s3_bucket" "public_assets" {
  bucket = "demo-public-assets"
  acl    = "public-read"
}
