# METADATA
# title: No Public S3 Buckets
# description: Prevents S3 buckets from being publicly accessible
# severity: critical

package sentinelflow.s3

# Deny S3 buckets with public ACL
deny_public_buckets[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    resource.change.after.acl == "public-read"
    
    msg := sprintf("S3 bucket '%s' has public-read ACL", [resource.name])
}

deny_public_buckets[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    resource.change.after.acl == "public-read-write"
    
    msg := sprintf("S3 bucket '%s' has public-read-write ACL", [resource.name])
}

# Deny S3 buckets without public access block
deny_public_buckets[msg] {
    bucket := input.resource_changes[_]
    bucket.type == "aws_s3_bucket"
    
    # Check if public access block exists for this bucket
    not has_public_access_block(bucket.name)
    
    msg := sprintf("S3 bucket '%s' is missing public access block configuration", [bucket.name])
}

has_public_access_block(bucket_name) {
    block := input.resource_changes[_]
    block.type == "aws_s3_bucket_public_access_block"
    block.change.after.bucket == bucket_name
}
