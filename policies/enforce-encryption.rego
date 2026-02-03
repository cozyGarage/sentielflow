# METADATA
# title: Enforce Encryption at Rest
# description: Requires encryption at rest for storage resources
# severity: high

package sentinelflow.encryption

# Deny unencrypted S3 buckets
deny_unencrypted_s3[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    not has_encryption(resource.name)
    
    msg := sprintf("S3 bucket '%s' does not have encryption enabled", [resource.name])
}

has_encryption(bucket_name) {
    encryption := input.resource_changes[_]
    encryption.type == "aws_s3_bucket_server_side_encryption_configuration"
    encryption.change.after.bucket == bucket_name
}

# Deny unencrypted RDS instances
deny_unencrypted_rds[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_db_instance"
    resource.change.after.storage_encrypted == false
    
    msg := sprintf("RDS instance '%s' does not have encryption enabled", [resource.name])
}

# Deny unencrypted EBS volumes
deny_unencrypted_ebs[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_ebs_volume"
    resource.change.after.encrypted == false
    
    msg := sprintf("EBS volume '%s' is not encrypted", [resource.name])
}

# Deny unencrypted EFS
deny_unencrypted_efs[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_efs_file_system"
    resource.change.after.encrypted == false
    
    msg := sprintf("EFS file system '%s' is not encrypted", [resource.name])
}
