---
title: "AWS S3 Security Architecture & Hardening Guide"
tags: ["cloud", "aws", "s3", "storage", "hardening", "access-control"]
source: "CIS AWS Benchmark v2.0 Section 2 / NIST SP 800-144"
---

# AWS S3 Security Architecture & Hardening Guide
## Source & Authority
CIS AWS Foundations Benchmark v2.0 Section 2.1; NIST SP 800-144 (Guidelines on Security and Privacy in Public Cloud Computing).

## Core Security Controls
1. **Public Access Block:** Enable S3 Block Public Access at the AWS Organization and Account level. Enforce all four flags: `BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`, and `RestrictPublicBuckets`.
2. **Encryption at Rest:** Enforce Server-Side Encryption with AWS KMS Customer Managed Keys (`aws:kms` CMK) with key rotation enabled. Do not rely solely on default `AES256`.
3. **Transport Security:** Deny all unencrypted HTTP traffic via bucket policy requiring `aws:SecureTransport: true`.
4. **Data Integrity & Versioning:** Enable S3 Object Versioning and MFA Delete (`aws s3api put-bucket-versioning --mfa ...`). Prevent accidental or malicious bulk destruction.
5. **Auditing & Telemetry:** Forward S3 Server Access Logging and CloudTrail S3 Data Events to an isolated, immutable security log archive bucket.

## Diagnostic & Remediation Commands
```bash
# Verify Block Public Access status
aws s3api get-public-access-block --bucket <bucket-name>

# Enforce secure HTTPS-only bucket policy
aws s3api put-bucket-policy --bucket <bucket-name> --policy '{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "EnforceTLSRequestsOnly",
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:*",
    "Resource": ["arn:aws:s3:::<bucket-name>", "arn:aws:s3:::<bucket-name>/*"],
    "Condition": {"Bool": {"aws:SecureTransport": "false"}}
  }]
}'
```
