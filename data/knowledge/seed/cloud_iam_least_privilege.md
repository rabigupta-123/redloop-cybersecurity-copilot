---
title: "AWS IAM Least Privilege & Role Security Guide"
tags: ["cloud", "aws", "iam", "least-privilege", "roles", "scp"]
source: "NIST SP 800-53 Rev 5 AC-6 / CIS AWS Benchmark Section 1"
---

# AWS IAM Least Privilege & Role Security Guide
## Source & Authority
NIST SP 800-53 Rev 5 Control AC-6 (Least Privilege); CIS AWS Foundations Benchmark v2.0 Section 1.

## Architecture & Implementation
1. **Zero Long-Lived Credentials:** Do not create static IAM users or long-lived access keys for applications. Utilize IAM Roles with AWS STS temporary credentials (assume role duration capped).
2. **Permission Boundaries & SCPs:** Enforce Service Control Policies (SCPs) at the AWS Organizations root to explicitly deny high-risk administrative operations (`iam:DeactivateMFADevice`, `organizations:LeaveOrganization`).
3. **Action-Level Scoping:** Restrict wildcard permissions (`*`). Define resource ARNs explicitly in `Resource` stanzas.
4. **Conditional Access:** Use IAM policy conditions: require `aws:MultiFactorAuthPresent: true` for sensitive operations and `aws:SourceIp` / `aws:VpcSourceIp` restrictions.
5. **Continuous Credential Pruning:** Automate identification of unused credentials with AWS IAM Access Analyzer and credential reports. Deactivate keys unused for > 90 days.
