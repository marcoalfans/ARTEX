---
name: cloud-misconfig
description: "Invoke this skill when the task requires testing for cloud infrastructure misconfigurations under authorized engagement: AWS, GCP, and Azure. Covers S3/GCS/Blob bucket policy flaws, IAM privilege escalation, metadata service exposure, security group and firewall misconfigurations, exposed credentials, serverless function abuse, and cross-account trust issues. Tools include aws-cli, gcloud, az, and manual API enumeration."
---

# Cloud Misconfiguration Testing (AWS, GCP, Azure)

This skill covers identification and exploitation of cloud infrastructure misconfigurations across the three major providers. Findings require proof of unauthorized access, data exposure, or privilege escalation; a misconfigured setting alone is informational unless its impact is demonstrated.

## Boundaries

| Allowed | Prohibited |
|---|---|
| Enumerating bucket policies, IAM roles, and security groups within scope | Accessing cloud accounts or subscriptions outside authorized scope |
| Reading objects from misconfigured public buckets to prove exposure | Mass downloading or exfiltrating production data beyond proof samples |
| Demonstrating IAM escalation paths with test credentials | Using escalated permissions to modify production infrastructure |
| Enumerating metadata services from authorized compute instances | Pivoting to other customers' resources via shared infrastructure |
| Testing serverless function configurations within scope | Deploying persistent backdoor functions or modifying production functions |
| Documenting exposed credentials found in public repos or responses | Using discovered credentials to access resources beyond proving validity |
| Testing cross-account trust with authorized accounts only | Accessing third-party accounts via misconfigured trust relationships |

## Phase 0: Pre-engagement setup

### 0.1 Scope confirmation

1. Confirm which cloud accounts, subscriptions, or projects are in scope (by account ID, project ID, or subscription ID).
2. Identify which services are authorized for testing (storage, compute, IAM, networking, serverless, databases).
3. Confirm the credentials or access provided for testing (read-only audit role, specific IAM user, etc.).
4. Determine whether the engagement allows active exploitation or only configuration audit.

### 0.2 Tool setup

```bash
# AWS CLI
aws --version
aws sts get-caller-identity    # Verify authenticated identity

# GCP
gcloud --version
gcloud auth list
gcloud config get-value project

# Azure
az --version
az account show

# Additional tools
pip install pacu               # AWS exploitation framework (if approved)
pip install ScoutSuite          # Multi-cloud audit (if approved)
```

### 0.3 Working directory

```bash
mkdir -p work/cloud-misconfig/{aws,gcp,azure,credentials,proofs}
```

## Phase 1: Storage bucket misconfiguration

### 1.1 AWS S3

**Discovery:**
```bash
# Check if bucket exists and is accessible
aws s3 ls s3://BUCKET_NAME/ --no-sign-request 2>&1
aws s3 ls s3://BUCKET_NAME/ 2>&1    # with credentials

# Get bucket policy
aws s3api get-bucket-policy --bucket BUCKET_NAME --output json 2>&1
aws s3api get-bucket-acl --bucket BUCKET_NAME 2>&1

# Check public access block settings
aws s3api get-public-access-block --bucket BUCKET_NAME 2>&1

# Check bucket versioning (may expose deleted sensitive files)
aws s3api get-bucket-versioning --bucket BUCKET_NAME 2>&1
aws s3api list-object-versions --bucket BUCKET_NAME --max-keys 10 2>&1
```

**Exploitation proof:**
```bash
# List contents (unauthenticated)
aws s3 ls s3://BUCKET_NAME/ --no-sign-request --recursive --max-items 20

# Read a file (proof of access)
aws s3 cp s3://BUCKET_NAME/sample-file.txt /tmp/proof.txt --no-sign-request

# Check for write access
echo "privesc-test" > /tmp/write-test.txt
aws s3 cp /tmp/write-test.txt s3://BUCKET_NAME/write-test-DELETE-ME.txt --no-sign-request
# IMMEDIATELY delete if successful:
aws s3 rm s3://BUCKET_NAME/write-test-DELETE-ME.txt --no-sign-request
```

**Common S3 policy mistakes to check:**
- [ ] `Principal: "*"` with `s3:GetObject` (public read).
- [ ] `Principal: "*"` with `s3:PutObject` (public write).
- [ ] `Principal: "*"` with `s3:ListBucket` (public listing).
- [ ] ACL granting `AllUsers` or `AuthenticatedUsers` read/write.
- [ ] Bucket policy allowing access from any AWS account.
- [ ] Server-side encryption not enforced (`s3:PutObject` without encryption condition).

### 1.2 GCP Cloud Storage

```bash
# Public bucket access
gsutil ls gs://BUCKET_NAME/ 2>&1
gsutil cat gs://BUCKET_NAME/sample-file.txt 2>&1

# Bucket IAM policy
gsutil iam get gs://BUCKET_NAME/ 2>&1

# Check for allUsers / allAuthenticatedUsers bindings
gsutil iam get gs://BUCKET_NAME/ 2>&1 | grep -E 'allUsers|allAuthenticatedUsers'
```

### 1.3 Azure Blob Storage

```bash
# Public container access
az storage blob list --account-name ACCOUNT --container-name CONTAINER --auth-mode anonymous 2>&1

# Check container access level
az storage container show --account-name ACCOUNT --name CONTAINER --auth-mode anonymous 2>&1

# Enumerate storage accounts
az storage account list --query '[].{name:name,id:id}' -o table 2>&1
```

## Phase 2: IAM privilege escalation

### 2.1 AWS IAM enumeration

```bash
# Current identity and permissions
aws sts get-caller-identity
aws iam get-user 2>&1
aws iam list-attached-user-policies --user-name USERNAME 2>&1
aws iam list-user-policies --user-name USERNAME 2>&1

# Enumerate all policies (if permitted)
aws iam list-policies --only-attached --query 'Policies[*].{Name:PolicyName,Arn:Arn}' -o table 2>&1
aws iam list-roles --query 'Roles[*].{Name:RoleName,Arn:Arn}' -o table 2>&1

# Get specific policy version (to read the actual permissions)
aws iam get-policy-version --policy-arn POLICY_ARN --version-id v1 2>&1
```

### 2.2 AWS IAM escalation paths

Check whether the current user/role can perform any of these escalation actions:

| Escalation path | Required permission | Technique |
|---|---|---|
| Attach admin policy | `iam:AttachUserPolicy` | Attach `AdministratorAccess` to self |
| Create policy version | `iam:CreatePolicyVersion` | Create a new version of an attached policy with `*:*` |
| Set default version | `iam:SetDefaultPolicyVersion` | Promote a permissive policy version |
| Create access key | `iam:CreateAccessKey` | Create key for a more privileged user |
| Assume role | `sts:AssumeRole` | Assume a role with broader permissions |
| Pass role + Lambda | `iam:PassRole` + `lambda:CreateFunction` | Create Lambda with privileged execution role |
| Pass role + EC2 | `iam:PassRole` + `ec2:RunInstances` | Launch EC2 with a privileged instance profile |
| Pass role + CloudFormation | `iam:PassRole` + `cloudformation:CreateStack` | Deploy stack with privileged service role |
| Update function code | `lambda:UpdateFunctionCode` | Modify existing Lambda to exfiltrate its role creds |
| Put user/group policy | `iam:PutUserPolicy` / `iam:PutGroupPolicy` | Add inline policy with `*:*` |
| Create login profile | `iam:CreateLoginProfile` | Create console password for a privileged user |

```bash
# Test: can we attach AdministratorAccess?
aws iam attach-user-policy --user-name USERNAME \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess --dry-run 2>&1

# Test: can we assume a privileged role?
aws sts assume-role --role-arn arn:aws:iam::ACCOUNT:role/ROLE_NAME \
  --role-session-name test 2>&1
```

### 2.3 GCP IAM escalation

```bash
# Current permissions
gcloud projects get-iam-policy PROJECT_ID --format=json 2>&1

# Service account enumeration
gcloud iam service-accounts list --project PROJECT_ID 2>&1

# Check for service account key creation permission
gcloud iam service-accounts keys list --iam-account SA_EMAIL 2>&1

# Service account impersonation
gcloud auth print-access-token --impersonate-service-account=SA_EMAIL 2>&1
```

**GCP escalation vectors:**
- [ ] `iam.serviceAccountKeys.create` on a privileged SA.
- [ ] `iam.serviceAccounts.actAs` + compute or cloud functions create.
- [ ] `resourcemanager.projects.setIamPolicy` (grant self Owner).
- [ ] `deploymentmanager.deployments.create` with SA impersonation.

### 2.4 Azure IAM escalation

```bash
# Current role assignments
az role assignment list --assignee CURRENT_USER --all -o table 2>&1

# Check for custom role definitions with broad permissions
az role definition list --custom-role-only --query '[*].{Name:roleName,Actions:permissions[0].actions}' -o table 2>&1

# Service principal enumeration
az ad sp list --all --query '[*].{Name:displayName,AppId:appId}' -o table 2>&1
```

## Phase 3: Metadata service exposure

Test from authorized compute instances within the scope.

### 3.1 AWS EC2 metadata

```bash
# IMDSv1 (no token required)
curl -s http://169.254.169.254/latest/meta-data/
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
curl -s http://169.254.169.254/latest/user-data

# IMDSv2 check
TOKEN=$(curl -s -X PUT http://169.254.169.254/latest/api/token \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s http://169.254.169.254/latest/meta-data/ \
  -H "X-aws-ec2-metadata-token: $TOKEN"

# Check if IMDSv1 is disabled (IMDSv2-only)
# If IMDSv1 works without token, that itself is a finding
```

### 3.2 GCP metadata

```bash
curl -s -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
curl -s -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/project/attributes/
```

### 3.3 Azure IMDS

```bash
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

### 3.4 Metadata findings classification

- **Critical**: temporary credentials with broad permissions (admin, `*:*`) accessible from metadata.
- **High**: temporary credentials with limited but sensitive permissions (S3 write, IAM read).
- **Medium**: IMDSv1 enabled when IMDSv2 should be enforced (credential theft via SSRF risk).
- **Low**: metadata accessible but no sensitive data (instance ID, region only).

## Phase 4: Network and security group misconfiguration

### 4.1 AWS security groups

```bash
# List security groups with open ingress
aws ec2 describe-security-groups \
  --filters "Name=ip-permission.cidr,Values=0.0.0.0/0" \
  --query 'SecurityGroups[*].{GroupId:GroupId,GroupName:GroupName,Permissions:IpPermissions}' \
  -o json 2>&1

# Check for overly permissive rules
aws ec2 describe-security-groups \
  --query 'SecurityGroups[*].IpPermissions[?contains(IpRanges[].CidrIp, `0.0.0.0/0`)]' \
  -o json 2>&1
```

**Critical open ports to flag:**
- [ ] SSH (22) open to `0.0.0.0/0`.
- [ ] RDP (3389) open to `0.0.0.0/0`.
- [ ] Database ports (3306, 5432, 1433, 27017) open to `0.0.0.0/0`.
- [ ] All traffic (`-1` protocol) open to `0.0.0.0/0`.

### 4.2 GCP firewall rules

```bash
gcloud compute firewall-rules list --format=json \
  --filter="sourceRanges:0.0.0.0/0" 2>&1
```

### 4.3 Azure network security groups

```bash
az network nsg list --query '[*].{Name:name,Rules:securityRules}' -o json 2>&1
az network nsg rule list --nsg-name NSG_NAME --resource-group RG_NAME -o table 2>&1
```

## Phase 5: Exposed credentials

### 5.1 Source code and configuration scanning

```bash
# Search for AWS keys in environment variables and config files
grep -rn 'AKIA[A-Z0-9]{16}' /path/to/codebase/ 2>/dev/null    # AWS access keys
grep -rn 'aws_secret_access_key' /path/to/codebase/ 2>/dev/null
grep -rn 'aws_session_token' /path/to/codebase/ 2>/dev/null

# GCP service account keys
find /path/to/codebase/ -name '*.json' -exec grep -l '"type": "service_account"' {} \; 2>/dev/null

# Azure credentials
grep -rn 'client_secret' /path/to/codebase/ 2>/dev/null
grep -rn 'subscription_id' /path/to/codebase/ 2>/dev/null

# General secrets
grep -rnE '(password|passwd|secret|token|api_key|apikey)[\s]*[=:]' /path/to/codebase/ 2>/dev/null
```

### 5.2 Credential validation (read-only)

```bash
# Validate AWS key (read-only identity check)
AWS_ACCESS_KEY_ID=FOUND_KEY AWS_SECRET_ACCESS_KEY=FOUND_SECRET \
  aws sts get-caller-identity 2>&1

# Validate GCP SA key
gcloud auth activate-service-account --key-file=found-key.json 2>&1
gcloud auth list 2>&1

# Validate Azure SP
az login --service-principal -u APP_ID -p SECRET --tenant TENANT_ID 2>&1
az account show 2>&1
```

**Do not exercise the credentials beyond identity verification.** Document the identity, permissions (via policy enumeration), and exposure vector.

### 5.3 Public exposure checks

- [ ] GitHub/GitLab search for the organization's key patterns.
- [ ] Docker Hub images with embedded credentials.
- [ ] Terraform state files (`.tfstate`) in public buckets.
- [ ] CI/CD pipeline logs exposing environment variables.
- [ ] Public `.env` files via web server misconfiguration.

## Phase 6: Serverless misconfiguration

### 6.1 AWS Lambda

```bash
# List functions
aws lambda list-functions --query 'Functions[*].{Name:FunctionName,Runtime:Runtime,Role:Role}' -o table 2>&1

# Get function configuration (environment variables may contain secrets)
aws lambda get-function-configuration --function-name FUNCTION_NAME 2>&1

# Get function code (if permissions allow)
aws lambda get-function --function-name FUNCTION_NAME --query 'Code.Location' -o text 2>&1

# Check resource policy (who can invoke)
aws lambda get-policy --function-name FUNCTION_NAME 2>&1
```

**Lambda findings to check:**
- [ ] Environment variables containing plaintext secrets.
- [ ] Overly permissive execution role (admin access).
- [ ] Public invocation allowed (`Principal: "*"` in resource policy).
- [ ] Outdated runtime with known vulnerabilities.
- [ ] Function URL with no auth (`AuthType: NONE`).

### 6.2 GCP Cloud Functions

```bash
gcloud functions list --format=json 2>&1
gcloud functions describe FUNCTION_NAME --format=json 2>&1
# Check invoker permissions
gcloud functions get-iam-policy FUNCTION_NAME 2>&1
```

### 6.3 Azure Functions

```bash
az functionapp list --query '[*].{Name:name,State:state,URL:defaultHostName}' -o table 2>&1
az functionapp config appsettings list --name FUNCTION_NAME --resource-group RG_NAME 2>&1
```

## Phase 7: Cross-account and cross-service trust

### 7.1 AWS cross-account roles

```bash
# Check role trust policies for external account access
aws iam list-roles --query 'Roles[*].{Name:RoleName,Trust:AssumeRolePolicyDocument}' -o json 2>&1

# Look for trust policies that allow:
# - External account IDs in Principal
# - Missing ExternalId condition (confused deputy)
# - Principal: "*" (any AWS account can assume)
# - Overly broad conditions
```

### 7.2 Resource-based policy checks

```bash
# S3 bucket policy allowing cross-account access
aws s3api get-bucket-policy --bucket BUCKET_NAME 2>&1

# SNS topic policy
aws sns get-topic-attributes --topic-arn TOPIC_ARN 2>&1

# SQS queue policy
aws sqs get-queue-attributes --queue-url QUEUE_URL --attribute-names Policy 2>&1

# KMS key policy
aws kms get-key-policy --key-id KEY_ID --policy-name default 2>&1
```

## Verification requirements

A finding is **confirmed** only when ALL of the following are met:

1. **Impact demonstration**: the misconfiguration leads to actual unauthorized access, data exposure, or privilege escalation, not merely a suboptimal setting:
   - Bucket finding: at least one object was read (or write was proven and immediately cleaned up).
   - IAM finding: the escalation path was walked to the point of elevated identity verification (`sts get-caller-identity` or equivalent with the new permissions).
   - Credential finding: the credential was validated as active and its permission scope documented.
   - Network finding: the exposed service was confirmed reachable from an unauthorized network position.
2. **Replayable artifact**: CLI commands or API calls that reproduce the finding.
3. **Provider and service documented**: specific AWS/GCP/Azure service, resource ARN/ID/URL, and the misconfigured setting.
4. **Scope of impact**: what data or systems are reachable via the misconfiguration (count of objects, breadth of IAM permissions, number of exposed instances).
5. **No production modification**: infrastructure was not changed, data was not deleted, and credentials were not used beyond validation.

## Output format

```markdown
## Cloud Misconfiguration Finding: [provider] - [service] - [issue]

**Severity**: Critical / High / Medium / Low
**Provider**: AWS / GCP / Azure
**Service**: S3 / IAM / EC2 / Lambda / etc.
**Account/Project**: 123456789012 / project-id / subscription-id

### Misconfiguration
- **Resource**: arn:aws:s3:::company-backup-bucket
- **Setting**: Bucket policy allows `s3:GetObject` with `Principal: "*"`
- **Public access block**: disabled

### Proof of impact
- **Objects accessible**: 14,328 objects in bucket (listed first 20)
- **Sample file read**: `backup-2024-01-15.sql.gz` (8.2 GB) - confirmed downloadable
- **Data classification**: database backups containing user PII

### Replayable commands
\```bash
aws s3 ls s3://company-backup-bucket/ --no-sign-request --recursive | head -20
aws s3 cp s3://company-backup-bucket/sample.txt /tmp/proof.txt --no-sign-request
\```

### Impact
- Full read access to production database backups without authentication.
- Backups contain user PII (names, emails, password hashes).
- Bucket has been public since [creation date if determinable].

### Remediation
- Enable S3 Block Public Access at the account level.
- Remove `Principal: "*"` from the bucket policy.
- Restrict access to specific IAM roles via bucket policy conditions.
- Enable S3 access logging and review historical access patterns.
- Rotate any credentials found in exposed backups.
```

## Completion self-check

- [ ] Storage buckets in scope tested for public read, write, and listing.
- [ ] IAM policies and roles enumerated; escalation paths identified and tested.
- [ ] Metadata services tested from all authorized compute instances.
- [ ] Security groups / firewall rules reviewed for overly permissive ingress.
- [ ] Source code and configuration scanned for exposed credentials.
- [ ] Serverless functions checked for environment variable secrets and permissive invocation policies.
- [ ] Cross-account trust relationships reviewed for confused deputy and overly broad access.
- [ ] Every finding has demonstrated impact, not just configuration weakness.
- [ ] All replayable commands are saved; no production modifications were made.
- [ ] Credentials found were validated (identity check only) and not exercised further.
