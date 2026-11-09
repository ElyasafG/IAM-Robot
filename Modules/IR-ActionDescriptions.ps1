# ================================================================
# IR-ActionDescriptions.ps1
# ----------------------------------------------------------------
# Plain-English descriptions for common AWS IAM actions.
# Used by the role/resource detail page action-info modal to give
# the auditor an instant "what does this do" alongside the
# capability check info.
#
# The map is keyed by full "service:Action" string (lowercase service).
# For actions not in the map, the modal falls back to a heuristic
# message based on the verb prefix (Get*, Put*, Delete*, List*, etc.)
# ----------------------------------------------------------------

$Global:IR_ActionDescriptions = @{
    # IAM - core identity management
    'iam:CreateRole'                = 'Creates a new IAM role. Lets the holder mint identities other principals can assume.'
    'iam:DeleteRole'                = 'Deletes an IAM role. Service roles tied to running workloads will break if deleted.'
    'iam:CreateUser'                = 'Creates a new IAM user. Often a precursor to credential-creation persistence.'
    'iam:DeleteUser'                = 'Deletes an IAM user. Used in cleanup but also in evasion to hide a created backdoor user.'
    'iam:CreatePolicy'              = 'Creates a managed IAM policy. By itself benign; combined with attach actions enables privesc.'
    'iam:CreatePolicyVersion'       = 'Adds a new version to an existing managed policy. Pairing with SetDefaultPolicyVersion is a classic privilege-escalation primitive.'
    'iam:SetDefaultPolicyVersion'   = 'Changes which version of a managed policy is active. Lets an attacker activate a previously-created malicious version.'
    'iam:DeletePolicy'              = 'Deletes a managed policy. Use case: blast-radius limitation; abuse case: defense evasion.'
    'iam:AttachRolePolicy'          = 'Attaches a managed policy to an IAM role. Direct privilege-escalation primitive if the policy is permissive (e.g. AdministratorAccess).'
    'iam:DetachRolePolicy'          = 'Detaches a managed policy from a role. Can be used to break protections, not to escalate.'
    'iam:AttachUserPolicy'          = 'Attaches a managed policy to a user. Direct privesc primitive.'
    'iam:DetachUserPolicy'          = 'Detaches a managed policy from a user.'
    'iam:AttachGroupPolicy'         = 'Attaches a managed policy to a group. Direct privesc primitive when combined with group membership control.'
    'iam:DetachGroupPolicy'         = 'Detaches a managed policy from a group.'
    'iam:PutRolePolicy'             = 'Embeds an inline policy on a role. Direct privesc primitive.'
    'iam:PutUserPolicy'             = 'Embeds an inline policy on a user. Direct privesc primitive.'
    'iam:PutGroupPolicy'            = 'Embeds an inline policy on a group. Direct privesc primitive.'
    'iam:DeleteRolePolicy'          = 'Removes an inline role policy.'
    'iam:DeleteUserPolicy'          = 'Removes an inline user policy.'
    'iam:DeleteGroupPolicy'         = 'Removes an inline group policy.'
    'iam:AddUserToGroup'            = 'Adds a user to a group, inheriting its policies. Privesc when paired with a privileged group.'
    'iam:RemoveUserFromGroup'       = 'Removes a user from a group.'
    'iam:CreateAccessKey'           = 'Creates long-lived access keys for an IAM user. Persistence primitive - usable from anywhere on the internet.'
    'iam:DeleteAccessKey'           = 'Deletes an IAM access key. Cleanup or evasion.'
    'iam:UpdateAccessKey'           = 'Enables/disables an access key (does not rotate). Can re-enable a previously disabled backdoor key.'
    'iam:CreateLoginProfile'        = 'Creates a console-login password for an IAM user. Persistence primitive.'
    'iam:UpdateLoginProfile'        = 'Updates the console password. Useful to take over an existing user.'
    'iam:DeleteLoginProfile'        = 'Removes the console password from a user.'
    'iam:UpdateAssumeRolePolicy'    = 'Rewrites a role''s trust policy. Lets the holder grant themselves (or anyone) the ability to assume the role.'
    'iam:PassRole'                  = 'Allows passing a role to another service. The single most important privilege-escalation primitive in AWS.'
    'iam:CreateInstanceProfile'     = 'Creates an EC2 instance profile (the wrapper that carries a role).'
    'iam:AddRoleToInstanceProfile'  = 'Attaches a role to an instance profile, which an EC2 instance can then use.'
    'iam:RemoveRoleFromInstanceProfile' = 'Detaches a role from an instance profile.'
    'iam:CreateOpenIDConnectProvider'  = 'Creates an OIDC provider. Federation primitive - allows external IdPs to assume roles.'
    'iam:CreateSAMLProvider'        = 'Creates a SAML federation provider.'
    'iam:UpdateOpenIDConnectProviderThumbprint' = 'Updates the OIDC thumbprint - changing it can enable spoofing of trusted token issuers.'
    'iam:ListUsers'                 = 'Enumerates IAM users in the account. Discovery primitive.'
    'iam:ListRoles'                 = 'Enumerates IAM roles in the account. Discovery primitive.'
    'iam:ListPolicies'              = 'Enumerates IAM policies. Discovery primitive.'
    'iam:ListAccessKeys'            = 'Lists access keys for a user.'
    'iam:GetRole'                   = 'Reads a role''s trust policy and metadata.'
    'iam:GetPolicy'                 = 'Reads a managed policy''s metadata (not the body).'
    'iam:GetPolicyVersion'          = 'Reads a specific version of a managed policy. Together with ListPolicies, lets you read every policy doc.'
    'iam:GetRolePolicy'             = 'Reads an inline role policy''s document.'
    'iam:SimulatePrincipalPolicy'   = 'Simulates IAM policy evaluation for a principal. Reconnaissance primitive.'
    'iam:GetAccountAuthorizationDetails' = 'Bulk-dumps every IAM identity, group, role, and policy in the account.'

    # STS
    'sts:AssumeRole'                = 'Assumes an IAM role, returning temporary credentials. Lateral movement primitive.'
    'sts:AssumeRoleWithSAML'        = 'Assumes a role using SAML federation.'
    'sts:AssumeRoleWithWebIdentity' = 'Assumes a role using an OIDC token. Used by EKS pod identity / GitHub Actions.'
    'sts:GetCallerIdentity'         = 'Returns the calling identity. Effectively a no-op; useful for reconnaissance.'
    'sts:GetSessionToken'           = 'Issues temporary credentials for the current user.'
    'sts:GetFederationToken'        = 'Issues temporary credentials for a federated user.'
    'sts:DecodeAuthorizationMessage'= 'Decodes the encoded AccessDenied message from a failed API call. Useful for debugging.'

    # S3
    's3:GetObject'                  = 'Reads object data. Most common data-exfiltration primitive in AWS.'
    's3:PutObject'                  = 'Writes object data. Can stage malicious code, replace deploy artifacts, or seed phishing pages.'
    's3:DeleteObject'               = 'Deletes objects. Destruction primitive.'
    's3:ListBucket'                 = 'Lists objects in a bucket. Discovery primitive.'
    's3:ListAllMyBuckets'           = 'Lists every bucket in the account.'
    's3:GetBucketPolicy'            = 'Reads the bucket policy document.'
    's3:PutBucketPolicy'            = 'Rewrites a bucket policy. Lets the holder grant Principal:* (public read/write).'
    's3:DeleteBucketPolicy'         = 'Removes a bucket policy entirely.'
    's3:GetBucketAcl'               = 'Reads the bucket ACL.'
    's3:PutBucketAcl'               = 'Rewrites bucket ACL. Can grant AllUsers full access.'
    's3:GetBucketPublicAccessBlock' = 'Reads the bucket''s Public-Access-Block configuration.'
    's3:PutBucketPublicAccessBlock' = 'Disables or weakens the bucket''s Public-Access-Block - precondition for making buckets public.'
    's3:DeleteBucketPublicAccessBlock' = 'Removes the Public-Access-Block entirely.'
    's3:GetBucketLogging'           = 'Reads the bucket''s access-logging config.'
    's3:PutBucketLogging'           = 'Changes or disables bucket access logging. Defense evasion.'
    's3:GetBucketVersioning'        = 'Reads the bucket''s versioning config.'
    's3:PutBucketVersioning'        = 'Toggles versioning. Disabling versioning makes deletes permanent and untraceable.'
    's3:GetEncryptionConfiguration' = 'Reads the bucket''s default encryption config.'
    's3:PutEncryptionConfiguration' = 'Changes the bucket''s default encryption. Can remove encryption entirely.'
    's3:DeleteBucket'               = 'Deletes a bucket (must be empty). Destruction primitive.'
    's3:CreateBucket'               = 'Creates a new bucket. Often part of attacker staging infrastructure.'
    's3:GetObjectAcl'               = 'Reads an object''s ACL.'
    's3:PutObjectAcl'               = 'Rewrites an object''s ACL. Can grant public-read on individual objects.'
    's3:RestoreObject'              = 'Restores an archived object from Glacier.'
    's3:AbortMultipartUpload'       = 'Cancels a multipart upload.'

    # EC2
    'ec2:RunInstances'              = 'Launches new EC2 instances. With iam:PassRole, escalates to the passed role. Without it, can still run code under the default profile or be abused for cryptomining.'
    'ec2:TerminateInstances'        = 'Destroys EC2 instances. Destruction primitive.'
    'ec2:StartInstances'            = 'Starts stopped instances.'
    'ec2:StopInstances'             = 'Stops running instances.'
    'ec2:RebootInstances'           = 'Reboots running instances.'
    'ec2:DescribeInstances'         = 'Lists EC2 instances and their config. Discovery primitive.'
    'ec2:DescribeSecurityGroups'    = 'Lists security groups and their rules. Discovery primitive.'
    'ec2:AuthorizeSecurityGroupIngress' = 'Adds an inbound rule to a security group. With 0.0.0.0/0, opens services to the internet.'
    'ec2:AuthorizeSecurityGroupEgress'  = 'Adds an outbound rule to a security group. Egress filtering bypass.'
    'ec2:RevokeSecurityGroupIngress'    = 'Removes an inbound rule from a security group.'
    'ec2:CreateSecurityGroup'       = 'Creates a new security group.'
    'ec2:DeleteSecurityGroup'       = 'Deletes a security group.'
    'ec2:ModifyInstanceAttribute'   = 'Modifies an instance''s userData, IAM role, or other attributes. Powerful primitive.'
    'ec2:ModifyInstanceMetadataOptions' = 'Re-enables IMDSv1, which is exploitable via SSRF for credential theft. Defense evasion.'
    'ec2:AssociateIamInstanceProfile'   = 'Attaches a role to a running instance. Privesc primitive.'
    'ec2:ReplaceIamInstanceProfileAssociation' = 'Swaps one role for another on a running instance.'
    'ec2:DisassociateIamInstanceProfile' = 'Removes an IAM role from a running instance.'
    'ec2:CreateImage'               = 'Creates an AMI from a running instance, including any data on its volumes.'
    'ec2:CopyImage'                 = 'Copies an AMI - can copy to a different account for exfil.'
    'ec2:ModifyImageAttribute'      = 'Changes who can launch an AMI. Can share private AMIs with arbitrary AWS accounts.'
    'ec2:CreateSnapshot'            = 'Creates an EBS snapshot. Snapshots include all data on the volume.'
    'ec2:CopySnapshot'              = 'Copies an EBS snapshot - can be used for cross-account exfil.'
    'ec2:ModifySnapshotAttribute'   = 'Changes who can access a snapshot. Can make snapshots public or share to external accounts.'
    'ec2:DeleteSnapshot'            = 'Deletes an EBS snapshot. Destruction primitive.'
    'ec2:GetPasswordData'           = 'Retrieves the encrypted Windows Administrator password for an EC2 instance. Credential access.'
    'ec2:GetConsoleOutput'          = 'Retrieves the boot-time console output of an instance. Can leak credentials in some configs.'
    'ec2:GetConsoleScreenshot'      = 'Returns a screenshot of the instance console. Can reveal interactive credentials.'
    'ec2:CreateKeyPair'             = 'Creates a new EC2 key pair. Persistence primitive.'
    'ec2:ImportKeyPair'             = 'Imports an attacker-controlled SSH public key as a key pair.'
    'ec2:DeleteKeyPair'             = 'Deletes a key pair.'
    'ec2:DescribeRegions'           = 'Lists enabled regions in the account. Discovery primitive.'

    # Lambda
    'lambda:CreateFunction'         = 'Creates a Lambda function. With iam:PassRole, lets the holder assume the passed role.'
    'lambda:UpdateFunctionCode'     = 'Rewrites a Lambda''s code. If the function''s execution role is more privileged, this is a direct privesc primitive.'
    'lambda:UpdateFunctionConfiguration' = 'Changes a Lambda''s config - environment variables, role, runtime.'
    'lambda:InvokeFunction'         = 'Invokes a Lambda. With UpdateFunctionCode, lets you run code under the function''s role.'
    'lambda:DeleteFunction'         = 'Deletes a Lambda function.'
    'lambda:AddPermission'          = 'Adds a permission to a Lambda''s resource policy. Can expose the function to external accounts or public.'
    'lambda:RemovePermission'       = 'Removes a permission from a Lambda''s resource policy.'
    'lambda:CreateFunctionUrlConfig'    = 'Exposes a Lambda function via a public URL.'
    'lambda:UpdateFunctionUrlConfig'    = 'Changes the auth model of a function URL. Can disable IAM auth.'
    'lambda:GetFunction'            = 'Reads function metadata, including environment variables (which often contain secrets).'
    'lambda:GetPolicy'              = 'Reads a Lambda''s resource policy.'
    'lambda:ListFunctions'          = 'Lists all Lambda functions in the region.'

    # KMS
    'kms:Decrypt'                   = 'Decrypts ciphertext encrypted by a KMS key. Credential-access primitive when applied to envelope-encrypted secrets.'
    'kms:Encrypt'                   = 'Encrypts data with a KMS key.'
    'kms:GenerateDataKey'           = 'Returns a plaintext + encrypted data key. Used for envelope encryption.'
    'kms:ReEncrypt'                 = 'Re-encrypts data with a different KMS key. Can be abused to switch keys.'
    'kms:CreateKey'                 = 'Creates a new KMS key.'
    'kms:ScheduleKeyDeletion'       = 'Schedules a KMS key for deletion. 7-30 day window after which everything encrypted by it is unrecoverable.'
    'kms:DisableKey'                = 'Disables a KMS key. Anything encrypted by it temporarily unrecoverable.'
    'kms:PutKeyPolicy'              = 'Rewrites a KMS key policy. Direct credential-access primitive: grant yourself kms:Decrypt.'
    'kms:GetKeyPolicy'              = 'Reads a KMS key policy.'
    'kms:CreateGrant'               = 'Grants another principal the use of a key. Alternative to key policy.'
    'kms:RevokeGrant'               = 'Revokes a KMS grant.'
    'kms:ListKeys'                  = 'Lists KMS keys.'
    'kms:DescribeKey'               = 'Reads a KMS key''s metadata.'

    # Secrets Manager
    'secretsmanager:GetSecretValue' = 'Reads the secret value. Direct credential access.'
    'secretsmanager:PutSecretValue' = 'Writes a new secret version. Can overwrite a legitimate secret with attacker-controlled value.'
    'secretsmanager:CreateSecret'   = 'Creates a new secret.'
    'secretsmanager:UpdateSecret'   = 'Updates secret metadata or value.'
    'secretsmanager:DeleteSecret'   = 'Schedules a secret for deletion.'
    'secretsmanager:RestoreSecret'  = 'Cancels deletion of a scheduled-deletion secret.'
    'secretsmanager:DescribeSecret' = 'Reads secret metadata (not the value).'
    'secretsmanager:ListSecrets'    = 'Lists all secrets. Discovery primitive.'
    'secretsmanager:PutResourcePolicy'   = 'Rewrites a secret''s resource policy.'
    'secretsmanager:GetResourcePolicy'   = 'Reads a secret''s resource policy.'
    'secretsmanager:RotateSecret'   = 'Triggers secret rotation.'

    # SSM
    'ssm:GetParameter'              = 'Reads a parameter value. For SecureString parameters, this is credential access.'
    'ssm:GetParameters'             = 'Reads multiple parameters at once.'
    'ssm:GetParametersByPath'       = 'Reads every parameter under a path prefix. Often used to enumerate secrets.'
    'ssm:PutParameter'              = 'Writes a parameter value.'
    'ssm:DeleteParameter'           = 'Deletes a parameter.'
    'ssm:SendCommand'               = 'Runs commands on managed EC2 instances. Code-execution primitive on every covered instance.'
    'ssm:StartSession'              = 'Opens an interactive shell session on a managed instance. Lateral movement primitive.'
    'ssm:CreateDocument'            = 'Creates an SSM document - automation, command, or session template.'
    'ssm:UpdateDocument'            = 'Updates an SSM document.'
    'ssm:DescribeAssociation'       = 'Reads SSM associations (which documents run on which instances).'
    'ssm:ModifyDocumentPermission'  = 'Shares an SSM document with other accounts.'
    'ssm:CreateAssociation'         = 'Schedules an SSM document to run on instances. Persistence primitive.'
    'ssm:GetCommandInvocation'      = 'Reads the output of a previously-issued SendCommand.'

    # CloudTrail
    'cloudtrail:CreateTrail'        = 'Creates a CloudTrail trail.'
    'cloudtrail:UpdateTrail'        = 'Updates a CloudTrail trail config.'
    'cloudtrail:DeleteTrail'        = 'Deletes a CloudTrail trail. Defense evasion.'
    'cloudtrail:StopLogging'        = 'Stops logging on a trail without deleting it. Stealth defense evasion.'
    'cloudtrail:StartLogging'       = 'Resumes logging on a trail.'
    'cloudtrail:PutEventSelectors'  = 'Changes which event types are recorded. Can exclude attacker activity from logs.'
    'cloudtrail:GetTrail'           = 'Reads trail config.'
    'cloudtrail:DescribeTrails'     = 'Lists all trails.'
    'cloudtrail:LookupEvents'       = 'Searches CloudTrail logs.'

    # Config
    'config:DeleteConfigurationRecorder'    = 'Deletes a Config recorder. Defense evasion.'
    'config:StopConfigurationRecorder'      = 'Stops a Config recorder. Defense evasion.'
    'config:DeleteDeliveryChannel'          = 'Deletes the Config delivery channel.'
    'config:DeleteConfigRule'               = 'Deletes a Config rule. Disables compliance check.'
    'config:DeleteRemediationConfiguration' = 'Deletes auto-remediation for a Config rule.'

    # CloudWatch
    'cloudwatch:PutMetricAlarm'     = 'Creates or updates a CloudWatch alarm.'
    'cloudwatch:DeleteAlarms'       = 'Deletes alarms. Defense evasion.'
    'cloudwatch:DisableAlarmActions'= 'Disables actions on an alarm without deleting it. Stealth defense evasion.'

    # CloudWatch Logs
    'logs:CreateLogGroup'           = 'Creates a CloudWatch log group.'
    'logs:DeleteLogGroup'           = 'Deletes a log group with all its data. Defense evasion.'
    'logs:DeleteLogStream'          = 'Deletes a log stream.'
    'logs:PutRetentionPolicy'       = 'Sets log retention. Setting to 1 day effectively destroys older logs.'
    'logs:CreateExportTask'         = 'Exports logs to S3 - can be used to exfil logs to attacker-controlled buckets.'
    'logs:PutResourcePolicy'        = 'Rewrites the log-group resource policy.'

    # GuardDuty / SecurityHub / Macie / Inspector
    'guardduty:DeleteDetector'      = 'Deletes a GuardDuty detector, disabling all threat detection in the region. Critical defense evasion.'
    'guardduty:UpdateDetector'      = 'Disables a GuardDuty detector (Status=DISABLED). Stealth defense evasion.'
    'guardduty:CreateFilter'        = 'Creates a GuardDuty suppression filter - can hide attacker findings.'
    'guardduty:UpdateFilter'        = 'Updates a suppression filter to hide more findings.'
    'guardduty:CreateIPSet'         = 'Creates a trusted-IP list. Adding attacker IPs disables alerting on them.'
    'securityhub:DisableSecurityHub'= 'Disables Security Hub entirely.'
    'securityhub:UpdateStandardsControl' = 'Disables specific compliance controls.'
    'macie2:DisableMacie'           = 'Disables Macie data classification.'
    'inspector2:Disable'            = 'Disables Inspector vulnerability scanning.'

    # Organizations
    'organizations:LeaveOrganization' = 'Removes the current account from its AWS Organization. Detaches it from SCPs, central CloudTrail, etc. Catastrophic defense evasion.'
    'organizations:RemoveAccountFromOrganization' = 'Removes another account from the organization.'

    # Cognito / SSO
    'cognito-idp:AdminSetUserPassword'    = 'Sets a Cognito user''s password directly.'
    'cognito-idp:AdminCreateUser'         = 'Creates a Cognito user.'
    'cognito-identity:SetIdentityPoolRoles' = 'Sets the auth/unauth roles for a Cognito identity pool. Lets unauthenticated users assume those roles.'

    # ECR
    'ecr:GetAuthorizationToken'     = 'Returns a token to authenticate Docker against ECR.'
    'ecr:BatchGetImage'             = 'Reads container images.'
    'ecr:PutImage'                  = 'Pushes a container image.'
    'ecr:DeleteRepository'          = 'Deletes an ECR repository.'
    'ecr:SetRepositoryPolicy'       = 'Sets the ECR repository policy. Can grant cross-account pull/push.'

    # ECS / EKS
    'ecs:RunTask'                   = 'Runs an ECS task. With iam:PassRole, can run code as the task role.'
    'ecs:RegisterTaskDefinition'    = 'Registers a task definition. Pairs with RunTask + PassRole for privesc.'
    'ecs:UpdateService'             = 'Updates an ECS service. Can change task definition to an attacker-controlled one.'
    'ecs:ExecuteCommand'            = 'Opens an interactive shell into a running ECS task.'
    'eks:AccessKubernetesApi'       = 'Calls the Kubernetes API via IAM-authenticated access. Cluster-takeover primitive.'
    'eks:UpdateClusterConfig'       = 'Updates EKS cluster config, e.g. making the API endpoint public.'
    'eks:DescribeCluster'           = 'Reads EKS cluster metadata including the API endpoint.'
}

# ----------------------------------------------------------------
# Get-ActionDescription - returns a human description for an action.
# Falls back to a verb-prefix heuristic for unknown actions.
# ----------------------------------------------------------------
function Get-ActionDescription {
    param([string]$Action)
    if (-not $Action) { return '' }
    if ($Global:IR_ActionDescriptions.ContainsKey($Action)) {
        return $Global:IR_ActionDescriptions[$Action]
    }
    # Heuristic fallback by verb prefix
    $parts = $Action -split ':',2
    if ($parts.Count -ne 2) { return 'IAM action.' }
    $svc = $parts[0]
    $act = $parts[1]
    $verb = ''
    if ($act -match '^([A-Z][a-z]+)') { $verb = $Matches[1] }
    switch ($verb) {
        'Get'        { return "Read operation on $svc. Reconnaissance value depends on the resource - often returns metadata; sometimes returns secrets or configuration." }
        'List'       { return "Enumeration operation on $svc. Discovery primitive - lists resources of a given type." }
        'Describe'   { return "Read operation on $svc. Reads resource metadata. Discovery primitive when broad." }
        'Search'     { return "Search operation on $svc. Discovery primitive." }
        'Batch'      { return "Bulk operation on $svc. Higher impact than equivalent single-resource operation." }
        'Create'     { return "Resource-creation in $svc. Persistence or staging primitive if uncontrolled." }
        'Put'        { return "Write/replace operation on $svc. Modifies existing or creates new state." }
        'Update'     { return "Mutation in $svc. Modifies existing state." }
        'Modify'     { return "Mutation in $svc. Often more powerful than Update." }
        'Delete'     { return "Destruction in $svc. Irreversible without backups." }
        'Remove'     { return "Removal operation in $svc. Sometimes destructive, sometimes detaching." }
        'Detach'     { return "Detachment operation in $svc." }
        'Attach'     { return "Attachment operation in $svc. Privesc primitive when attaching policies." }
        'Start'      { return "State-change in $svc - starts something." }
        'Stop'       { return "State-change in $svc - stops something. Sometimes used in defense evasion." }
        'Restart'    { return "State-change in $svc." }
        'Run'        { return "Execution primitive in $svc. Often code-execution-grade." }
        'Invoke'     { return "Invocation primitive in $svc." }
        'Execute'    { return "Execution primitive in $svc." }
        'Send'       { return "Outbound action in $svc - sends data somewhere." }
        'Publish'    { return "Outbound publication in $svc." }
        'Assume'     { return "Identity-assumption in $svc. Lateral movement primitive." }
        'Pass'       { return "Identity-passing in $svc. Privesc primitive." }
        'Decrypt'    { return "Cryptographic operation in $svc - reveals plaintext from ciphertext." }
        'Encrypt'    { return "Cryptographic operation in $svc - produces ciphertext." }
        'Sign'       { return "Cryptographic operation in $svc - produces a signature." }
        default      { return "$svc action. Effect depends on the specific operation - check the AWS documentation for $Action." }
    }
}
