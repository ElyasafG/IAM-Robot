# Modules/IR-CapabilityLibrary.ps1
# ============================================================
#  Single source of truth for all role-capability findings.
#  Each entry describes:
#    Id        - short stable code (Cxxx)
#    Name      - display name
#    Severity  - CRITICAL/HIGH/MEDIUM/LOW/INFO
#    MitreTactic - MITRE ATT&CK Cloud Matrix tactic + technique ID
#    Vendor    - which industry sources document the pattern
#    Reference - URL(s) to relevant blog/KB/research article
#    Description, Impact, Recommend
#    Match     - a script-block that takes $Effective (hashtable) and
#                returns @{ Matched=[bool]; Actions=@(); Notes='' }
# ============================================================

# ----------------------------------------------------------------
# Match helpers - return matched-action-list (non-empty == matched).
# Honor Effect: only Allow counts. Deny overrides suppress matching.
# ----------------------------------------------------------------
function Get-AllowedActions {
    param([hashtable]$Effective, [string[]]$Required)
    $hits = New-Object System.Collections.Generic.List[string]
    foreach ($a in $Required) {
        if ($Effective.ContainsKey($a) -and $Effective[$a].Effect -eq 'Allow') {
            [void]$hits.Add($a)
        }
    }
    return $hits.ToArray()
}

function Test-ResourceWildcard {
    param([hashtable]$Effective, [string]$Action)
    if (-not $Effective.ContainsKey($Action)) { return $false }
    $rec = $Effective[$Action]
    if ($rec.Effect -ne 'Allow') { return $false }
    if ($rec.Resources.Count -eq 0) { return $true }
    foreach ($r in $rec.Resources) { if ($r -eq '*') { return $true } }
    return $false
}

# Find which source policies contributed to a matched action set
function Get-SourcePolicies {
    param([hashtable]$Effective, [string[]]$Actions)
    $set = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($a in $Actions) {
        if (-not $Effective.ContainsKey($a)) { continue }
        foreach ($p in $Effective[$a].AllowVia) { [void]$set.Add($p) }
    }
    return @($set)
}

# ----------------------------------------------------------------
# The full capability library.
# Each pattern is a hashtable. Detection logic is in 'Match' as a script block.
# ----------------------------------------------------------------
$Global:IR_Capabilities = @(

    # ============ PRIVILEGE ESCALATION ============
    @{
        Id='C001'; Name='PrivEsc: CreatePolicyVersion + SetDefaultPolicyVersion'
        Severity='CRITICAL'; MitreTactic='TA0004 Privilege Escalation (T1098.003)'
        Vendor='Rhino Security Labs, Prisma Cloud, Wiz'
        Reference='https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/'
        Description='Role can create a new version of a customer-managed policy and set it as default. Grants any permission to itself or another principal.'
        Impact='Full account compromise. Attacker writes a wildcard policy version, sets default, instantly admin.'
        Recommend='Remove iam:CreatePolicyVersion and iam:SetDefaultPolicyVersion or scope to specific policy ARNs.'
        Required=@('iam:CreatePolicyVersion','iam:SetDefaultPolicyVersion')
    }
    @{
        Id='C002'; Name='PrivEsc: iam:PassRole + Lambda CreateFunction+InvokeFunction'
        Severity='CRITICAL'; MitreTactic='TA0004 Privilege Escalation (T1078.004)'
        Vendor='Rhino Security Labs, Prisma Cloud, Wiz, Crowdstrike Falcon Cloud'
        Reference='https://bishopfox.com/blog/privilege-escalation-in-aws'
        Description='Role can pass any IAM role to a new Lambda function that it then invokes - assumes the passed role indirectly.'
        Impact='Lateral pivot to higher-privilege roles via Lambda execution context.'
        Recommend='Scope iam:PassRole to a specific role ARN list. Use iam:PassedToService condition.'
        Required=@('iam:PassRole','lambda:CreateFunction','lambda:InvokeFunction')
    }
    @{
        Id='C003'; Name='PrivEsc: iam:PassRole + Lambda UpdateFunctionCode'
        Severity='CRITICAL'; MitreTactic='TA0004 Privilege Escalation'
        Vendor='Rhino Security Labs'
        Reference='https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/'
        Description='Role can replace existing Lambda function code that runs under a higher-privilege role.'
        Impact='Backdoor in existing production Lambda; runs with that Lambda role''s permissions.'
        Recommend='Restrict lambda:UpdateFunctionCode to specific function ARNs you control.'
        Required=@('iam:PassRole','lambda:UpdateFunctionCode')
    }
    @{
        Id='C004'; Name='PrivEsc: iam:PassRole + ec2:RunInstances'
        Severity='CRITICAL'; MitreTactic='TA0004 Privilege Escalation (T1078.004)'
        Vendor='Rhino Security Labs, Prisma Cloud, Wiz'
        Reference='https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/'
        Description='Launch EC2 instance with an instance profile that has higher privileges, then pull creds from IMDS.'
        Impact='Persistent compute with elevated role; classic IMDSv1 credential theft surface.'
        Recommend='Limit iam:PassRole to specific instance-profile roles. Enforce IMDSv2 across account.'
        Required=@('iam:PassRole','ec2:RunInstances')
    }
    @{
        Id='C005'; Name='PrivEsc: iam:PassRole + Glue CreateJob+StartJobRun'
        Severity='CRITICAL'; MitreTactic='TA0004 Privilege Escalation'
        Vendor='Rhino Security Labs'
        Reference='https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/'
        Description='Use AWS Glue jobs to run arbitrary code under a passed higher-privilege role.'
        Impact='Code execution under target role. Often missed because Glue is a less-watched service.'
        Recommend='Scope iam:PassRole. Audit Glue job creation in CloudTrail data events.'
        Required=@('iam:PassRole','glue:CreateJob','glue:StartJobRun')
    }
    @{
        Id='C006'; Name='PrivEsc: iam:PassRole + CodeBuild'
        Severity='CRITICAL'; MitreTactic='TA0004 Privilege Escalation'
        Vendor='Rhino Security Labs, Wiz'
        Reference='https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/'
        Description='Run arbitrary code in CodeBuild project that uses a passed higher-privilege service role.'
        Impact='Code-execution under target role; primary CI/CD escalation vector.'
        Recommend='Scope iam:PassRole. Use permission boundaries on CI/CD service roles.'
        Required=@('iam:PassRole','codebuild:CreateProject','codebuild:StartBuild')
    }
    @{
        Id='C007'; Name='PrivEsc: iam:PassRole + SageMaker Notebook'
        Severity='CRITICAL'; MitreTactic='TA0004 Privilege Escalation'
        Vendor='Rhino Security Labs, Crowdstrike Falcon Cloud'
        Reference='https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/'
        Description='Spin up SageMaker notebook with an attached execution role, then access via presigned URL to run code.'
        Impact='Interactive code execution surface with the attached role''s permissions.'
        Recommend='Scope iam:PassRole. Restrict sagemaker:CreateNotebookInstance and CreatePresignedNotebookInstanceUrl.'
        Required=@('iam:PassRole','sagemaker:CreateNotebookInstance','sagemaker:CreatePresignedNotebookInstanceUrl')
    }
    @{
        Id='C008'; Name='PrivEsc: iam:PassRole + ECS RegisterTaskDefinition+RunTask'
        Severity='CRITICAL'; MitreTactic='TA0004 Privilege Escalation'
        Vendor='Wiz, Prisma Cloud'
        Reference='https://www.wiz.io/blog/aws-iam-privilege-escalation-techniques'
        Description='Register an ECS task definition with a privileged task/execution role and run it.'
        Impact='Container with elevated role; can pull creds from task metadata endpoint.'
        Recommend='Scope iam:PassRole. Restrict ecs:RegisterTaskDefinition by tag/account conditions.'
        Required=@('iam:PassRole','ecs:RegisterTaskDefinition','ecs:RunTask')
    }
    @{
        Id='C009'; Name='PrivEsc: iam:UpdateAssumeRolePolicy'
        Severity='CRITICAL'; MitreTactic='TA0004 Privilege Escalation (T1098)'
        Vendor='Rhino Security Labs, Wiz, Prisma Cloud'
        Reference='https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/'
        Description='Role can rewrite the trust policy of any role to trust itself, then assume it.'
        Impact='Hijack any role in the account, including AdministratorAccess-bound roles.'
        Recommend='Restrict iam:UpdateAssumeRolePolicy to specific role ARNs and add MFA/ExternalId conditions.'
        Required=@('iam:UpdateAssumeRolePolicy')
    }
    @{
        Id='C010'; Name='PrivEsc: iam:AttachUserPolicy'
        Severity='CRITICAL'; MitreTactic='TA0004 Privilege Escalation (T1098.003)'
        Vendor='Rhino Security Labs, Prisma Cloud'
        Reference='https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/'
        Description='Attach AdministratorAccess (or any managed policy) to any IAM user.'
        Impact='Direct admin escalation if attacker controls or can create a user.'
        Recommend='Restrict iam:AttachUserPolicy to specific user/policy ARNs.'
        Required=@('iam:AttachUserPolicy')
    }
    @{
        Id='C011'; Name='PrivEsc: iam:AttachRolePolicy'
        Severity='CRITICAL'; MitreTactic='TA0004 Privilege Escalation (T1098.003)'
        Vendor='Rhino Security Labs, Prisma Cloud'
        Reference='https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/'
        Description='Attach AdministratorAccess or any managed policy to any IAM role.'
        Impact='Direct admin escalation by attaching managed policies to a role the attacker can assume.'
        Recommend='Restrict iam:AttachRolePolicy to specific role/policy ARNs.'
        Required=@('iam:AttachRolePolicy')
    }
    @{
        Id='C012'; Name='PrivEsc: iam:AttachGroupPolicy + AddUserToGroup'
        Severity='CRITICAL'; MitreTactic='TA0004 Privilege Escalation (T1098.003)'
        Vendor='Rhino Security Labs, Prisma Cloud'
        Reference='https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/'
        Description='Attach admin policies to a group, then add target user to the group.'
        Impact='Indirect admin escalation through group membership.'
        Recommend='Restrict iam:AttachGroupPolicy and iam:AddUserToGroup to specific ARNs.'
        Required=@('iam:AttachGroupPolicy','iam:AddUserToGroup')
    }
    @{
        Id='C013'; Name='PrivEsc: iam:PutUserPolicy'
        Severity='CRITICAL'; MitreTactic='TA0004 Privilege Escalation'
        Vendor='Rhino Security Labs, Prisma Cloud, Wiz'
        Reference='https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/'
        Description='Write an arbitrary inline policy on any IAM user. Equivalent to attaching AdministratorAccess.'
        Impact='Direct admin escalation.'
        Recommend='Restrict iam:PutUserPolicy to specific user ARNs.'
        Required=@('iam:PutUserPolicy')
    }
    @{
        Id='C014'; Name='PrivEsc: iam:PutRolePolicy'
        Severity='CRITICAL'; MitreTactic='TA0004 Privilege Escalation'
        Vendor='Rhino Security Labs, Prisma Cloud, Wiz'
        Reference='https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/'
        Description='Write an arbitrary inline policy on any IAM role.'
        Impact='Hijack any role''s permissions.'
        Recommend='Restrict iam:PutRolePolicy to specific role ARNs.'
        Required=@('iam:PutRolePolicy')
    }
    @{
        Id='C015'; Name='PrivEsc: iam:PutGroupPolicy'
        Severity='CRITICAL'; MitreTactic='TA0004 Privilege Escalation'
        Vendor='Rhino Security Labs, Prisma Cloud'
        Reference='https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/'
        Description='Write an arbitrary inline policy on any IAM group.'
        Impact='All users in the group inherit the added permissions.'
        Recommend='Restrict iam:PutGroupPolicy to specific group ARNs.'
        Required=@('iam:PutGroupPolicy')
    }

    # ============ PERSISTENCE ============
    @{
        Id='C020'; Name='Persistence: iam:CreateAccessKey'
        Severity='HIGH'; MitreTactic='TA0003 Persistence (T1098.001)'
        Vendor='Rhino Security Labs, Crowdstrike Falcon Cloud'
        Reference='https://attack.mitre.org/techniques/T1098/001/'
        Description='Create long-lived access keys for any IAM user - backdoor credentials.'
        Impact='Persistent access surviving credential rotation if not detected.'
        Recommend='Scope iam:CreateAccessKey to self only via aws:Username condition.'
        Required=@('iam:CreateAccessKey')
    }
    @{
        Id='C021'; Name='Persistence: iam:CreateLoginProfile / UpdateLoginProfile'
        Severity='HIGH'; MitreTactic='TA0003 Persistence (T1098.001)'
        Vendor='Rhino Security Labs, Crowdstrike Falcon Cloud'
        Reference='https://attack.mitre.org/techniques/T1098/001/'
        Description='Set or change console password for any IAM user - persistence with web-console access.'
        Impact='Console-based persistence path that bypasses programmatic-only monitoring.'
        Recommend='Restrict iam:CreateLoginProfile and iam:UpdateLoginProfile to specific user ARNs.'
        Required=@('iam:CreateLoginProfile')
    }
    @{
        Id='C022'; Name='Persistence: lambda:CreateFunction + AddPermission'
        Severity='MEDIUM'; MitreTactic='TA0003 Persistence (T1525)'
        Vendor='Crowdstrike Falcon Cloud'
        Reference='https://attack.mitre.org/techniques/T1525/'
        Description='Plant a Lambda backdoor invokable by an external principal.'
        Impact='External invocation route into the account; can chain with PassRole for elevated execution.'
        Recommend='Audit lambda:AddPermission usage. Restrict to specific function ARNs.'
        Required=@('lambda:CreateFunction','lambda:AddPermission')
    }
    @{
        Id='C023'; Name='Persistence: ssm:CreateDocument + ModifyDocumentPermission'
        Severity='HIGH'; MitreTactic='TA0003 Persistence'
        Vendor='Wiz'
        Reference='https://www.wiz.io/blog/cloud-attack-paths'
        Description='Create SSM document and share it externally - persistent code execution via SSM agent.'
        Impact='Backdoor that runs on every patched/managed EC2 instance.'
        Recommend='Restrict ssm:CreateDocument and ssm:ModifyDocumentPermission to specific document names.'
        Required=@('ssm:CreateDocument','ssm:ModifyDocumentPermission')
    }

    # ============ DEFENSE EVASION ============
    @{
        Id='C030'; Name='DefEvasion: CloudTrail tampering'
        Severity='CRITICAL'; MitreTactic='TA0005 Defense Evasion (T1562.008)'
        Vendor='CIS AWS Benchmark, Prisma Cloud, Wiz, Crowdstrike Falcon Cloud'
        Reference='https://attack.mitre.org/techniques/T1562/008/'
        Description='Role can stop, delete, or modify CloudTrail trails.'
        Impact='Removes audit evidence of attacker activity. Effectively blinds detection.'
        Recommend='Deny these actions account-wide via SCP. Require MFA for trail management.'
        Required=@('cloudtrail:StopLogging','cloudtrail:DeleteTrail','cloudtrail:UpdateTrail','cloudtrail:PutEventSelectors')
        MatchMode='Any'
    }
    @{
        Id='C031'; Name='DefEvasion: AWS Config tampering'
        Severity='HIGH'; MitreTactic='TA0005 Defense Evasion (T1562.001)'
        Vendor='CIS AWS Benchmark, Wiz'
        Reference='https://attack.mitre.org/techniques/T1562/001/'
        Description='Role can disable or delete AWS Config recording or delivery.'
        Impact='Breaks compliance monitoring and resource-change history.'
        Recommend='Deny these actions via SCP. Centralise Config recording in a security account.'
        Required=@('config:DeleteConfigurationRecorder','config:StopConfigurationRecorder','config:DeleteDeliveryChannel')
        MatchMode='Any'
    }
    @{
        Id='C032'; Name='DefEvasion: CloudWatch Logs tampering'
        Severity='HIGH'; MitreTactic='TA0005 Defense Evasion (T1070.002)'
        Vendor='Prisma Cloud, Wiz'
        Reference='https://attack.mitre.org/techniques/T1070/002/'
        Description='Role can delete CloudWatch log groups or retention policies.'
        Impact='Destroys application and security logs.'
        Recommend='Deny logs:DeleteLogGroup, logs:DeleteRetentionPolicy at SCP level.'
        Required=@('logs:DeleteLogGroup','logs:DeleteRetentionPolicy')
        MatchMode='Any'
    }
    @{
        Id='C033'; Name='DefEvasion: CloudWatch Alarm tampering'
        Severity='MEDIUM'; MitreTactic='TA0005 Defense Evasion (T1562.006)'
        Vendor='Prisma Cloud'
        Reference='https://attack.mitre.org/techniques/T1562/006/'
        Description='Role can disable or delete CloudWatch alarms.'
        Impact='Prevents alerting on attacker activity.'
        Recommend='Restrict cloudwatch:DeleteAlarms and DisableAlarmActions to specific alarm ARNs.'
        Required=@('cloudwatch:DeleteAlarms','cloudwatch:DisableAlarmActions')
        MatchMode='Any'
    }
    @{
        Id='C034'; Name='DefEvasion: GuardDuty/SecurityHub/Macie/Inspector disable'
        Severity='CRITICAL'; MitreTactic='TA0005 Defense Evasion (T1562.001)'
        Vendor='Prisma Cloud, Wiz, Crowdstrike Falcon Cloud'
        Reference='https://attack.mitre.org/techniques/T1562/001/'
        Description='Role can disable threat-detection services.'
        Impact='Removes detection across the account; primary kill-the-EDR-style move.'
        Recommend='Deny these actions via SCP. Centralise detection management in a security account.'
        Required=@('guardduty:DeleteDetector','guardduty:UpdateDetector','securityhub:DisableSecurityHub','macie2:DisableMacie','inspector:DisableEnableInUseAccounts')
        MatchMode='Any'
    }
    @{
        Id='C035'; Name='DefEvasion: ec2:ModifyInstanceMetadataOptions'
        Severity='MEDIUM'; MitreTactic='TA0005 Defense Evasion'
        Vendor='Wiz, Crowdstrike Falcon Cloud'
        Reference='https://aws.amazon.com/blogs/security/get-the-full-benefits-of-imdsv2-and-disable-imdsv1-across-your-aws-infrastructure/'
        Description='Role can re-enable IMDSv1 on EC2 instances.'
        Impact='Re-opens SSRF-exploitable IMDSv1 surface; classic credential theft vector.'
        Recommend='Deny ec2:ModifyInstanceMetadataOptions or require condition for HttpTokens=required.'
        Required=@('ec2:ModifyInstanceMetadataOptions')
    }
    @{
        Id='C036'; Name='DefEvasion: s3:PutBucketLogging or s3:DeleteBucketLogging'
        Severity='MEDIUM'; MitreTactic='TA0005 Defense Evasion (T1562.008)'
        Vendor='Prisma Cloud, Wiz'
        Reference='https://attack.mitre.org/techniques/T1562/008/'
        Description='Role can change or disable S3 access logging.'
        Impact='Hides S3 access from audit. Combined with GetObject = silent exfil.'
        Recommend='SCP-deny s3:PutBucketLogging and DeleteBucketLogging on logging-required buckets.'
        Required=@('s3:PutBucketLogging','s3:DeleteBucketLogging')
        MatchMode='Any'
    }
    @{
        Id='C037'; Name='DefEvasion: VPC Flow Logs deletion'
        Severity='HIGH'; MitreTactic='TA0005 Defense Evasion (T1562.008)'
        Vendor='Wiz, CIS'
        Reference='https://attack.mitre.org/techniques/T1562/008/'
        Description='Role can delete VPC Flow Logs.'
        Impact='Hides network-level attack traffic from detection.'
        Recommend='SCP-deny ec2:DeleteFlowLogs.'
        Required=@('ec2:DeleteFlowLogs')
    }

    # ============ CREDENTIAL EXPOSURE ============
    @{
        Id='C040'; Name='CredAccess: secretsmanager:GetSecretValue with Resource:*'
        Severity='HIGH'; MitreTactic='TA0006 Credential Access (T1552.005)'
        Vendor='Prisma Cloud, Wiz'
        Reference='https://attack.mitre.org/techniques/T1552/005/'
        Description='Read all secrets in Secrets Manager.'
        Impact='All stored credentials, API keys, DB passwords accessible. Frequent compromise vector.'
        Recommend='Scope to specific secret ARNs. Use resource policies on secrets.'
        Required=@('secretsmanager:GetSecretValue'); WildcardOnly=$true
    }
    @{
        Id='C041'; Name='CredAccess: ssm:GetParameter wildcard'
        Severity='MEDIUM'; MitreTactic='TA0006 Credential Access (T1552.005)'
        Vendor='Prisma Cloud, Crowdstrike Falcon Cloud'
        Reference='https://attack.mitre.org/techniques/T1552/005/'
        Description='Read all SSM parameters including SecureString values.'
        Impact='Captures credentials, configuration secrets, and DB connection strings.'
        Recommend='Scope ssm:GetParameter and ssm:GetParameters to specific path prefixes.'
        Required=@('ssm:GetParameter','ssm:GetParameters','ssm:GetParametersByPath'); MatchMode='Any'
    }
    @{
        Id='C042'; Name='CredAccess: kms:Decrypt with Resource:*'
        Severity='HIGH'; MitreTactic='TA0006 Credential Access (T1552)'
        Vendor='Wiz, Prisma Cloud'
        Reference='https://www.wiz.io/blog/aws-iam-privilege-escalation-techniques'
        Description='Decrypt with any KMS key in the account.'
        Impact='Unlocks every KMS-encrypted secret, snapshot, parameter, EBS volume, RDS snapshot.'
        Recommend='Scope kms:Decrypt to specific key ARNs. Use key policies as the enforcement boundary.'
        Required=@('kms:Decrypt'); WildcardOnly=$true
    }
    @{
        Id='C043'; Name='CredAccess: ec2:GetPasswordData'
        Severity='HIGH'; MitreTactic='TA0006 Credential Access (T1552)'
        Vendor='Rhino Security Labs, Prisma Cloud'
        Reference='https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/'
        Description='Retrieve Windows Administrator password for EC2 instances.'
        Impact='Direct host takeover if combined with kms:Decrypt for the keypair.'
        Recommend='Restrict ec2:GetPasswordData to instance owners.'
        Required=@('ec2:GetPasswordData')
    }
    @{
        Id='C044'; Name='CredAccess: codebuild:BatchGetProjects (env vars)'
        Severity='MEDIUM'; MitreTactic='TA0006 Credential Access (T1552.001)'
        Vendor='Wiz'
        Reference='https://www.wiz.io/blog/cloud-attack-paths'
        Description='Read CodeBuild project env vars, often containing secrets.'
        Impact='Captures CI/CD secrets and API tokens stored in build env.'
        Recommend='Move build secrets to Secrets Manager. Restrict codebuild:BatchGetProjects.'
        Required=@('codebuild:BatchGetProjects')
    }
    @{
        Id='C045'; Name='CredAccess: lambda:GetFunction (env vars)'
        Severity='MEDIUM'; MitreTactic='TA0006 Credential Access (T1552.001)'
        Vendor='Wiz, Prisma Cloud'
        Reference='https://www.wiz.io/blog/cloud-attack-paths'
        Description='Read Lambda function environment variables, often containing secrets.'
        Impact='API keys and DB credentials commonly stored in Lambda env.'
        Recommend='Use Secrets Manager / Parameter Store. Restrict lambda:GetFunction to specific functions.'
        Required=@('lambda:GetFunction')
    }

    # ============ DATA EXFILTRATION ============
    @{
        Id='C050'; Name='Exfil: s3:GetObject with Resource:*'
        Severity='HIGH'; MitreTactic='TA0010 Exfiltration (T1530)'
        Vendor='Wiz, Prisma Cloud, Crowdstrike Falcon Cloud'
        Reference='https://attack.mitre.org/techniques/T1530/'
        Description='Read objects from ANY S3 bucket in the account.'
        Impact='Account-wide data exposure. Primary exfiltration surface.'
        Recommend='Scope s3:GetObject to specific bucket ARNs.'
        Required=@('s3:GetObject'); WildcardOnly=$true
    }
    @{
        Id='C051'; Name='Exfil: RDS snapshot cross-account share'
        Severity='CRITICAL'; MitreTactic='TA0010 Exfiltration (T1537)'
        Vendor='Rhino Security Labs, Wiz, Prisma Cloud'
        Reference='https://attack.mitre.org/techniques/T1537/'
        Description='Copy RDS snapshots and share them with an external AWS account.'
        Impact='Full database exfiltrated to attacker-controlled account; bypasses VPC controls.'
        Recommend='SCP-deny rds:ModifyDBSnapshotAttribute and rds:CopyDBSnapshot for cross-account.'
        Required=@('rds:CopyDBSnapshot','rds:ModifyDBSnapshotAttribute')
    }
    @{
        Id='C052'; Name='Exfil: EBS snapshot cross-account share'
        Severity='CRITICAL'; MitreTactic='TA0010 Exfiltration (T1537)'
        Vendor='Rhino Security Labs, Wiz'
        Reference='https://attack.mitre.org/techniques/T1537/'
        Description='Create EBS snapshots and share them with an external AWS account.'
        Impact='Volume content exfiltrated. Often used to extract Windows DPAPI / Linux secrets.'
        Recommend='SCP-deny ec2:ModifySnapshotAttribute for cross-account access.'
        Required=@('ec2:CreateSnapshot','ec2:ModifySnapshotAttribute')
    }
    @{
        Id='C053'; Name='Exfil: dynamodb:Scan / ExportTableToPointInTime'
        Severity='MEDIUM'; MitreTactic='TA0010 Exfiltration (T1530)'
        Vendor='Wiz'
        Reference='https://attack.mitre.org/techniques/T1530/'
        Description='Bulk-read DynamoDB tables or export them to S3.'
        Impact='Database table contents exfiltrated.'
        Recommend='Scope dynamodb:Scan/ExportTableToPointInTime to specific table ARNs.'
        Required=@('dynamodb:Scan'); MatchMode='Any'
    }
    @{
        Id='C054'; Name='Exfil: ec2:CopyImage to external account'
        Severity='HIGH'; MitreTactic='TA0010 Exfiltration (T1537)'
        Vendor='Wiz'
        Reference='https://attack.mitre.org/techniques/T1537/'
        Description='Copy AMIs that may contain baked-in secrets to external account.'
        Impact='Hardcoded creds, config files in image content exfiltrated.'
        Recommend='SCP-deny ec2:ModifyImageAttribute for cross-account.'
        Required=@('ec2:CopyImage','ec2:ModifyImageAttribute')
    }

    # ============ RESOURCE ABUSE ============
    @{
        Id='C060'; Name='ResourceAbuse: ec2:RunInstances without conditions'
        Severity='HIGH'; MitreTactic='TA0040 Impact (T1496)'
        Vendor='Wiz, Prisma Cloud, Crowdstrike Falcon Cloud'
        Reference='https://attack.mitre.org/techniques/T1496/'
        Description='Launch unlimited EC2 instances with no instance-type / region restriction.'
        Impact='Cryptomining and resource hijack; massive AWS bills.'
        Recommend='Require ec2:InstanceType, aws:RequestedRegion conditions.'
        Required=@('ec2:RunInstances'); RequireNoCondition=$true
    }
    @{
        Id='C061'; Name='ResourceAbuse: SageMaker notebook hijack'
        Severity='HIGH'; MitreTactic='TA0040 Impact (T1496)'
        Vendor='Rhino Security Labs, Crowdstrike Falcon Cloud'
        Reference='https://attack.mitre.org/techniques/T1496/'
        Description='Create SageMaker notebook and presigned URL for interactive access.'
        Impact='Cryptomining and code-execution surface on managed compute.'
        Recommend='Restrict sagemaker:CreateNotebookInstance and sagemaker:CreatePresignedNotebookInstanceUrl.'
        Required=@('sagemaker:CreateNotebookInstance','sagemaker:CreatePresignedNotebookInstanceUrl')
    }
    @{
        Id='C062'; Name='ResourceAbuse: Batch / Lambda for cryptomining'
        Severity='MEDIUM'; MitreTactic='TA0040 Impact (T1496)'
        Vendor='Crowdstrike Falcon Cloud'
        Reference='https://attack.mitre.org/techniques/T1496/'
        Description='Run mining workloads via Lambda or AWS Batch.'
        Impact='Compute abuse; lower per-unit cost but high parallelism.'
        Recommend='Set account-level Service Quotas and budget alarms.'
        Required=@('lambda:CreateFunction','lambda:InvokeFunction'); MatchMode='All'
    }

    # ============ LATERAL MOVEMENT ============
    @{
        Id='C070'; Name='Lateral: sts:AssumeRole with Resource:*'
        Severity='HIGH'; MitreTactic='TA0008 Lateral Movement (T1078.004)'
        Vendor='Prisma Cloud, Wiz, Crowdstrike Falcon Cloud'
        Reference='https://attack.mitre.org/techniques/T1078/004/'
        Description='Assume any role in the account, and possibly external accounts.'
        Impact='Pivot point. Combined with iam:UpdateAssumeRolePolicy = account compromise.'
        Recommend='Scope sts:AssumeRole to specific role ARNs.'
        Required=@('sts:AssumeRole'); WildcardOnly=$true
    }
    @{
        Id='C071'; Name='Lateral: ec2:AssociateIamInstanceProfile'
        Severity='HIGH'; MitreTactic='TA0008 Lateral Movement (T1078.004)'
        Vendor='Rhino Security Labs, Wiz'
        Reference='https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/'
        Description='Attach or replace an EC2 instance profile.'
        Impact='Elevate an existing EC2 instance to a higher-privilege role without rebuild.'
        Recommend='Restrict ec2:AssociateIamInstanceProfile and ReplaceIamInstanceProfileAssociation.'
        Required=@('ec2:AssociateIamInstanceProfile','ec2:ReplaceIamInstanceProfileAssociation'); MatchMode='Any'
    }
    @{
        Id='C072'; Name='Lateral: ssm:SendCommand / StartSession'
        Severity='MEDIUM'; MitreTactic='TA0008 Lateral Movement (T1021.007)'
        Vendor='Wiz, Crowdstrike Falcon Cloud'
        Reference='https://attack.mitre.org/techniques/T1021/007/'
        Description='Run arbitrary commands on managed EC2 instances via SSM.'
        Impact='Code execution on every patched / SSM-managed instance.'
        Recommend='Restrict ssm:SendCommand by instance tag or document name.'
        Required=@('ssm:SendCommand','ssm:StartSession'); MatchMode='Any'
    }
    @{
        Id='C073'; Name='Lateral: ecs:ExecuteCommand'
        Severity='MEDIUM'; MitreTactic='TA0008 Lateral Movement (T1609)'
        Vendor='Wiz'
        Reference='https://attack.mitre.org/techniques/T1609/'
        Description='Exec into running ECS containers.'
        Impact='Direct shell to any container task with execute-command enabled.'
        Recommend='Restrict ecs:ExecuteCommand to specific clusters/tasks.'
        Required=@('ecs:ExecuteCommand')
    }
    @{
        Id='C074'; Name='Lateral: eks:AccessKubernetesApi'
        Severity='HIGH'; MitreTactic='TA0008 Lateral Movement (T1078.004)'
        Vendor='Wiz, Crowdstrike Falcon Cloud'
        Reference='https://attack.mitre.org/techniques/T1078/004/'
        Description='Access the Kubernetes API of any EKS cluster.'
        Impact='Container escape and cluster-wide compromise possible if cluster RBAC also wide-open.'
        Recommend='Use EKS access entries with least-privilege Kubernetes RBAC.'
        Required=@('eks:AccessKubernetesApi')
    }

    # ============ DESTRUCTION / RANSOMWARE ============
    @{
        Id='C080'; Name='Impact: kms:ScheduleKeyDeletion'
        Severity='HIGH'; MitreTactic='TA0040 Impact (T1485)'
        Vendor='Wiz, Prisma Cloud'
        Reference='https://attack.mitre.org/techniques/T1485/'
        Description='Schedule any KMS key for deletion - ransomware vector.'
        Impact='All data encrypted with deleted keys permanently unrecoverable.'
        Recommend='SCP-deny kms:ScheduleKeyDeletion. Enable key rotation and CloudTrail alarms.'
        Required=@('kms:ScheduleKeyDeletion')
    }
    @{
        Id='C081'; Name='Impact: s3:DeleteBucket with Resource:*'
        Severity='HIGH'; MitreTactic='TA0040 Impact (T1485)'
        Vendor='Wiz, Prisma Cloud'
        Reference='https://attack.mitre.org/techniques/T1485/'
        Description='Delete any S3 bucket in the account.'
        Impact='Mass data destruction. Versioning + MFA-delete needed as compensating control.'
        Recommend='Enable MFA-delete and bucket versioning on critical buckets. Scope s3:DeleteBucket.'
        Required=@('s3:DeleteBucket'); WildcardOnly=$true
    }
    @{
        Id='C082'; Name='Impact: rds:DeleteDBInstance / DeleteDBSnapshot'
        Severity='HIGH'; MitreTactic='TA0040 Impact (T1485)'
        Vendor='Wiz, Prisma Cloud'
        Reference='https://attack.mitre.org/techniques/T1485/'
        Description='Delete RDS databases and snapshots.'
        Impact='Database destruction with no recovery if snapshots also deleted.'
        Recommend='Enable deletion protection. SCP-deny rds:DeleteDBSnapshot for production tags.'
        Required=@('rds:DeleteDBInstance','rds:DeleteDBSnapshot'); MatchMode='Any'
    }
    @{
        Id='C083'; Name='Impact: organizations:LeaveOrganization'
        Severity='CRITICAL'; MitreTactic='TA0040 Impact'
        Vendor='Prisma Cloud, Crowdstrike Falcon Cloud'
        Reference='https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_accounts_remove.html'
        Description='Remove this account from its AWS Organization.'
        Impact='Severs SCP controls and central governance. Hard to reverse.'
        Recommend='SCP-deny organizations:LeaveOrganization at the OU root level.'
        Required=@('organizations:LeaveOrganization')
    }
    @{
        Id='C084'; Name='Impact: dynamodb:DeleteTable'
        Severity='MEDIUM'; MitreTactic='TA0040 Impact (T1485)'
        Vendor='Wiz'
        Reference='https://attack.mitre.org/techniques/T1485/'
        Description='Delete DynamoDB tables.'
        Impact='Application database destruction. PITR backups must be enabled to recover.'
        Recommend='Enable deletion protection. Use PITR. SCP-deny by tag.'
        Required=@('dynamodb:DeleteTable')
    }

    # ============ DISCOVERY (broad permissions) ============
    @{
        Id='C090'; Name='Discovery: iam:ListUsers + ListRoles + ListPolicies'
        Severity='LOW'; MitreTactic='TA0007 Discovery (T1087.004)'
        Vendor='Wiz, Crowdstrike Falcon Cloud'
        Reference='https://attack.mitre.org/techniques/T1087/004/'
        Description='Enumerate IAM principals and policies.'
        Impact='Reconnaissance baseline for targeted attacks.'
        Recommend='Most roles legitimately need this; combine with anomaly detection on bulk calls.'
        Required=@('iam:ListUsers','iam:ListRoles','iam:ListPolicies'); MatchMode='All'
    }
    @{
        Id='C091'; Name='Discovery: iam:SimulatePrincipalPolicy'
        Severity='LOW'; MitreTactic='TA0007 Discovery'
        Vendor='Wiz'
        Reference='https://attack.mitre.org/techniques/T1087/004/'
        Description='Simulate what a principal can do - effectively offline-test for privesc paths.'
        Impact='Attacker can map their privileges without triggering Allow events.'
        Recommend='Audit iam:SimulatePrincipalPolicy usage. Restrict where possible.'
        Required=@('iam:SimulatePrincipalPolicy')
    }

    # ============ MISCONFIGURATION ============
    @{
        Id='C100'; Name='Misconfig: ec2:AuthorizeSecurityGroupIngress unscoped'
        Severity='MEDIUM'; MitreTactic='TA0001 Initial Access (T1190)'
        Vendor='Prisma Cloud, Wiz'
        Reference='https://attack.mitre.org/techniques/T1190/'
        Description='Modify any security group ingress without conditions.'
        Impact='Can open 0.0.0.0/0:any-port to any instance.'
        Recommend='Use VPC Network Firewall. Scope ec2:AuthorizeSecurityGroupIngress by SG tag.'
        Required=@('ec2:AuthorizeSecurityGroupIngress'); WildcardOnly=$true; RequireNoCondition=$true
    }
    @{
        Id='C101'; Name='Misconfig: s3:PutBucketPolicy unscoped'
        Severity='MEDIUM'; MitreTactic='TA0005 Defense Evasion'
        Vendor='Wiz, Prisma Cloud'
        Reference='https://docs.aws.amazon.com/AmazonS3/latest/userguide/example-bucket-policies.html'
        Description='Write bucket policies on any bucket.'
        Impact='Can grant public read/write on any bucket; bypass account-level Block Public Access if BPA not at account level.'
        Recommend='Enable account-level S3 Block Public Access. Restrict s3:PutBucketPolicy.'
        Required=@('s3:PutBucketPolicy'); WildcardOnly=$true
    }
    @{
        Id='C102'; Name='Misconfig: ec2:CreateVpcPeeringConnection'
        Severity='MEDIUM'; MitreTactic='TA0008 Lateral Movement'
        Vendor='Wiz'
        Reference='https://attack.mitre.org/techniques/T1078/004/'
        Description='Create VPC peering connections to external VPCs.'
        Impact='Establishes network path to attacker-controlled VPC.'
        Recommend='Restrict ec2:CreateVpcPeeringConnection to specific VPC IDs.'
        Required=@('ec2:CreateVpcPeeringConnection')
    }
    @{
        Id='C103'; Name='Misconfig: NotAction with Allow effect'
        Severity='HIGH'; MitreTactic='TA0004 Privilege Escalation'
        Vendor='Wiz'
        Reference='https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notaction.html'
        Description='Policy uses NotAction with Effect=Allow - dangerous and rarely needed.'
        Impact='Implicitly grants every action except the listed ones, including future AWS actions.'
        Recommend='Replace NotAction-Allow with explicit Action lists. Use NotAction only with Deny.'
        # Match logic detects this differently - flagged inside Build-EffectivePermissions
        Required=@('__NOTACTION_ALLOW__')
    }
)

# ----------------------------------------------------------------
# Run all capability checks against an effective-permission map.
# Returns enriched findings with SourcePolicies, AffectedResources, etc.
# ----------------------------------------------------------------
function Invoke-CapabilityChecks {
    param(
        [hashtable]$Effective,
        [object[]]$ResourcesUsingRole = @()
    )
    if (-not $Effective) { return @() }

    $results = New-Object System.Collections.Generic.List[object]
    foreach ($cap in $Global:IR_Capabilities) {
        $matched = @()
        $matchMode = if ($cap.MatchMode) { $cap.MatchMode } else { 'All' }

        if ($cap.WildcardOnly) {
            # Match only when the action has Resource:*
            foreach ($req in $cap.Required) {
                if (Test-ResourceWildcard -Effective $Effective -Action $req) {
                    $matched += $req
                }
            }
            $required = $cap.Required
            $hit = $matched.Count -gt 0
        }
        elseif ($cap.Required -contains '__NOTACTION_ALLOW__') {
            # Special-case: NotAction-Allow detection
            $hit = $false
            foreach ($act in $Effective.Keys) {
                if ($Effective[$act].FromNotActionAllow) { $hit = $true; $matched = @($act); break }
            }
        }
        else {
            $matched = Get-AllowedActions -Effective $Effective -Required $cap.Required
            if ($matchMode -eq 'All') {
                $hit = ($matched.Count -eq $cap.Required.Count)
            } else {
                $hit = ($matched.Count -gt 0)
            }
        }

        # Optional: RequireNoCondition - must NOT have any condition on the matched action
        if ($hit -and $cap.RequireNoCondition) {
            $stillHit = $false
            foreach ($a in $matched) {
                if ($Effective.ContainsKey($a) -and $Effective[$a].Conditions.Count -eq 0) {
                    $stillHit = $true; break
                }
            }
            if (-not $stillHit) { $hit = $false }
        }

        if (-not $hit) { continue }

        # Source policies that granted the matched actions
        $sources = Get-SourcePolicies -Effective $Effective -Actions $matched

        # ----- Severity downgrade for conditional or specifically-scoped capabilities -----
        # A capability that only fires because of an Allow with Condition blocks, or
        # an Allow scoped to specific (non-*) resource ARNs, is a less-immediate risk
        # than one with unconditional Resource:* grants. Mark these as "limited" and
        # downgrade the severity by one tier. The original severity is preserved.
        $allConditioned = $true
        $allScoped      = $true
        $anyMatch       = $false
        $conditionedActions = New-Object System.Collections.Generic.List[string]
        $scopedActions      = New-Object System.Collections.Generic.List[string]
        foreach ($a in $matched) {
            if (-not $Effective.ContainsKey($a)) { continue }
            $rec = $Effective[$a]
            $anyMatch = $true
            $isCond = ($rec.Conditions.Count -gt 0)
            $isWildRes = $false
            foreach ($r in $rec.Resources) {
                if ("$r" -eq '*' -or "$r" -match '^arn:aws:[^:]+:::?\*$') { $isWildRes = $true; break }
            }
            if (-not $isCond) { $allConditioned = $false }
            else { [void]$conditionedActions.Add($a) }
            if ($isWildRes) { $allScoped = $false }
            else { [void]$scopedActions.Add($a) }
        }
        if (-not $anyMatch) { $allConditioned = $false; $allScoped = $false }

        # Severity downgrade: one tier per "limiter" applied (max 2 tiers).
        $sevOrder = @('CRITICAL','HIGH','MEDIUM','LOW','INFO')
        $origSev = "$($cap.Severity)"
        $idx = $sevOrder.IndexOf($origSev)
        if ($idx -lt 0) { $idx = 4 }  # default to INFO if unknown
        $downgrades = 0
        if ($allConditioned) { $downgrades++ }
        if ($allScoped)      { $downgrades++ }
        $newIdx = [Math]::Min($idx + $downgrades, $sevOrder.Length - 1)
        $finalSev = $sevOrder[$newIdx]
        # Build a label describing why this got downgraded
        $limitedReason = ''
        if ($allConditioned -and $allScoped) {
            $limitedReason = 'limited: every matching action is both conditioned and resource-scoped'
        } elseif ($allConditioned) {
            $limitedReason = 'limited: every matching action has a Condition block'
        } elseif ($allScoped) {
            $limitedReason = 'limited: every matching action is scoped to specific resource ARNs'
        }

        # Affected resources: any resource from $ResourcesUsingRole that uses this role
        $affected = @()
        foreach ($r in $ResourcesUsingRole) {
            $affected += [PSCustomObject]@{
                ResourceType = $r.ResourceType
                ResourceName = $r.ResourceName
                ResourceArn  = $r.ResourceArn
                Region       = $r.Region
                AttachmentType = $r.AttachmentType
                RiskLevel    = $r.RiskLevel
            }
        }

        $results.Add(@{
            Id              = $cap.Id
            Name            = $cap.Name
            Severity        = $finalSev
            OriginalSeverity = $origSev
            LimitedReason   = $limitedReason
            ConditionedActions = $conditionedActions.ToArray()
            ScopedActions      = $scopedActions.ToArray()
            MitreTactic     = $cap.MitreTactic
            Vendor          = $cap.Vendor
            Reference       = $cap.Reference
            Description     = $cap.Description
            Impact          = $cap.Impact
            Recommend       = $cap.Recommend
            MatchedActions  = $matched
            SourcePolicies  = $sources
            AffectedResources = $affected
            Hit             = $true
        })
    }
    return $results.ToArray()
}

# ----------------------------------------------------------------
# Return the full capability library for the findings-catalog page.
# Each entry annotated with Hit=$true/$false based on global RoleCapabilities.
# ----------------------------------------------------------------
function Get-CapabilityCatalogStatus {
    # Build map: capId -> list of roleArns that triggered it
    $hitMap = @{}
    if ($Global:IR.RoleCapabilities) {
        foreach ($arn in $Global:IR.RoleCapabilities.Keys) {
            foreach ($cap in $Global:IR.RoleCapabilities[$arn]) {
                if (-not $hitMap.ContainsKey($cap.Id)) {
                    $hitMap[$cap.Id] = New-Object System.Collections.Generic.List[string]
                }
                [void]$hitMap[$cap.Id].Add($arn)
            }
        }
    }

    $catalog = New-Object System.Collections.Generic.List[object]
    foreach ($cap in $Global:IR_Capabilities) {
        $hits = if ($hitMap.ContainsKey($cap.Id)) { $hitMap[$cap.Id].ToArray() } else { @() }
        $catalog.Add(@{
            Id = $cap.Id
            Name = $cap.Name
            Severity = $cap.Severity
            MitreTactic = $cap.MitreTactic
            Vendor = $cap.Vendor
            Reference = $cap.Reference
            Description = $cap.Description
            Impact = $cap.Impact
            Recommend = $cap.Recommend
            Required = $cap.Required
            HitCount = $hits.Count
            HitRoles = $hits
            Hit = ($hits.Count -gt 0)
        })
    }
    return $catalog.ToArray()
}
