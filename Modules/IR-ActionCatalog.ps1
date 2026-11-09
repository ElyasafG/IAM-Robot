# Modules/IR-ActionCatalog.ps1
# ============================================================
#  Static catalog of high-value AWS IAM actions used to:
#   1. Expand wildcards (iam:*  ->  every IAM action in catalog)
#   2. Layer Deny statements on top of Allow expansions
#   3. Produce a per-action effective-permission table
#   4. Run capability checks (combinations of actions that
#      enable privilege escalation, data exfil, etc.)
#
#  The catalog is curated, not exhaustive. AWS has 10,000+ actions
#  across 300+ services; listing all of them statically is not
#  practical. The list below covers:
#   - All actions referenced by known privilege-escalation paths
#     (Rhino Security Labs research, used by Prisma/Wiz/Crowdstrike)
#   - All actions that destroy audit logs or break detection
#   - All actions that grant or modify IAM
#   - High-impact destructive actions per service
#   - All actions that move data or expose secrets
#
#  Any policy action NOT in the catalog is still tracked - it just
#  doesn't get expanded when a wildcard is used. Explicit actions
#  in policies always appear in the per-role table.
# ============================================================

$Global:IR_ActionCatalog = @{
    'iam' = @(
        # Identity / credential creation
        'CreateAccessKey','CreateLoginProfile','CreateUser','CreateGroup','CreateRole',
        'CreatePolicy','CreatePolicyVersion','CreateServiceLinkedRole',
        # Privilege modification
        'AttachUserPolicy','AttachGroupPolicy','AttachRolePolicy',
        'PutUserPolicy','PutGroupPolicy','PutRolePolicy',
        'AddUserToGroup','UpdateAssumeRolePolicy','UpdateLoginProfile',
        'SetDefaultPolicyVersion','PassRole',
        # Identity / credential reading
        'GetUser','GetRole','GetPolicy','GetPolicyVersion','GetRolePolicy','GetUserPolicy',
        'GetGroupPolicy','GetAccessKeyLastUsed','GetServiceLastAccessedDetails',
        'ListUsers','ListRoles','ListGroups','ListPolicies','ListAccessKeys',
        'ListAttachedRolePolicies','ListRolePolicies','ListUserPolicies','ListGroupPolicies',
        'SimulatePrincipalPolicy','SimulateCustomPolicy',
        # Destructive
        'DeleteUser','DeleteRole','DeletePolicy','DeletePolicyVersion','DeleteAccessKey',
        'DeleteLoginProfile','DeleteUserPolicy','DeleteRolePolicy','DeleteGroupPolicy',
        'DetachUserPolicy','DetachRolePolicy','DetachGroupPolicy',
        'RemoveUserFromGroup','UpdateAccessKey','UpdateUser',
        # MFA / SSH / certs
        'ChangePassword','DeactivateMFADevice','DeleteVirtualMFADevice','EnableMFADevice',
        'UploadSSHPublicKey','DeleteSSHPublicKey','UploadServerCertificate'
    )
    'sts' = @(
        'AssumeRole','AssumeRoleWithSAML','AssumeRoleWithWebIdentity',
        'GetSessionToken','GetCallerIdentity','GetFederationToken','DecodeAuthorizationMessage'
    )
    's3' = @(
        # Read / list
        'GetObject','GetObjectVersion','GetObjectAcl','GetObjectTagging','GetObjectAttributes',
        'ListBucket','ListBucketVersions','ListBucketMultipartUploads','ListAllMyBuckets',
        'GetBucketPolicy','GetBucketAcl','GetBucketLogging','GetBucketVersioning',
        'GetBucketLocation','GetBucketEncryption','GetBucketPublicAccessBlock',
        # Write
        'PutObject','PutObjectAcl','PutObjectTagging',
        'PutBucketPolicy','PutBucketAcl','PutBucketLogging','PutBucketVersioning',
        'PutBucketEncryption','PutBucketPublicAccessBlock','PutBucketNotification',
        # Destructive
        'DeleteObject','DeleteObjectVersion','DeleteBucket','DeleteBucketPolicy',
        'DeleteBucketLogging','DeleteBucketEncryption',
        # Multipart / replication / inventory
        'AbortMultipartUpload','RestoreObject',
        'PutBucketReplication','GetBucketReplication','DeleteBucketReplication'
    )
    'ec2' = @(
        # Create / launch
        'RunInstances','StartInstances','StopInstances','RebootInstances','TerminateInstances',
        'CreateImage','CopyImage','CreateSnapshot','CopySnapshot','RestoreSnapshotFromRecycleBin',
        'CreateVolume','AttachVolume','DetachVolume','DeleteVolume','DeleteSnapshot',
        'CreateKeyPair','ImportKeyPair','DeleteKeyPair',
        'CreateSecurityGroup','AuthorizeSecurityGroupIngress','AuthorizeSecurityGroupEgress',
        'RevokeSecurityGroupIngress','RevokeSecurityGroupEgress','DeleteSecurityGroup',
        'ModifyInstanceAttribute','ModifyImageAttribute','ModifyVolumeAttribute',
        'CreateNetworkAclEntry','DeleteNetworkAclEntry','ReplaceNetworkAclEntry',
        # Read
        'DescribeInstances','DescribeImages','DescribeSnapshots','DescribeVolumes',
        'DescribeSecurityGroups','DescribeKeyPairs','DescribeVpcs','DescribeSubnets',
        'GetPasswordData','GetConsoleScreenshot','GetConsoleOutput',
        # IAM-adjacent
        'AssociateIamInstanceProfile','ReplaceIamInstanceProfileAssociation','DisassociateIamInstanceProfile',
        # VPC peering / sharing
        'CreateVpcPeeringConnection','AcceptVpcPeeringConnection','CreateClientVpnEndpoint',
        # IMDS
        'ModifyInstanceMetadataOptions'
    )
    'lambda' = @(
        'CreateFunction','UpdateFunctionCode','UpdateFunctionConfiguration',
        'AddPermission','RemovePermission','AddLayerVersionPermission',
        'InvokeFunction','InvokeAsync',
        'GetFunction','GetFunctionConfiguration','GetPolicy','ListFunctions',
        'PublishLayerVersion','PublishVersion','CreateAlias','UpdateAlias',
        'DeleteFunction','DeleteAlias','DeleteLayerVersion',
        'PutFunctionConcurrency','PutFunctionEventInvokeConfig'
    )
    'kms' = @(
        'Encrypt','Decrypt','GenerateDataKey','GenerateDataKeyPair','GenerateDataKeyWithoutPlaintext',
        'ReEncryptFrom','ReEncryptTo','Sign','Verify',
        'CreateKey','CreateAlias','PutKeyPolicy','UpdateKeyDescription',
        'EnableKey','DisableKey','EnableKeyRotation','DisableKeyRotation',
        'ScheduleKeyDeletion','CancelKeyDeletion',
        'CreateGrant','RevokeGrant','RetireGrant',
        'DescribeKey','GetKeyPolicy','GetKeyRotationStatus','ListKeys','ListAliases','ListGrants','ListKeyPolicies'
    )
    'secretsmanager' = @(
        'GetSecretValue','DescribeSecret','GetResourcePolicy','ListSecrets',
        'PutSecretValue','UpdateSecret','CreateSecret','DeleteSecret','RestoreSecret',
        'RotateSecret','UpdateSecretVersionStage','PutResourcePolicy','DeleteResourcePolicy',
        'GetRandomPassword'
    )
    'ssm' = @(
        'GetParameter','GetParameters','GetParametersByPath','DescribeParameters','ListTagsForResource',
        'PutParameter','DeleteParameter','DeleteParameters',
        'SendCommand','StartSession','GetCommandInvocation','ListCommands','ListCommandInvocations',
        'CreateDocument','UpdateDocument','DeleteDocument','ModifyDocumentPermission',
        'ResumeSession','TerminateSession','DescribeInstanceInformation'
    )
    'cloudtrail' = @(
        'StopLogging','StartLogging','DeleteTrail','UpdateTrail','PutEventSelectors',
        'CreateTrail','DescribeTrails','GetTrail','GetTrailStatus','ListTrails',
        'PutInsightSelectors','LookupEvents'
    )
    'config' = @(
        'DeleteConfigurationRecorder','StopConfigurationRecorder','DeleteDeliveryChannel',
        'DeleteConfigRule','DeleteRemediationConfiguration','DeleteOrganizationConfigRule',
        'PutConfigurationRecorder','PutConfigRule','PutRemediationConfiguration','PutDeliveryChannel',
        'DescribeConfigurationRecorders','DescribeConfigRules','DescribeComplianceByConfigRule'
    )
    'cloudwatch' = @(
        'DeleteAlarms','PutMetricAlarm','DisableAlarmActions','EnableAlarmActions',
        'PutMetricData','DescribeAlarms','GetMetricStatistics','GetMetricData','ListMetrics'
    )
    'logs' = @(
        'DeleteLogGroup','DeleteLogStream','DeleteRetentionPolicy','DeleteSubscriptionFilter',
        'PutLogEvents','PutSubscriptionFilter','PutRetentionPolicy','CreateLogGroup','CreateLogStream',
        'DescribeLogGroups','DescribeLogStreams','GetLogEvents','FilterLogEvents','StartQuery'
    )
    'organizations' = @(
        'LeaveOrganization','RemoveAccountFromOrganization','DeleteOrganization',
        'InviteAccountToOrganization','CreateAccount','EnableAllFeatures',
        'AttachPolicy','DetachPolicy','CreatePolicy','UpdatePolicy','DeletePolicy',
        'ListAccounts','DescribeOrganization','ListPolicies','ListOrganizationalUnitsForParent'
    )
    'sqs' = @(
        'SendMessage','SendMessageBatch','ReceiveMessage','DeleteMessage','DeleteMessageBatch',
        'PurgeQueue','DeleteQueue','SetQueueAttributes','AddPermission','RemovePermission',
        'CreateQueue','GetQueueAttributes','GetQueueUrl','ListQueues'
    )
    'sns' = @(
        'Publish','Subscribe','Unsubscribe','ConfirmSubscription',
        'AddPermission','RemovePermission','SetTopicAttributes','SetSubscriptionAttributes',
        'CreateTopic','DeleteTopic','ListTopics','GetTopicAttributes'
    )
    'dynamodb' = @(
        'GetItem','BatchGetItem','Query','Scan','DescribeTable','ListTables','PartiQLSelect',
        'PutItem','BatchWriteItem','UpdateItem','DeleteItem','DeleteTable',
        'CreateTable','UpdateTable','CreateBackup','RestoreTableFromBackup',
        'ExportTableToPointInTime','PartiQLInsert','PartiQLUpdate','PartiQLDelete'
    )
    'rds' = @(
        'CreateDBInstance','RestoreDBInstanceFromDBSnapshot','RestoreDBInstanceToPointInTime',
        'ModifyDBInstance','RebootDBInstance','StartDBInstance','StopDBInstance','DeleteDBInstance',
        'CreateDBSnapshot','CopyDBSnapshot','DeleteDBSnapshot','ModifyDBSnapshotAttribute',
        'CreateDBClusterSnapshot','RestoreDBClusterFromSnapshot','ModifyDBClusterSnapshotAttribute',
        'DownloadDBLogFilePortion','DescribeDBInstances','DescribeDBSnapshots'
    )
    'sagemaker' = @(
        'CreateNotebookInstance','CreatePresignedNotebookInstanceUrl','CreateTrainingJob',
        'CreateProcessingJob','CreateTransformJob','CreateModel','CreateEndpoint',
        'UpdateNotebookInstance','StartNotebookInstance','InvokeEndpoint','InvokeEndpointAsync'
    )
    'glue' = @(
        'CreateJob','UpdateJob','DeleteJob','StartJobRun','BatchStopJobRun',
        'CreateDevEndpoint','UpdateDevEndpoint','CreateScript',
        'GetJob','GetJobRun','ListJobs','GetConnection','GetConnections'
    )
    'ecr' = @(
        'GetAuthorizationToken','GetDownloadUrlForLayer','BatchGetImage','DescribeImages',
        'InitiateLayerUpload','UploadLayerPart','CompleteLayerUpload','PutImage',
        'BatchDeleteImage','DeleteRepository','SetRepositoryPolicy','DeleteRepositoryPolicy'
    )
    'eks' = @(
        'CreateCluster','UpdateClusterConfig','UpdateClusterVersion','DeleteCluster',
        'CreateNodegroup','UpdateNodegroupConfig','DeleteNodegroup',
        'AssociateAccessPolicy','CreateAccessEntry','UpdateAccessEntry','DeleteAccessEntry',
        'DescribeCluster','ListClusters','AccessKubernetesApi'
    )
    'ecs' = @(
        'RunTask','StartTask','StopTask','UpdateService','CreateService','DeleteService',
        'RegisterTaskDefinition','DeregisterTaskDefinition','ExecuteCommand',
        'DescribeTasks','DescribeServices','ListTasks','ListServices'
    )
    'codebuild' = @(
        'StartBuild','UpdateProject','CreateProject','DeleteProject',
        'BatchGetProjects','ListProjects','BatchGetBuilds','RetryBuild','StopBuild',
        'ImportSourceCredentials'
    )
    'codepipeline' = @(
        'StartPipelineExecution','UpdatePipeline','CreatePipeline','DeletePipeline',
        'PutActionRevision','PutApprovalResult','RetryStageExecution'
    )
    # Identity & access (additional)
    'access-analyzer' = @(
        'CreateAnalyzer','DeleteAnalyzer','UpdateArchiveRule','CreateArchiveRule',
        'StartPolicyGeneration','ApplyArchiveRule','GetAnalyzer','GetArchiveRule',
        'ListAnalyzers','ListArchiveRules','ListAccessPreviewFindings','ListFindings',
        'ValidatePolicy','CheckAccessNotGranted','CheckNoNewAccess','CheckNoPublicAccess'
    )
    'sso' = @(
        'CreatePermissionSet','UpdatePermissionSet','DeletePermissionSet',
        'AttachManagedPolicyToPermissionSet','DetachManagedPolicyFromPermissionSet',
        'PutInlinePolicyToPermissionSet','DeleteInlinePolicyFromPermissionSet',
        'ProvisionPermissionSet','CreateAccountAssignment','DeleteAccountAssignment',
        'GetInlinePolicyForPermissionSet','ListPermissionSets','ListAccountAssignments'
    )
    'identitystore' = @(
        'CreateUser','UpdateUser','DeleteUser','CreateGroup','DeleteGroup',
        'CreateGroupMembership','DeleteGroupMembership',
        'DescribeUser','DescribeGroup','ListUsers','ListGroups','ListGroupMemberships'
    )
    'ds' = @(
        'CreateDirectory','DeleteDirectory','UpdateDirectorySetup',
        'CreateMicrosoftAD','CreateTrust','DeleteTrust','AcceptSharedDirectory',
        'EnableLDAPS','DisableLDAPS','ResetUserPassword',
        'DescribeDirectories','DescribeDomainControllers','DescribeTrusts'
    )
    'cognito-idp' = @(
        'CreateUserPool','UpdateUserPool','DeleteUserPool',
        'AdminCreateUser','AdminDeleteUser','AdminSetUserPassword','AdminResetUserPassword',
        'AdminAddUserToGroup','AdminUpdateUserAttributes','AdminConfirmSignUp',
        'CreateUserPoolClient','UpdateUserPoolClient','SetUserPoolMfaConfig',
        'DescribeUserPool','ListUsers','ListUserPools','GetUserPoolMfaConfig'
    )
    'cognito-identity' = @(
        'CreateIdentityPool','UpdateIdentityPool','DeleteIdentityPool',
        'SetIdentityPoolRoles','GetCredentialsForIdentity','GetOpenIdToken',
        'GetIdentityPoolRoles','ListIdentityPools'
    )
    # Storage
    'elasticfilesystem' = @(
        'CreateFileSystem','DeleteFileSystem','UpdateFileSystem',
        'CreateMountTarget','DeleteMountTarget',
        'PutFileSystemPolicy','DeleteFileSystemPolicy',
        'PutBackupPolicy','DescribeFileSystemPolicy','DescribeFileSystems'
    )
    'fsx' = @(
        'CreateFileSystem','DeleteFileSystem','UpdateFileSystem',
        'CreateBackup','DeleteBackup','RestoreVolumeFromSnapshot',
        'CreateStorageVirtualMachine','DescribeFileSystems','DescribeBackups'
    )
    'backup' = @(
        'CreateBackupPlan','DeleteBackupPlan','UpdateBackupPlan',
        'CreateBackupVault','DeleteBackupVault','PutBackupVaultAccessPolicy',
        'DeleteBackupVaultAccessPolicy','PutBackupVaultNotifications',
        'StartBackupJob','StartRestoreJob','StartCopyJob',
        'DescribeBackupVault','GetBackupVaultAccessPolicy','ListBackupVaults','ListRecoveryPointsByBackupVault'
    )
    'storagegateway' = @(
        'CreateGateway','DeleteGateway','UpdateGatewayInformation',
        'CreateSMBFileShare','CreateNFSFileShare','DeleteFileShare',
        'StartGateway','ShutdownGateway','ListGateways'
    )
    # Database
    'elasticache' = @(
        'CreateCacheCluster','DeleteCacheCluster','ModifyCacheCluster',
        'CreateReplicationGroup','DeleteReplicationGroup','ModifyReplicationGroup',
        'CreateUser','DeleteUser','ModifyUser','CreateUserGroup','ModifyUserGroup',
        'AuthorizeCacheSecurityGroupIngress','RevokeCacheSecurityGroupIngress',
        'DescribeCacheClusters','DescribeReplicationGroups','DescribeUsers'
    )
    'memorydb' = @(
        'CreateCluster','DeleteCluster','UpdateCluster',
        'CreateUser','DeleteUser','UpdateUser','CreateACL','DeleteACL','UpdateACL',
        'DescribeClusters','DescribeUsers','DescribeAcls'
    )
    'neptune' = @(
        'CreateDBCluster','DeleteDBCluster','ModifyDBCluster',
        'CreateDBInstance','DeleteDBInstance','ModifyDBInstance',
        'DescribeDBClusters','DescribeDBInstances'
    )
    'docdb' = @(
        'CreateDBCluster','DeleteDBCluster','ModifyDBCluster',
        'CreateDBInstance','DeleteDBInstance','ModifyDBInstance',
        'DescribeDBClusters','DescribeDBInstances'
    )
    'timestream' = @(
        'CreateDatabase','DeleteDatabase','UpdateDatabase',
        'CreateTable','DeleteTable','UpdateTable',
        'WriteRecords','Select','DescribeDatabase','DescribeTable','ListDatabases','ListTables'
    )
    'cassandra' = @(
        'Create','Alter','Drop','Modify','Select','TagResource','UntagResource'
    )
    # Container / serverless
    'apprunner' = @(
        'CreateService','DeleteService','UpdateService','PauseService','ResumeService',
        'CreateConnection','DeleteConnection','CreateAutoScalingConfiguration',
        'DescribeService','ListServices'
    )
    'appmesh' = @(
        'CreateMesh','DeleteMesh','UpdateMesh',
        'CreateVirtualGateway','CreateVirtualNode','CreateVirtualRouter','CreateVirtualService',
        'CreateRoute','CreateGatewayRoute',
        'DescribeMesh','ListMeshes'
    )
    # Networking & content delivery
    'cloudfront' = @(
        'CreateDistribution','UpdateDistribution','DeleteDistribution',
        'CreateOriginAccessControl','UpdateOriginAccessControl','DeleteOriginAccessControl',
        'CreatePublicKey','DeletePublicKey','CreateKeyGroup','DeleteKeyGroup',
        'CreateFunction','UpdateFunction','DeleteFunction','PublishFunction','TestFunction',
        'GetDistribution','ListDistributions','GetFunction','ListFunctions'
    )
    'route53' = @(
        'CreateHostedZone','DeleteHostedZone','UpdateHostedZoneComment',
        'ChangeResourceRecordSets','CreateHealthCheck','DeleteHealthCheck',
        'AssociateVPCWithHostedZone','DisassociateVPCFromHostedZone',
        'GetHostedZone','ListHostedZones','ListResourceRecordSets'
    )
    'globalaccelerator' = @(
        'CreateAccelerator','DeleteAccelerator','UpdateAccelerator',
        'CreateEndpointGroup','UpdateEndpointGroup','DeleteEndpointGroup',
        'CreateListener','UpdateListener','DeleteListener',
        'DescribeAccelerator','ListAccelerators'
    )
    'apigateway' = @(
        'GET','POST','PUT','PATCH','DELETE','OPTIONS','HEAD',
        'UpdateRestApiPolicy','UpdateDomainName','UpdateApiKey'
    )
    'elasticloadbalancing' = @(
        'CreateLoadBalancer','DeleteLoadBalancer','ModifyLoadBalancerAttributes',
        'CreateListener','DeleteListener','ModifyListener',
        'CreateTargetGroup','DeleteTargetGroup','RegisterTargets','DeregisterTargets',
        'CreateRule','DeleteRule','ModifyRule',
        'SetSecurityGroups','SetSubnets','DescribeLoadBalancers','DescribeListeners','DescribeTargetHealth'
    )
    # Security & compliance services
    'guardduty' = @(
        'CreateDetector','UpdateDetector','DeleteDetector',
        'CreateFilter','UpdateFilter','DeleteFilter',
        'CreateIPSet','UpdateIPSet','DeleteIPSet',
        'CreateThreatIntelSet','UpdateThreatIntelSet','DeleteThreatIntelSet',
        'CreateMembers','InviteMembers','DisassociateFromMasterAccount',
        'CreatePublishingDestination','UpdatePublishingDestination','DeletePublishingDestination',
        'GetDetector','ListDetectors','GetFindings','ListFindings'
    )
    'securityhub' = @(
        'EnableSecurityHub','DisableSecurityHub','EnableImportFindingsForProduct',
        'DisableImportFindingsForProduct','UpdateStandardsControl','BatchEnableStandards',
        'BatchDisableStandards','CreateActionTarget','DeleteActionTarget',
        'CreateInsight','UpdateInsight','DeleteInsight','UpdateSecurityHubConfiguration',
        'GetEnabledStandards','ListEnabledProductsForImport','DescribeHub'
    )
    'macie2' = @(
        'EnableMacie','DisableMacie','UpdateMacieSession',
        'CreateAllowList','UpdateAllowList','DeleteAllowList',
        'CreateClassificationJob','CreateCustomDataIdentifier','DeleteCustomDataIdentifier',
        'PutClassificationExportConfiguration','GetMacieSession','ListClassificationJobs'
    )
    'inspector2' = @(
        'Enable','Disable','UpdateConfiguration','BatchUpdateMemberEc2DeepInspectionStatus',
        'CreateFilter','UpdateFilter','DeleteFilter','CreateFindingsReport',
        'BatchGetAccountStatus','ListMembers','ListFindings'
    )
    'detective' = @(
        'CreateGraph','DeleteGraph','CreateMembers','DeleteMembers',
        'EnableOrganizationAdminAccount','DisableOrganizationAdminAccount',
        'ListGraphs','ListMembers'
    )
    'fms' = @(
        'PutPolicy','DeletePolicy','PutNotificationChannel','DeleteNotificationChannel',
        'AssociateAdminAccount','DisassociateAdminAccount',
        'GetPolicy','ListPolicies'
    )
    'wafv2' = @(
        'CreateWebACL','UpdateWebACL','DeleteWebACL',
        'CreateRuleGroup','UpdateRuleGroup','DeleteRuleGroup','PutLoggingConfiguration',
        'DeleteLoggingConfiguration','AssociateWebACL','DisassociateWebACL',
        'GetWebACL','ListWebACLs','GetRuleGroup','ListRuleGroups'
    )
    'shield' = @(
        'CreateProtection','DeleteProtection','UpdateProtectionGroup','CreateProtectionGroup',
        'DeleteProtectionGroup','EnableProactiveEngagement','DisableProactiveEngagement',
        'AssociateDRTLogBucket','DisassociateDRTLogBucket','AssociateDRTRole','DisassociateDRTRole',
        'DescribeProtection','ListProtections'
    )
    'acm' = @(
        'RequestCertificate','DeleteCertificate','RenewCertificate','ImportCertificate',
        'AddTagsToCertificate','RemoveTagsFromCertificate','ResendValidationEmail',
        'DescribeCertificate','ListCertificates','GetCertificate','ExportCertificate'
    )
    'acm-pca' = @(
        'CreateCertificateAuthority','UpdateCertificateAuthority','DeleteCertificateAuthority',
        'IssueCertificate','RevokeCertificate','ImportCertificateAuthorityCertificate',
        'PutPolicy','DeletePolicy','RestoreCertificateAuthority',
        'DescribeCertificateAuthority','ListCertificateAuthorities','GetCertificate'
    )
    'signer' = @(
        'StartSigningJob','RevokeSignature','RevokeSigningProfile',
        'PutSigningProfile','RemoveProfilePermission','AddProfilePermission',
        'GetSigningProfile','ListSigningProfiles'
    )
    'cloudhsm' = @(
        'CreateCluster','DeleteCluster','CreateHsm','DeleteHsm','CreateBackup','DeleteBackup',
        'CopyBackupToRegion','RestoreBackup','InitializeCluster',
        'DescribeClusters','DescribeBackups'
    )
    'verifiedpermissions' = @(
        'CreatePolicyStore','DeletePolicyStore','UpdatePolicyStore',
        'CreatePolicy','UpdatePolicy','DeletePolicy',
        'CreatePolicyTemplate','UpdatePolicyTemplate','DeletePolicyTemplate',
        'CreateIdentitySource','UpdateIdentitySource','DeleteIdentitySource',
        'IsAuthorized','IsAuthorizedWithToken','GetPolicyStore','ListPolicyStores'
    )
    'ram' = @(
        'CreateResourceShare','UpdateResourceShare','DeleteResourceShare',
        'AssociateResourceShare','DisassociateResourceShare',
        'AcceptResourceShareInvitation','RejectResourceShareInvitation',
        'CreatePermission','DeletePermission','EnableSharingWithAwsOrganization',
        'GetResourceShares','ListResources'
    )
    # Networking deeper
    'network-firewall' = @(
        'CreateFirewall','UpdateFirewallPolicyChangeProtection','DeleteFirewall',
        'CreateFirewallPolicy','UpdateFirewallPolicy','DeleteFirewallPolicy',
        'CreateRuleGroup','UpdateRuleGroup','DeleteRuleGroup',
        'PutResourcePolicy','DeleteResourcePolicy','DescribeFirewall','ListFirewalls'
    )
    'vpc-lattice' = @(
        'CreateService','DeleteService','UpdateService',
        'CreateServiceNetwork','DeleteServiceNetwork','UpdateServiceNetwork',
        'CreateListener','DeleteListener','UpdateListener',
        'CreateTargetGroup','DeleteTargetGroup','UpdateTargetGroup',
        'PutAuthPolicy','DeleteAuthPolicy','PutResourcePolicy','DeleteResourcePolicy',
        'GetService','ListServices'
    )
    # Application integration
    'states' = @(
        'CreateStateMachine','UpdateStateMachine','DeleteStateMachine',
        'StartExecution','StartSyncExecution','StopExecution',
        'CreateActivity','DeleteActivity',
        'PutSourceCode','DescribeStateMachine','ListStateMachines'
    )
    'events' = @(
        'PutRule','DeleteRule','EnableRule','DisableRule',
        'PutTargets','RemoveTargets','PutEvents',
        'CreateEventBus','DeleteEventBus','PutPermission','RemovePermission',
        'CreateApiDestination','DeleteApiDestination','CreateConnection','DeleteConnection',
        'DescribeRule','ListRules','ListTargetsByRule'
    )
    'scheduler' = @(
        'CreateSchedule','UpdateSchedule','DeleteSchedule',
        'CreateScheduleGroup','DeleteScheduleGroup',
        'GetSchedule','ListSchedules'
    )
    'pipes' = @(
        'CreatePipe','UpdatePipe','DeletePipe','StartPipe','StopPipe',
        'DescribePipe','ListPipes'
    )
    'mq' = @(
        'CreateBroker','UpdateBroker','DeleteBroker','RebootBroker',
        'CreateConfiguration','UpdateConfiguration','CreateUser','UpdateUser','DeleteUser',
        'DescribeBroker','ListBrokers'
    )
    'appflow' = @(
        'CreateFlow','UpdateFlow','DeleteFlow','StartFlow','StopFlow',
        'CreateConnectorProfile','UpdateConnectorProfile','DeleteConnectorProfile',
        'DescribeFlow','ListFlows'
    )
    # Analytics
    'athena' = @(
        'StartQueryExecution','StopQueryExecution','GetQueryResults','GetQueryExecution',
        'CreateWorkGroup','UpdateWorkGroup','DeleteWorkGroup',
        'CreateDataCatalog','UpdateDataCatalog','DeleteDataCatalog',
        'CreatePreparedStatement','UpdatePreparedStatement','DeletePreparedStatement',
        'GetWorkGroup','ListWorkGroups'
    )
    'firehose' = @(
        'CreateDeliveryStream','DeleteDeliveryStream','UpdateDestination',
        'PutRecord','PutRecordBatch','StartDeliveryStreamEncryption','StopDeliveryStreamEncryption',
        'DescribeDeliveryStream','ListDeliveryStreams'
    )
    'lakeformation' = @(
        'PutDataLakeSettings','RegisterResource','DeregisterResource',
        'GrantPermissions','RevokePermissions','BatchGrantPermissions','BatchRevokePermissions',
        'CreateDataCellsFilter','DeleteDataCellsFilter','UpdateDataCellsFilter',
        'GetDataLakeSettings','ListPermissions','ListResources'
    )
    'quicksight' = @(
        'CreateAccountSubscription','DeleteAccountSubscription','UpdateAccountSettings',
        'CreateUser','DeleteUser','UpdateUser','CreateGroup','DeleteGroup',
        'CreateDataSource','UpdateDataSource','DeleteDataSource',
        'CreateDataSet','UpdateDataSet','DeleteDataSet','PassDataSet',
        'CreateAnalysis','UpdateAnalysis','DeleteAnalysis',
        'CreateDashboard','UpdateDashboard','DeleteDashboard','UpdateDashboardPermissions',
        'DescribeUser','ListUsers'
    )
    'opensearch' = @(
        'CreateDomain','DeleteDomain','UpdateDomainConfig',
        'CreateOutboundConnection','DeleteOutboundConnection','AcceptInboundConnection',
        'UpdateRoleMapping','DescribeDomain','ListDomainNames'
    )
    'es' = @(
        'CreateElasticsearchDomain','DeleteElasticsearchDomain','UpdateElasticsearchDomainConfig',
        'DescribeElasticsearchDomain','ListDomainNames'
    )
    'kinesisanalytics' = @(
        'CreateApplication','UpdateApplication','DeleteApplication',
        'StartApplication','StopApplication','AddApplicationInput','AddApplicationOutput',
        'DescribeApplication','ListApplications'
    )
    'kafka' = @(
        'CreateCluster','UpdateClusterConfiguration','DeleteCluster',
        'CreateConfiguration','UpdateConfiguration','DeleteConfiguration',
        'PutClusterPolicy','DeleteClusterPolicy','BatchAssociateScramSecret','BatchDisassociateScramSecret',
        'DescribeCluster','ListClusters'
    )
    # Machine Learning extra
    'bedrock' = @(
        'CreateModelCustomizationJob','StopModelCustomizationJob','DeleteCustomModel',
        'CreateAgent','UpdateAgent','DeleteAgent','PrepareAgent',
        'CreateGuardrail','UpdateGuardrail','DeleteGuardrail',
        'CreateKnowledgeBase','UpdateKnowledgeBase','DeleteKnowledgeBase',
        'InvokeModel','InvokeModelWithResponseStream','InvokeAgent',
        'PutFoundationModelEntitlement','GetFoundationModel','ListFoundationModels'
    )
    'comprehend' = @(
        'CreateDocumentClassifier','DeleteDocumentClassifier','CreateEntityRecognizer','DeleteEntityRecognizer',
        'StartEntitiesDetectionJob','StartSentimentDetectionJob','StartKeyPhrasesDetectionJob',
        'CreateFlywheel','UpdateFlywheel','DeleteFlywheel',
        'DescribeFlywheel','ListFlywheels'
    )
    'rekognition' = @(
        'CreateCollection','DeleteCollection','CreateProject','DeleteProject',
        'CreateStreamProcessor','StartStreamProcessor','StopStreamProcessor','DeleteStreamProcessor',
        'IndexFaces','DeleteFaces','SearchFaces','SearchFacesByImage',
        'DescribeCollection','ListCollections'
    )
    'textract' = @(
        'StartDocumentTextDetection','StartDocumentAnalysis','StartExpenseAnalysis','StartLendingAnalysis',
        'CreateAdapter','UpdateAdapter','DeleteAdapter','GetAdapter','ListAdapters'
    )
    'transcribe' = @(
        'StartTranscriptionJob','DeleteTranscriptionJob','StartMedicalTranscriptionJob',
        'CreateVocabulary','UpdateVocabulary','DeleteVocabulary','CreateLanguageModel'
    )
    'translate' = @(
        'TranslateText','TranslateDocument','StartTextTranslationJob','StopTextTranslationJob',
        'ImportTerminology','DeleteTerminology','CreateParallelData','DeleteParallelData'
    )
    'lex' = @(
        'CreateBot','UpdateBot','DeleteBot','BuildBotLocale',
        'CreateIntent','UpdateIntent','DeleteIntent','CreateSlot','UpdateSlot','DeleteSlot',
        'PutResourcePolicy','DeleteResourcePolicy',
        'DescribeBot','ListBots'
    )
    'kendra' = @(
        'CreateIndex','UpdateIndex','DeleteIndex','CreateDataSource','UpdateDataSource','DeleteDataSource',
        'StartDataSourceSyncJob','StopDataSourceSyncJob','Query','Retrieve',
        'DescribeIndex','ListIndices'
    )
    'omics' = @(
        'CreateAnnotationStore','DeleteAnnotationStore','CreateReferenceStore','DeleteReferenceStore',
        'CreateSequenceStore','DeleteSequenceStore','CreateVariantStore','DeleteVariantStore',
        'StartReadSetExportJob','StartReadSetImportJob','StartReferenceImportJob',
        'CreateWorkflow','DeleteWorkflow','StartRun','CancelRun',
        'GetWorkflow','ListWorkflows'
    )
    # Migration
    'dms' = @(
        'CreateReplicationInstance','DeleteReplicationInstance','ModifyReplicationInstance',
        'CreateReplicationTask','DeleteReplicationTask','StartReplicationTask','StopReplicationTask',
        'CreateEndpoint','DeleteEndpoint','ModifyEndpoint',
        'DescribeReplicationInstances','DescribeReplicationTasks'
    )
    'datasync' = @(
        'CreateTask','UpdateTask','DeleteTask','StartTaskExecution','CancelTaskExecution',
        'CreateAgent','DeleteAgent',
        'CreateLocationS3','CreateLocationEfs','CreateLocationFsxLustre','CreateLocationNfs','CreateLocationSmb',
        'DeleteLocation','DescribeTask','ListTasks'
    )
    'transfer' = @(
        'CreateServer','UpdateServer','DeleteServer','StartServer','StopServer',
        'CreateUser','UpdateUser','DeleteUser','ImportSshPublicKey','DeleteSshPublicKey',
        'CreateAccess','UpdateAccess','DeleteAccess',
        'DescribeServer','ListServers'
    )
    # End-user / front-end
    'amplify' = @(
        'CreateApp','UpdateApp','DeleteApp','CreateBranch','UpdateBranch','DeleteBranch',
        'CreateDeployment','StartDeployment','CreateDomainAssociation','DeleteDomainAssociation',
        'GetApp','ListApps'
    )
    'appsync' = @(
        'CreateGraphqlApi','UpdateGraphqlApi','DeleteGraphqlApi',
        'CreateApiKey','UpdateApiKey','DeleteApiKey',
        'CreateDataSource','UpdateDataSource','DeleteDataSource',
        'CreateResolver','UpdateResolver','DeleteResolver',
        'GetGraphqlApi','ListGraphqlApis'
    )
    'devicefarm' = @(
        'CreateProject','UpdateProject','DeleteProject','CreateUpload','DeleteUpload',
        'CreateNetworkProfile','UpdateNetworkProfile','CreateInstanceProfile','UpdateInstanceProfile',
        'GetProject','ListProjects'
    )
    'ses' = @(
        'CreateConfigurationSet','DeleteConfigurationSet','UpdateConfigurationSetSendingEnabled',
        'CreateEmailTemplate','UpdateEmailTemplate','DeleteEmailTemplate',
        'CreateReceiptRule','UpdateReceiptRule','DeleteReceiptRule','CreateReceiptRuleSet',
        'SendEmail','SendRawEmail','SendBulkEmail','SendTemplatedEmail',
        'PutAccountSendingAttributes','PutIdentityNotificationAttributes',
        'GetConfigurationSet','ListConfigurationSets'
    )
    'cloudshell' = @(
        'CreateEnvironment','StartEnvironment','StopEnvironment','DeleteEnvironment',
        'CreateSession','PutCredentials','GetFileDownloadUrls','GetFileUploadUrls'
    )
    'cloud9' = @(
        'CreateEnvironmentEC2','CreateEnvironmentSSH','UpdateEnvironment','DeleteEnvironment',
        'CreateEnvironmentMembership','UpdateEnvironmentMembership','DeleteEnvironmentMembership',
        'DescribeEnvironments','ListEnvironments'
    )
    # Cost / billing
    'ce' = @(
        'CreateAnomalyMonitor','DeleteAnomalyMonitor','UpdateAnomalyMonitor',
        'CreateAnomalySubscription','DeleteAnomalySubscription','UpdateAnomalySubscription',
        'CreateCostCategoryDefinition','UpdateCostCategoryDefinition','DeleteCostCategoryDefinition',
        'GetCostAndUsage','GetCostForecast','GetReservationUtilization'
    )
    'budgets' = @(
        'CreateBudget','UpdateBudget','DeleteBudget','CreateBudgetAction','UpdateBudgetAction','DeleteBudgetAction',
        'DescribeBudgetAction','ViewBudget'
    )
    # Misc but security-relevant
    'iot' = @(
        'CreateThing','DeleteThing','UpdateThing','CreatePolicy','DeletePolicy','UpdatePolicy',
        'AttachPolicy','DetachPolicy','AttachThingPrincipal','DetachThingPrincipal',
        'CreateCertificate','DeleteCertificate','UpdateCertificate',
        'CreateRoleAlias','DeleteRoleAlias','UpdateRoleAlias',
        'CreateAuthorizer','DeleteAuthorizer','SetDefaultAuthorizer',
        'CreateTopicRule','DeleteTopicRule','ReplaceTopicRule','EnableTopicRule','DisableTopicRule',
        'DescribeThing','ListThings'
    )
    'greengrass' = @(
        'CreateComponentVersion','DeleteComponentVersion','CreateDeployment','CancelDeployment',
        'AssociateRoleToGroup','DisassociateRoleFromGroup','AssociateServiceRoleToAccount',
        'CreateGroup','DeleteGroup','UpdateGroup','DescribeComponent','ListComponents'
    )
    # Management & governance
    'cloudformation' = @(
        'CreateStack','UpdateStack','DeleteStack','ExecuteChangeSet','CreateChangeSet','DeleteChangeSet',
        'CreateStackSet','UpdateStackSet','DeleteStackSet','CreateStackInstances','DeleteStackInstances',
        'SetStackPolicy','RegisterType','DeregisterType','PublishType',
        'DescribeStacks','ListStacks'
    )
    'controltower' = @(
        'CreateLandingZone','UpdateLandingZone','DeleteLandingZone','ResetLandingZone',
        'EnableControl','DisableControl','UpdateEnabledControl',
        'GetLandingZone','ListLandingZones'
    )
    'servicecatalog' = @(
        'CreatePortfolio','UpdatePortfolio','DeletePortfolio','CreateProduct','UpdateProduct','DeleteProduct',
        'AssociateProductWithPortfolio','DisassociateProductFromPortfolio',
        'CreateConstraint','UpdateConstraint','DeleteConstraint',
        'ProvisionProduct','TerminateProvisionedProduct','UpdateProvisionedProduct',
        'DescribePortfolio','ListPortfolios'
    )
    'license-manager' = @(
        'CreateLicenseConfiguration','UpdateLicenseConfiguration','DeleteLicenseConfiguration',
        'CreateGrant','UpdateGrantVersion','CreateGrantVersion','DeleteGrant','AcceptGrant','RejectGrant',
        'GetGrant','ListLicenses'
    )
    'autoscaling' = @(
        'CreateAutoScalingGroup','UpdateAutoScalingGroup','DeleteAutoScalingGroup',
        'CreateLaunchConfiguration','DeleteLaunchConfiguration','AttachInstances','DetachInstances',
        'AttachLoadBalancerTargetGroups','DetachLoadBalancerTargetGroups',
        'PutScalingPolicy','DeletePolicy','ExecutePolicy','SetDesiredCapacity',
        'DescribeAutoScalingGroups','DescribeLaunchConfigurations'
    )
    'workspaces' = @(
        'CreateWorkspaces','TerminateWorkspaces','RebootWorkspaces','RebuildWorkspaces','StartWorkspaces',
        'StopWorkspaces','ModifyWorkspaceProperties','ModifyWorkspaceState',
        'CreateWorkspaceBundle','DeleteWorkspaceBundle','UpdateWorkspaceBundle',
        'AssociateConnectionAlias','DisassociateConnectionAlias',
        'DescribeWorkspaces','ListAvailableManagementCidrRanges'
    )
}

# Friendly names for action categories used by capability checks
$Global:IR_ActionCategories = @{
    'PrivilegeEscalation' = @(
        'iam:CreateAccessKey','iam:CreateLoginProfile','iam:UpdateLoginProfile',
        'iam:AttachUserPolicy','iam:AttachGroupPolicy','iam:AttachRolePolicy',
        'iam:PutUserPolicy','iam:PutGroupPolicy','iam:PutRolePolicy',
        'iam:CreatePolicyVersion','iam:SetDefaultPolicyVersion',
        'iam:UpdateAssumeRolePolicy','iam:PassRole','iam:AddUserToGroup',
        'sts:AssumeRole'
    )
    'CredentialExposure' = @(
        'secretsmanager:GetSecretValue','ssm:GetParameter','ssm:GetParameters','ssm:GetParametersByPath',
        'kms:Decrypt','kms:GenerateDataKey',
        'ec2:GetPasswordData','iam:GetAccessKeyLastUsed','iam:CreateAccessKey',
        'lambda:GetFunction','codebuild:BatchGetProjects'
    )
    'DataExfiltration' = @(
        's3:GetObject','s3:ListBucket','s3:GetBucketPolicy',
        'dynamodb:Scan','dynamodb:Query','dynamodb:ExportTableToPointInTime',
        'rds:CopyDBSnapshot','rds:CreateDBSnapshot','rds:ModifyDBSnapshotAttribute',
        'rds:DownloadDBLogFilePortion','ec2:CopyImage','ec2:CopySnapshot',
        'ec2:ModifySnapshotAttribute','ecr:BatchGetImage','ecr:GetDownloadUrlForLayer'
    )
    'LogTampering' = @(
        'cloudtrail:StopLogging','cloudtrail:DeleteTrail','cloudtrail:UpdateTrail',
        'cloudtrail:PutEventSelectors',
        'config:DeleteConfigurationRecorder','config:StopConfigurationRecorder',
        'config:DeleteDeliveryChannel','config:DeleteConfigRule',
        'logs:DeleteLogGroup','logs:DeleteLogStream','logs:DeleteRetentionPolicy',
        'cloudwatch:DeleteAlarms','cloudwatch:DisableAlarmActions',
        's3:DeleteBucketLogging','s3:PutBucketLogging'
    )
    'Persistence' = @(
        'iam:CreateUser','iam:CreateAccessKey','iam:CreateLoginProfile',
        'iam:CreateRole','iam:UpdateAssumeRolePolicy',
        'lambda:CreateFunction','lambda:UpdateFunctionCode',
        'ec2:RunInstances','ssm:CreateDocument','ssm:UpdateDocument','ssm:ModifyDocumentPermission'
    )
    'DefenseEvasion' = @(
        'iam:DeleteAccessKey','cloudtrail:DeleteTrail','cloudtrail:StopLogging',
        'guardduty:DeleteDetector','guardduty:DisassociateFromMasterAccount',
        'guardduty:UpdateDetector','securityhub:DisableSecurityHub',
        'inspector:DisableEnableInUseAccounts','macie2:DisableMacie',
        'config:DeleteConfigurationRecorder','config:StopConfigurationRecorder'
    )
    'LateralMovement' = @(
        'sts:AssumeRole','sts:AssumeRoleWithSAML','sts:AssumeRoleWithWebIdentity',
        'ec2:AssociateIamInstanceProfile','ec2:ReplaceIamInstanceProfileAssociation',
        'ssm:SendCommand','ssm:StartSession',
        'lambda:InvokeFunction','ecs:ExecuteCommand','eks:AccessKubernetesApi'
    )
    'ResourceHijack' = @(
        'ec2:RunInstances','ec2:StartInstances','sagemaker:CreateNotebookInstance',
        'sagemaker:CreateTrainingJob','lambda:CreateFunction','lambda:InvokeFunction',
        'glue:CreateJob','glue:StartJobRun','codebuild:StartBuild','batch:SubmitJob'
    )
    'Destruction' = @(
        's3:DeleteBucket','s3:DeleteObject','ec2:TerminateInstances','ec2:DeleteVolume',
        'rds:DeleteDBInstance','rds:DeleteDBSnapshot','dynamodb:DeleteTable',
        'iam:DeleteUser','iam:DeleteRole','kms:ScheduleKeyDeletion',
        'logs:DeleteLogGroup','cloudtrail:DeleteTrail','config:DeleteConfigurationRecorder',
        'organizations:LeaveOrganization','organizations:RemoveAccountFromOrganization'
    )
}

# ----------------------------------------------------------------
# Expand an action string ("s3:*", "*", "ec2:Describe*") into the
# concrete list it would actually grant.
# ----------------------------------------------------------------
function Expand-ActionPattern {
    param([string]$Pattern)
    if (-not $Pattern) { return @() }
    $Pattern = $Pattern.Trim()

    # Full wildcard - return EVERY action in the catalog
    if ($Pattern -eq '*') {
        $all = New-Object System.Collections.Generic.List[string]
        foreach ($svc in $Global:IR_ActionCatalog.Keys) {
            foreach ($act in $Global:IR_ActionCatalog[$svc]) {
                $all.Add("${svc}:${act}")
            }
        }
        return $all.ToArray()
    }

    # Service wildcard - "service:*"
    if ($Pattern -match '^([^:]+):\*$') {
        $svc = $Matches[1].ToLower()
        if ($Global:IR_ActionCatalog.ContainsKey($svc)) {
            return @($Global:IR_ActionCatalog[$svc] | ForEach-Object { "${svc}:${_}" })
        }
        # Unknown service - emit the pattern itself as a single placeholder
        # so the auditor still sees that the policy grants a service-wide wildcard.
        return @("${svc}:*")
    }

    # Action-level wildcard - "service:Action*" or "service:Get*"
    if ($Pattern -match '^([^:]+):(.+\*.*)$') {
        $svc = $Matches[1].ToLower()
        $glob = $Matches[2]
        $regex = '^' + ([regex]::Escape($glob) -replace '\\\*','.*') + '$'
        if ($Global:IR_ActionCatalog.ContainsKey($svc)) {
            $matched = $Global:IR_ActionCatalog[$svc] | Where-Object { $_ -match $regex }
            if ($matched) {
                return @($matched | ForEach-Object { "${svc}:${_}" })
            }
        }
        # Unknown service or no catalog match - emit the literal pattern so
        # it still shows up in the action table.
        return @("${svc}:${glob}")
    }

    # Exact action - return as-is, normalised case
    if ($Pattern -match '^([^:]+):(.+)$') {
        return @("$($Matches[1].ToLower()):$($Matches[2])")
    }
    return @($Pattern)
}

# ----------------------------------------------------------------
# Build the per-action effective-permission map for a role.
#  Input:  AttachedPolicies + InlinePolicies (list of {Doc=...})
#  Output: hashtable action -> @{
#            Effect      = 'Allow' / 'Deny' / 'AllowOverriddenByDeny'
#            Resources   = list of resource ARN patterns
#            Conditions  = list of condition strings (if any)
#            SourcePolicies = list of policy names that mention this action
#          }
#  Deny always wins per AWS evaluation logic.
# ----------------------------------------------------------------
function Build-EffectivePermissions {
    param(
        [object[]]$AttachedPolicies = @(),
        [object[]]$InlinePolicies   = @()
    )

    $effective = @{}    # action -> @{ ... }
    $allPols = @()
    foreach ($p in $AttachedPolicies) { $allPols += ,@{ Name = $p.Name; Doc = $p.Doc; Kind = 'Managed' } }
    foreach ($p in $InlinePolicies)   { $allPols += ,@{ Name = $p.Name; Doc = $p.Doc; Kind = 'Inline'  } }

    foreach ($pol in $allPols) {
        if (-not $pol.Doc) { continue }
        $stmts = if ($pol.Doc.Statement -is [array]) { $pol.Doc.Statement } else { @($pol.Doc.Statement) }
        foreach ($s in $stmts) {
            if (-not $s) { continue }
            $effect = if ($s.Effect) { "$($s.Effect)" } else { 'Allow' }

            $actions = @()
            if ($s.Action -is [array]) { $actions = $s.Action }
            elseif ($s.Action)         { $actions = @($s.Action) }
            $notActions = @()
            if ($s.NotAction -is [array]) { $notActions = $s.NotAction }
            elseif ($s.NotAction)         { $notActions = @($s.NotAction) }

            $resources = @()
            if ($s.Resource -is [array]) { $resources = $s.Resource }
            elseif ($s.Resource)         { $resources = @($s.Resource) }
            $resStr = if ($resources.Count -gt 0) { ($resources -join ',') } else { '*' }
            $hasCondition = [bool]$s.Condition
            $condStr = ''
            if ($hasCondition) {
                try { $condStr = ($s.Condition | ConvertTo-Json -Compress -Depth 5) } catch { $condStr = '<unparsable>' }
            }

            # NotAction means "everything except these" - it's an inverted match.
            # Mark all catalogued actions for matching services as covered, except the ones listed.
            $expandedActions = New-Object System.Collections.Generic.List[string]
            if ($notActions.Count -gt 0) {
                # NotAction is rare and dangerous - flag it explicitly.
                # We expand to everything in the catalog NOT in notActions.
                $notActSet = [System.Collections.Generic.HashSet[string]]::new()
                foreach ($na in $notActions) {
                    foreach ($e in (Expand-ActionPattern $na)) { [void]$notActSet.Add($e) }
                }
                foreach ($svc in $Global:IR_ActionCatalog.Keys) {
                    foreach ($act in $Global:IR_ActionCatalog[$svc]) {
                        $full = "${svc}:${act}"
                        if (-not $notActSet.Contains($full)) { $expandedActions.Add($full) }
                    }
                }
            } else {
                foreach ($a in $actions) {
                    foreach ($e in (Expand-ActionPattern "$a")) { $expandedActions.Add($e) }
                }
            }

            foreach ($act in $expandedActions) {
                if (-not $effective.ContainsKey($act)) {
                    $effective[$act] = @{
                        Effect         = $effect
                        Resources      = New-Object System.Collections.Generic.List[string]
                        Conditions     = New-Object System.Collections.Generic.List[string]
                        SourcePolicies = New-Object System.Collections.Generic.List[string]
                        AllowVia       = New-Object System.Collections.Generic.List[string]
                        DenyVia        = New-Object System.Collections.Generic.List[string]
                    }
                }
                $rec = $effective[$act]
                if (-not $rec.SourcePolicies.Contains($pol.Name)) {
                    [void]$rec.SourcePolicies.Add($pol.Name)
                }
                if ($effect -eq 'Allow') {
                    if (-not $rec.AllowVia.Contains($pol.Name)) { [void]$rec.AllowVia.Add($pol.Name) }
                } else {
                    if (-not $rec.DenyVia.Contains($pol.Name)) { [void]$rec.DenyVia.Add($pol.Name) }
                }
                foreach ($r in $resources) {
                    if (-not $rec.Resources.Contains("$r")) { [void]$rec.Resources.Add("$r") }
                }
                if ($hasCondition -and -not $rec.Conditions.Contains($condStr)) {
                    [void]$rec.Conditions.Add($condStr)
                }
            }
        }
    }

    # Final pass: compute the resolved effect.
    # Deny always wins (AWS evaluation logic).
    foreach ($act in $effective.Keys) {
        $rec = $effective[$act]
        if ($rec.DenyVia.Count -gt 0 -and $rec.AllowVia.Count -gt 0) {
            $rec.Effect = 'AllowOverriddenByDeny'
        } elseif ($rec.DenyVia.Count -gt 0) {
            $rec.Effect = 'Deny'
        } else {
            $rec.Effect = 'Allow'
        }
    }

    return $effective
}

# ----------------------------------------------------------------
# Capability check - does the role's effective permissions include
# all actions in a given list? Returns the matched subset (which
# may be partial - useful for partial-match detection).
# ----------------------------------------------------------------
function Test-Capability {
    param(
        [hashtable]$Effective,
        [string[]]$RequiredActions
    )
    $matched = New-Object System.Collections.Generic.List[string]
    foreach ($req in $RequiredActions) {
        if ($Effective.ContainsKey($req)) {
            $rec = $Effective[$req]
            if ($rec.Effect -eq 'Allow') {
                [void]$matched.Add($req)
            }
        }
    }
    return $matched.ToArray()
}

# ----------------------------------------------------------------
# Detect resource scope on an action - did the statement grant
# this action on Resource:* (universal) or a specific ARN?
# ----------------------------------------------------------------
function Get-ActionResourceScope {
    param([object]$EffectiveRec)
    if (-not $EffectiveRec) { return 'NONE' }
    if ($EffectiveRec.Resources.Count -eq 0) { return 'ALL' }
    foreach ($r in $EffectiveRec.Resources) {
        if ($r -eq '*') { return 'ALL' }
    }
    return 'SCOPED'
}
