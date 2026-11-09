# Modules/IR-Collect.ps1
# ============================================================
#  Resource collectors - each function scans one AWS service
#  family in a given region and calls New-Attachment for every
#  IAM identity attached to a resource.
#  All functions follow the signature: Collect-<Service> -Region $r
# ============================================================

# ============================================================
# COMPUTE
# ============================================================

function Collect-EC2 {
    param([string]$Region)
    Write-ServiceHeader "EC2 Instances" $Region
    $count = 0

    $items = Invoke-IRAWSPaged -Arguments @('ec2','describe-instances','--query','Reservations[].Instances[]') -Region $Region -Description "EC2 instances"
    foreach ($inst in $items) {
        $Global:IR.Stats.ResourcesScanned++
        if (-not $inst.IamInstanceProfile) { continue }

        $name    = ($inst.Tags | Where-Object { $_.Key -eq 'Name' } | Select-Object -First 1).Value
        $resArn  = "arn:aws:ec2:${Region}:$($Global:IR.AccountId):instance/$($inst.InstanceId)"
        $roleArn = $inst.IamInstanceProfile.Arn
        $roleName= $roleArn.Split('/')[-1]

        $isAdmin = $false  # would need to fetch role policies - flagged via IAM audit

        New-Attachment -Region $Region -ResourceType 'EC2::Instance' `
            -ResourceId $inst.InstanceId -ResourceName $name -ResourceArn $resArn `
            -AttachmentType 'InstanceProfile' -IdentityType 'Role' `
            -IdentityArn $roleArn -IdentityName $roleName `
            -RiskLevel 'MEDIUM' -Notes "State=$($inst.State.Name) Type=$($inst.InstanceType)"
        $count++
    }
    Write-ServiceResult $count

    # VPC Flow Logs with IAM role
    Write-ServiceHeader "VPC Flow Logs" $Region
    $count = 0
    $r = Invoke-IRAWSCLI -Arguments @('ec2','describe-flow-logs') -Region $Region -Description "Flow logs"
    if ($r.Success -and $r.Output.FlowLogs) {
        foreach ($fl in $r.Output.FlowLogs) {
            if (-not $fl.DeliverLogsPermissionArn) { continue }
            New-Attachment -Region $Region -ResourceType 'EC2::FlowLog' `
                -ResourceId $fl.FlowLogId -ResourceName $fl.FlowLogId `
                -ResourceArn "arn:aws:ec2:${Region}:$($Global:IR.AccountId):vpc-flow-log/$($fl.FlowLogId)" `
                -AttachmentType 'DeliveryRole' -IdentityType 'Role' `
                -IdentityArn $fl.DeliverLogsPermissionArn `
                -IdentityName $fl.DeliverLogsPermissionArn.Split('/')[-1] `
                -RiskLevel 'LOW' -Notes "LogDestType=$($fl.LogDestinationType)"
            $count++
        }
    }
    Write-ServiceResult $count
}

function Collect-Lambda {
    param([string]$Region)
    Write-ServiceHeader "Lambda Functions" $Region
    $count = 0

    $items = Invoke-IRAWSPaged -Arguments @('lambda','list-functions') -Region $Region -ResultKey 'Functions' -Description "Lambda functions"
    foreach ($fn in $items) {
        $Global:IR.Stats.ResourcesScanned++
        # Execution role
        if ($fn.Role) {
            New-Attachment -Region $Region -ResourceType 'Lambda::Function' `
                -ResourceId $fn.FunctionName -ResourceName $fn.FunctionName -ResourceArn $fn.FunctionArn `
                -AttachmentType 'ExecutionRole' -IdentityType 'Role' `
                -IdentityArn $fn.Role -IdentityName $fn.Role.Split('/')[-1] `
                -RiskLevel 'MEDIUM' -Notes "Runtime=$($fn.Runtime) Modified=$($fn.LastModified)"
            $count++
        }

        # Resource-based policy (who can invoke this function)
        $pr = Invoke-IRAWSCLI -Arguments @('lambda','get-policy','--function-name',$fn.FunctionName) -Region $Region -Description "Lambda policy: $($fn.FunctionName)"
        if ($pr.Success -and $pr.Output.Policy) {
            try {
                $pDoc = $pr.Output.Policy | ConvertFrom-Json
                Add-PolicyPrincipalAttachments -PolicyDoc $pDoc -Region $Region `
                    -ResourceType 'Lambda::Function' -ResourceId $fn.FunctionName `
                    -ResourceName $fn.FunctionName -ResourceArn $fn.FunctionArn `
                    -AttachmentType 'ResourcePolicy'
                $count++
            } catch {}
        }
    }
    Write-ServiceResult $count
}

function Collect-ECS {
    param([string]$Region)
    Write-ServiceHeader "ECS Task Definitions" $Region
    $count = 0

    # List active task definition families
    $r = Invoke-IRAWSCLI -Arguments @('ecs','list-task-definition-families','--status','ACTIVE') -Region $Region -Description "ECS task families"
    if (-not $r.Success -or -not $r.Output.families) { Write-ServiceResult 0; return }

    foreach ($family in $r.Output.families | Select-Object -First 50) {
        $dr = Invoke-IRAWSCLI -Arguments @('ecs','describe-task-definition','--task-definition',$family,'--query','taskDefinition') -Region $Region -Description "ECS task def: $family"
        if (-not $dr.Success -or -not $dr.Output) { continue }

        $td  = $dr.Output
        $arn = $td.taskDefinitionArn
        $Global:IR.Stats.ResourcesScanned++

        # Task Role (what the container can DO)
        if ($td.taskRoleArn) {
            New-Attachment -Region $Region -ResourceType 'ECS::TaskDefinition' `
                -ResourceId $family -ResourceName $family -ResourceArn $arn `
                -AttachmentType 'TaskRole' -IdentityType 'Role' `
                -IdentityArn $td.taskRoleArn -IdentityName $td.taskRoleArn.Split('/')[-1] `
                -RiskLevel 'MEDIUM' -Notes "Family=$family Rev=$($td.revision)"
            $count++
        }
        # Execution Role (ECS control plane pull/log)
        if ($td.executionRoleArn) {
            New-Attachment -Region $Region -ResourceType 'ECS::TaskDefinition' `
                -ResourceId $family -ResourceName $family -ResourceArn $arn `
                -AttachmentType 'ExecutionRole' -IdentityType 'Role' `
                -IdentityArn $td.executionRoleArn -IdentityName $td.executionRoleArn.Split('/')[-1] `
                -RiskLevel 'LOW' -Notes "Family=$family Rev=$($td.revision)"
            $count++
        }
    }
    Write-ServiceResult $count
}

function Collect-EKS {
    param([string]$Region)
    Write-ServiceHeader "EKS Clusters" $Region
    $count = 0

    $r = Invoke-IRAWSCLI -Arguments @('eks','list-clusters') -Region $Region -Description "EKS clusters"
    if (-not $r.Success -or -not $r.Output.clusters) { Write-ServiceResult 0; return }

    foreach ($clusterName in $r.Output.clusters) {
        $dr = Invoke-IRAWSCLI -Arguments @('eks','describe-cluster','--name',$clusterName,'--query','cluster') -Region $Region -Description "EKS cluster: $clusterName"
        if (-not $dr.Success -or -not $dr.Output) { continue }

        $cl  = $dr.Output
        $arn = $cl.arn
        $Global:IR.Stats.ResourcesScanned++

        # Cluster IAM Role
        if ($cl.roleArn) {
            New-Attachment -Region $Region -ResourceType 'EKS::Cluster' `
                -ResourceId $clusterName -ResourceName $clusterName -ResourceArn $arn `
                -AttachmentType 'ClusterRole' -IdentityType 'Role' `
                -IdentityArn $cl.roleArn -IdentityName $cl.roleArn.Split('/')[-1] `
                -RiskLevel 'HIGH' -Notes "Version=$($cl.version) Status=$($cl.status)"
            $count++
        }

        # Node groups
        $ngr = Invoke-IRAWSCLI -Arguments @('eks','list-nodegroups','--cluster-name',$clusterName) -Region $Region -Description "EKS nodegroups: $clusterName"
        if ($ngr.Success -and $ngr.Output.nodegroups) {
            foreach ($ng in $ngr.Output.nodegroups) {
                $ngd = Invoke-IRAWSCLI -Arguments @('eks','describe-nodegroup','--cluster-name',$clusterName,'--nodegroup-name',$ng,'--query','nodegroup') -Region $Region -Description "EKS NG: $ng"
                if ($ngd.Success -and $ngd.Output.nodeRole) {
                    New-Attachment -Region $Region -ResourceType 'EKS::NodeGroup' `
                        -ResourceId "$clusterName/$ng" -ResourceName $ng -ResourceArn $ngd.Output.nodegroupArn `
                        -AttachmentType 'NodeInstanceRole' -IdentityType 'Role' `
                        -IdentityArn $ngd.Output.nodeRole -IdentityName $ngd.Output.nodeRole.Split('/')[-1] `
                        -RiskLevel 'HIGH' -Notes "Cluster=$clusterName"
                    $count++
                }
            }
        }

        # IRSA / Pod Identity associations (EKS access entries)
        $aer = Invoke-IRAWSCLI -Arguments @('eks','list-access-entries','--cluster-name',$clusterName) -Region $Region -Description "EKS access entries: $clusterName"
        if ($aer.Success -and $aer.Output.accessEntries) {
            foreach ($entry in $aer.Output.accessEntries | Select-Object -First 20) {
                $info = Get-PrincipalInfo -Principal $entry -OwnAccountId $Global:IR.AccountId
                New-Attachment -Region $Region -ResourceType 'EKS::Cluster' `
                    -ResourceId $clusterName -ResourceName $clusterName -ResourceArn $arn `
                    -AttachmentType 'AccessEntry' -IdentityType $info.IdentityType `
                    -IdentityArn $entry -IdentityName $info.IdentityName `
                    -IsExternal $info.IsExternal `
                    -RiskLevel $(if ($info.IsExternal) { 'HIGH' } else { 'MEDIUM' }) `
                    -Notes "Cluster=$clusterName"
                $count++
            }
        }
    }
    Write-ServiceResult $count
}

function Collect-EMR {
    param([string]$Region)
    Write-ServiceHeader "EMR Clusters" $Region
    $count = 0

    $r = Invoke-IRAWSCLI -Arguments @('emr','list-clusters','--active') -Region $Region -Description "EMR clusters"
    if (-not $r.Success -or -not $r.Output.Clusters) { Write-ServiceResult 0; return }

    foreach ($cl in $r.Output.Clusters | Select-Object -First 20) {
        $dr = Invoke-IRAWSCLI -Arguments @('emr','describe-cluster','--cluster-id',$cl.Id,'--query','Cluster') -Region $Region -Description "EMR cluster: $($cl.Id)"
        if (-not $dr.Success -or -not $dr.Output) { continue }
        $c = $dr.Output
        $Global:IR.Stats.ResourcesScanned++

        if ($c.ServiceRole) {
            New-Attachment -Region $Region -ResourceType 'EMR::Cluster' `
                -ResourceId $cl.Id -ResourceName $cl.Name -ResourceArn $c.ClusterArn `
                -AttachmentType 'ServiceRole' -IdentityType 'Role' `
                -IdentityArn $c.ServiceRole -IdentityName $c.ServiceRole.Split('/')[-1] `
                -RiskLevel 'HIGH' -Notes "State=$($c.Status.State)"
            $count++
        }
        if ($c.Ec2InstanceAttributes.IamInstanceProfile) {
            New-Attachment -Region $Region -ResourceType 'EMR::Cluster' `
                -ResourceId $cl.Id -ResourceName $cl.Name -ResourceArn $c.ClusterArn `
                -AttachmentType 'InstanceProfile' -IdentityType 'Role' `
                -IdentityArn "arn:aws:iam::$($Global:IR.AccountId):instance-profile/$($c.Ec2InstanceAttributes.IamInstanceProfile)" `
                -IdentityName $c.Ec2InstanceAttributes.IamInstanceProfile `
                -RiskLevel 'HIGH' -Notes "Node instance profile"
            $count++
        }
    }
    Write-ServiceResult $count
}

function Collect-Batch {
    param([string]$Region)
    Write-ServiceHeader "AWS Batch" $Region
    $count = 0

    $r = Invoke-IRAWSCLI -Arguments @('batch','describe-compute-environments') -Region $Region -Description "Batch compute envs"
    if ($r.Success -and $r.Output.computeEnvironments) {
        foreach ($ce in $r.Output.computeEnvironments) {
            $Global:IR.Stats.ResourcesScanned++
            if ($ce.serviceRole) {
                New-Attachment -Region $Region -ResourceType 'Batch::ComputeEnvironment' `
                    -ResourceId $ce.computeEnvironmentName -ResourceName $ce.computeEnvironmentName `
                    -ResourceArn $ce.computeEnvironmentArn `
                    -AttachmentType 'ServiceRole' -IdentityType 'Role' `
                    -IdentityArn $ce.serviceRole -IdentityName $ce.serviceRole.Split('/')[-1] `
                    -RiskLevel 'MEDIUM' -Notes "Type=$($ce.type) State=$($ce.state)"
                $count++
            }
            if ($ce.computeResources -and $ce.computeResources.instanceRole) {
                New-Attachment -Region $Region -ResourceType 'Batch::ComputeEnvironment' `
                    -ResourceId $ce.computeEnvironmentName -ResourceName $ce.computeEnvironmentName `
                    -ResourceArn $ce.computeEnvironmentArn `
                    -AttachmentType 'InstanceProfile' -IdentityType 'Role' `
                    -IdentityArn $ce.computeResources.instanceRole `
                    -IdentityName $ce.computeResources.instanceRole.Split('/')[-1] `
                    -RiskLevel 'HIGH' -Notes "EC2 node instance profile"
                $count++
            }
        }
    }

    # Job definitions with job role
    $jr = Invoke-IRAWSCLI -Arguments @('batch','describe-job-definitions','--status','ACTIVE') -Region $Region -Description "Batch job definitions"
    if ($jr.Success -and $jr.Output.jobDefinitions) {
        foreach ($jd in $jr.Output.jobDefinitions | Select-Object -First 30) {
            if ($jd.containerProperties -and $jd.containerProperties.jobRoleArn) {
                New-Attachment -Region $Region -ResourceType 'Batch::JobDefinition' `
                    -ResourceId $jd.jobDefinitionName -ResourceName $jd.jobDefinitionName `
                    -ResourceArn $jd.jobDefinitionArn `
                    -AttachmentType 'JobRole' -IdentityType 'Role' `
                    -IdentityArn $jd.containerProperties.jobRoleArn `
                    -IdentityName $jd.containerProperties.jobRoleArn.Split('/')[-1] `
                    -RiskLevel 'MEDIUM' -Notes "Rev=$($jd.revision)"
                $count++
            }
        }
    }
    Write-ServiceResult $count
}

function Collect-ElasticBeanstalk {
    param([string]$Region)
    Write-ServiceHeader "Elastic Beanstalk" $Region
    $count = 0

    $r = Invoke-IRAWSCLI -Arguments @('elasticbeanstalk','describe-environments') -Region $Region -Description "EB environments"
    if (-not $r.Success -or -not $r.Output.Environments) { Write-ServiceResult 0; return }

    foreach ($env in $r.Output.Environments) {
        $Global:IR.Stats.ResourcesScanned++
        # Fetch configuration to get IAM roles
        $cr = Invoke-IRAWSCLI -Arguments @('elasticbeanstalk','describe-configuration-settings',
            '--application-name',$env.ApplicationName,'--environment-name',$env.EnvironmentName) -Region $Region -Description "EB config: $($env.EnvironmentName)"
        if (-not $cr.Success) { continue }

        $optionSettings = $cr.Output.ConfigurationSettings | Select-Object -First 1 | Select-Object -ExpandProperty OptionSettings
        foreach ($opt in $optionSettings) {
            if ($opt.OptionName -eq 'IamInstanceProfile' -and $opt.Value) {
                New-Attachment -Region $Region -ResourceType 'ElasticBeanstalk::Environment' `
                    -ResourceId $env.EnvironmentId -ResourceName $env.EnvironmentName -ResourceArn $env.EnvironmentArn `
                    -AttachmentType 'InstanceProfile' -IdentityType 'Role' `
                    -IdentityArn "arn:aws:iam::$($Global:IR.AccountId):instance-profile/$($opt.Value)" `
                    -IdentityName $opt.Value -RiskLevel 'MEDIUM' -Notes "App=$($env.ApplicationName)"
                $count++
            }
            if ($opt.OptionName -eq 'ServiceRole' -and $opt.Value) {
                New-Attachment -Region $Region -ResourceType 'ElasticBeanstalk::Environment' `
                    -ResourceId $env.EnvironmentId -ResourceName $env.EnvironmentName -ResourceArn $env.EnvironmentArn `
                    -AttachmentType 'ServiceRole' -IdentityType 'Role' `
                    -IdentityArn $opt.Value -IdentityName $opt.Value.Split('/')[-1] `
                    -RiskLevel 'LOW' -Notes "EB service role"
                $count++
            }
        }
    }
    Write-ServiceResult $count
}

# ============================================================
# SERVERLESS / INTEGRATION
# ============================================================

function Collect-StepFunctions {
    param([string]$Region)
    Write-ServiceHeader "Step Functions" $Region
    $count = 0

    $items = Invoke-IRAWSPaged -Arguments @('stepfunctions','list-state-machines') -Region $Region -ResultKey 'stateMachines' -Description "State machines"
    foreach ($sm in $items) {
        $Global:IR.Stats.ResourcesScanned++
        $dr = Invoke-IRAWSCLI -Arguments @('stepfunctions','describe-state-machine','--state-machine-arn',$sm.stateMachineArn) -Region $Region -Description "SFN: $($sm.name)"
        if ($dr.Success -and $dr.Output.roleArn) {
            New-Attachment -Region $Region -ResourceType 'StepFunctions::StateMachine' `
                -ResourceId $sm.name -ResourceName $sm.name -ResourceArn $sm.stateMachineArn `
                -AttachmentType 'ExecutionRole' -IdentityType 'Role' `
                -IdentityArn $dr.Output.roleArn -IdentityName $dr.Output.roleArn.Split('/')[-1] `
                -RiskLevel 'MEDIUM' -Notes "Type=$($dr.Output.type)"
            $count++
        }
    }
    Write-ServiceResult $count
}

function Collect-EventBridge {
    param([string]$Region)
    Write-ServiceHeader "EventBridge Rules" $Region
    $count = 0

    $r = Invoke-IRAWSCLI -Arguments @('events','list-rules') -Region $Region -Description "EventBridge rules"
    if (-not $r.Success -or -not $r.Output.Rules) { Write-ServiceResult 0; return }

    foreach ($rule in $r.Output.Rules | Select-Object -First 50) {
        $Global:IR.Stats.ResourcesScanned++
        $tr = Invoke-IRAWSCLI -Arguments @('events','list-targets-by-rule','--rule',$rule.Name) -Region $Region -Description "EB targets: $($rule.Name)"
        if ($tr.Success -and $tr.Output.Targets) {
            foreach ($target in $tr.Output.Targets) {
                if ($target.RoleArn) {
                    New-Attachment -Region $Region -ResourceType 'EventBridge::Rule' `
                        -ResourceId $rule.Name -ResourceName $rule.Name -ResourceArn $rule.Arn `
                        -AttachmentType 'TargetRole' -IdentityType 'Role' `
                        -IdentityArn $target.RoleArn -IdentityName $target.RoleArn.Split('/')[-1] `
                        -RiskLevel 'MEDIUM' -Notes "Target=$($target.Arn.Split(':')[-1])"
                    $count++
                }
            }
        }
    }
    Write-ServiceResult $count
}

function Collect-APIGateway {
    param([string]$Region)
    Write-ServiceHeader "API Gateway" $Region
    $count = 0

    # REST APIs
    $r = Invoke-IRAWSCLI -Arguments @('apigateway','get-rest-apis') -Region $Region -Description "REST APIs"
    if ($r.Success -and $r.Output.items) {
        foreach ($api in $r.Output.items | Select-Object -First 30) {
            $Global:IR.Stats.ResourcesScanned++
            # Resource policy
            if ($api.policy) {
                try {
                    $pDoc = [Uri]::UnescapeDataString($api.policy) | ConvertFrom-Json
                    Add-PolicyPrincipalAttachments -PolicyDoc $pDoc -Region $Region `
                        -ResourceType 'APIGateway::RestAPI' -ResourceId $api.id `
                        -ResourceName $api.name `
                        -ResourceArn "arn:aws:apigateway:${Region}::/restapis/$($api.id)" `
                        -AttachmentType 'ResourcePolicy'
                    $count++
                } catch {}
            }
        }
    }

    # HTTP APIs (API Gateway v2)
    $r2 = Invoke-IRAWSCLI -Arguments @('apigatewayv2','get-apis') -Region $Region -Description "HTTP APIs"
    if ($r2.Success -and $r2.Output.Items) {
        foreach ($api in $r2.Output.Items | Select-Object -First 30) {
            $Global:IR.Stats.ResourcesScanned++
            # Integrations with credentials
            $ir = Invoke-IRAWSCLI -Arguments @('apigatewayv2','get-integrations','--api-id',$api.ApiId) -Region $Region -Description "APIGW v2 integrations: $($api.ApiId)"
            if ($ir.Success -and $ir.Output.Items) {
                foreach ($integ in $ir.Output.Items | Where-Object { $_.CredentialsArn }) {
                    New-Attachment -Region $Region -ResourceType 'APIGateway::HTTPAPI' `
                        -ResourceId $api.ApiId -ResourceName $api.Name `
                        -ResourceArn "arn:aws:apigateway:${Region}::/apis/$($api.ApiId)" `
                        -AttachmentType 'IntegrationRole' -IdentityType 'Role' `
                        -IdentityArn $integ.CredentialsArn -IdentityName $integ.CredentialsArn.Split('/')[-1] `
                        -RiskLevel 'MEDIUM' -Notes "IntegType=$($integ.IntegrationType)"
                    $count++
                }
            }
        }
    }
    Write-ServiceResult $count
}

function Collect-Kinesis {
    param([string]$Region)
    Write-ServiceHeader "Kinesis Firehose" $Region
    $count = 0

    $r = Invoke-IRAWSCLI -Arguments @('firehose','list-delivery-streams') -Region $Region -Description "Firehose streams"
    if (-not $r.Success -or -not $r.Output.DeliveryStreamNames) { Write-ServiceResult 0; return }

    foreach ($name in $r.Output.DeliveryStreamNames | Select-Object -First 20) {
        $dr = Invoke-IRAWSCLI -Arguments @('firehose','describe-delivery-stream','--delivery-stream-name',$name,'--query','DeliveryStreamDescription') -Region $Region -Description "Firehose: $name"
        if (-not $dr.Success -or -not $dr.Output) { continue }
        $ds = $dr.Output
        $Global:IR.Stats.ResourcesScanned++

        # Role in destination config
        $destConfs = @($ds.Destinations)
        foreach ($dest in $destConfs) {
            $roleArn = if ($dest.S3DestinationDescription.RoleARN) { $dest.S3DestinationDescription.RoleARN }
                       elseif ($dest.ExtendedS3DestinationDescription.RoleARN) { $dest.ExtendedS3DestinationDescription.RoleARN }
                       elseif ($dest.RedshiftDestinationDescription.RoleARN) { $dest.RedshiftDestinationDescription.RoleARN }
                       elseif ($dest.ElasticsearchDestinationDescription.RoleARN) { $dest.ElasticsearchDestinationDescription.RoleARN }
                       else { $null }
            if ($roleArn) {
                New-Attachment -Region $Region -ResourceType 'Kinesis::FirehoseStream' `
                    -ResourceId $name -ResourceName $name -ResourceArn $ds.DeliveryStreamARN `
                    -AttachmentType 'DeliveryRole' -IdentityType 'Role' `
                    -IdentityArn $roleArn -IdentityName $roleArn.Split('/')[-1] `
                    -RiskLevel 'MEDIUM' -Notes "Status=$($ds.DeliveryStreamStatus)"
                $count++
            }
        }
    }
    Write-ServiceResult $count
}

# ============================================================
# CICD
# ============================================================

function Collect-CodeBuild {
    param([string]$Region)
    Write-ServiceHeader "CodeBuild Projects" $Region
    $count = 0

    $r = Invoke-IRAWSCLI -Arguments @('codebuild','list-projects') -Region $Region -Description "CodeBuild projects"
    if (-not $r.Success -or -not $r.Output.projects -or $r.Output.projects.Count -eq 0) { Write-ServiceResult 0; return }

    # batch-get-projects accepts up to 100 names
    $chunks = @()
    $names  = $r.Output.projects
    for ($i = 0; $i -lt $names.Count; $i += 25) {
        $chunks += ,@($names[$i..([math]::Min($i + 24, $names.Count - 1))])
    }
    foreach ($chunk in $chunks) {
        $dr = Invoke-IRAWSCLI -Arguments (@('codebuild','batch-get-projects','--names') + $chunk) -Region $Region -Description "CodeBuild batch get"
        if (-not $dr.Success -or -not $dr.Output.projects) { continue }
        foreach ($proj in $dr.Output.projects) {
            $Global:IR.Stats.ResourcesScanned++
            if ($proj.serviceRole) {
                New-Attachment -Region $Region -ResourceType 'CodeBuild::Project' `
                    -ResourceId $proj.name -ResourceName $proj.name `
                    -ResourceArn $proj.arn `
                    -AttachmentType 'ServiceRole' -IdentityType 'Role' `
                    -IdentityArn $proj.serviceRole -IdentityName $proj.serviceRole.Split('/')[-1] `
                    -IsHighPrivilege $true -RiskLevel 'CRITICAL' `
                    -Notes "CI/CD: code execution with this role"
                $count++
            }
        }
    }
    Write-ServiceResult $count
}

function Collect-CodePipeline {
    param([string]$Region)
    Write-ServiceHeader "CodePipeline" $Region
    $count = 0

    $items = Invoke-IRAWSPaged -Arguments @('codepipeline','list-pipelines') -Region $Region -ResultKey 'pipelines' -Description "CodePipeline pipelines"
    foreach ($pl in $items) {
        $dr = Invoke-IRAWSCLI -Arguments @('codepipeline','get-pipeline','--name',$pl.name,'--query','pipeline') -Region $Region -Description "Pipeline: $($pl.name)"
        if (-not $dr.Success -or -not $dr.Output) { continue }
        $Global:IR.Stats.ResourcesScanned++
        $pip = $dr.Output

        if ($pip.roleArn) {
            New-Attachment -Region $Region -ResourceType 'CodePipeline::Pipeline' `
                -ResourceId $pip.name -ResourceName $pip.name `
                -ResourceArn "arn:aws:codepipeline:${Region}:$($Global:IR.AccountId):$($pip.name)" `
                -AttachmentType 'ServiceRole' -IdentityType 'Role' `
                -IdentityArn $pip.roleArn -IdentityName $pip.roleArn.Split('/')[-1] `
                -IsHighPrivilege $true -RiskLevel 'CRITICAL' -Notes "CI/CD pipeline service role"
            $count++
        }

        # Per-action roles in stages
        foreach ($stage in $pip.stages) {
            foreach ($action in $stage.actions) {
                if ($action.roleArn) {
                    New-Attachment -Region $Region -ResourceType 'CodePipeline::Pipeline' `
                        -ResourceId "$($pip.name)/$($stage.name)/$($action.name)" -ResourceName $pip.name `
                        -ResourceArn "arn:aws:codepipeline:${Region}:$($Global:IR.AccountId):$($pip.name)" `
                        -AttachmentType 'ActionRole' -IdentityType 'Role' `
                        -IdentityArn $action.roleArn -IdentityName $action.roleArn.Split('/')[-1] `
                        -RiskLevel 'HIGH' -Notes "Stage=$($stage.name) Action=$($action.name)"
                    $count++
                }
            }
        }
    }
    Write-ServiceResult $count
}

function Collect-CodeDeploy {
    param([string]$Region)
    Write-ServiceHeader "CodeDeploy" $Region
    $count = 0

    $r = Invoke-IRAWSCLI -Arguments @('deploy','list-applications') -Region $Region -Description "CodeDeploy apps"
    if (-not $r.Success -or -not $r.Output.applications) { Write-ServiceResult 0; return }

    foreach ($app in $r.Output.applications | Select-Object -First 20) {
        $dgr = Invoke-IRAWSCLI -Arguments @('deploy','list-deployment-groups','--application-name',$app) -Region $Region -Description "DG: $app"
        if (-not $dgr.Success -or -not $dgr.Output.deploymentGroups) { continue }
        foreach ($dg in $dgr.Output.deploymentGroups | Select-Object -First 10) {
            $dr = Invoke-IRAWSCLI -Arguments @('deploy','get-deployment-group','--application-name',$app,'--deployment-group-name',$dg,'--query','deploymentGroupInfo') -Region $Region -Description "DG detail: $dg"
            if ($dr.Success -and $dr.Output.serviceRoleArn) {
                $Global:IR.Stats.ResourcesScanned++
                New-Attachment -Region $Region -ResourceType 'CodeDeploy::DeploymentGroup' `
                    -ResourceId "$app/$dg" -ResourceName $dg `
                    -ResourceArn $dr.Output.deploymentGroupId `
                    -AttachmentType 'ServiceRole' -IdentityType 'Role' `
                    -IdentityArn $dr.Output.serviceRoleArn -IdentityName $dr.Output.serviceRoleArn.Split('/')[-1] `
                    -RiskLevel 'HIGH' -Notes "App=$app"
                $count++
            }
        }
    }
    Write-ServiceResult $count
}

# ============================================================
# DATA / STORAGE
# ============================================================

function Collect-S3 {
    param([string]$Region)
    Write-ServiceHeader "S3 Buckets" $Region
    $count = 0

    # S3 is global but we only collect once (from us-east-1 caller)
    if ($Region -ne 'us-east-1' -and $Region -ne ($Global:IR.Regions | Select-Object -First 1)) {
        Write-ServiceResult 0; return
    }

    $r = Invoke-IRAWSCLI -Arguments @('s3api','list-buckets') -Region 'us-east-1' -Description "S3 buckets"
    if (-not $r.Success -or -not $r.Output.Buckets) { Write-ServiceResult 0; return }

    foreach ($bucket in $r.Output.Buckets) {
        $Global:IR.Stats.ResourcesScanned++
        $bucketArn = "arn:aws:s3:::$($bucket.Name)"

        # Bucket policy
        $pr = Invoke-IRAWSCLI -Arguments @('s3api','get-bucket-policy','--bucket',$bucket.Name) -Region 'us-east-1' -Description "S3 policy: $($bucket.Name)"
        if ($pr.Success -and $pr.Output.Policy) {
            try {
                $pDoc = $pr.Output.Policy | ConvertFrom-Json
                Add-PolicyPrincipalAttachments -PolicyDoc $pDoc -Region 'global' `
                    -ResourceType 'S3::Bucket' -ResourceId $bucket.Name `
                    -ResourceName $bucket.Name -ResourceArn $bucketArn `
                    -AttachmentType 'BucketPolicy'
                $count++
            } catch {}
        }
    }
    Write-ServiceResult $count
}

function Collect-RDS {
    param([string]$Region)
    Write-ServiceHeader "RDS/Aurora" $Region
    $count = 0

    # RDS Instances
    $r = Invoke-IRAWSCLI -Arguments @('rds','describe-db-instances','--query','DBInstances') -Region $Region -Description "RDS instances"
    if ($r.Success -and $r.Output) {
        foreach ($db in $r.Output) {
            $Global:IR.Stats.ResourcesScanned++
            foreach ($assoc in $db.AssociatedRoles) {
                New-Attachment -Region $Region -ResourceType 'RDS::DBInstance' `
                    -ResourceId $db.DBInstanceIdentifier -ResourceName $db.DBInstanceIdentifier `
                    -ResourceArn $db.DBInstanceArn `
                    -AttachmentType 'AssociatedRole' -IdentityType 'Role' `
                    -IdentityArn $assoc.RoleArn -IdentityName $assoc.RoleArn.Split('/')[-1] `
                    -RiskLevel 'MEDIUM' -Notes "Feature=$($assoc.FeatureName) Status=$($assoc.Status)"
                $count++
            }
            if ($db.MonitoringRoleArn) {
                New-Attachment -Region $Region -ResourceType 'RDS::DBInstance' `
                    -ResourceId $db.DBInstanceIdentifier -ResourceName $db.DBInstanceIdentifier `
                    -ResourceArn $db.DBInstanceArn `
                    -AttachmentType 'MonitoringRole' -IdentityType 'Role' `
                    -IdentityArn $db.MonitoringRoleArn -IdentityName $db.MonitoringRoleArn.Split('/')[-1] `
                    -RiskLevel 'LOW' -Notes "Enhanced monitoring"
                $count++
            }
        }
    }

    # Aurora Clusters
    $cr = Invoke-IRAWSCLI -Arguments @('rds','describe-db-clusters','--query','DBClusters') -Region $Region -Description "RDS clusters"
    if ($cr.Success -and $cr.Output) {
        foreach ($cl in $cr.Output) {
            $Global:IR.Stats.ResourcesScanned++
            foreach ($assoc in $cl.AssociatedRoles) {
                New-Attachment -Region $Region -ResourceType 'RDS::DBCluster' `
                    -ResourceId $cl.DBClusterIdentifier -ResourceName $cl.DBClusterIdentifier `
                    -ResourceArn $cl.DBClusterArn `
                    -AttachmentType 'AssociatedRole' -IdentityType 'Role' `
                    -IdentityArn $assoc.RoleArn -IdentityName $assoc.RoleArn.Split('/')[-1] `
                    -RiskLevel 'MEDIUM' -Notes "Feature=$($assoc.FeatureName)"
                $count++
            }
        }
    }
    Write-ServiceResult $count
}

function Collect-Redshift {
    param([string]$Region)
    Write-ServiceHeader "Redshift" $Region
    $count = 0

    $r = Invoke-IRAWSCLI -Arguments @('redshift','describe-clusters','--query','Clusters') -Region $Region -Description "Redshift clusters"
    if (-not $r.Success -or -not $r.Output) { Write-ServiceResult 0; return }

    foreach ($cl in $r.Output) {
        $Global:IR.Stats.ResourcesScanned++
        foreach ($role in $cl.IamRoles) {
            New-Attachment -Region $Region -ResourceType 'Redshift::Cluster' `
                -ResourceId $cl.ClusterIdentifier -ResourceName $cl.ClusterIdentifier `
                -ResourceArn "arn:aws:redshift:${Region}:$($Global:IR.AccountId):cluster:$($cl.ClusterIdentifier)" `
                -AttachmentType 'AssociatedRole' -IdentityType 'Role' `
                -IdentityArn $role.IamRoleArn -IdentityName $role.IamRoleArn.Split('/')[-1] `
                -RiskLevel 'HIGH' -Notes "ApplyStatus=$($role.ApplyStatus)"
            $count++
        }
    }
    Write-ServiceResult $count
}

function Collect-Glue {
    param([string]$Region)
    Write-ServiceHeader "Glue" $Region
    $count = 0

    # Glue Jobs
    $r = Invoke-IRAWSCLI -Arguments @('glue','get-jobs','--query','Jobs') -Region $Region -Description "Glue jobs"
    if ($r.Success -and $r.Output) {
        foreach ($job in $r.Output | Select-Object -First 50) {
            $Global:IR.Stats.ResourcesScanned++
            if ($job.Role) {
                New-Attachment -Region $Region -ResourceType 'Glue::Job' `
                    -ResourceId $job.Name -ResourceName $job.Name `
                    -ResourceArn "arn:aws:glue:${Region}:$($Global:IR.AccountId):job/$($job.Name)" `
                    -AttachmentType 'JobRole' -IdentityType 'Role' `
                    -IdentityArn $job.Role -IdentityName $job.Role.Split('/')[-1] `
                    -IsHighPrivilege $true -RiskLevel 'HIGH' `
                    -Notes "Type=$($job.Command.Name) Glue dev endpoint SSH-accessible"
                $count++
            }
        }
    }

    # Glue Crawlers
    $cr = Invoke-IRAWSCLI -Arguments @('glue','get-crawlers','--query','Crawlers') -Region $Region -Description "Glue crawlers"
    if ($cr.Success -and $cr.Output) {
        foreach ($crawler in $cr.Output | Select-Object -First 50) {
            if ($crawler.Role) {
                New-Attachment -Region $Region -ResourceType 'Glue::Crawler' `
                    -ResourceId $crawler.Name -ResourceName $crawler.Name `
                    -ResourceArn "arn:aws:glue:${Region}:$($Global:IR.AccountId):crawler/$($crawler.Name)" `
                    -AttachmentType 'CrawlerRole' -IdentityType 'Role' `
                    -IdentityArn $crawler.Role -IdentityName $crawler.Role.Split('/')[-1] `
                    -RiskLevel 'MEDIUM' -Notes "State=$($crawler.State)"
                $count++
            }
        }
    }
    Write-ServiceResult $count
}

function Collect-SageMaker {
    param([string]$Region)
    Write-ServiceHeader "SageMaker" $Region
    $count = 0

    # Notebook instances
    $r = Invoke-IRAWSCLI -Arguments @('sagemaker','list-notebook-instances','--query','NotebookInstances') -Region $Region -Description "SageMaker notebooks"
    if ($r.Success -and $r.Output) {
        foreach ($nb in $r.Output | Select-Object -First 30) {
            $Global:IR.Stats.ResourcesScanned++
            if ($nb.RoleArn) {
                New-Attachment -Region $Region -ResourceType 'SageMaker::NotebookInstance' `
                    -ResourceId $nb.NotebookInstanceName -ResourceName $nb.NotebookInstanceName `
                    -ResourceArn $nb.NotebookInstanceArn `
                    -AttachmentType 'ExecutionRole' -IdentityType 'Role' `
                    -IdentityArn $nb.RoleArn -IdentityName $nb.RoleArn.Split('/')[-1] `
                    -RiskLevel 'HIGH' -Notes "Status=$($nb.NotebookInstanceStatus) Container with persistent role"
                $count++
            }
        }
    }

    # Domains (Studio)
    $dr = Invoke-IRAWSCLI -Arguments @('sagemaker','list-domains','--query','Domains') -Region $Region -Description "SageMaker domains"
    if ($dr.Success -and $dr.Output) {
        foreach ($dom in $dr.Output | Select-Object -First 10) {
            $ddr = Invoke-IRAWSCLI -Arguments @('sagemaker','describe-domain','--domain-id',$dom.DomainId,'--query','DefaultUserSettings') -Region $Region -Description "SM domain: $($dom.DomainId)"
            if ($ddr.Success -and $ddr.Output.ExecutionRole) {
                New-Attachment -Region $Region -ResourceType 'SageMaker::Domain' `
                    -ResourceId $dom.DomainId -ResourceName $dom.DomainName -ResourceArn $dom.DomainArn `
                    -AttachmentType 'ExecutionRole' -IdentityType 'Role' `
                    -IdentityArn $ddr.Output.ExecutionRole -IdentityName $ddr.Output.ExecutionRole.Split('/')[-1] `
                    -RiskLevel 'HIGH' -Notes "Studio domain default execution role"
                $count++
            }
        }
    }
    Write-ServiceResult $count
}

# ============================================================
# SECURITY / KEY MANAGEMENT
# ============================================================

function Collect-KMS {
    param([string]$Region)
    Write-ServiceHeader "KMS Key Policies" $Region
    $count = 0

    $items = Invoke-IRAWSPaged -Arguments @('kms','list-keys') -Region $Region -ResultKey 'Keys' -Description "KMS keys"
    foreach ($key in $items | Select-Object -First 50) {
        $Global:IR.Stats.ResourcesScanned++
        # Get key metadata to check if it's customer-managed
        $mr = Invoke-IRAWSCLI -Arguments @('kms','describe-key','--key-id',$key.KeyId,'--query','KeyMetadata') -Region $Region -Description "KMS key meta: $($key.KeyId)"
        if (-not $mr.Success -or $mr.Output.KeyManager -eq 'AWS') { continue }  # Skip AWS-managed keys

        $alias = $mr.Output.KeyId
        $pr = Invoke-IRAWSCLI -Arguments @('kms','get-key-policy','--key-id',$key.KeyId,'--policy-name','default') -Region $Region -Description "KMS policy: $($key.KeyId)"
        if ($pr.Success -and $pr.Output.Policy) {
            try {
                $pDoc = $pr.Output.Policy | ConvertFrom-Json
                Add-PolicyPrincipalAttachments -PolicyDoc $pDoc -Region $Region `
                    -ResourceType 'KMS::Key' -ResourceId $key.KeyId `
                    -ResourceName $alias -ResourceArn $key.KeyArn `
                    -AttachmentType 'KeyPolicy'
                $count++
            } catch {}
        }
    }
    Write-ServiceResult $count
}

function Collect-SecretsManager {
    param([string]$Region)
    Write-ServiceHeader "Secrets Manager" $Region
    $count = 0

    $items = Invoke-IRAWSPaged -Arguments @('secretsmanager','list-secrets') -Region $Region -ResultKey 'SecretList' -Description "Secrets"
    foreach ($secret in $items | Select-Object -First 50) {
        $Global:IR.Stats.ResourcesScanned++
        if (-not $secret.ResourcePolicy) { continue }
        try {
            $pDoc = $secret.ResourcePolicy | ConvertFrom-Json
            Add-PolicyPrincipalAttachments -PolicyDoc $pDoc -Region $Region `
                -ResourceType 'SecretsManager::Secret' -ResourceId $secret.Name `
                -ResourceName $secret.Name -ResourceArn $secret.ARN `
                -AttachmentType 'ResourcePolicy'
            $count++
        } catch {}
    }

    # Secrets with rotation - check rotation Lambda role
    foreach ($secret in $items | Where-Object { $_.RotationEnabled } | Select-Object -First 20) {
        if ($secret.RotationLambdaARN) {
            New-Attachment -Region $Region -ResourceType 'SecretsManager::Secret' `
                -ResourceId $secret.Name -ResourceName $secret.Name -ResourceArn $secret.ARN `
                -AttachmentType 'RotationLambda' -IdentityType 'Role' `
                -IdentityArn $secret.RotationLambdaARN -IdentityName $secret.RotationLambdaARN.Split('/')[-1] `
                -RiskLevel 'HIGH' -Notes "Rotation Lambda has access to this secret value"
            $count++
        }
    }
    Write-ServiceResult $count
}

# ============================================================
# MESSAGING / QUEUES
# ============================================================

function Collect-SQS {
    param([string]$Region)
    Write-ServiceHeader "SQS Queues" $Region
    $count = 0

    $r = Invoke-IRAWSCLI -Arguments @('sqs','list-queues') -Region $Region -Description "SQS queues"
    if (-not $r.Success -or -not $r.Output.QueueUrls) { Write-ServiceResult 0; return }

    foreach ($url in $r.Output.QueueUrls | Select-Object -First 50) {
        $Global:IR.Stats.ResourcesScanned++
        $qName = $url.Split('/')[-1]
        $ar = Invoke-IRAWSCLI -Arguments @('sqs','get-queue-attributes','--queue-url',$url,'--attribute-names','Policy','QueueArn') -Region $Region -Description "SQS attrs: $qName"
        if (-not $ar.Success -or -not $ar.Output.Attributes.Policy) { continue }
        try {
            $pDoc = $ar.Output.Attributes.Policy | ConvertFrom-Json
            Add-PolicyPrincipalAttachments -PolicyDoc $pDoc -Region $Region `
                -ResourceType 'SQS::Queue' -ResourceId $qName `
                -ResourceName $qName -ResourceArn $ar.Output.Attributes.QueueArn `
                -AttachmentType 'QueuePolicy'
            $count++
        } catch {}
    }
    Write-ServiceResult $count
}

function Collect-SNS {
    param([string]$Region)
    Write-ServiceHeader "SNS Topics" $Region
    $count = 0

    $items = Invoke-IRAWSPaged -Arguments @('sns','list-topics') -Region $Region -ResultKey 'Topics' -Description "SNS topics"
    foreach ($topic in $items | Select-Object -First 50) {
        $Global:IR.Stats.ResourcesScanned++
        $ar = Invoke-IRAWSCLI -Arguments @('sns','get-topic-attributes','--topic-arn',$topic.TopicArn) -Region $Region -Description "SNS attrs: $($topic.TopicArn.Split(':')[-1])"
        if (-not $ar.Success -or -not $ar.Output.Attributes.Policy) { continue }
        try {
            $pDoc = $ar.Output.Attributes.Policy | ConvertFrom-Json
            Add-PolicyPrincipalAttachments -PolicyDoc $pDoc -Region $Region `
                -ResourceType 'SNS::Topic' -ResourceId $topic.TopicArn.Split(':')[-1] `
                -ResourceName $topic.TopicArn.Split(':')[-1] -ResourceArn $topic.TopicArn `
                -AttachmentType 'TopicPolicy'
            $count++
        } catch {}
    }
    Write-ServiceResult $count
}

function Collect-ECR {
    param([string]$Region)
    Write-ServiceHeader "ECR Repositories" $Region
    $count = 0

    $items = Invoke-IRAWSPaged -Arguments @('ecr','describe-repositories') -Region $Region -ResultKey 'repositories' -Description "ECR repos"
    foreach ($repo in $items | Select-Object -First 50) {
        $Global:IR.Stats.ResourcesScanned++
        $pr = Invoke-IRAWSCLI -Arguments @('ecr','get-repository-policy','--repository-name',$repo.repositoryName) -Region $Region -Description "ECR policy: $($repo.repositoryName)"
        if (-not $pr.Success -or -not $pr.Output.policyText) { continue }
        try {
            $pDoc = $pr.Output.policyText | ConvertFrom-Json
            Add-PolicyPrincipalAttachments -PolicyDoc $pDoc -Region $Region `
                -ResourceType 'ECR::Repository' -ResourceId $repo.repositoryName `
                -ResourceName $repo.repositoryName -ResourceArn $repo.repositoryArn `
                -AttachmentType 'ResourcePolicy'
            $count++
        } catch {}
    }
    Write-ServiceResult $count
}

# ============================================================
# MANAGEMENT / GOVERNANCE
# ============================================================

function Collect-CloudFormation {
    param([string]$Region)
    Write-ServiceHeader "CloudFormation Stacks" $Region
    $count = 0

    $items = Invoke-IRAWSPaged -Arguments @('cloudformation','list-stacks','--stack-status-filter','CREATE_COMPLETE','UPDATE_COMPLETE','ROLLBACK_COMPLETE') -Region $Region -ResultKey 'StackSummaries' -Description "CFN stacks"
    foreach ($stack in $items | Select-Object -First 50) {
        $Global:IR.Stats.ResourcesScanned++
        $dr = Invoke-IRAWSCLI -Arguments @('cloudformation','describe-stacks','--stack-name',$stack.StackName,'--query','Stacks[0]') -Region $Region -Description "CFN stack: $($stack.StackName)"
        if ($dr.Success -and $dr.Output.RoleARN) {
            New-Attachment -Region $Region -ResourceType 'CloudFormation::Stack' `
                -ResourceId $stack.StackName -ResourceName $stack.StackName `
                -ResourceArn $stack.StackId `
                -AttachmentType 'StackServiceRole' -IdentityType 'Role' `
                -IdentityArn $dr.Output.RoleARN -IdentityName $dr.Output.RoleARN.Split('/')[-1] `
                -IsHighPrivilege $true -RiskLevel 'HIGH' `
                -Notes "IaC deployment role - PassRole escalation path"
            $count++
        }
    }
    Write-ServiceResult $count
}

function Collect-CloudTrail {
    param([string]$Region)
    Write-ServiceHeader "CloudTrail Trails" $Region
    $count = 0

    $r = Invoke-IRAWSCLI -Arguments @('cloudtrail','describe-trails','--include-shadow-trails','false') -Region $Region -Description "CloudTrail trails"
    if (-not $r.Success -or -not $r.Output.trailList) { Write-ServiceResult 0; return }

    foreach ($trail in $r.Output.trailList) {
        $Global:IR.Stats.ResourcesScanned++
        if ($trail.CloudWatchLogsRoleArn) {
            New-Attachment -Region $Region -ResourceType 'CloudTrail::Trail' `
                -ResourceId $trail.Name -ResourceName $trail.Name -ResourceArn $trail.TrailARN `
                -AttachmentType 'CloudWatchLogsRole' -IdentityType 'Role' `
                -IdentityArn $trail.CloudWatchLogsRoleArn -IdentityName $trail.CloudWatchLogsRoleArn.Split('/')[-1] `
                -RiskLevel 'LOW' -Notes "Delivers logs to CW Logs"
            $count++
        }
    }
    Write-ServiceResult $count
}

function Collect-Config {
    param([string]$Region)
    Write-ServiceHeader "AWS Config" $Region
    $count = 0

    $r = Invoke-IRAWSCLI -Arguments @('configservice','describe-configuration-recorders') -Region $Region -Description "Config recorders"
    if ($r.Success -and $r.Output.ConfigurationRecorders) {
        foreach ($rec in $r.Output.ConfigurationRecorders) {
            $Global:IR.Stats.ResourcesScanned++
            if ($rec.roleARN) {
                New-Attachment -Region $Region -ResourceType 'Config::Recorder' `
                    -ResourceId $rec.name -ResourceName $rec.name `
                    -ResourceArn "arn:aws:config:${Region}:$($Global:IR.AccountId):config-recorder/$($rec.name)" `
                    -AttachmentType 'RecorderRole' -IdentityType 'Role' `
                    -IdentityArn $rec.roleARN -IdentityName $rec.roleARN.Split('/')[-1] `
                    -RiskLevel 'LOW' -Notes "Config recorder service role"
                $count++
            }
        }
    }

    # Config rules with remediation roles
    $rr = Invoke-IRAWSCLI -Arguments @('configservice','describe-remediation-configurations') -Region $Region -Description "Config remediation"
    if ($rr.Success -and $rr.Output.RemediationConfigurations) {
        foreach ($rem in $rr.Output.RemediationConfigurations) {
            if ($rem.ExecutionControls.SsmControls -or $rem.Automatic) {
                New-Attachment -Region $Region -ResourceType 'Config::RemediationConfig' `
                    -ResourceId $rem.ConfigRuleName -ResourceName $rem.ConfigRuleName `
                    -ResourceArn "arn:aws:config:${Region}:$($Global:IR.AccountId):remediation-configuration/$($rem.ConfigRuleName)" `
                    -AttachmentType 'RemediationRole' -IdentityType 'Role' `
                    -IdentityArn (if ($rem.Arn) { $rem.Arn } else { "arn:unknown" }) -IdentityName "AutoRemediation" `
                    -RiskLevel 'MEDIUM' -Notes "Automatic=$($rem.Automatic)"
                $count++
            }
        }
    }
    Write-ServiceResult $count
}

function Collect-SSM {
    param([string]$Region)
    Write-ServiceHeader "SSM Automation" $Region
    $count = 0

    # SSM Associations with AssumeRole
    $r = Invoke-IRAWSCLI -Arguments @('ssm','list-associations','--query','Associations') -Region $Region -Description "SSM associations"
    if ($r.Success -and $r.Output) {
        foreach ($assoc in $r.Output | Where-Object { $_.Overview.AssociationStatusAggregatedCount } | Select-Object -First 30) {
            $dr = Invoke-IRAWSCLI -Arguments @('ssm','describe-association','--association-id',$assoc.AssociationId,'--query','AssociationDescription') -Region $Region -Description "SSM assoc: $($assoc.AssociationId)"
            if ($dr.Success -and $dr.Output.AutomationTargetParameterName) {
                $Global:IR.Stats.ResourcesScanned++
                New-Attachment -Region $Region -ResourceType 'SSM::Association' `
                    -ResourceId $assoc.AssociationId -ResourceName $assoc.Name `
                    -ResourceArn "arn:aws:ssm:${Region}:$($Global:IR.AccountId):association/$($assoc.AssociationId)" `
                    -AttachmentType 'AutomationAssumeRole' -IdentityType 'Role' `
                    -IdentityArn ($dr.Output.AutomationTargetParameterName) `
                    -IdentityName ($dr.Output.AutomationTargetParameterName.Split('/')[-1]) `
                    -RiskLevel 'MEDIUM' -Notes "SSM Automation assume role"
                $count++
            }
        }
    }
    Write-ServiceResult $count
}

function Collect-TransferFamily {
    param([string]$Region)
    Write-ServiceHeader "Transfer Family" $Region
    $count = 0

    $r = Invoke-IRAWSCLI -Arguments @('transfer','list-servers') -Region $Region -Description "Transfer servers"
    if (-not $r.Success -or -not $r.Output.Servers) { Write-ServiceResult 0; return }

    foreach ($srv in $r.Output.Servers) {
        $Global:IR.Stats.ResourcesScanned++
        $dr = Invoke-IRAWSCLI -Arguments @('transfer','describe-server','--server-id',$srv.ServerId,'--query','Server') -Region $Region -Description "Transfer server: $($srv.ServerId)"
        if (-not $dr.Success -or -not $dr.Output) { continue }
        $s = $dr.Output

        if ($s.LoggingRole) {
            New-Attachment -Region $Region -ResourceType 'Transfer::Server' `
                -ResourceId $srv.ServerId -ResourceName $srv.ServerId -ResourceArn $s.Arn `
                -AttachmentType 'LoggingRole' -IdentityType 'Role' `
                -IdentityArn $s.LoggingRole -IdentityName $s.LoggingRole.Split('/')[-1] `
                -RiskLevel 'LOW' -Notes "Protocol=$($s.Protocols -join ',')"
            $count++
        }

        # Per-user roles
        $ur = Invoke-IRAWSCLI -Arguments @('transfer','list-users','--server-id',$srv.ServerId) -Region $Region -Description "Transfer users: $($srv.ServerId)"
        if ($ur.Success -and $ur.Output.Users) {
            foreach ($user in $ur.Output.Users) {
                if ($user.Role) {
                    New-Attachment -Region $Region -ResourceType 'Transfer::User' `
                        -ResourceId "$($srv.ServerId)/$($user.UserName)" -ResourceName $user.UserName -ResourceArn $user.Arn `
                        -AttachmentType 'UserRole' -IdentityType 'Role' `
                        -IdentityArn $user.Role -IdentityName $user.Role.Split('/')[-1] `
                        -RiskLevel 'MEDIUM' -Notes "SFTP/FTPS user scoped role"
                    $count++
                }
            }
        }
    }
    Write-ServiceResult $count
}

function Collect-OpenSearch {
    param([string]$Region)
    Write-ServiceHeader "OpenSearch Domains" $Region
    $count = 0

    $r = Invoke-IRAWSCLI -Arguments @('opensearch','list-domain-names') -Region $Region -Description "OpenSearch domains"
    if (-not $r.Success -or -not $r.Output.DomainNames) { Write-ServiceResult 0; return }

    foreach ($d in $r.Output.DomainNames) {
        $Global:IR.Stats.ResourcesScanned++
        $dr = Invoke-IRAWSCLI -Arguments @('opensearch','describe-domain','--domain-name',$d.DomainName,'--query','DomainStatus') -Region $Region -Description "OpenSearch domain: $($d.DomainName)"
        if (-not $dr.Success -or -not $dr.Output.AccessPolicies) { continue }
        try {
            $pDoc = $dr.Output.AccessPolicies | ConvertFrom-Json
            Add-PolicyPrincipalAttachments -PolicyDoc $pDoc -Region $Region `
                -ResourceType 'OpenSearch::Domain' -ResourceId $d.DomainName `
                -ResourceName $d.DomainName -ResourceArn $dr.Output.ARN `
                -AttachmentType 'ResourcePolicy'
            $count++
        } catch {}
    }
    Write-ServiceResult $count
}

function Collect-MSK {
    param([string]$Region)
    Write-ServiceHeader "MSK Clusters" $Region
    $count = 0

    $r = Invoke-IRAWSCLI -Arguments @('kafka','list-clusters') -Region $Region -Description "MSK clusters"
    if (-not $r.Success -or -not $r.Output.ClusterInfoList) { Write-ServiceResult 0; return }

    foreach ($cl in $r.Output.ClusterInfoList) {
        $Global:IR.Stats.ResourcesScanned++
        # MSK uses client-auth IAM - note its presence
        $iam = $cl.BrokerNodeGroupInfo.ConnectivityInfo.VpcConnectivity.ClientAuthentication.Sasl.Iam.Enabled
        if ($iam) {
            New-Attachment -Region $Region -ResourceType 'MSK::Cluster' `
                -ResourceId $cl.ClusterName -ResourceName $cl.ClusterName -ResourceArn $cl.ClusterArn `
                -AttachmentType 'IAMAuth' -IdentityType 'AWSAccount' `
                -IdentityArn "arn:aws:iam::$($Global:IR.AccountId):root" -IdentityName "IAM Auth enabled" `
                -RiskLevel 'MEDIUM' -Notes "MSK IAM authentication enabled - any IAM principal with kafka: permissions"
            $count++
        }
    }
    Write-ServiceResult $count
}

function Collect-DataSync {
    param([string]$Region)
    Write-ServiceHeader "DataSync" $Region
    $count = 0

    $r = Invoke-IRAWSCLI -Arguments @('datasync','list-tasks') -Region $Region -Description "DataSync tasks"
    if (-not $r.Success -or -not $r.Output.Tasks) { Write-ServiceResult 0; return }

    foreach ($task in $r.Output.Tasks | Select-Object -First 20) {
        $Global:IR.Stats.ResourcesScanned++
        $dr = Invoke-IRAWSCLI -Arguments @('datasync','describe-task','--task-arn',$task.TaskArn,'--query','CloudWatchLogGroupArn') -Region $Region -Description "DataSync task: $($task.TaskArn)"
        # Note task ARN and association
        New-Attachment -Region $Region -ResourceType 'DataSync::Task' `
            -ResourceId $task.TaskArn.Split('/')[-1] -ResourceName $task.Name -ResourceArn $task.TaskArn `
            -AttachmentType 'TaskExecution' -IdentityType 'ServicePrincipal' `
            -IdentityArn 'datasync.amazonaws.com' -IdentityName 'DataSync Service' `
            -RiskLevel 'LOW' -Notes "Status=$($task.Status) DataSync service role"
        $count++
    }
    Write-ServiceResult $count
}

function Collect-AppRunner {
    param([string]$Region)
    Write-ServiceHeader "App Runner" $Region
    $count = 0

    $r = Invoke-IRAWSCLI -Arguments @('apprunner','list-services','--query','ServiceSummaryList') -Region $Region -Description "App Runner services"
    if (-not $r.Success -or -not $r.Output) { Write-ServiceResult 0; return }

    foreach ($svc in $r.Output | Select-Object -First 20) {
        $Global:IR.Stats.ResourcesScanned++
        $dr = Invoke-IRAWSCLI -Arguments @('apprunner','describe-service','--service-arn',$svc.ServiceArn,'--query','Service') -Region $Region -Description "App Runner svc: $($svc.ServiceName)"
        if (-not $dr.Success -or -not $dr.Output) { continue }
        $s = $dr.Output

        if ($s.InstanceConfiguration.InstanceRoleArn) {
            New-Attachment -Region $Region -ResourceType 'AppRunner::Service' `
                -ResourceId $svc.ServiceName -ResourceName $svc.ServiceName -ResourceArn $svc.ServiceArn `
                -AttachmentType 'InstanceRole' -IdentityType 'Role' `
                -IdentityArn $s.InstanceConfiguration.InstanceRoleArn `
                -IdentityName $s.InstanceConfiguration.InstanceRoleArn.Split('/')[-1] `
                -RiskLevel 'MEDIUM' -Notes "Container execution role"
            $count++
        }
        if ($s.SourceConfiguration.AuthenticationConfiguration.AccessRoleArn) {
            New-Attachment -Region $Region -ResourceType 'AppRunner::Service' `
                -ResourceId $svc.ServiceName -ResourceName $svc.ServiceName -ResourceArn $svc.ServiceArn `
                -AttachmentType 'AccessRole' -IdentityType 'Role' `
                -IdentityArn $s.SourceConfiguration.AuthenticationConfiguration.AccessRoleArn `
                -IdentityName $s.SourceConfiguration.AuthenticationConfiguration.AccessRoleArn.Split('/')[-1] `
                -RiskLevel 'LOW' -Notes "ECR pull role"
            $count++
        }
    }
    Write-ServiceResult $count
}

# ============================================================
# ORCHESTRATOR
# ============================================================

$script:COLLECTORS = @(
    # Compute
    'Collect-EC2', 'Collect-Lambda', 'Collect-ECS', 'Collect-EKS',
    'Collect-EMR', 'Collect-Batch', 'Collect-ElasticBeanstalk', 'Collect-AppRunner',
    # Serverless / Integration
    'Collect-StepFunctions', 'Collect-EventBridge', 'Collect-APIGateway', 'Collect-Kinesis',
    # CI/CD
    'Collect-CodeBuild', 'Collect-CodePipeline', 'Collect-CodeDeploy',
    # Data
    'Collect-S3', 'Collect-RDS', 'Collect-Redshift', 'Collect-Glue', 'Collect-SageMaker',
    # Security
    'Collect-KMS', 'Collect-SecretsManager',
    # Messaging
    'Collect-SQS', 'Collect-SNS', 'Collect-ECR',
    # Management
    'Collect-CloudFormation', 'Collect-CloudTrail', 'Collect-Config', 'Collect-SSM',
    # Other
    'Collect-TransferFamily', 'Collect-OpenSearch', 'Collect-MSK', 'Collect-DataSync'
)

function Invoke-AllCollectors {
    param([string[]]$Regions)

    foreach ($region in $Regions) {
        if ($Global:IR.Stats.RegionsScanned -notcontains $region) {
            $Global:IR.Stats.RegionsScanned.Add($region)
        }
        Write-Host ""
        Write-Host "  [REGION] $region" -ForegroundColor Magenta
        Write-Host "  -------------------------------------------------" -ForegroundColor DarkGray

        foreach ($fn in $script:COLLECTORS) {
            try {
                & $fn -Region $region
            } catch {
                Write-Host " ERROR" -ForegroundColor Red
                Write-IRError -Service $fn -Region $region -Message $_.ToString()
                if ($Global:IR.Stats.ServicesFailed -notcontains "$region/$fn") {
                    $Global:IR.Stats.ServicesFailed.Add("$region/$fn")
                }
            }
        }
    }
}
