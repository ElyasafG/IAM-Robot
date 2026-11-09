<img width="1774" height="887" alt="b7831ddc-ddb0-4b5b-9199-30d04d7c903f" src="https://github.com/user-attachments/assets/fac404cc-83c1-452b-894b-e983ab3079f3" />

# IAM-Robot

**An AWS IAM attack-surface mapper for red teams and cloud-security auditors.**

IAM-Robot is a read-only PowerShell tool that enumerates IAM identities, role attachments, and resource policies across an AWS account, then renders a complete interactive HTML report describing what every identity can do, which resources are exposed, and which attack paths exist between them.

The tool is designed to surface the exact information a human auditor needs to reason about privilege escalation, lateral movement, data exfiltration, and defense evasion: not just which roles look risky, but how their effective permissions combine, which resources they touch, and which documented attack patterns they enable.

---

## Table of Contents

1. [Design Goals](#design-goals)
2. [Quick Start](#quick-start)
3. [Workflow: how a full run executes](#workflow)
4. [Output Pages](#output-pages)
5. [Capability Library — what gets detected](#capability-library)
6. [Attack Paths — node and edge model](#attack-paths)
7. [Effective Permission Resolution](#effective-permission-resolution)
8. [Identity Classification](#identity-classification)
9. [Resume Mode and State Cache](#resume-mode)
10. [Command Line Reference](#command-line-reference)
11. [Module Architecture](#module-architecture)
12. [Service Coverage](#service-coverage)
13. [Trade-offs and Known Limitations](#trade-offs)
14. [What to look for when reading the output](#reading-the-output)

---

## Design Goals

IAM-Robot was built around four constraints that shape every architectural decision:

**Read-only by construction.** No write, modify, or delete API is ever called. The tool can be run with credentials that have only `*:Describe*`, `*:List*`, `*:Get*`, and `iam:Simulate*` permissions. This is enforced by the collector design — every AWS CLI invocation is reviewed against this constraint, and no other verbs are present in the codebase.

**Offline-readable output.** Every report renders as static HTML with no server component. CSS, JS, and data live in the same file; charts use Chart.js and D3 loaded from public CDNs but the data is embedded. You can email a `.zip` of the output directory to a client without dependencies.

**Auditor-grade findings, not vendor noise.** Each capability finding is mapped to MITRE ATT&CK Cloud techniques (TA0001 through TA0008 + TA0040) and references documented research from at least one of: Rhino Security Labs, Prisma Cloud, Wiz, Crowdstrike Falcon Cloud, or CIS AWS Benchmark. Findings include affected roles, granting policies, vulnerable resources, impact descriptions, and remediation guidance.

**Resumable.** Long-running runs serialize their state to `.ir-state.json`. If an STS credential expires mid-run or AWS CLI fails, you can re-run with `-Resume` and the tool will skip data collection and regenerate the report from cached state.

---

## Quick Start

```powershell
# Drop the IAM-Robot folder anywhere
cd "C:\Audits\TargetAccount"

# Set credentials in your shell (audit-ro role recommended)
$env:AWS_ACCESS_KEY_ID     = 'ASIA...'
$env:AWS_SECRET_ACCESS_KEY = '...'
$env:AWS_SESSION_TOKEN     = '...'

# Run
.\IAM-Robot\IAM-Robot.ps1

# Or with a named profile and specific regions
.\IAM-Robot\IAM-Robot.ps1 -Profile audit-ro -Regions "us-east-1,us-west-2"
```

The script auto-unblocks all `.ps1` files in its tree, so you won't hit the Windows ExecutionPolicy "not digitally signed" block. After the run, open `IAM-Robot-<timestamp>/index.html` in any browser.

---

## Workflow

A full run executes nine phases. Phase numbering preserves backwards compatibility with prior versions, hence the lettered sub-phases.

### Phase 1 — Credential check
Calls `sts get-caller-identity`. On failure: if `-Resume` or `-ResumeFrom` was passed, jumps to report generation using the cached state file. Otherwise prints credential setup instructions and exits gracefully (the window stays open with a "Press Enter" prompt).

### Phase 2 — Region discovery
Calls `ec2 describe-regions --all-regions` and filters to opt-in regions. Skipped if `-Regions` was passed explicitly.

### Phase 3 — Resource collection
Iterates every region across 33+ service collectors. Each collector:
- Enumerates resources for its service
- Identifies IAM relationships (instance profiles, execution roles, resource policies, trust policies)
- Records each relationship as an "attachment" in `$Global:IR.Attachments`

Every attachment has fields: `ResourceType`, `ResourceArn`, `ResourceName`, `Region`, `IdentityType`, `IdentityArn`, `IdentityName`, `AttachmentType`, `Effect`, `Permissions`, `ResourceScope`, `IsExternal`, `IsPublic`, `IsHighPrivilege`, `RiskLevel`. The data shape is described in `Modules/IR-Utils.ps1::New-Attachment`.

### Phase 4 — IAM role enrichment
For every unique role ARN in the collected attachments (capped by `-MaxRolesToEnrich`, default 200):
- `iam get-role` for trust policy
- `iam list-attached-role-policies` + `iam get-policy-version` for managed policies
- `iam list-role-policies` + `iam get-role-policy` for inline policies

Each enriched role is stored in `$Global:IR.RoleCatalog` keyed by ARN, with parsed Allow/Deny statements, all referenced actions, all referenced resource ARNs, and parsed trust principals.

### Phase 4b — IAM-Audit cross-reference (optional)
If a sibling `IAM-Audit/` folder is detected (or `-IAMAuditDir` was passed), reads its findings and boosts risk on matching identities/resources. Skipped if no sibling folder exists. This lets IAM-Robot complement deeper static IAM-only analysis from a separate tool.

### Phase 4c — Per-role detail pages
For every enriched role, generates `roles/role-<name>.html` containing:
- Header counters (Allow / Deny / OverriddenByDeny / capability count)
- Capability cards with MITRE tactic, vendor references, source policies, vulnerable resources, impact and remediation
- Full action table — every action in the static catalog (~270 across 23 services), with effective state (Allow / Deny / AllowOverriddenByDeny / NotPermitted)
- Per-action ARN dropdown with scope coloring (scoped / external / public / all)
- Trust principals with ExternalId/MFA flags
- Resources using this role
- Raw policy documents (collapsible, anchored for jump-from-capability-card)

Also populates `$Global:IR.RoleCapabilities` (map of role ARN → list of triggered capabilities) used by the catalog and attack-paths pages.

### Phase 4d — Per-resource detail pages
For every unique resource ARN, generates `resources/res-<id>.html` containing:
- Combined effective permissions union'd across all attached role identities
- Capability analysis on those combined permissions
- "Identities this resource uses" table (instance profiles, execution roles, task roles, etc.) with enriched/not-enriched badge
- "Identities granted access to this resource" table (resource policy principals)
- Full action table on the combined permissions
- Raw policy documents from each attached role

### Phase 5 — Main report pages
- `index.html` — dashboard with stats, charts, top findings
- `resources.html` — every attachment in a sortable filtered table
- `identities.html` — grouped by identity, with classification badges (AWS-known green, modified default purple, anomalous services red)
- `assume.html` — trust relationships, with non-assuming rows greyed and sorted below
- `findings.html` — broad/risky permissions analysis
- `command-log.html` — every AWS CLI call with success/error/interesting-output highlighting

### Phase 5b — Index, catalog, and attack-graph pages
- `roles.html` — sortable index of every enriched role linking to its detail page
- `resources-detail.html` — sortable index of every resource with a detail page
- `findings-catalog.html` — MITRE matrix grid plus full capability catalog
- `attack-paths.html` — interactive D3 force-directed graph

### State serialization
At the end of Phase 4d, `.ir-state.json` is written to the output directory. This captures account context, stats, all attachments, and the role catalog. Pass `-Resume` on the next run to skip Phases 1-4 and regenerate the report from cache.

---

## Output Pages

The report consists of 13 navigable pages plus per-role and per-resource detail pages.

| Page | What it shows | Key signals |
|---|---|---|
| Dashboard | Overall counters, severity distribution, top findings | Quick triage |
| Resources | Every attachment | Filter by service, identity type, effect, scope |
| Identities | Grouped by IAM identity | AWS-known vs. customer-managed, modified defaults, anomalous service touch |
| Assume-Role | Trust relationships | External, public, MFA-required, ExternalId-required |
| Findings | Resource-level broad/risky permission patterns | Service:* admin grants, external trust, etc. |
| Findings Catalog | Every capability check + MITRE matrix | Hit vs. miss across the catalog |
| Roles | Index of per-role pages | Sortable by worst capability severity |
| Resource Detail | Index of per-resource pages | Sortable by worst risk |
| Attack Paths | Interactive graph | Click any node to highlight paths; preset attack flows |
| Command Log | Every AWS CLI call | Green = interesting output, red = error |
| Raw CSV | Flat attachment data | For spreadsheet / Excel ingestion |

Per-role pages (`roles/role-*.html`) and per-resource pages (`resources/res-*.html`) are the deepest level of detail. Both are reachable from the index pages and from links throughout the main report.

---

## Capability Library

The capability library lives in `Modules/IR-CapabilityLibrary.ps1` and currently contains **57 capability checks** organized by MITRE Cloud tactic. Each entry has:

- **Id** — `C001` through `C103`
- **Name** — short description, formatted `Tactic: Pattern`
- **Severity** — `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO`
- **MitreTactic** — `TAxxxx Tactic Name (Txxxx[.xxx])`
- **Vendor** — comma-separated list of vendors that document this pattern
- **Reference** — public URL to the canonical write-up
- **Description** — what the role can do
- **Impact** — what an attacker gains
- **Recommend** — remediation guidance
- **Required** — exact actions that must all be Allow for the capability to trigger

### Full capability catalog

**Privilege Escalation (TA0004)**

| Id | Name | Severity | Required actions |
|----|------|----------|------------------|
| C001 | CreatePolicyVersion + SetDefaultPolicyVersion | CRITICAL | `iam:CreatePolicyVersion`, `iam:SetDefaultPolicyVersion` |
| C002 | iam:PassRole + Lambda CreateFunction+InvokeFunction | CRITICAL | `iam:PassRole`, `lambda:CreateFunction`, `lambda:InvokeFunction` |
| C003 | iam:PassRole + Lambda UpdateFunctionCode | CRITICAL | `iam:PassRole`, `lambda:UpdateFunctionCode` |
| C004 | iam:PassRole + ec2:RunInstances | CRITICAL | `iam:PassRole`, `ec2:RunInstances` |
| C005 | iam:PassRole + Glue CreateJob+StartJobRun | CRITICAL | `iam:PassRole`, `glue:CreateJob`, `glue:StartJobRun` |
| C006 | iam:PassRole + CodeBuild | CRITICAL | `iam:PassRole`, `codebuild:CreateProject`, `codebuild:StartBuild` |
| C007 | iam:PassRole + SageMaker Notebook | CRITICAL | `iam:PassRole`, `sagemaker:CreateNotebookInstance`, `sagemaker:CreatePresignedNotebookInstanceUrl` |
| C008 | iam:PassRole + ECS RegisterTaskDefinition+RunTask | CRITICAL | `iam:PassRole`, `ecs:RegisterTaskDefinition`, `ecs:RunTask` |
| C009 | iam:UpdateAssumeRolePolicy | CRITICAL | `iam:UpdateAssumeRolePolicy` |
| C010 | iam:AttachUserPolicy | CRITICAL | `iam:AttachUserPolicy` |
| C011 | iam:AttachRolePolicy | CRITICAL | `iam:AttachRolePolicy` |
| C012 | iam:AttachGroupPolicy + AddUserToGroup | CRITICAL | `iam:AttachGroupPolicy`, `iam:AddUserToGroup` |
| C013 | iam:PutUserPolicy | CRITICAL | `iam:PutUserPolicy` |
| C014 | iam:PutRolePolicy | CRITICAL | `iam:PutRolePolicy` |
| C015 | iam:PutGroupPolicy | CRITICAL | `iam:PutGroupPolicy` |

**Persistence (TA0003)**

| Id | Name | Severity |
|----|------|----------|
| C020 | iam:CreateAccessKey for other users | HIGH |
| C021 | iam:CreateLoginProfile / UpdateLoginProfile | HIGH |
| C022 | lambda:CreateFunction + AddPermission | MEDIUM |
| C023 | ssm:CreateDocument with persistent agent | MEDIUM |

**Defense Evasion (TA0005)**

| Id | Name | Severity |
|----|------|----------|
| C030 | CloudTrail tampering (StopLogging / DeleteTrail) | CRITICAL |
| C031 | AWS Config tampering | HIGH |
| C032 | CloudWatch Logs tampering | HIGH |
| C033 | CloudWatch Alarm tampering | MEDIUM |
| C034 | GuardDuty / SecurityHub / Macie disable | CRITICAL |
| C035 | ec2:ModifyInstanceMetadataOptions (IMDSv1 re-enable) | MEDIUM |
| C036 | s3:PutBucketLogging / DeleteBucketLogging | MEDIUM |
| C037 | VPC Flow Logs delete | MEDIUM |

**Credential Access (TA0006)**

| Id | Name | Severity |
|----|------|----------|
| C040 | secretsmanager:GetSecretValue (scope-dependent) | HIGH/MEDIUM |
| C041 | ssm:GetParameter on SecureString | MEDIUM |
| C042 | kms:Decrypt with Resource:* | HIGH |
| C043 | ec2:GetPasswordData | HIGH |
| C044 | codebuild project environment variables read | MEDIUM |
| C045 | lambda function env vars read | MEDIUM |

**Exfiltration (TA0010)**

| Id | Name | Severity |
|----|------|----------|
| C050 | s3:GetObject with Resource:* | HIGH |
| C051 | RDS snapshot cross-account share | CRITICAL |
| C052 | EBS snapshot cross-account share | CRITICAL |
| C053 | DynamoDB Scan with Resource:* | MEDIUM |
| C054 | EC2 CopyImage to external account | HIGH |

**Resource Abuse / Cryptomining (TA0040)**

| Id | Name | Severity |
|----|------|----------|
| C060 | ec2:RunInstances without instance-type Conditions | HIGH |
| C061 | sagemaker:CreateNotebookInstance | HIGH |
| C062 | Batch / Lambda cryptomining vectors | MEDIUM |

**Lateral Movement (TA0008)**

| Id | Name | Severity |
|----|------|----------|
| C070 | sts:AssumeRole with Resource:* | HIGH |
| C071 | EC2 AssociateIamInstanceProfile | MEDIUM |
| C072 | ssm:SendCommand / StartSession | MEDIUM |
| C073 | ecs:ExecuteCommand | MEDIUM |
| C074 | eks:AccessKubernetesApi | HIGH |

**Impact / Destruction (TA0040)**

| Id | Name | Severity |
|----|------|----------|
| C080 | kms:ScheduleKeyDeletion | HIGH |
| C081 | s3:DeleteBucket with Resource:* | HIGH |
| C082 | rds:DeleteDBInstance | HIGH |
| C083 | organizations:LeaveOrganization | CRITICAL |
| C084 | dynamodb:DeleteTable | MEDIUM |

**Discovery (TA0007)**

| Id | Name | Severity |
|----|------|----------|
| C090 | IAM enumeration (full ListUsers/ListRoles/ListPolicies) | LOW |
| C091 | iam:SimulatePrincipalPolicy abuse | MEDIUM |

**Misconfiguration**

| Id | Name | Severity |
|----|------|----------|
| C100 | ec2:AuthorizeSecurityGroupIngress unscoped | MEDIUM |
| C101 | s3:PutBucketPolicy unscoped | HIGH |
| C102 | VPC peering creation | LOW |
| C103 | NotAction + Allow (rare and dangerous) | HIGH |

Capabilities only trigger if the role's **effective** permission resolves to `Allow` for every required action. A `Deny` statement covering one of the required actions suppresses the finding even if other policies grant it. This matches AWS evaluation logic.

---

## Attack Paths

The attack graph in `attack-paths.html` is a force-directed D3 visualization of every entity in the report and the edges between them.

### Node types

| Type | Color | Source |
|------|-------|--------|
| Role | Purple (`#a855f7`) | Every enriched role with at least one capability |
| Resource | Teal (`#00d4aa`) | Every resource that has an enriched-role attachment |
| Capability | Orange (`#ff8c00`) | Every triggered capability across all roles |
| Trust Principal | Red (`#ff3366`) | Every assumer (AWS account, federated, public) |

Node stroke color and width follow severity: critical = red thick, high = orange, medium = yellow, low = green, info = blue.

### Edge types

| Type | Style | Meaning |
|------|-------|---------|
| enables | Solid line | Role grants this capability |
| attached-to | Dashed line | Role is attached to this resource (instance profile / execution role / etc.) |
| can-assume | Dotted line | Principal can assume this role per its trust policy |

Edge severity inherits from the capability severity (for `enables`) or attachment risk (for `attached-to`) or trust-principal severity (for `can-assume`).

### Interactive controls

- **Hover** any node to see a contextual explanation of what it represents and what clicking will do
- **Click** any node to highlight the connected sub-graph (BFS both incoming and outgoing edges) and populate the right-side detail panel with every adjacent edge grouped by type. Items in the panel are clickable to pivot the graph
- **Click background** to clear the highlight
- **Drag** the canvas to pan, **scroll** to zoom, **drag** nodes to rearrange
- **Filter** by text search, node type, or severity to dim non-matching nodes
- **Preset attack flows** dropdown: 6 pre-built filters that highlight all paths through capability nodes matching a kill-chain category — Cryptomining, Data exfiltration, Privilege escalation, Log tampering, Credential access, Lateral movement
- **Re-layout** restarts the force simulation if nodes get tangled

### Reading the graph

A typical attack path reads left-to-right or center-out:

```
[Trust Principal] --can-assume--> [Role] --enables--> [Capability]
                                       --attached-to--> [Resource]
```

If you see a CRITICAL trust-principal edge (e.g. a cross-account AWS principal with no ExternalId) connecting to a role that has multiple HIGH+ capabilities, that's an external-actor takeover path. If you see a Lambda or EC2 resource attached to a role with CRITICAL `enables` edges, that's a code-execution-leads-to-account-takeover path.

---

## Effective Permission Resolution

Every policy statement is expanded into individual concrete actions before evaluation. This matters because policies say `s3:*` but auditors need to see what that *actually* grants.

### Expansion rules

1. **`Action: "*"`** — expanded to every action in the static catalog across every service (`~270 actions` across `23 services`)
2. **`Action: "s3:*"`** — expanded to every catalogued action in the `s3` service
3. **`Action: "ec2:Describe*"`** — expanded to every catalogued `ec2:Describe*` action via regex glob
4. **`Action: "iam:ChangePassword"`** — kept as-is

Unknown services (e.g. `foobar:*`) are not expanded since they're not in the catalog. The literal pattern is recorded so the audit doesn't silently drop it.

### Deny resolution

The standard AWS policy evaluation logic applies:

- An action with no statement at all → `NotPermitted` (implicit deny)
- An action with one or more Allow statements and zero Deny statements → `Allow`
- An action with one or more Deny statements → `Deny` (regardless of Allow)
- An action with both Allow and Deny → `AllowOverriddenByDeny`

Capability checks require `Effect=Allow`. `AllowOverriddenByDeny` does not trigger capabilities.

### `NotAction` handling

`NotAction` (the inverted action match) is rare and dangerous. When present, the expander records the inverse — everything in the catalog NOT in the listed actions — and marks the action with `FromNotActionAllow=true` so it can be flagged.

### Resource scope classification

For every Allow statement, each resource ARN is classified:

- `all` — `*` or `arn:aws:service::*` (red, unscoped)
- `public` — ARN known to have a resource policy allowing `Principal:*`
- `external` — ARN in an account different from the current one (orange)
- `scoped` — specific ARN in this account (green)
- `broad` — service wildcard like `arn:aws:s3:::*` (yellow)

The role detail page's action table shows these as colored pills inside an inline expand row.

---

## Identity Classification

The Identities page tags every identity with badges that distinguish customer-managed roles from AWS-managed defaults.

| Badge | Color | Meaning |
|-------|-------|---------|
| `AWS-KNOWN` | Green | `AWSServiceRoleFor*`, `AWSReservedSSO_*`, `OrganizationAccountAccessRole`, AWS service principals, federated providers |
| `MODIFIED` | Purple | An AWS-KNOWN identity that touches more than two unrelated service families (likely tampered) |
| `EXT` | Orange | Identity has at least one external-resource attachment |
| `PUB` | Red | Identity has at least one public-resource attachment |
| `HP` | Red | Identity flagged as high-privilege by the IAM-Audit cross-reference |
| `ADMIN *` | Red | At least one statement grants `Action: *` |

### Anomalous services in red

For customer-managed identities, the tool infers a "primary service" from the identity name (e.g. `lambda-exec-role` → Lambda primary). Services touched by the identity that don't appear in that service's "natural co-services" map are highlighted in red.

Example: an identity named `s3-backup-role` that touches `SageMaker` would have `SageMaker` rendered in red. The list of natural co-services per primary is in `Modules/IR-Report.ps1::naturalCoServices`.

This is a heuristic. It will produce false positives if your naming convention is non-standard. It's intentionally noisy because false positives are cheap to triage and a real anomaly is expensive to miss.

---

## Resume Mode

State is serialized to `<output>/.ir-state.json` at the end of Phase 4d. Two flags trigger resume:

- `-Resume` — search the current directory for the newest `IAM-Robot-*` folder and use its `.ir-state.json`
- `-ResumeFrom <path>` — point at a specific state file or output directory

Resume is automatic if credentials fail. If your STS token expires mid-run, you can fix credentials and re-run with `-Resume`; the tool will detect cached state and jump straight to report generation.

What gets cached:
- Account ID and alias
- Output directory path
- Stats (regions scanned, resources scanned, attachments found)
- Every attachment record
- Every enriched role's full data (policies, trust, all referenced actions)

What does *not* get cached:
- Per-role generated HTML pages (rebuilt from the catalog)
- Per-resource generated HTML pages (rebuilt)
- Command log (a new one starts on resume)

---

## Command Line Reference

```
.\IAM-Robot.ps1 [options]

  -OutputDir <path>       Where to write reports (default: .\IAM-Robot-<timestamp>)
  -Profile <name>         AWS CLI named profile to use
  -Regions <csv>          Comma-separated region list. Default: auto-discover opt-in regions
  -TimeoutSeconds <int>   Per-command timeout (default: 30). Press 'S' to skip a hung command
  -SkipRegionDiscovery    Don't enumerate regions, use whatever AWS CLI defaults to
  -MaxRolesToEnrich <int> Cap on Phase 4 role enrichment (default: 200). Increase for large accounts
  -SkipEnrichment         Skip Phase 4 entirely - useful for first-pass collection-only runs
  -IAMAuditDir <path>     Path to sibling IAM-Audit output for cross-reference (default: auto-detect)
  -SkipIAMAuditImport     Don't try to read the IAM-Audit folder
  -Resume                 Find the newest IAM-Robot-* folder and use its cached state
  -ResumeFrom <path>      Use the .ir-state.json at this specific path or folder
```

---

## Module Architecture

```
IAM-Robot/
├── IAM-Robot.ps1               # Orchestrator: param parsing, banner, phase sequencing
└── Modules/
    ├── IR-Utils.ps1            # Context init, AWS CLI wrapper, attachment builder, logging
    ├── IR-Collect.ps1          # 33 service collectors (Phase 3)
    ├── IR-Enrich.ps1           # Role enrichment via iam get-role / get-policy-version (Phase 4)
    ├── IR-Import.ps1           # Optional IAM-Audit cross-reference (Phase 4b)
    ├── IR-ActionCatalog.ps1    # 270+ IAM action catalog + policy expansion logic
    ├── IR-CapabilityLibrary.ps1 # 57 capability findings with MITRE + vendor + reference
    ├── IR-RolePages.ps1        # Per-role detail page builder (Phase 4c)
    ├── IR-ResourcePages.ps1    # Per-resource detail page builder (Phase 4d)
    ├── IR-IndexPages.ps1       # Roles/Resources-Detail/Findings-Catalog/Attack-Paths (Phase 5b)
    └── IR-Report.ps1           # Dashboard + Resources + Identities + Assume + Findings + Log (Phase 5)
```

Module load order is enforced by the orchestrator. Modules dot-source each other's functions at run time; there is no `Export-ModuleMember` because we don't use `.psm1`.

### Key globals

| Variable | Type | Populated by | Used by |
|---|---|---|---|
| `$Global:IR` | hashtable | `Initialize-IRContext` | every module |
| `$Global:IR.Attachments` | `List[object]` | Collect-* | every report |
| `$Global:IR.CommandLog` | `List[object]` | `Invoke-IRAWSCLI` | Command Log page |
| `$Global:IR.RoleCatalog` | `hashtable` | `Invoke-RoleEnrichment` | Per-role pages, capability checks |
| `$Global:IR.RoleCapabilities` | `hashtable` | Phase 4c | Findings, Findings Catalog, Attack Paths |
| `$Global:IR.RoleFileMap` | `hashtable` | Phase 4c | Cross-page links |
| `$Global:IR.ResourceFileMap` | `hashtable` | Phase 4d | Cross-page links |
| `$Global:IR_ActionCatalog` | `hashtable` | `IR-ActionCatalog.ps1` load | `Expand-ActionPattern`, `Build-FullActionTable` |
| `$Global:IR_Capabilities` | `array` | `IR-CapabilityLibrary.ps1` load | Capability detection, catalog page |

---

## Service Coverage

The collector currently enumerates IAM-relevant resources across the following services. "IAM relationship" means either the resource has a role attached (instance profile / execution role / service role / task role / etc.), the resource has a resource-based policy that grants principals access, or both.

### Compute
EC2 (Instance, FlowLog), Lambda (Function, FunctionUrl), Batch (ComputeEnvironment, JobDefinition), AppRunner (Service), ElasticBeanstalk (Environment)

### Containers
ECS (TaskDefinition), EKS (Cluster, NodeGroup, AccessEntry), ECR (Repository)

### Storage
S3 (Bucket — bucket policy + ACL + Public Access Block)

### Database
RDS (DBInstance, DBCluster), Redshift (Cluster)

### Networking & Delivery
API Gateway (RestAPI, HTTPAPI)

### Developer Tools
CodeBuild (Project), CodePipeline (Pipeline), CodeDeploy (DeploymentGroup)

### Management & Governance
CloudFormation (Stack), CloudTrail (Trail), Config (Recorder, RemediationConfig), SSM (Association)

### Analytics
EMR (Cluster), Glue (Crawler, Job), Kinesis (FirehoseStream), MSK (Cluster), OpenSearch (Domain)

### Machine Learning
SageMaker (Domain, NotebookInstance)

### Security
KMS (Key — key policy), SecretsManager (Secret — resource policy)

### Integration
StepFunctions (StateMachine), EventBridge (Rule), SQS (Queue — resource policy), SNS (Topic — resource policy)

### Migration & Transfer
Transfer Family (Server, User), DataSync (Task)

### Total
33 collectors, 42 resource types, ~270 IAM actions in the action catalog.

### Coverage gaps

Services in the AWS catalog that are not yet enumerated but could be added. These are listed roughly in order of security relevance:

- **DynamoDB::Table** — table resource policies, IAM access patterns
- **EFS::FileSystem** — file system policies (cross-account access)
- **FSx::FileSystem** — Windows AD integration, Lambda hooks
- **ElastiCache::Cluster** + **ReplicationGroup** — cluster IAM
- **IAM::User** / **IAM::Group** / **IAM::InstanceProfile** — direct enumeration (currently only seen via role attachments)
- **CloudWatch::LogGroup** — cross-account log destination policies
- **Cognito::UserPool** + **IdentityPool** — authenticated / unauthenticated roles
- **Backup::Vault** — backup vault access policies
- **AppSync::GraphQLAPI** — service roles, auth mode
- **Athena::WorkGroup** — workgroup IAM
- **Amplify::App** — app service roles
- **GuardDuty::Detector** — detectors that can be disabled
- **SecurityHub** — enabled standards, custom action targets
- **WAFv2::WebACL** — IAM-modifiable rule groups
- **LakeFormation** — data lake permissions (often a separate model from IAM)
- **Cloud9::Environment** — IDE environments
- **VPC endpoints** — endpoint resource policies

If you need a specific gap closed, raise it and I'll add the collector.

---

## Trade-offs and Known Limitations

**Static action catalog vs. live AWS API.** The expansion catalog has ~270 actions across 23 services. AWS has 14,000+ actions across 300+ services. New actions in services we already cover may not be expanded from wildcards. Trade-off: a live API would require `iam:GetServiceLastAccessedDetails` or scraping the docs site, both fragile. The catalog covers every action used in documented attack patterns.

**Capability false negatives.** Capabilities only trigger if the role's effective permissions include every required action with `Effect=Allow`. A capability requiring three actions where the role has two will not fire. This is intentional — we report only confirmed paths, not partial matches.

**Resource policy collection is best-effort.** S3 bucket policies, KMS key policies, SQS queue policies, SNS topic policies, and Secrets Manager resource policies are fetched where the role calling the tool has read access. If permissions are missing for any specific resource, the resource appears in the collected list but with empty policy data; downstream analysis treats this as "no resource policy" which may understate exposure.

**MaxRolesToEnrich cap.** Default 200. Large accounts (1000+ roles) need this raised. Increase to a higher number, or run with `-SkipEnrichment` first to get a collection-only baseline, then re-run for enrichment.

**Cross-account graph blindness.** Attack paths are scoped to the current account. A `can-assume` edge from an external principal is shown, but where that principal *also* exists in another account, the chain stops at the boundary. Multi-account analysis requires running IAM-Robot per account and merging results manually (not automated).

**Heuristics are heuristics.** Anomalous-service detection, modified-default detection, action-without-resource detection, and resource-without-action detection all use rules that approximate human judgment. They surface candidates; they don't replace review.

**No remediation execution.** Read-only is the constraint. The Recommend field in capabilities tells you what to change; nothing in IAM-Robot will change it for you.

---

## Reading the output

### Triage order

When opening a fresh report, work this order:

1. **Dashboard** — check the critical/high counts. If both are zero, the account is unusually clean or the audit was scoped too narrowly. If critical > 50, focus on the most-attached roles first.

2. **Findings Catalog → MITRE matrix** — every red/orange box in the matrix is a documented attack pattern that fired in this account. Critical-tactic columns (Privilege Escalation, Defense Evasion) deserve attention first.

3. **Attack Paths** — load the graph, apply the `Critical only` severity filter. Roles connected to many resources or many capabilities are the high-value targets. Use the preset attack flows to walk specific kill-chains.

4. **Identities page** — filter to customer-managed only (un-check AWS-known). The remaining identities are your attack surface. Anomalous services (red) and modified-default identities (purple) deserve immediate explanation.

5. **Per-role detail pages** — for each high-risk role, open its detail page. The Capability Analysis section explains exactly what it can do and what an attacker gains. The Effective Action Table shows what it can specifically execute. The Trust Policy section shows who can become this role.

6. **Per-resource detail pages** — for each high-value resource (production database, central S3 bucket), open its detail page. The combined effective permissions show what every attached identity can do *to this resource*.

7. **Assume-Role page** — focus on rows that are NOT greyed out (those have an actual assume relationship). Cross-account trust without ExternalId is the classic external-actor entry point.

8. **Command Log → Errors only** — failed AWS CLI calls indicate where the audit has incomplete data. Most are permission-related and harmless; some indicate region-specific blackouts worth re-running with credentials in that region.

### Severity rubric

- **CRITICAL** — single-action exploitable, full account takeover possible, no chained conditions required. Should be remediated within hours.
- **HIGH** — exploit requires modest chaining (e.g. compromise a Lambda first, then exfil) or unusual conditions. Days, not weeks.
- **MEDIUM** — exploit requires significant chaining or specific configurations. Reviewable in a normal sprint.
- **LOW** — informational, surveillance value, or potential future risk if combined with other findings.
- **INFO** — context only, not actionable on its own.

### What "not found" means in the catalog

A capability marked "not found" in the catalog grid means: no role in this account has the effective permissions to perform that pattern. This is positive news. The catalog is not a checklist of things you should not do; it's a list of attack patterns the auditor knows how to detect. Empty cells indicate detection capability that didn't fire, not detection capability that's missing.

---

## Technical Stack

This section describes every external dependency and technology the tool uses, so an auditor can verify nothing surprising happens on the host running the audit.

### Runtime

**Windows PowerShell 5.1+ or PowerShell Core 7+** on Windows. Linux PowerShell is not tested. The code avoids PowerShell 7-only syntax (no null-coalescing `??`, no `-AsArray`) so it runs on stock Windows installations without upgrading PowerShell.

**No external PowerShell modules.** The tool does not `Import-Module` anything outside the built-in `Microsoft.PowerShell.*` set. No PSGallery downloads, no AWS Tools for PowerShell, no `dbatools` or similar. Everything is plain script.

### AWS interaction

**AWS CLI v2** is the sole AWS SDK. Every API call is made by spawning `cmd.exe /c aws ...` and capturing stdout/stderr through temp files (this routing exists because async pipeline reads were unreliable in older PowerShell ISE versions; the temp-file approach is universally compatible).

The wrapper is `Invoke-IRAWSCLI` in `IR-Utils.ps1`. Every invocation:
- Records the full command in `$Global:IR.CommandLog`
- Times out after `-TimeoutSeconds` (default 30 seconds)
- Captures exit code, raw stdout, raw stderr separately
- Auto-parses JSON output when AWS returns it
- Marks the result as "Interesting" if more than ~30 bytes of non-empty JSON came back

The full list of AWS CLI verbs called: `sts get-caller-identity`, `ec2 describe-regions`, and per-service `describe-*` / `list-*` / `get-*` verbs across ~33 services. No `create-*`, `delete-*`, `put-*`, `modify-*`, `update-*`, `attach-*`, `detach-*`, `start-*`, `stop-*`, `assume-role`, or `simulate-*` verbs are present in the codebase. You can verify with `grep -rE "aws [a-z]+:(create|delete|put|update|modify|attach|detach|start|stop|reboot|terminate)" Modules/` — it should return nothing.

### Output format

**Static HTML with no server component.** Reports render as `.html` files using CSS variables for theming. No build step, no bundler, no transpiler. You can open the output in any browser, or zip the directory and email it.

**JavaScript runs in-browser only.** Every interactive page (filtering, sorting, the attack graph) embeds the data as a JSON literal in a `<script>` tag and processes it with vanilla JS. No `fetch()`, no `XMLHttpRequest` to any backend. Pages will load and function correctly with the browser offline.

**Two third-party JS libraries are loaded from public CDNs:**

| Library | Version | Used on | CDN |
|---|---|---|---|
| Chart.js | 4.4.1 | Dashboard, Findings Catalog | cdnjs.cloudflare.com |
| D3.js | 7.x | Attack Paths force-directed graph | cdn.jsdelivr.net |

If your audit environment blocks outbound HTTPS, the dashboard and attack-paths pages will render but their visualizations will fail silently; everything else continues to work. To go fully offline, save the two libraries locally and replace the `<script src=>` URLs.

**No external CSS.** All styling is inline `<style>` blocks. Font stack is the OS sans-serif default plus Cascadia Code / Consolas / monospace for ARNs and actions. No webfonts are loaded.

### State and caching

**`.ir-state.json`** — a single JSON file written to the output directory at the end of Phase 4d, holding the account context, attachments list, and full role catalog. `-Resume` reads this file to skip data collection.

**No external database, no Redis, no message queue.** Inter-phase state lives in `$Global:IR`, a single hashtable in PowerShell memory.

### Cross-page links

The report directory layout:

```
IAM-Robot-<timestamp>/
├── index.html                   # Dashboard
├── resources.html               # Every attachment
├── identities.html              # Grouped by IAM identity
├── assume.html                  # Trust relationships
├── findings.html                # Resource-level broad permissions
├── findings-catalog.html        # MITRE matrix + capability cards
├── roles.html                   # Per-role index
├── resources-detail.html        # Per-resource index
├── attack-paths.html            # D3 force-directed graph
├── command-log.html             # Every AWS CLI call
├── .ir-state.json               # Resume cache (not browsable)
├── roles/
│   └── role-<name>.html         # One file per enriched role
└── resources/
    └── res-<id>.html            # One file per resource
```

Cross-page links use relative paths. The attack graph and findings catalog jump into per-role and per-resource pages by URL.

### Wildcard search

The Resources Detail page (`resources-detail.html`) supports wildcard search in its search box. `*` matches zero or more characters. Implementation: input string is escaped against regex metacharacters except `*`, then `*` is replaced with `.*` and compiled as a case-insensitive `RegExp`. Falls back to substring match if the regex is invalid. URL parameters `?q=...&wild=1` populate the search on load, so other pages can deep-link.

### What the tool does not use

- No package manager (`npm`, `yarn`, `pip`, NuGet) at runtime or build time
- No serverless or cloud functions; everything runs locally
- No telemetry or phone-home
- No write API calls to AWS
- No filesystem operations outside the output directory and Windows temp (used for AWS CLI stdout/stderr capture, deleted after each call)
- No registry edits

---

## Recent Changes

### Resource Detail page now ingests resource policies

Resource detail pages previously showed an empty Effective Action Table when a resource only had a resource-based policy (e.g. ECR repository policy granting `ecr:BatchGetImage` to `Principal:*` with no IAM role attached). The page now parses these policies into the combined effective permissions, so the action table is populated and capability analysis runs. Empty-state messages have been rewritten to explain exactly why a section is empty when it is.

### Action click → capability tooltip

Every action name in the Effective Action Table on both role detail and resource detail pages is now clickable. Clicking opens a modal showing every capability in the catalog that requires that action, with severity, impact, and remediation guidance. Actions associated with a capability are marked with a trailing asterisk so you can spot the meaningful ones at a glance.

### ARN click → wildcard resource search

Every Resource ARN in the action table is clickable. Clicking navigates to the Resources Detail index page with that ARN as the search query and wildcard matching enabled. Patterns like `arn:aws:lambda:eu-central-1:*:function:` work as expected — every Lambda function in `eu-central-1` is returned regardless of account ID.

### BROAD and MEGA-BROAD role tagging

Roles with very wide effective permissions are now tagged:

- **`BROAD`** — at least 100 allowed actions across at least 10 service families. Purple badge.
- **`MEGA-BROAD`** — at least 500 allowed actions across at least 25 service families. Red pulsing badge.

These complement the existing `ADMIN *` and `SVC:*` tags. The Roles index has a new column showing the total allow-action count and service count per role, plus a breadth filter dropdown.

### Attack paths now distinguish conditioned and ARN-specific edges

Edges connecting roles to capabilities now carry two extra flags:

- **`conditioned`** — at least one of the actions required by the capability has a `Condition` block in the granting policy. These edges render in light orange (`#ffb86c`) with a dashed pattern, overriding the severity color.
- **`arnSpecific`** — at least one of the actions is scoped to specific resource ARNs (not `*`).

The side panel shows `COND` and `ARN` pills next to instances that have these properties. A legend entry explains the conditioned-edge color.

### Side panel readability

The Attack Paths side panel section headers (`Outgoing: enables`, `Incoming: attached-to`, etc.) used to be the same color as the instance entries underneath. Headers are now uppercase teal badges (outgoing) or orange badges (incoming), with a clear left-border indent on the instance list. Hover state on list items is now visible.

### Action catalog expansion

The static action catalog grew from 23 services / ~270 actions to 105 services / ~1,549 action tokens. Newly covered services include access-analyzer, sso, identitystore, ds, cognito-idp, cognito-identity, elasticfilesystem, fsx, backup, storagegateway, elasticache, memorydb, neptune, docdb, timestream, cassandra, apprunner, appmesh, cloudfront, route53, globalaccelerator, elasticloadbalancing, guardduty, securityhub, macie2, inspector2, detective, fms, wafv2, shield, acm, acm-pca, signer, cloudhsm, verifiedpermissions, ram, network-firewall, vpc-lattice, states, events, scheduler, pipes, mq, appflow, athena, firehose, lakeformation, quicksight, opensearch, es, kinesisanalytics, kafka, bedrock, comprehend, rekognition, textract, transcribe, translate, lex, kendra, omics, dms, datasync, transfer, amplify, appsync, devicefarm, ses, cloudshell, cloud9, ce, budgets, iot, greengrass, cloudformation, controltower, servicecatalog, license-manager, autoscaling, workspaces.

### Filter parity across table pages

The Resources page filter set (text + multiple selects + checkboxes) has been mirrored across Identities, Assume-Role, Roles, and Resource Detail. Each page now exposes filters that match the data on it (e.g. Identities adds AWS-Known / Customer-managed / Modified, Assume-Role adds Actually-assumes / Non-assuming, Roles adds capability-count tiers and breadth tiers).

### Inline expand replaces clipped dropdowns

The previous ARN dropdown (absolute-positioned `<ul>`) was being clipped by table `overflow:hidden`. Replaced everywhere with an inline expand-row pattern: clicking `[expand]` opens a second `<tr>` below the action row with the full ARN list. Works inside tables without clipping.

### Findings Catalog: MITRE ATT&CK matrix

A MITRE Cloud tactic matrix appears above the capability cards. Each tactic gets a column; each capability is a colored box in its column (red/orange when found in this account, grey when not). Clicking a box scrolls to the capability's full card below.

### Command Log highlights interesting output

The Command Log page now adds Total / Interesting / Successful / Errors stat cards, a status filter, and per-row colored borders: green for commands that returned meaningful output, red for failures.

---

## Versioning

This document describes IAM-Robot as built across multiple iterations. The codebase is organized so future capability additions slot into `IR-CapabilityLibrary.ps1`, new service collectors into `IR-Collect.ps1`, and new pages into either `IR-Report.ps1` or `IR-IndexPages.ps1` without touching other modules.

If you extend the tool: keep the read-only invariant, add a Reference URL to every new capability, and write a one-line description that a non-AWS person can understand.
