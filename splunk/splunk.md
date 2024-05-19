
[\meta_rules\cloud\mr_aws_ec2_download_userdata.yml]

search = eventSource="ec2.amazonaws.com" requestParameters.attribute="userData" eventName="DescribeInstanceAttribute" | eval rule="26ff4080-194e-47e7-9889-ef7602efed0c", title="AWS EC2 Download Userdata" | collect index=notable_events
description = Detects bulk downloading of User Data associated with AWS EC2 instances. Instance User Data may include installation scripts and hard-coded secrets for deployment.

| bin _time span=30m
| stats count as event_count by _time eventSource

| search event_count > 10

[\meta_rules\cloud\mr_aws_enum_backup.yml]

search = eventSource="ec2.amazonaws.com" eventName IN ("GetPasswordData", "GetEbsEncryptionByDefault", "GetEbsDefaultKmsKeyId", "GetBucketReplication", "DescribeVolumes", "DescribeVolumesModifications", "DescribeSnapshotAttribute", "DescribeSnapshotTierStatus", "DescribeImages") | eval rule="76255e09-755e-4675-8b6b-dbce9842cd2a", title="Potential Backup Enumeration on AWS" | collect index=notable_events
description = Detects potential enumeration activity targeting an AWS instance backups

| bin _time span=10m
| stats count as event_count by _time eventSource

| search event_count > 5

[\meta_rules\cloud\mr_aws_enum_listing.yml]

search = eventName="list*" | table userIdentity.arn | eval rule="e9c14b23-47e2-4a8b-8a63-d36618e33d70", title="Account Enumeration on AWS" | collect index=notable_events
description = Detects enumeration of accounts configuration via api call to list different instances and services within a short period of time.

| bin _time span=10m
| stats count as event_count by _time eventSource

| search event_count > 50

[\meta_rules\cloud\mr_aws_enum_network.yml]

search = eventSource="ec2.amazonaws.com" eventName IN ("DescribeCarrierGateways", "DescribeVpcEndpointConnectionNotifications", "DescribeTransitGatewayMulticastDomains", "DescribeClientVpnRoutes", "DescribeDhcpOptions", "GetTransitGatewayRouteTableAssociations") | eval rule="c3d53999-4b14-4ddd-9d9b-e618c366b54d", title="Potential Network Enumeration on AWS" | collect index=notable_events
description = Detects network enumeration performed on AWS.

| bin _time span=10m
| stats count as event_count by _time eventSource

| search event_count > 5

[\meta_rules\cloud\mr_aws_enum_storage.yml]

search = eventSource="s3.amazonaws.com" eventName IN ("ListBuckets", "GetBucketCors", "GetBucketInventoryConfiguration", "GetBucketPublicAccessBlock", "GetBucketMetricsConfiguration", "GetBucketPolicy", "GetBucketTagging") | eval rule="4723218f-2048-41f6-bcb0-417f2d784f61", title="Potential Storage Enumeration on AWS" | collect index=notable_events
description = Detects potential enumeration activity targeting AWS storage

| bin _time span=10m
| stats count as event_count by _time eventSource

| search event_count > 5
| multisearch
[ search 
[\meta_rules\cloud\mr_aws_lambda_function_created_or_invoked.yml]

search = eventSource="lambda.amazonaws.com" eventName="CreateFunction" | eval rule="d914951b-52c8-485f-875e-86abab710c0b", title="AWS Lambda Function Created" | collect index=notable_events
description = Detects when an user creates or invokes a lambda function. | eval event_type="d914951b-52c8-485f-875e-86abab710c0b" ]
[ search 
[\meta_rules\cloud\mr_aws_lambda_function_created_or_invoked.yml]

search = eventSource="lambda.amazonaws.com" eventName="Invoke" | eval rule="53baf6c8-e3a2-4769-8378-f20df75f550d", title="AWS Lambda Function Invoked" | collect index=notable_events
description = Detects when an user creates or invokes a lambda function. | eval event_type="53baf6c8-e3a2-4769-8378-f20df75f550d" ]

| bin _time span=5m
| stats dc(event_type) as event_type_count by _time eventSource

| search event_type_count >= 2

[\meta_rules\cloud\mr_aws_macic_evasion.yml]

search = eventName IN ("ArchiveFindings", "CreateFindingsFilter", "DeleteMember", "DisassociateFromMasterAccount", "DisassociateMember", "DisableMacie", "DisableOrganizationAdminAccount", "UpdateFindingsFilter", "UpdateMacieSession", "UpdateMemberSession", "UpdateClassificationJob") | eval rule="91f6a16c-ef71-437a-99ac-0b070e3ad221", title="AWS Macie Evasion" | collect index=notable_events
description = Detects evade to Macie detection.

| bin _time span=10m
| stats count as event_count by _time sourceIPAddress

| search event_count > 5
| multisearch
[ search 
[\meta_rules\cloud\mr_aws_ses_messaging_enabled.yml]

search = eventSource="ses.amazonaws.com" eventName="UpdateAccountSendingEnabled" | eval rule="60b84424-a724-4502-bd0d-cc676e1bc90e", title="Potential AWS Cloud Email Service Abuse" | collect index=notable_events
description = Detects when the email sending feature is enabled for an AWS account and the email address verification request is dispatched in quick succession | eval event_type="60b84424-a724-4502-bd0d-cc676e1bc90e" ]
[ search 
[\meta_rules\cloud\mr_aws_ses_messaging_enabled.yml]

search = eventSource="ses.amazonaws.com" eventName="VerifyEmailIdentity" | eval rule="aa3e4183-c864-4bde-a46f-2bf178fd1080", title="Potential AWS Cloud Email Service Abuse" | collect index=notable_events
description = Detects when the email sending feature is enabled for an AWS account and the email address verification request is dispatched in quick succession | eval event_type="aa3e4183-c864-4bde-a46f-2bf178fd1080" ]

| bin _time span=5m
| stats dc(event_type) as event_type_count by _time eventSource

| search event_type_count >= 2

[\meta_rules\cloud\mr_azure_aad_secops_signin_failure_bad_password_threshold.yml]

search = ResultType=50126 ResultDescription="Invalid username or password or Invalid on-premises username or password." NOT TargetUserName="*$" | eval rule="dff74231-dbed-42ab-ba49-83289be2ac3a", title="Sign-in Failure Bad Password Threshold" | collect index=notable_events
description = Define a baseline threshold and then monitor and adjust to suit your organizational behaviors and limit false alerts from being generated.

| bin _time span=5m
| stats dc(TargetUserName) as value_count by _time IpAddress

| search value_count > 10

[\meta_rules\other\mr_generic_brute_force.yml]

search = action="failure" | table src_ip,dst_ip,user | eval rule="53c7cca0-2901-493a-95db-d00d6fcf0a37", title="Brute Force" | collect index=notable_events
description = Detects many authentication failures from one source to one destination which is may indicate Brute Force activity

| bin _time span=600s
| stats dc(category) as value_count by _time dst_ip

| search value_count > 30
