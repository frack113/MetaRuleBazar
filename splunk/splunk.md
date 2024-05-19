
[meta_rules\cloud\mr_aws_ec2_download_userdata.yml]
search = eventSource="ec2.amazonaws.com" requestParameters.attribute="userData" eventName="DescribeInstanceAttribute" | eval rule="26ff4080-194e-47e7-9889-ef7602efed0c", title="AWS EC2 Download Userdata" | collect index=notable_events
description = Detects bulk downloading of User Data associated with AWS EC2 instances. Instance User Data may include installation scripts and hard-coded secrets for deployment.

| bin _time span=30m
| stats count as event_count by _time eventSource

| search event_count > 10

[meta_rules\cloud\mr_aws_enum_backup.yml]
search = eventSource="ec2.amazonaws.com" eventName IN ("GetPasswordData", "GetEbsEncryptionByDefault", "GetEbsDefaultKmsKeyId", "GetBucketReplication", "DescribeVolumes", "DescribeVolumesModifications", "DescribeSnapshotAttribute", "DescribeSnapshotTierStatus", "DescribeImages") | eval rule="76255e09-755e-4675-8b6b-dbce9842cd2a", title="Potential Backup Enumeration on AWS" | collect index=notable_events
description = Detects potential enumeration activity targeting an AWS instance backups

| bin _time span=10m
| stats count as event_count by _time eventSource

| search event_count > 5

[meta_rules\cloud\mr_aws_enum_listing.yml]
search = eventName="list*" | table userIdentity.arn | eval rule="e9c14b23-47e2-4a8b-8a63-d36618e33d70", title="Account Enumeration on AWS" | collect index=notable_events
description = Detects enumeration of accounts configuration via api call to list different instances and services within a short period of time.

| bin _time span=10m
| stats count as event_count by _time eventSource

| search event_count > 50

[meta_rules\cloud\mr_aws_enum_network.yml]
search = eventSource="ec2.amazonaws.com" eventName IN ("DescribeCarrierGateways", "DescribeVpcEndpointConnectionNotifications", "DescribeTransitGatewayMulticastDomains", "DescribeClientVpnRoutes", "DescribeDhcpOptions", "GetTransitGatewayRouteTableAssociations") | eval rule="c3d53999-4b14-4ddd-9d9b-e618c366b54d", title="Potential Network Enumeration on AWS" | collect index=notable_events
description = Detects network enumeration performed on AWS.

| bin _time span=10m
| stats count as event_count by _time eventSource

| search event_count > 5

[meta_rules\cloud\mr_aws_enum_storage.yml]
search = eventSource="s3.amazonaws.com" eventName IN ("ListBuckets", "GetBucketCors", "GetBucketInventoryConfiguration", "GetBucketPublicAccessBlock", "GetBucketMetricsConfiguration", "GetBucketPolicy", "GetBucketTagging") | eval rule="4723218f-2048-41f6-bcb0-417f2d784f61", title="Potential Storage Enumeration on AWS" | collect index=notable_events
description = Detects potential enumeration activity targeting AWS storage

| bin _time span=10m
| stats count as event_count by _time eventSource

| search event_count > 5
| multisearch
[ search 
[meta_rules\cloud\mr_aws_lambda_function_created_or_invoked.yml]
search = eventSource="lambda.amazonaws.com" eventName="CreateFunction" | eval rule="d914951b-52c8-485f-875e-86abab710c0b", title="AWS Lambda Function Created" | collect index=notable_events
description = Detects when an user creates or invokes a lambda function. | eval event_type="d914951b-52c8-485f-875e-86abab710c0b" ]
[ search 
[meta_rules\cloud\mr_aws_lambda_function_created_or_invoked.yml]
search = eventSource="lambda.amazonaws.com" eventName="Invoke" | eval rule="53baf6c8-e3a2-4769-8378-f20df75f550d", title="AWS Lambda Function Invoked" | collect index=notable_events
description = Detects when an user creates or invokes a lambda function. | eval event_type="53baf6c8-e3a2-4769-8378-f20df75f550d" ]

| bin _time span=5m
| stats dc(event_type) as event_type_count by _time eventSource

| search event_type_count >= 2

[meta_rules\cloud\mr_aws_macic_evasion.yml]
search = eventName IN ("ArchiveFindings", "CreateFindingsFilter", "DeleteMember", "DisassociateFromMasterAccount", "DisassociateMember", "DisableMacie", "DisableOrganizationAdminAccount", "UpdateFindingsFilter", "UpdateMacieSession", "UpdateMemberSession", "UpdateClassificationJob") | eval rule="91f6a16c-ef71-437a-99ac-0b070e3ad221", title="AWS Macie Evasion" | collect index=notable_events
description = Detects evade to Macie detection.

| bin _time span=10m
| stats count as event_count by _time sourceIPAddress

| search event_count > 5
| multisearch
[ search 
[meta_rules\cloud\mr_aws_ses_messaging_enabled.yml]
search = eventSource="ses.amazonaws.com" eventName="UpdateAccountSendingEnabled" | eval rule="60b84424-a724-4502-bd0d-cc676e1bc90e", title="Potential AWS Cloud Email Service Abuse" | collect index=notable_events
description = Detects when the email sending feature is enabled for an AWS account and the email address verification request is dispatched in quick succession | eval event_type="60b84424-a724-4502-bd0d-cc676e1bc90e" ]
[ search 
[meta_rules\cloud\mr_aws_ses_messaging_enabled.yml]
search = eventSource="ses.amazonaws.com" eventName="VerifyEmailIdentity" | eval rule="aa3e4183-c864-4bde-a46f-2bf178fd1080", title="Potential AWS Cloud Email Service Abuse" | collect index=notable_events
description = Detects when the email sending feature is enabled for an AWS account and the email address verification request is dispatched in quick succession | eval event_type="aa3e4183-c864-4bde-a46f-2bf178fd1080" ]

| bin _time span=5m
| stats dc(event_type) as event_type_count by _time eventSource

| search event_type_count >= 2

[meta_rules\cloud\mr_azure_aad_secops_signin_failure_bad_password_threshold.yml]
search = ResultType=50126 ResultDescription="Invalid username or password or Invalid on-premises username or password." NOT TargetUserName="*$" | eval rule="dff74231-dbed-42ab-ba49-83289be2ac3a", title="Sign-in Failure Bad Password Threshold" | collect index=notable_events
description = Define a baseline threshold and then monitor and adjust to suit your organizational behaviors and limit false alerts from being generated.

| bin _time span=5m
| stats dc(TargetUserName) as value_count by _time IpAddress

| search value_count > 10

[meta_rules\linux\mr_lnx_auditd_cve_2021_3156_sudo_buffer_overflow.yml]
search = type="EXECVE" a0="/usr/bin/sudoedit" a1="-s" OR a2="-s" OR a3="-s" OR a4="-s" a1="\\" OR a2="\\" OR a3="\\" OR a4="\\" | eval rule="5ee37487-4eb8-4ac2-9be1-d7d14cdc559f", title="CVE-2021-3156 Exploitation Attempt" | collect index=notable_events
description = Detects exploitation attempt of vulnerability described in CVE-2021-3156.
Alternative approach might be to look for flooding of auditd logs due to bruteforcing
required to trigger the heap-based buffer overflow.


| bin _time span=24h
| stats count as event_count by _time host

| search event_count > 50

[meta_rules\linux\mr_lnx_auditd_cve_2021_3156_sudo_buffer_overflow_brutforce.yml]
search = type="SYSCALL" exe="/usr/bin/sudoedit" | eval rule="b9748c98-9ea7-4fdb-80b6-29bed6ba71d2", title="CVE-2021-3156 Exploitation Attempt Bruteforcing" | collect index=notable_events
description = Detects exploitation attempt of vulnerability described in CVE-2021-3156.
Alternative approach might be to look for flooding of auditd logs due to bruteforcing.
required to trigger the heap-based buffer overflow.


| bin _time span=24h
| stats count as event_count by _time host

| search event_count > 50
| multisearch
[ search 
[meta_rules\linux\mr_lnx_auditd_cve_2021_4034.yml]
search = type="PROCTITLE" proctitle="(null)" | eval rule="40a016ab-4f48-4eee-adde-bbf612695c53", title="Potential CVE-2021-4034 Exploitation Attempt" | collect index=notable_events
description = Detects exploitation attempt of the vulnerability described in CVE-2021-4034. | eval event_type="40a016ab-4f48-4eee-adde-bbf612695c53" ]
[ search 
[meta_rules\linux\mr_lnx_auditd_cve_2021_4034.yml]
search = type="SYSCALL" comm="pkexec" exe="/usr/bin/pkexec" | eval rule="3f4efb10-b8e0-4253-9cbb-32d4b2ef53d0", title="Potential CVE-2021-4034 Exploitation Attempt" | collect index=notable_events
description = Detects exploitation attempt of the vulnerability described in CVE-2021-4034. | eval event_type="3f4efb10-b8e0-4253-9cbb-32d4b2ef53d0" ]

| bin _time span=1m
| stats dc(event_type) as event_type_count by _time computer

| search event_type_count >= 2
| multisearch
[ search 
[meta_rules\linux\mr_lnx_auditd_debugfs_usage.yml]
search = type="EXECVE" a0="debugfs" | eval rule="fb0647d7-371a-4553-8e20-33bbbe122956", title="Use of Debugfs to Access a Raw Disk" | collect index=notable_events
description = Detects access to a raw disk on a host to evade detection by security products. | eval event_type="fb0647d7-371a-4553-8e20-33bbbe122956" ]
[ search 
[meta_rules\linux\mr_lnx_auditd_debugfs_usage.yml]
search = type="EXECVE" a0 IN ("df", "lsblk", "pvs", "fdisk", "blkid", "parted", "hwinfo", "inxi") | eval rule="e33e10c1-e376-4dc5-906b-f37c0814d96b", title="Use of Debugfs to Access a Raw Disk" | collect index=notable_events
description = Detects access to a raw disk on a host to evade detection by security products. | eval event_type="e33e10c1-e376-4dc5-906b-f37c0814d96b" ]

| bin _time span=5m
| stats dc(event_type) as event_type_count by _time computer

| search event_type_count >= 2

[meta_rules\linux\mr_lnx_auth_susp_failed_logons_single_source.yml]
search = pam_message="authentication failure" pam_user="*" pam_rhost="*" | eval rule="fc947f8e-ea81-4b14-9a7b-13f888f94e18", title="Failed Logins with Different Accounts from Single Source - Linux" | collect index=notable_events
description = Detects suspicious failed logins with different user accounts from a single source system

| bin _time span=24h
| stats dc(pam_user) as value_count by _time pam_rhost

| search value_count > 3

[meta_rules\linux\mr_lnx_shell_priv_esc_prep.yml]
search = "cat /etc/issue" OR "cat /etc/*-release" OR "cat /proc/version" OR "uname -a" OR "uname -mrs" OR "rpm -q kernel" OR "dmesg | grep Linux" OR "ls /boot | grep vmlinuz-" OR "cat /etc/profile" OR "cat /etc/bashrc" OR "cat ~/.bash_profile" OR "cat ~/.bashrc" OR "cat ~/.bash_logout" OR "ps -aux | grep root" OR "ps -ef | grep root" OR "crontab -l" OR "cat /etc/cron*" OR "cat /etc/cron.allow" OR "cat /etc/cron.deny" OR "cat /etc/crontab" OR "grep -i user *" OR "grep -i pass *" OR "ifconfig" OR "cat /etc/network/interfaces" OR "cat /etc/sysconfig/network" OR "cat /etc/resolv.conf" OR "cat /etc/networks" OR "iptables -L" OR "ip6tables -L" OR "lsof -i" OR "netstat -antup" OR "netstat -antpx" OR "netstat -tulpn" OR "arp -e" OR "route" OR "cat /etc/passwd" OR "cat /etc/group" OR "cat /etc/shadow" OR "find / -perm -u=s" OR "find / -perm -g=s" OR "find / -perm -4000" OR "find / -perm -2000" OR "find / -perm -o+w" | eval rule="444ade84-c362-4260-b1f3-e45e20e1a905", title="Privilege Escalation Preparation" | collect index=notable_events
description = Detects suspicious shell commands indicating the information gathering phase as preparation for the Privilege Escalation.

| bin _time span=30m
| stats count as event_count by _time host

| search event_count > 6

[meta_rules\network\mr_net_dns_c2_detection.yml]
search = parent_domain="*" | eval rule="1ec4b281-aa65-46a2-bdae-5fd830ed914e", title="Possible DNS Tunneling" | collect index=notable_events
description = Normally, DNS logs contain a limited amount of different dns queries for a single domain. This rule detects a high amount of queries for a single domain, which can be an indicator that DNS is used to transfer data.

| bin _time span=1h
| stats dc(dns_query) as value_count by _time parent_domain

| search value_count > 1000

[meta_rules\network\mr_net_dns_high_null_records_requests_rate.yml]
search = record_type="NULL" | eval rule="44ae5117-9c44-40cf-9c7c-7edad385ca70", title="High NULL Records Requests Rate" | collect index=notable_events
description = Extremely high rate of NULL record type DNS requests from host per short period of time. Possible result of iodine tool execution

| bin _time span=1m
| stats count as event_count by _time src_ip

| search event_count > 50

[meta_rules\network\mr_net_dns_high_requests_rate.yml]
search = query="*" | eval rule="b4163085-4001-46a3-a79a-55d8bbbc7a3a", title="High DNS Requests Rate" | collect index=notable_events
description = High DNS requests amount from host per short period of time

| bin _time span=1m
| stats count as event_count by _time src_ip

| search event_count > 1000

[meta_rules\network\mr_net_dns_high_txt_records_requests_rate.yml]
search = record_type="TXT" | eval rule="f0a8cedc-1d22-4453-9c44-8d9f4ebd5d35", title="High TXT Records Requests Rate" | collect index=notable_events
description = Extremely high rate of TXT record type DNS requests from host per short period of time. Possible result of Do-exfiltration tool execution

| bin _time span=1m
| stats count as event_count by _time src_ip

| search event_count > 50

[meta_rules\network\mr_net_firewall_high_dns_requests_rate.yml]
search = dst_port=53 | eval rule="51186749-7415-46be-90e5-6914865c825a", title="High DNS Requests Rate - Firewall" | collect index=notable_events
description = High DNS requests amount from host per short period of time

| bin _time span=1m
| stats count as event_count by _time src_ip

| search event_count > 1000

[meta_rules\network\mr_net_firewall_susp_network_scan_by_ip.yml]
search = action="denied" | table src_ip,dst_ip,dst_port | eval rule="4601eaec-6b45-4052-ad32-2d96d26ce0d8", title="Network Scans Count By Destination IP" | collect index=notable_events
description = Detects many failed connection attempts to different ports or hosts

| bin _time span=24h
| stats dc(dst_ip) as value_count by _time src_ip

| search value_count > 10

[meta_rules\network\mr_net_firewall_susp_network_scan_by_port.yml]
search = action="denied" | table src_ip,dst_ip,dst_port | eval rule="fab0ddf0-b8a9-4d70-91ce-a20547209afb", title="Network Scans Count By Destination Port" | collect index=notable_events
description = Detects many failed connection attempts to different ports or hosts

| bin _time span=24h
| stats dc(dst_port) as value_count by _time src_ip

| search value_count > 10

[meta_rules\network\mr_net_possible_dns_rebinding.yml]
search = answer="*" ttl=">0" ttl="<10" | eval rule="ec5b8711-b550-4879-9660-568aaae2c3ea", title="Possible DNS Rebinding" | collect index=notable_events
description = Detects DNS-answer with TTL <10.

| bin _time span=30s
| stats dc(answer) as value_count by _time src_ip

| search value_count > 3

[meta_rules\other\mr_generic_brute_force.yml]
search = action="failure" | table src_ip,dst_ip,user | eval rule="53c7cca0-2901-493a-95db-d00d6fcf0a37", title="Brute Force" | collect index=notable_events
description = Detects many authentication failures from one source to one destination which is may indicate Brute Force activity

| bin _time span=600s
| stats dc(category) as value_count by _time dst_ip

| search value_count > 30

[meta_rules\other\mr_modsec_mulitple_blocks.yml]
search = "mod_security: Access denied" OR "ModSecurity: Access denied" OR "mod_security-message: Access denied" | eval rule="a06eea10-d932-4aa6-8ba9-186df72c8d23", title="Multiple Modsecurity Blocks" | collect index=notable_events
description = Detects multiple blocks by the mod_security module (Web Application Firewall)

| bin _time span=120m
| stats count as event_count by _time host

| search event_count > 6

[meta_rules\web\web_multiple_susp_resp_codes_single_source.yml]
search = "sc-status" IN (400, 401, 403, 500) | table client_ip,vhost,url,response | eval rule="6fdfc796-06b3-46e8-af08-58f3505318af", title="Multiple Suspicious Resp Codes Caused by Single Client" | collect index=notable_events
description = Detects possible exploitation activity or bugs in a web application

| bin _time span=10m
| stats count as event_count by _time clientip

| search event_count > 10

[meta_rules\zeek\zeek_dce_rpc_domain_user_enumeration.yml]
search = operation IN ("LsarLookupNames3", "LsarLookupSids3", "SamrGetGroupsForUser", "SamrLookupIdsInDomain", "SamrLookupNamesInDomain", "SamrQuerySecurityObject", "SamrQueryInformationGroup") | eval rule="66a0bdc6-ee04-441a-9125-99d2eb547942", title="Domain User Enumeration Network Recon 01" | collect index=notable_events
description = Domain user and group enumeration via network reconnaissance.
Seen in APT 29 and other common tactics and actors. Detects a set of RPC (remote procedure calls) used to enumerate a domain controller.
The rule was created based off the datasets and hackathon from https://github.com/OTRF/detection-hackathon-apt29


| bin _time span=30s
| stats dc(operation) as value_count by _time src_ip

| search value_count > 4
