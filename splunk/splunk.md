
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

[meta_rules\windows\mr_dns_query_win_possible_dns_rebinding.yml]
search = QueryName="*" QueryStatus="0" QueryResults IN ("(::ffff:)*10.*", "(::ffff:)*192.168.*", "(::ffff:)*172.16.*", "(::ffff:)*172.17.*", "(::ffff:)*172.18.*", "(::ffff:)*172.19.*", "(::ffff:)*172.20.*", "(::ffff:)*172.21.*", "(::ffff:)*172.22.*", "(::ffff:)*172.23.*", "(::ffff:)*172.24.*", "(::ffff:)*172.25.*", "(::ffff:)*172.26.*", "(::ffff:)*172.27.*", "(::ffff:)*172.28.*", "(::ffff:)*172.29.*", "(::ffff:)*172.30.*", "(::ffff:)*172.31.*", "(::ffff:)*127.*") QueryName="*" QueryStatus="0" NOT (QueryResults IN ("(::ffff:)*10.*", "(::ffff:)*192.168.*", "(::ffff:)*172.16.*", "(::ffff:)*172.17.*", "(::ffff:)*172.18.*", "(::ffff:)*172.19.*", "(::ffff:)*172.20.*", "(::ffff:)*172.21.*", "(::ffff:)*172.22.*", "(::ffff:)*172.23.*", "(::ffff:)*172.24.*", "(::ffff:)*172.25.*", "(::ffff:)*172.26.*", "(::ffff:)*172.27.*", "(::ffff:)*172.28.*", "(::ffff:)*172.29.*", "(::ffff:)*172.30.*", "(::ffff:)*172.31.*", "(::ffff:)*127.*")) | eval rule="eb07e747-2552-44cd-af36-b659ae0958e4", title="Possible DNS Rebinding" | collect index=notable_events
description = Detects several different DNS-answers by one domain with IPs from internal and external networks. Normally, DNS-answer contain TTL >100. (DNS-record will saved in host cache for a while TTL).

| bin _time span=30s
| stats dc(QueryName) as value_count by _time ComputerName

| search value_count > 3

[meta_rules\windows\mr_posh_ps_cl_invocation_lolscript_count.yml]
search = ScriptBlockText IN ("*CL_Invocation.ps1*", "*SyncInvoke*") | eval rule="f588e69b-0750-46bb-8f87-0e9320d57536", title="Execution via CL_Invocation.ps1 (2 Lines)" | collect index=notable_events
description = Detects Execution via SyncInvoke in CL_Invocation.ps1 module

| bin _time span=1m
| stats dc(ScriptBlockText) as value_count by _time Computer

| search value_count > 2

[meta_rules\windows\mr_posh_ps_cl_mutexverifiers_lolscript_count.yml]
search = ScriptBlockText IN ("*CL_Mutexverifiers.ps1*", "*runAfterCancelProcess*") | eval rule="6609c444-9670-4eab-9636-fe4755a851ce", title="Execution via CL_Mutexverifiers.ps1 (2 Lines)" | collect index=notable_events
description = Detects Execution via runAfterCancelProcess in CL_Mutexverifiers.ps1 module

| bin _time span=10m
| stats dc(ScriptBlockText) as value_count by _time Computer

| search value_count > 2
| multisearch
[ search 
[meta_rules\windows\mr_proc_creation_win_correlation_apt_silence_downloader_v3.yml]
search = Image IN ("*\\tasklist.exe", "*\\qwinsta.exe", "*\\ipconfig.exe", "*\\hostname.exe") CommandLine="*>>*" CommandLine="*temps.dat" | table ComputerName,User,Image,CommandLine | eval rule="170901d1-de11-4de7-bccb-8fa13678d857", title="Silence.Downloader V3" | collect index=notable_events
description = Detects Silence downloader. These commands are hardcoded into the binary. | eval event_type="170901d1-de11-4de7-bccb-8fa13678d857" ]
[ search 
[meta_rules\windows\mr_proc_creation_win_correlation_apt_silence_downloader_v3.yml]
search = CommandLine="*/C REG ADD \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"WinNetworkSecurity\" /t REG_SZ /d*" | table ComputerName,User,Image,CommandLine | eval rule="0af723a1-0222-4427-a07d-3be9bb8d12d7", title="Silence.Downloader V3" | collect index=notable_events
description = Detects Silence downloader. These commands are hardcoded into the binary. | eval event_type="0af723a1-0222-4427-a07d-3be9bb8d12d7" ]

| bin _time span=5m
| stats dc(event_type) as event_type_count by _time computer

| search event_type_count >= 2
| multisearch
[ search 
[meta_rules\windows\mr_proc_creation_win_correlation_apt_turla_commands_medium.yml]
search = CommandLine="net view /DOMAIN" | eval rule="75925535-ca97-4e0a-a850-00b5c00779dc", title="Automated Turla Group Lateral Movement" | collect index=notable_events
description = Detects automated lateral movement by Turla group | eval event_type="75925535-ca97-4e0a-a850-00b5c00779dc" ]
[ search 
[meta_rules\windows\mr_proc_creation_win_correlation_apt_turla_commands_medium.yml]
search = CommandLine="net session" | eval rule="ad03ed33-9323-41f4-be14-1827cd645a77", title="Automated Turla Group Lateral Movement" | collect index=notable_events
description = Detects automated lateral movement by Turla group | eval event_type="ad03ed33-9323-41f4-be14-1827cd645a77" ]
[ search 
[meta_rules\windows\mr_proc_creation_win_correlation_apt_turla_commands_medium.yml]
search = CommandLine="net share" | eval rule="73c3b7a0-d45e-4f48-875c-71114564a1a0", title="Automated Turla Group Lateral Movement" | collect index=notable_events
description = Detects automated lateral movement by Turla group | eval event_type="73c3b7a0-d45e-4f48-875c-71114564a1a0" ]

| bin _time span=1m
| stats dc(event_type) as event_type_count by _time computer

| search event_type_count >= 3

[meta_rules\windows\mr_proc_creation_win_correlation_dnscat2_powershell_implementation.yml]
search = ParentImage IN ("*\\powershell.exe", "*\\pwsh.exe") Image="*\\nslookup.exe" CommandLine="*\\nslookup.exe" | table Image,CommandLine,ParentImage | eval rule="b11d75d6-d7c1-11ea-87d0-0242ac130003", title="DNSCat2 Powershell Implementation Detection Via Process Creation" | collect index=notable_events
description = The PowerShell implementation of DNSCat2 calls nslookup to craft queries. Counting nslookup processes spawned by PowerShell will show hundreds or thousands of instances if PS DNSCat2 is active locally.

| bin _time span=1h
| stats dc(Image) as value_count by _time ParentImage

| search value_count > 100

[meta_rules\windows\mr_proc_creation_win_correlation_multiple_susp_cli.yml]
search = CommandLine IN ("*arp.exe*", "*at.exe*", "*attrib.exe*", "*cscript.exe*", "*dsquery.exe*", "*hostname.exe*", "*ipconfig.exe*", "*mimikatz.exe*", "*nbtstat.exe*", "*net.exe*", "*netsh.exe*", "*nslookup.exe*", "*ping.exe*", "*quser.exe*", "*qwinsta.exe*", "*reg.exe*", "*runas.exe*", "*sc.exe*", "*schtasks.exe*", "*ssh.exe*", "*systeminfo.exe*", "*taskkill.exe*", "*telnet.exe*", "*tracert.exe*", "*wscript.exe*", "*xcopy.exe*", "*pscp.exe*", "*copy.exe*", "*robocopy.exe*", "*certutil.exe*", "*vssadmin.exe*", "*powershell.exe*", "*pwsh.exe*", "*wevtutil.exe*", "*psexec.exe*", "*bcedit.exe*", "*wbadmin.exe*", "*icacls.exe*", "*diskpart.exe*") | eval rule="61ab5496-748e-4818-a92f-de78e20fe7f1", title="Quick Execution of a Series of Suspicious Commands" | collect index=notable_events
description = Detects multiple suspicious process in a limited timeframe

| bin _time span=5m
| stats count as event_count by _time MachineName

| search event_count > 5

[meta_rules\windows\mr_proc_creation_win_correlation_susp_builtin_commands_recon.yml]
search = CommandLine IN ("tasklist", "net time", "systeminfo", "whoami", "nbtstat", "net start", "qprocess", "nslookup", "hostname.exe", "netstat -an") OR CommandLine IN ("*\\net1 start", "*\\net1 user /domain", "*\\net1 group /domain", "*\\net1 group \"domain admins\" /domain", "*\\net1 group \"Exchange Trusted Subsystem\" /domain", "*\\net1 accounts /domain", "*\\net1 user net localgroup administrators") | eval rule="2887e914-ce96-435f-8105-593937e90757", title="Reconnaissance Activity Using BuiltIn Commands" | collect index=notable_events
description = Detects execution of a set of builtin commands often used in recon stages by different attack groups

| bin _time span=15s
| stats count as event_count by _time CommandLine

| search event_count > 4
| multisearch
[ search 
[meta_rules\windows\mr_win_apt_apt29_tor.yml]
search = EventID=7045 Provider_Name="Service Control Manager" ServiceName="Google Update" | eval rule="aac6bade-ac91-40b6-9336-4b79f4df7c97", title="APT29 Google Update Service Install" | collect index=notable_events
description = This method detects malicious services mentioned in APT29 report by FireEye. The legitimate path for the Google update service is C:\Program Files (x86)\Google\Update\GoogleUpdate.exe so the service names and executable locations used by APT29 are specific enough to be detected in log files. | eval event_type="aac6bade-ac91-40b6-9336-4b79f4df7c97" ]
[ search 
[meta_rules\windows\mr_win_apt_apt29_tor.yml]
search = Image IN ("C:\\Program Files(x86)\\Google\\GoogleService.exe", "C:\\Program Files(x86)\\Google\\GoogleUpdate.exe") | table ComputerName,User,CommandLine | eval rule="c069f460-2b87-4010-8dcf-e45bab362624", title="APT29 Google Update Service Install" | collect index=notable_events
description = None | eval event_type="c069f460-2b87-4010-8dcf-e45bab362624" ]

| bin _time span=5m
| stats dc(event_type) as event_type_count by _time computer

| search event_type_count >= 2

[meta_rules\windows\mr_win_security_global_catalog_enumeration.yml]
search = EventID=5156 DestPort IN (3268, 3269) | eval rule="619b020f-0fd7-4f23-87db-3f51ef837a34", title="Enumeration via the Global Catalog" | collect index=notable_events
description = Detects enumeration of the global catalog (that can be performed using BloodHound or others AD reconnaissance tools). Adjust Threshold according to domain width.

| bin _time span=1h
| stats count as event_count by _time SourceAddress

| search event_count > 2000

[meta_rules\windows\mr_win_security_rare_schtasks_creations.yml]
search = EventID=4698 | eval rule="b0d77106-7bb0-41fe-bd94-d1752164d066", title="Rare Schtasks Creations" | collect index=notable_events
description = Detects rare scheduled tasks creations that only appear a few times per time frame and could reveal password dumpers, backdoor installs or other types of malicious code

| bin _time span=7d
| stats count as event_count by _time TaskName

| search event_count < 5

[meta_rules\windows\mr_win_security_susp_failed_logons_explicit_credentials.yml]
search = EventID=4648 NOT SubjectUserName="*$" | eval rule="196a29c2-e378-48d8-ba07-8a9e61f7fab9", title="Password Spraying via Explicit Credentials" | collect index=notable_events
description = Detects a single user failing to authenticate to multiple users using explicit credentials.

| bin _time span=1h
| stats dc(TargetUserName) as value_count by _time SubjectUserName

| search value_count > 10

[meta_rules\windows\mr_win_security_susp_failed_logons_single_process.yml]
search = EventID=4625 LogonType=2 NOT ProcessName="-" | eval rule="fe563ab6-ded4-4916-b49f-a3a8445fe280", title="Multiple Users Failing to Authenticate from Single Process" | collect index=notable_events
description = Detects failed logins with multiple accounts from a single process on the system.

| bin _time span=24h
| stats dc(TargetUserName) as value_count by _time ProcessName

| search value_count > 10

[meta_rules\windows\mr_win_security_susp_failed_logons_single_source.yml]
search = EventID IN (529, 4625) TargetUserName="*" WorkstationName="*" | eval rule="e98374a6-e2d9-4076-9b5c-11bdb2569995", title="Failed Logins with Different Accounts from Single Source System" | collect index=notable_events
description = Detects suspicious failed logins with different user accounts from a single source system

| bin _time span=24h
| stats dc(TargetUserName) as value_count by _time WorkstationName

| search value_count > 3

[meta_rules\windows\mr_win_security_susp_failed_logons_single_source2.yml]
search = EventID=4776 TargetUserName="*" Workstation="*" | eval rule="6309ffc4-8fa2-47cf-96b8-a2f72e58e538", title="Failed NTLM Logins with Different Accounts from Single Source System" | collect index=notable_events
description = Detects suspicious failed logins with different user accounts from a single source system

| bin _time span=24h
| stats dc(TargetUserName) as value_count by _time "Workstation - Workstation"

| search value_count > 10

[meta_rules\windows\mr_win_security_susp_failed_logons_single_source_kerberos.yml]
search = EventID=4771 Status="0x18" NOT TargetUserName="*$" | eval rule="5d1d946e-32e6-4d9a-a0dc-0ac022c7eb98", title="Valid Users Failing to Authenticate From Single Source Using Kerberos" | collect index=notable_events
description = Detects multiple failed logins with multiple valid domain accounts from a single source system using the Kerberos protocol.

| bin _time span=24h
| stats dc(TargetUserName) as value_count by _time IpAddress

| search value_count > 10

[meta_rules\windows\mr_win_security_susp_failed_logons_single_source_kerberos2.yml]
search = EventID=4768 Status="0x12" NOT TargetUserName="*$" | eval rule="4b6fe998-b69c-46d8-901b-13677c9fb663", title="Disabled Users Failing To Authenticate From Source Using Kerberos" | collect index=notable_events
description = Detects failed logins with multiple disabled domain accounts from a single source system using the Kerberos protocol.

| bin _time span=24h
| stats dc(TargetUserName) as value_count by _time IpAddress

| search value_count > 10

[meta_rules\windows\mr_win_security_susp_failed_logons_single_source_kerberos3.yml]
search = EventID=4768 Status="0x6" NOT TargetUserName="*$" | eval rule="bc93dfe6-8242-411e-a2dd-d16fa0cc8564", title="Invalid Users Failing To Authenticate From Source Using Kerberos" | collect index=notable_events
description = Detects failed logins with multiple invalid domain accounts from a single source system using the Kerberos protocol.

| bin _time span=24h
| stats dc(TargetUserName) as value_count by _time IpAddress

| search value_count > 10

[meta_rules\windows\mr_win_security_susp_failed_logons_single_source_ntlm.yml]
search = EventID=4776 Status="*0xC000006A" NOT TargetUserName="*$" | eval rule="f88bab7f-b1f4-41bb-bdb1-4b8af35b0470", title="Valid Users Failing to Authenticate from Single Source Using NTLM" | collect index=notable_events
description = Detects failed logins with multiple valid domain accounts from a single source system using the NTLM protocol.

| bin _time span=24h
| stats dc(TargetUserName) as value_count by _time Workstation

| search value_count > 10

[meta_rules\windows\mr_win_security_susp_failed_logons_single_source_ntlm2.yml]
search = EventID=4776 Status="*0xC0000064" NOT TargetUserName="*$" | eval rule="56d62ef8-3462-4890-9859-7b41e541f8d5", title="Invalid Users Failing To Authenticate From Single Source Using NTLM" | collect index=notable_events
description = Detects failed logins with multiple invalid domain accounts from a single source system using the NTLM protocol.

| bin _time span=24h
| stats dc(TargetUserName) as value_count by _time Workstation

| search value_count > 10

[meta_rules\windows\mr_win_security_susp_failed_remote_logons_single_source.yml]
search = EventID=4625 LogonType=3 NOT IpAddress="-" | eval rule="add2ef8d-dc91-4002-9e7e-f2702369f53a", title="Multiple Users Remotely Failing To Authenticate From Single Source" | collect index=notable_events
description = Detects a source system failing to authenticate against a remote host with multiple users.

| bin _time span=24h
| stats dc(TargetUserName) as value_count by _time IpAddress

| search value_count > 10

[meta_rules\windows\mr_win_security_susp_multiple_files_renamed_or_deleted.yml]
search = EventID=4663 ObjectType="File" AccessList="%%1537" Keywords="0x8020000000000000" | eval rule="97919310-06a7-482c-9639-92b67ed63cf8", title="Suspicious Multiple File Rename Or Delete Occurred" | collect index=notable_events
description = Detects multiple file rename or delete events occurrence within a specified period of time by a same user (these events may signalize about ransomware activity).

| bin _time span=30s
| stats count as event_count by _time SubjectLogonId

| search event_count > 10
| multisearch
[ search 
[meta_rules\windows\mr_win_security_susp_samr_pwset.yml]
search = EventID=4738 NOT PasswordLastSet!=* | eval rule="7818b381-5eb1-4641-bea5-ef9e4cfb5951", title="Possible Remote Password Change Through SAMR" | collect index=notable_events
description = Detects a possible remote NTLM hash change through SAMR API SamiChangePasswordUser() or SamSetInformationUser().
"Audit User Account Management" in "Advanced Audit Policy Configuration" has to be enabled in your local security policy / GPO to see this events.
 | eval event_type="7818b381-5eb1-4641-bea5-ef9e4cfb5951" ]
[ search 
[meta_rules\windows\mr_win_security_susp_samr_pwset.yml]
search = EventID=5145 RelativeTargetName="samr" | eval rule="1b432ca1-3604-404b-9029-35c81975f6c6", title="Possible Remote Password Change Through SAMR" | collect index=notable_events
description = Detects a possible remote NTLM hash change through SAMR API SamiChangePasswordUser() or SamSetInformationUser().
"Audit User Account Management" in "Advanced Audit Policy Configuration" has to be enabled in your local security policy / GPO to see this events.
 | eval event_type="1b432ca1-3604-404b-9029-35c81975f6c6" ]

| bin _time span=15s
| stats dc(event_type) as event_type_count by _time computer

| search event_type_count >= 2

[meta_rules\windows\mr_win_susp_failed_hidden_share_mount.yml]
search = EventID=31010 ShareName="*$" | table ShareName | eval rule="1c3be8c5-6171-41d3-b792-cab6f717fcdb", title="Failed Mounting of Hidden Share" | collect index=notable_events
description = Detects repeated failed (outgoing) attempts to mount a hidden share

| bin _time span=1m
| stats count as event_count by _time Computer

| search event_count > 10

[meta_rules\windows\mr_win_system_rare_service_installs.yml]
search = Provider_Name="Service Control Manager" EventID=7045 | eval rule="66bfef30-22a5-4fcd-ad44-8d81e60922ae", title="Rare Service Installations" | collect index=notable_events
description = Detects rare service installs that only appear a few times per time frame and could reveal password dumpers, backdoor installs or other types of malicious services

| bin _time span=7d
| stats count as event_count by _time ServiceName

| search event_count > 5

[meta_rules\windows\mr_win_taskscheduler_rare_schtask_creation.yml]
search = EventID=106 NOT TaskName="\\Microsoft\\Windows\\Windows Defender\\Windows Defender Scheduled Scan" | eval rule="b20f6158-9438-41be-83da-a5a16ac90c2b", title="Rare Scheduled Task Creations" | collect index=notable_events
description = This rule detects rare scheduled task creations. Typically software gets installed on multiple systems and not only on a few. The aggregation and count function selects tasks with rare names.

| bin _time span=7d
| stats count as event_count by _time TaskName

| search event_count > 5

[meta_rules\zeek\zeek_dce_rpc_domain_user_enumeration.yml]
search = operation IN ("LsarLookupNames3", "LsarLookupSids3", "SamrGetGroupsForUser", "SamrLookupIdsInDomain", "SamrLookupNamesInDomain", "SamrQuerySecurityObject", "SamrQueryInformationGroup") | eval rule="66a0bdc6-ee04-441a-9125-99d2eb547942", title="Domain User Enumeration Network Recon 01" | collect index=notable_events
description = Domain user and group enumeration via network reconnaissance.
Seen in APT 29 and other common tactics and actors. Detects a set of RPC (remote procedure calls) used to enumerate a domain controller.
The rule was created based off the datasets and hackathon from https://github.com/OTRF/detection-hackathon-apt29


| bin _time span=30s
| stats dc(operation) as value_count by _time src_ip

| search value_count > 4
