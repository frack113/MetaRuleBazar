
[D:\rootme\github\MetaRuleBazar\meta_rules\cloud\mr_aws_ec2_download_userdata.yml]
search = eventSource="ec2.amazonaws.com" requestParameters.attribute="userData" eventName="DescribeInstanceAttribute"

| bin _time span=30m
| stats count as event_count by _time eventSource

| search event_count > 10 | eval rule="2c3c24a2-4240-4a5f-9f6f-2dea6f1fb174", title="Meta Rule AWS EC2 Download Userdata" | collect index=notable_events
description = None

[D:\rootme\github\MetaRuleBazar\meta_rules\cloud\mr_aws_enum_backup.yml]
search = eventSource="ec2.amazonaws.com" eventName IN ("GetPasswordData", "GetEbsEncryptionByDefault", "GetEbsDefaultKmsKeyId", "GetBucketReplication", "DescribeVolumes", "DescribeVolumesModifications", "DescribeSnapshotAttribute", "DescribeSnapshotTierStatus", "DescribeImages")

| bin _time span=10m
| stats count as event_count by _time eventSource

| search event_count > 5 | eval rule="1e74380d-27f2-4058-9b93-da7e8112153b", title="Meta Rule Potential Backup Enumeration on AWS" | collect index=notable_events
description = None

[D:\rootme\github\MetaRuleBazar\meta_rules\cloud\mr_aws_enum_listing.yml]
search = eventName="list*"

| bin _time span=10m
| stats count as event_count by _time eventSource

| search event_count > 50 | eval rule="74f013a7-3fd9-4687-a485-eb2daf630808", title="Meta Rule Account Enumeration on AWS" | collect index=notable_events
description = None

[D:\rootme\github\MetaRuleBazar\meta_rules\cloud\mr_aws_enum_network.yml]
search = eventSource="ec2.amazonaws.com" eventName IN ("DescribeCarrierGateways", "DescribeVpcEndpointConnectionNotifications", "DescribeTransitGatewayMulticastDomains", "DescribeClientVpnRoutes", "DescribeDhcpOptions", "GetTransitGatewayRouteTableAssociations")

| bin _time span=10m
| stats count as event_count by _time eventSource

| search event_count > 5 | eval rule="8d958c34-a187-4b87-869f-84ff260253bb", title="Meta Rule Potential Network Enumeration on AWS" | collect index=notable_events
description = None

[D:\rootme\github\MetaRuleBazar\meta_rules\cloud\mr_aws_enum_storage.yml]
search = eventSource="s3.amazonaws.com" eventName IN ("ListBuckets", "GetBucketCors", "GetBucketInventoryConfiguration", "GetBucketPublicAccessBlock", "GetBucketMetricsConfiguration", "GetBucketPolicy", "GetBucketTagging")

| bin _time span=10m
| stats count as event_count by _time eventSource

| search event_count > 5 | eval rule="d60929e7-7661-412c-bc77-aa3324686ab9", title="Meta Rule Potential Storage Enumeration on AWS" | collect index=notable_events
description = None

[D:\rootme\github\MetaRuleBazar\meta_rules\cloud\mr_aws_lambda_function_created_or_invoked.yml]
search = | multisearch
[ search eventSource="lambda.amazonaws.com" eventName="CreateFunction" | eval event_type="d914951b-52c8-485f-875e-86abab710c0b" ]
[ search eventSource="lambda.amazonaws.com" eventName="Invoke" | eval event_type="53baf6c8-e3a2-4769-8378-f20df75f550d" ]

| bin _time span=5m
| stats dc(event_type) as event_type_count by _time eventSource

| search event_type_count >= 2 | eval rule="345f61f8-caec-439b-a9d2-1684ca777ce2", title="Meta Rule Lamdba Fonction on AWS" | collect index=notable_events
description = None

[D:\rootme\github\MetaRuleBazar\meta_rules\cloud\mr_aws_macic_evasion.yml]
search = eventName IN ("ArchiveFindings", "CreateFindingsFilter", "DeleteMember", "DisassociateFromMasterAccount", "DisassociateMember", "DisableMacie", "DisableOrganizationAdminAccount", "UpdateFindingsFilter", "UpdateMacieSession", "UpdateMemberSession", "UpdateClassificationJob")

| bin _time span=10m
| stats count as event_count by _time sourceIPAddress

| search event_count > 5 | eval rule="72756b83-5f42-4fad-8703-08a885e32192", title="Meta Rule AWS Macie Evasion" | collect index=notable_events
description = None

[D:\rootme\github\MetaRuleBazar\meta_rules\cloud\mr_aws_ses_messaging_enabled.yml]
search = | multisearch
[ search eventSource="ses.amazonaws.com" eventName="UpdateAccountSendingEnabled" | eval event_type="60b84424-a724-4502-bd0d-cc676e1bc90e" ]
[ search eventSource="ses.amazonaws.com" eventName="VerifyEmailIdentity" | eval event_type="aa3e4183-c864-4bde-a46f-2bf178fd1080" ]

| bin _time span=5m
| stats dc(event_type) as event_type_count by _time eventSource

| search event_type_count >= 2 | eval rule="222ae290-4408-47b8-bc72-25858a03652d", title="Meta Rule Potential Cloud Email Service Abuse on AWS" | collect index=notable_events
description = None

[D:\rootme\github\MetaRuleBazar\meta_rules\cloud\mr_azure_aad_secops_signin_failure_bad_password_threshold.yml]
search = ResultType=50126 ResultDescription="Invalid username or password or Invalid on-premises username or password." NOT TargetUserName="*$"

| bin _time span=5m
| stats dc(TargetUserName) as value_count by _time IpAddress

| search value_count > 10 | eval rule="add3cec2-daf7-4d74-a63d-396ae40502d4", title="Meta Rule Sign-in Failure Bad Password Threshold" | collect index=notable_events
description = None

[D:\rootme\github\MetaRuleBazar\meta_rules\linux\mr_lnx_auditd_cve_2021_3156_sudo_buffer_overflow.yml]
search = type="EXECVE" a0="/usr/bin/sudoedit" a1="-s" OR a2="-s" OR a3="-s" OR a4="-s" a1="\\" OR a2="\\" OR a3="\\" OR a4="\\"

| bin _time span=24h
| stats count as event_count by _time host

| search event_count > 50 | eval rule="4088c559-180a-48ce-b85f-fc54c3a8181f", title="Meta Rule CVE-2021-3156 Exploitation Attempt" | collect index=notable_events
description = None

[D:\rootme\github\MetaRuleBazar\meta_rules\linux\mr_lnx_auditd_cve_2021_3156_sudo_buffer_overflow_brutforce.yml]
search = type="SYSCALL" exe="/usr/bin/sudoedit"

| bin _time span=24h
| stats count as event_count by _time host

| search event_count > 50 | eval rule="9fd5dd72-715d-4fd0-bb7a-28818e7de022", title="Meta Rule CVE-2021-3156 Exploitation Attempt Bruteforcing" | collect index=notable_events
description = None

[D:\rootme\github\MetaRuleBazar\meta_rules\linux\mr_lnx_auditd_cve_2021_4034.yml]
search = | multisearch
[ search type="PROCTITLE" proctitle="(null)" | eval event_type="40a016ab-4f48-4eee-adde-bbf612695c53" ]
[ search type="SYSCALL" comm="pkexec" exe="/usr/bin/pkexec" | eval event_type="3f4efb10-b8e0-4253-9cbb-32d4b2ef53d0" ]

| bin _time span=1m
| stats dc(event_type) as event_type_count by _time computer

| search event_type_count >= 2 | eval rule="32b49bfd-e524-4212-b58d-b9feb5e7fd87", title="Meta Rule Potential CVE-2021-4034 Exploitation Attempt" | collect index=notable_events
description = None

[D:\rootme\github\MetaRuleBazar\meta_rules\linux\mr_lnx_auditd_debugfs_usage.yml]
search = | multisearch
[ search type="EXECVE" a0="debugfs" | eval event_type="fb0647d7-371a-4553-8e20-33bbbe122956" ]
[ search type="EXECVE" a0 IN ("df", "lsblk", "pvs", "fdisk", "blkid", "parted", "hwinfo", "inxi") | eval event_type="e33e10c1-e376-4dc5-906b-f37c0814d96b" ]

| bin _time span=5m
| stats dc(event_type) as event_type_count by _time computer

| search event_type_count >= 2 | eval rule="61320051-cefa-4784-a413-89288a485470", title="Meta Rule Use of Debugfs to Access a Raw Disk" | collect index=notable_events
description = None

[D:\rootme\github\MetaRuleBazar\meta_rules\linux\mr_lnx_auth_susp_failed_logons_single_source.yml]
search = pam_message="authentication failure" pam_user="*" pam_rhost="*"

| bin _time span=24h
| stats dc(pam_user) as value_count by _time pam_rhost

| search value_count > 3 | eval rule="df21cf21-21c2-4adf-9039-9fdd954f7858", title="Meta Rule Failed Logins with Different Accounts from Single Source" | collect index=notable_events
description = None

[D:\rootme\github\MetaRuleBazar\meta_rules\linux\mr_lnx_shell_priv_esc_prep.yml]
search = "cat /etc/issue" OR "cat /etc/*-release" OR "cat /proc/version" OR "uname -a" OR "uname -mrs" OR "rpm -q kernel" OR "dmesg | grep Linux" OR "ls /boot | grep vmlinuz-" OR "cat /etc/profile" OR "cat /etc/bashrc" OR "cat ~/.bash_profile" OR "cat ~/.bashrc" OR "cat ~/.bash_logout" OR "ps -aux | grep root" OR "ps -ef | grep root" OR "crontab -l" OR "cat /etc/cron*" OR "cat /etc/cron.allow" OR "cat /etc/cron.deny" OR "cat /etc/crontab" OR "grep -i user *" OR "grep -i pass *" OR "ifconfig" OR "cat /etc/network/interfaces" OR "cat /etc/sysconfig/network" OR "cat /etc/resolv.conf" OR "cat /etc/networks" OR "iptables -L" OR "ip6tables -L" OR "lsof -i" OR "netstat -antup" OR "netstat -antpx" OR "netstat -tulpn" OR "arp -e" OR "route" OR "cat /etc/passwd" OR "cat /etc/group" OR "cat /etc/shadow" OR "find / -perm -u=s" OR "find / -perm -g=s" OR "find / -perm -4000" OR "find / -perm -2000" OR "find / -perm -o+w"

| bin _time span=30m
| stats count as event_count by _time host

| search event_count > 6 | eval rule="65d51929-d802-4902-8d19-eb43bf4c7581", title="Meta Rule Privilege Escalation Preparation" | collect index=notable_events
description = None

[D:\rootme\github\MetaRuleBazar\meta_rules\network\mr_net_dns_c2_detection.yml]
search = parent_domain="*"

| bin _time span=1h
| stats dc(dns_query) as value_count by _time parent_domain

| search value_count > 1000 | eval rule="7fab12cb-3e07-4596-a96d-eb678dccff54", title="Meta Rule Possible DNS Tunneling" | collect index=notable_events
description = None

[D:\rootme\github\MetaRuleBazar\meta_rules\network\mr_net_dns_high_null_records_requests_rate.yml]
search = record_type="NULL"

| bin _time span=1m
| stats count as event_count by _time src_ip

| search event_count > 50 | eval rule="a9c0ab1f-7dc1-4198-b050-15337f4ec7d8", title="Meta Rule High NULL Records Requests Rate" | collect index=notable_events
description = None

[D:\rootme\github\MetaRuleBazar\meta_rules\network\mr_net_dns_high_requests_rate.yml]
search = query="*"

| bin _time span=1m
| stats count as event_count by _time src_ip

| search event_count > 1000 | eval rule="76fb4ed0-fa1a-4bf3-ad34-75172866d52f", title="Meta Rule High DNS Requests Rate" | collect index=notable_events
description = None

[D:\rootme\github\MetaRuleBazar\meta_rules\network\mr_net_dns_high_txt_records_requests_rate.yml]
search = record_type="TXT"

| bin _time span=1m
| stats count as event_count by _time src_ip

| search event_count > 50 | eval rule="42816e16-d071-4e7f-8481-6ffdf6cae4c9", title="Meta Rule High TXT Records Requests Rate" | collect index=notable_events
description = None

[D:\rootme\github\MetaRuleBazar\meta_rules\network\mr_net_firewall_high_dns_requests_rate.yml]
search = dst_port=53

| bin _time span=1m
| stats count as event_count by _time src_ip

| search event_count > 1000 | eval rule="7380b975-7160-4a99-9a62-639371f5a9dd", title="Meta Rule High DNS Requests Rate - Firewall" | collect index=notable_events
description = None

[D:\rootme\github\MetaRuleBazar\meta_rules\network\mr_net_firewall_susp_network_scan_by_ip.yml]
search = action="denied"

| bin _time span=24h
| stats dc(dst_ip) as value_count by _time src_ip

| search value_count > 10 | eval rule="65ef9590-ef75-4e8b-900a-04eff5b0831e", title="Meta Rule Network Scans Count By Destination IP" | collect index=notable_events
description = None

[D:\rootme\github\MetaRuleBazar\meta_rules\network\mr_net_firewall_susp_network_scan_by_port.yml]
search = action="denied"

| bin _time span=24h
| stats dc(dst_port) as value_count by _time src_ip

| search value_count > 10 | eval rule="38d8bd04-a0a8-4002-bdae-8a8539cd5c09", title="Meta Rule Network Scans Count By Destination Port" | collect index=notable_events
description = None

[D:\rootme\github\MetaRuleBazar\meta_rules\network\mr_net_possible_dns_rebinding.yml]
search = answer="*" ttl>0 ttl<10

| bin _time span=30s
| stats dc(answer) as value_count by _time src_ip

| search value_count > 3 | eval rule="462970e8-77a2-449b-8af8-8395d5274c87", title="Meta Rule Possible DNS Rebinding" | collect index=notable_events
description = None

[D:\rootme\github\MetaRuleBazar\meta_rules\other\mr_generic_brute_force.yml]
search = action="failure"

| bin _time span=600s
| stats dc(category) as value_count by _time dst_ip

| search value_count > 30 | eval rule="ef911a55-7e8b-4f9a-b655-9c05bbc97ee1", title="MEta Rule Brute Force" | collect index=notable_events
description = Detects many authentication failures from one source to one destination which is may indicate Brute Force activity

[D:\rootme\github\MetaRuleBazar\meta_rules\other\mr_modsec_mulitple_blocks.yml]
search = "mod_security: Access denied" OR "ModSecurity: Access denied" OR "mod_security-message: Access denied"

| bin _time span=120m
| stats count as event_count by _time host

| search event_count > 6 | eval rule="8eaa06e6-00e8-41dc-9124-2efa5ead57df", title="Meta Rule Multiple Modsecurity Blocks" | collect index=notable_events
description = None

[D:\rootme\github\MetaRuleBazar\meta_rules\web\web_multiple_susp_resp_codes_single_source.yml]
search = "sc-status" IN (400, 401, 403, 500)

| bin _time span=10m
| stats count as event_count by _time clientip

| search event_count > 10 | eval rule="5d8f4722-3396-4612-b62f-9d16603fb97d", title="Meta Rule Multiple Suspicious Resp Codes Caused by Single Client" | collect index=notable_events
description = None

[D:\rootme\github\MetaRuleBazar\meta_rules\windows\mr_dns_query_win_possible_dns_rebinding.yml]
search = QueryName="*" QueryStatus="0" QueryResults IN ("(::ffff:)*10.*", "(::ffff:)*192.168.*", "(::ffff:)*172.16.*", "(::ffff:)*172.17.*", "(::ffff:)*172.18.*", "(::ffff:)*172.19.*", "(::ffff:)*172.20.*", "(::ffff:)*172.21.*", "(::ffff:)*172.22.*", "(::ffff:)*172.23.*", "(::ffff:)*172.24.*", "(::ffff:)*172.25.*", "(::ffff:)*172.26.*", "(::ffff:)*172.27.*", "(::ffff:)*172.28.*", "(::ffff:)*172.29.*", "(::ffff:)*172.30.*", "(::ffff:)*172.31.*", "(::ffff:)*127.*") QueryName="*" QueryStatus="0" NOT (QueryResults IN ("(::ffff:)*10.*", "(::ffff:)*192.168.*", "(::ffff:)*172.16.*", "(::ffff:)*172.17.*", "(::ffff:)*172.18.*", "(::ffff:)*172.19.*", "(::ffff:)*172.20.*", "(::ffff:)*172.21.*", "(::ffff:)*172.22.*", "(::ffff:)*172.23.*", "(::ffff:)*172.24.*", "(::ffff:)*172.25.*", "(::ffff:)*172.26.*", "(::ffff:)*172.27.*", "(::ffff:)*172.28.*", "(::ffff:)*172.29.*", "(::ffff:)*172.30.*", "(::ffff:)*172.31.*", "(::ffff:)*127.*"))

| bin _time span=30s
| stats dc(QueryName) as value_count by _time ComputerName

| search value_count > 3 | eval rule="6e121909-1ac3-4d66-8471-3445b718542d", title="Meta Rule Possible DNS Rebinding" | collect index=notable_events
description = None

[D:\rootme\github\MetaRuleBazar\meta_rules\windows\mr_posh_ps_cl_invocation_lolscript_count.yml]
search = ScriptBlockText IN ("*CL_Invocation.ps1*", "*SyncInvoke*")

| bin _time span=1m
| stats dc(ScriptBlockText) as value_count by _time Computer

| search value_count > 2 | eval rule="43596a51-af68-47a7-a739-0ac47f6f13b5", title="Meta Rule Execution via CL_Invocation.ps1 (2 Lines)" | collect index=notable_events
description = None

[D:\rootme\github\MetaRuleBazar\meta_rules\windows\mr_posh_ps_cl_mutexverifiers_lolscript_count.yml]
search = ScriptBlockText IN ("*CL_Mutexverifiers.ps1*", "*runAfterCancelProcess*")

| bin _time span=10m
| stats dc(ScriptBlockText) as value_count by _time Computer

| search value_count > 2 | eval rule="392cd8a5-b0f2-4387-86c2-85026cfea12d", title="Meta Rule Execution via CL_Mutexverifiers.ps1 (2 Lines)" | collect index=notable_events
description = None

[D:\rootme\github\MetaRuleBazar\meta_rules\windows\mr_proc_creation_win_correlation_apt_silence_downloader_v3.yml]
search = | multisearch
[ search Image IN ("*\\tasklist.exe", "*\\qwinsta.exe", "*\\ipconfig.exe", "*\\hostname.exe") CommandLine="*>>*" CommandLine="*temps.dat" | eval event_type="170901d1-de11-4de7-bccb-8fa13678d857" ]
[ search CommandLine="*/C REG ADD \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"WinNetworkSecurity\" /t REG_SZ /d*" | eval event_type="0af723a1-0222-4427-a07d-3be9bb8d12d7" ]

| bin _time span=5m
| stats dc(event_type) as event_type_count by _time computer

| search event_type_count >= 2 | eval rule="8a657050-cd0c-435e-a1bd-cfa557665b4d", title="Meta Rule APT29 Google Update Service Install" | collect index=notable_events
description = None

[D:\rootme\github\MetaRuleBazar\meta_rules\windows\mr_proc_creation_win_correlation_apt_turla_commands_medium.yml]
search = | multisearch
[ search CommandLine="net view /DOMAIN" | eval event_type="75925535-ca97-4e0a-a850-00b5c00779dc" ]
[ search CommandLine="net session" | eval event_type="ad03ed33-9323-41f4-be14-1827cd645a77" ]
[ search CommandLine="net share" | eval event_type="73c3b7a0-d45e-4f48-875c-71114564a1a0" ]

| bin _time span=1m
| stats dc(event_type) as event_type_count by _time computer

| search event_type_count >= 3 | eval rule="2a4afc99-f7f4-4413-9b4f-5140025d63aa", title="Meta Rule Automated Turla Group Lateral Movement" | collect index=notable_events
description = None

[D:\rootme\github\MetaRuleBazar\meta_rules\windows\mr_proc_creation_win_correlation_dnscat2_powershell_implementation.yml]
search = ParentImage IN ("*\\powershell.exe", "*\\pwsh.exe") Image="*\\nslookup.exe" CommandLine="*\\nslookup.exe"

| bin _time span=1h
| stats dc(Image) as value_count by _time ParentImage

| search value_count > 100 | eval rule="3349fd2a-5738-4217-8eaf-24482568b612", title="Meta Rule DNSCat2 Powershell Implementation Detection Via Process Creation" | collect index=notable_events
description = None

[D:\rootme\github\MetaRuleBazar\meta_rules\windows\mr_proc_creation_win_correlation_multiple_susp_cli.yml]
search = CommandLine IN ("*arp.exe*", "*at.exe*", "*attrib.exe*", "*cscript.exe*", "*dsquery.exe*", "*hostname.exe*", "*ipconfig.exe*", "*mimikatz.exe*", "*nbtstat.exe*", "*net.exe*", "*netsh.exe*", "*nslookup.exe*", "*ping.exe*", "*quser.exe*", "*qwinsta.exe*", "*reg.exe*", "*runas.exe*", "*sc.exe*", "*schtasks.exe*", "*ssh.exe*", "*systeminfo.exe*", "*taskkill.exe*", "*telnet.exe*", "*tracert.exe*", "*wscript.exe*", "*xcopy.exe*", "*pscp.exe*", "*copy.exe*", "*robocopy.exe*", "*certutil.exe*", "*vssadmin.exe*", "*powershell.exe*", "*pwsh.exe*", "*wevtutil.exe*", "*psexec.exe*", "*bcedit.exe*", "*wbadmin.exe*", "*icacls.exe*", "*diskpart.exe*")

| bin _time span=5m
| stats count as event_count by _time MachineName

| search event_count > 5 | eval rule="f4532314-38eb-4b90-8f5f-ee832f4d6680", title="Meta Rule Quick Execution of a Series of Suspicious Commands" | collect index=notable_events
description = None

[D:\rootme\github\MetaRuleBazar\meta_rules\windows\mr_proc_creation_win_correlation_susp_builtin_commands_recon.yml]
search = CommandLine IN ("tasklist", "net time", "systeminfo", "whoami", "nbtstat", "net start", "qprocess", "nslookup", "hostname.exe", "netstat -an") OR CommandLine IN ("*\\net1 start", "*\\net1 user /domain", "*\\net1 group /domain", "*\\net1 group \"domain admins\" /domain", "*\\net1 group \"Exchange Trusted Subsystem\" /domain", "*\\net1 accounts /domain", "*\\net1 user net localgroup administrators")

| bin _time span=15s
| stats count as event_count by _time CommandLine

| search event_count > 4 | eval rule="e143e657-98c2-4c6b-9962-594c201c5daf", title="Meta Rule  Reconnaissance Activity Using BuiltIn Commands" | collect index=notable_events
description = None

[D:\rootme\github\MetaRuleBazar\meta_rules\windows\mr_win_apt_apt29_tor.yml]
search = | multisearch
[ search EventID=7045 Provider_Name="Service Control Manager" ServiceName="Google Update" | eval event_type="aac6bade-ac91-40b6-9336-4b79f4df7c97" ]
[ search Image IN ("C:\\Program Files(x86)\\Google\\GoogleService.exe", "C:\\Program Files(x86)\\Google\\GoogleUpdate.exe") | eval event_type="c069f460-2b87-4010-8dcf-e45bab362624" ]

| bin _time span=5m
| stats dc(event_type) as event_type_count by _time computer

| search event_type_count >= 2 | eval rule="a9dfdda6-5dc0-4778-86a4-3ad028d18280", title="Meta Rule APT29 Google Update Service Install" | collect index=notable_events
description = None

[D:\rootme\github\MetaRuleBazar\meta_rules\windows\mr_win_security_global_catalog_enumeration.yml]
search = EventID=5156 DestPort IN (3268, 3269)

| bin _time span=1h
| stats count as event_count by _time SourceAddress

| search event_count > 2000 | eval rule="773c0f44-fc23-4310-8902-036e3950369d", title="Meta Rule Enumeration via the Global Catalog" | collect index=notable_events
description = None

[D:\rootme\github\MetaRuleBazar\meta_rules\windows\mr_win_security_rare_schtasks_creations.yml]
search = EventID=4698

| bin _time span=7d
| stats count as event_count by _time TaskName

| search event_count < 5 | eval rule="6b33b33f-857d-4359-8f2f-64502d22ba84", title="Meta Rule Rare Schtasks Creations" | collect index=notable_events
description = None

[D:\rootme\github\MetaRuleBazar\meta_rules\windows\mr_win_security_susp_failed_logons_explicit_credentials.yml]
search = EventID=4648 NOT SubjectUserName="*$"

| bin _time span=1h
| stats dc(TargetUserName) as value_count by _time SubjectUserName

| search value_count > 10 | eval rule="f76f8fa4-8aa7-4b4b-859a-ae884eea5c72", title="Meta Rule Password Spraying via Explicit Credentials" | collect index=notable_events
description = None

[D:\rootme\github\MetaRuleBazar\meta_rules\windows\mr_win_security_susp_failed_logons_single_process.yml]
search = EventID=4625 LogonType=2 NOT ProcessName="-"

| bin _time span=24h
| stats dc(TargetUserName) as value_count by _time ProcessName

| search value_count > 10 | eval rule="5662a1ba-a9e9-45b8-a772-4636295c9946", title="Meta Rule Multiple Users Failing to Authenticate from Single Process" | collect index=notable_events
description = None

[D:\rootme\github\MetaRuleBazar\meta_rules\windows\mr_win_security_susp_failed_logons_single_source.yml]
search = EventID IN (529, 4625) TargetUserName="*" WorkstationName="*"

| bin _time span=24h
| stats dc(TargetUserName) as value_count by _time WorkstationName

| search value_count > 3 | eval rule="f45bebfe-41ba-4c1f-8376-2d6a8f432708", title="Meta Rule Multiple Users Remotely Failing To Authenticate From Single Source" | collect index=notable_events
description = None

[D:\rootme\github\MetaRuleBazar\meta_rules\windows\mr_win_security_susp_failed_logons_single_source2.yml]
search = EventID=4776 TargetUserName="*" Workstation="*"

| bin _time span=24h
| stats dc(TargetUserName) as value_count by _time "Workstation - Workstation"

| search value_count > 10 | eval rule="43f33316-eaaa-4752-8a78-14100ec3570e", title="Meta Rule Failed NTLM Logins with Different Accounts from Single Source System" | collect index=notable_events
description = None

[D:\rootme\github\MetaRuleBazar\meta_rules\windows\mr_win_security_susp_failed_logons_single_source_kerberos.yml]
search = EventID=4771 Status="0x18" NOT TargetUserName="*$"

| bin _time span=24h
| stats dc(TargetUserName) as value_count by _time IpAddress

| search value_count > 10 | eval rule="9b7bfab4-e663-40fd-8d5b-b24a59a43048", title="Meta Rule Valid Users Failing to Authenticate From Single Source Using Kerberos" | collect index=notable_events
description = None

[D:\rootme\github\MetaRuleBazar\meta_rules\windows\mr_win_security_susp_failed_logons_single_source_kerberos2.yml]
search = EventID=4768 Status="0x12" NOT TargetUserName="*$"

| bin _time span=24h
| stats dc(TargetUserName) as value_count by _time IpAddress

| search value_count > 10 | eval rule="2bdc3f90-f3e8-43ca-8a8b-ee49c5eceb3c", title="Meta Rule Disabled Users Failing To Authenticate From Source Using Kerberos" | collect index=notable_events
description = None

[D:\rootme\github\MetaRuleBazar\meta_rules\windows\mr_win_security_susp_failed_logons_single_source_kerberos3.yml]
search = EventID=4768 Status="0x6" NOT TargetUserName="*$"

| bin _time span=24h
| stats dc(TargetUserName) as value_count by _time IpAddress

| search value_count > 10 | eval rule="afc224b1-17a3-4cae-8797-72d39d84eb7f", title="Meta Rule Invalid Users Failing To Authenticate From Source Using Kerberos" | collect index=notable_events
description = None

[D:\rootme\github\MetaRuleBazar\meta_rules\windows\mr_win_security_susp_failed_logons_single_source_ntlm.yml]
search = EventID=4776 Status="*0xC000006A" NOT TargetUserName="*$"

| bin _time span=24h
| stats dc(TargetUserName) as value_count by _time Workstation

| search value_count > 10 | eval rule="6e21204b-430f-4494-a7cf-37c87a2219ed", title="Meta Rule Valid Users Failing to Authenticate from Single Source Using NTLM" | collect index=notable_events
description = None

[D:\rootme\github\MetaRuleBazar\meta_rules\windows\mr_win_security_susp_failed_logons_single_source_ntlm2.yml]
search = EventID=4776 Status="*0xC0000064" NOT TargetUserName="*$"

| bin _time span=24h
| stats dc(TargetUserName) as value_count by _time Workstation

| search value_count > 10 | eval rule="0da075e6-88e7-4e37-8834-c418f8ebb642", title="Meta Rule Invalid Users Failing To Authenticate From Single Source Using NTLM" | collect index=notable_events
description = None

[D:\rootme\github\MetaRuleBazar\meta_rules\windows\mr_win_security_susp_failed_remote_logons_single_source.yml]
search = EventID=4625 LogonType=3 NOT IpAddress="-"

| bin _time span=24h
| stats dc(TargetUserName) as value_count by _time IpAddress

| search value_count > 10 | eval rule="d8cb0e79-61c6-41e5-a95e-d9e65b3a09ee", title="Meta Rule Multiple Users Remotely Failing To Authenticate From Single Source" | collect index=notable_events
description = None

[D:\rootme\github\MetaRuleBazar\meta_rules\windows\mr_win_security_susp_multiple_files_renamed_or_deleted.yml]
search = EventID=4663 ObjectType="File" AccessList="%%1537" Keywords="0x8020000000000000"

| bin _time span=30s
| stats count as event_count by _time SubjectLogonId

| search event_count > 10 | eval rule="2a11af6d-a41a-46fb-9e13-b3e265aaaf55", title="Meta Rule Suspicious Multiple File Rename Or Delete Occurred" | collect index=notable_events
description = None

[D:\rootme\github\MetaRuleBazar\meta_rules\windows\mr_win_security_susp_samr_pwset.yml]
search = | multisearch
[ search EventID=4738 NOT PasswordLastSet!=* | eval event_type="7818b381-5eb1-4641-bea5-ef9e4cfb5951" ]
[ search EventID=5145 RelativeTargetName="samr" | eval event_type="1b432ca1-3604-404b-9029-35c81975f6c6" ]

| bin _time span=15s
| stats dc(event_type) as event_type_count by _time computer

| search event_type_count >= 2 | eval rule="f136a764-c7af-437c-9a18-82091aa62bb1", title="Meta Rule Possible Remote Password Change Through SAMR" | collect index=notable_events
description = None

[D:\rootme\github\MetaRuleBazar\meta_rules\windows\mr_win_susp_failed_hidden_share_mount.yml]
search = EventID=31010 ShareName="*$"

| bin _time span=1m
| stats count as event_count by _time Computer

| search event_count > 10 | eval rule="7b620ec9-b171-4094-912c-e6c04ceeea7f", title="Meta Rule Failed Mounting of Hidden Share" | collect index=notable_events
description = None

[D:\rootme\github\MetaRuleBazar\meta_rules\windows\mr_win_system_rare_service_installs.yml]
search = Provider_Name="Service Control Manager" EventID=7045

| bin _time span=7d
| stats count as event_count by _time ServiceName

| search event_count > 5 | eval rule="8aefbbd8-5361-402b-a87c-69a6c4adf794", title="Meta Rule Rare Service Installations" | collect index=notable_events
description = None

[D:\rootme\github\MetaRuleBazar\meta_rules\windows\mr_win_taskscheduler_rare_schtask_creation.yml]
search = EventID=106 NOT TaskName="\\Microsoft\\Windows\\Windows Defender\\Windows Defender Scheduled Scan"

| bin _time span=7d
| stats count as event_count by _time TaskName

| search event_count > 5 | eval rule="322b4512-1ee1-4d3a-991a-6621353f70bf", title="Meta Rule Rare Scheduled Task Creations" | collect index=notable_events
description = None

[D:\rootme\github\MetaRuleBazar\meta_rules\zeek\zeek_dce_rpc_domain_user_enumeration.yml]
search = operation IN ("LsarLookupNames3", "LsarLookupSids3", "SamrGetGroupsForUser", "SamrLookupIdsInDomain", "SamrLookupNamesInDomain", "SamrQuerySecurityObject", "SamrQueryInformationGroup")

| bin _time span=30s
| stats dc(operation) as value_count by _time src_ip

| search value_count > 4 | eval rule="b0813dd8-ce7a-4d2e-8072-b029f2880e19", title="Meta Rule Domain User Enumeration Network Recon 01" | collect index=notable_events
description = None
