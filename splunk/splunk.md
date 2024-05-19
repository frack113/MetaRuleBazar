[meta_rules\other\mr_generic_brute_force.yml]

search = action="failure" | table src_ip,dst_ip,user | eval rule="53c7cca0-2901-493a-95db-d00d6fcf0a37", title="Brute Force" | collect index=notable_events
description = Detects many authentication failures from one source to one destination which is may indicate Brute Force activity

| bin _time span=600s
| stats dc(category) as value_count by _time dst_ip

| search value_count > 30
