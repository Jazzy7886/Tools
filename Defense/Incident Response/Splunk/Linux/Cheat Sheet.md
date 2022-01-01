<u>__Linux - Excessive SSH Login Failures:__</u>

index=linux sourcetype=linux_secure app=sshd action=failure NOT 
[| inputlookup {{ input_lookup_file }} 
| rename "ip_address" AS src_ip] 
| stats count by src_ip 
| where count >=3

<u>__Linux - User Creation with UID >=1000 OR <=1000:__</u>

User creation with UID >=1000 OR <=1000

<u>__Using a lookup file for querying:__</u>

index=linux sourcetype=linux_secure eventtype=useradd NOT [| inputlookup {{ input_lookup_file }} ]
| stats count by _time host user | rename user AS "user_created"
 
regex to get ip- string: ^([a-z][a-z]-)

<u>__Linux - sudo:__</u>

r_process 
r_command_full 
r_user 
sourcetype=linux_secure source="/var/log/secure" "sudo:" 
| table _time host r_user r_process r_command_full 
"session opened for user root by" 
sourcetype=linux_secure source="/var/log/secure" "sudo:" r_user!=nessus 
| rename r_user AS user 
| rename r_process AS process 
| rename r_command_full AS command 
| table _time host user process command
