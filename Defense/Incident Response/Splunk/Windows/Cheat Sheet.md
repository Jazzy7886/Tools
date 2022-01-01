<u>__One-off Searches:__</u>

(index=wineventlog OR index=test) sourcetype=wineventlog EventCode=4769 Ticket_Encryption_Type=0x17 Failure_Code=0x0 NOT (Service_Name=*$ OR Service_Name=krbtgt OR Service_Name={{ service_name }} OR Service_Name={{ service_name }})
| rename ComputerName AS Host
| eval info=Message[0]["Account Information"][1]
| table _time Host info


(index=wineventlog OR index=test) sourcetype=wineventlog EventCode=4769 Ticket_Encryption_Type=0x17 Failure_Code=0x0 NOT (Service_Name=*$ OR Service_Name=krbtgt OR Service_Name={{ service_name }} OR Service_Name={{ service_name }}) 
| stats count by Client_Address 
| where count >= 3

<u>__Detecting Kerberoasting Spn Request with RC4 Encryption in Splunk:__</u>

Sourcetype=wineventlog_security EventCode=4769 Ticket_Options=0x40810000 Ticket_Encryption_Type=0x17 | stats count min(_time) as firstTime max(_time) as lastTime by dest, service, service_id, Ticket_Encryption_Type, Ticket_Options | `security_content_ctime(lastTime)` | `security_content_ctime(firstTime)` | `kerberoasting_spn_request_with_rc4_encryption_filter`

