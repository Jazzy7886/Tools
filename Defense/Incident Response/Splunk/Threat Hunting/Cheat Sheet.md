index=security sourcetype=pan:threat eventtype=pan_url url={{ url }}

index=dns sourcetype=stream:dns query=*ustc* | stats count by src query