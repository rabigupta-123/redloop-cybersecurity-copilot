---
title: "Suricata & Snort Network IDS Signature Authoring"
tags: ["ids", "suricata", "snort", "network", "detection", "signatures"]
source: "Suricata User Guide v7.0 / Snort 3 User Manual"
---

# Suricata & Snort Network IDS Signature Authoring
## Source & Authority
Suricata User Guide v7.0; Snort 3 Official Rule Writing Guide.

## Signature Syntax & Anatomy
`action proto src_ip src_port -> dst_ip dst_port (options)`

```snort
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"ET MALWARE Cobalt Strike Beaconing User-Agent";
    flow:established,to_server;
    content:"POST"; http_method;
    content:"Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"; http_user_agent;
    content:"/submit.php?id="; http_uri;
    classtype:trojan-activity;
    sid:2045001;
    rev:1;
)
```
## Fast-Pattern Matching
Use `fast_pattern` on high-entropy unique strings to minimize packet inspection overhead on high-throughput network interfaces.
