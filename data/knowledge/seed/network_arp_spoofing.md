---
title: "ARP Spoofing, Poisoning & Local Network MITM Defenses"
tags: ["network", "arp", "mitm", "switching", "dai", "rfc826"]
source: "RFC 826 (Ethernet Address Resolution Protocol) / IEEE 802.1X"
---

# ARP Spoofing, Poisoning & Local Network MITM Defenses
## Source & Authority
IETF RFC 826 (An Ethernet Address Resolution Protocol); IEEE 802.1X Port-Based Network Access Control.

## Mechanics
Because ARP is stateless and lacks authentication, any device on the local broadcast domain can send unsolicited Gratuitous ARP replies associating its MAC address with the IP address of the default gateway or target host, enabling adversary-in-the-middle traffic interception.

## Layer 2 Defenses
1. **Dynamic ARP Inspection (DAI):** Managed switches intercept and validate all ARP packets against the DHCP Snooping binding database, dropping invalid IP-to-MAC associations.
2. **Static ARP Tables:** For critical servers and gateways, bind static ARP entries.
3. **802.1X Network Access Control:** Authenticate physical switch port connections.
