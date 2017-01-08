# asn-iptables-gen.sh

Script to create iptables rules for all subnets advertised by a specific AS

Based on *filter.sh* by Matthew Walster (https://github.com/dotwaffle)


##Notes

- Can process IPv4 or IPv6
- Uses ‘aggregate’ to optimise rules

##Dependencies

- iptables/ip6tables
- perl
- aggregate (if enabled)

##Optional

- generated script header file (see header.txt)

##Usage

> /path/to/asn-iptables-gen.sh --type iptables --ipv4 --aggregate --iptheader /etc/iptables/header.txt --iptdesc "ROSTELECOM_AS12389" --iptchain "BLOCKED_AS_LOG" AS12389

This will create the aggregated rules for IPv4 ranges advertised by AS12389 and add them to chain BLOCKED_IP_LOG.
Additionally, a header file will be used to generate the resulting script.

> /path/to/asn-iptables-gen.sh --type iptables --ipv6 --iptdesc "ROSTELECOM_V6_AS12389" --iptchain "BLOCKED_AS_LOG6" AS12389

This will create the rules for IPv6 ranges advertised by AS12389.
No aggregation of subnets will be performed nor any header file will be processed.


##Important

The script **will not** add any rules to the active iptables/ip6tables setup.
To enforce the rules you must explicitly execute the generated script.
