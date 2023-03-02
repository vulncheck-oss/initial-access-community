# VulnCheck Signature Intelligence

The following table describes overlapping signatures that VulnCheck and Emerging Threats have.

The difference between an "invalid rule" and an "IA bypass" is that an "invalid rule" would likely rarely (or never) hit on any variant of the exploit (e.g. they got something wrong in the rule.)

|CVE|Engine|Detects IA PCAP|Invalid Rule|IA Bypass| Note |
| --- | --- | --- | --- | --- | --- |
| CVE-2017-7577 | Suricata | ✔️ | | | Only detects Account1 |
| CVE-2017-7577 | Snort | ✔️ | | | Only detects Account1 |
| CVE-2018-14867| Suricata | |✔️ | | Hard-coded length |
| CVE-2018-14867| Snort | |✔️ | | Hard-coded length |
