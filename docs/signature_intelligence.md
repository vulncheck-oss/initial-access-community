# VulnCheck Signature Intelligence

The following table describes overlapping signatures that VulnCheck and Emerging Threats have.

Status emojis:

* ✔️ = Successfully detects IA pcap
* 💔 = Rule is broken or only catches a specific exploit variant (e.g. hardcoded payload or something)
* 🔥 = VulnCheck bypass

|CVE|Engine|Status| Note |
| --- | --- | --- | --- |
| CVE-2017-7577 | Suricata | ✔️| Only detects Account1 |
| CVE-2017-7577 | Snort | ✔️| Only detects Account1 |
| CVE-2018-14867| Suricata |💔| Hard-coded length |
| CVE-2018-14867| Snort |💔| Hard-coded length |
| CVE-2019-1652| Suricata |💔| Mistake reading pcap |
| CVE-2019-1652| Snort |💔| Mistake reading pcap |
| CVE-2019-1653| Suricata |✔️| |
| CVE-2019-1653| Snort | ✔️ | |
| CVE-2019-3929| Suricata |🔥| |
| CVE-2019-3929| Snort |🔥| |
| CVE-2019-15107| Suricata |🔥| |
| CVE-2019-15107| Snort |🔥| |
| CVE-2020-7961 | Suricata |🔥| |
| CVE-2020-7961 | Snort |🔥| |
| CVE-2020-22253| Suricata |💔| Only catches challenge/response variant |
| CVE-2020-22253| Snort |💔| Only catches challenge/response variant |
| CVE-2021-1497 | Suricata |💔| No URI payload support. Bad encoding assumptions. |
| CVE-2021-1497 | Snort |💔| No URI payload support. Bad encoding assumptions.|
| CVE-2021-1498 | Suricata |💔| No GET support. Only detects when ` is used.|
| CVE-2021-1498 | Snort |💔| No GET support. Only detects when ` is used.|
| CVE-2021-22205 | Suricata |💔| Mistake with URI |
| CVE-2021-22205 | Snort |💔| Mistake with URI |
