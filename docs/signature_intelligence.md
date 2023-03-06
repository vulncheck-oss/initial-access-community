# VulnCheck Signature Intelligence

The following table describes overlapping signatures that VulnCheck and Emerging Threats have.

Status emojis:

* ✔️ = Successfully detects IA pcap
* 💔 = Rule is broken or only catches a specific exploit variant (e.g. hardcoded payload or something)
* 🔥 = VulnCheck bypass

*Caveat: I skipped Log4Shell.

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
| CVE-2021-36260 | Suricata |🔥| Space in xml |
| CVE-2021-36260 | Snort |🔥| Space in xml |
| CVE-2021-39144| Suricata |💔| Hardcoded space between method and URI |
| CVE-2021-39144| Snort |💔| Hardcoded space between method and URI |
| CVE-2021-41773| Suricata |🔥| Gap in rule coverage|
| CVE-2021-41773| Snort |🔥| Gap in rule coverage|
| CVE-2021-43798| Suricata |🔥| Overly restrictive search size|
| CVE-2021-43798| Snort |🔥| Overly restrictive search size|
| CVE-2021-44077| Suricata |🔥| Requires quotes|
| CVE-2021-44077| Snort |🔥| Requires quotes|
| CVE-2021-44515| Suricata |💔| Assumes payload is in URI |
| CVE-2021-44515| Snort |💔| Assumes payload is in URI |
| CVE-2022-0543| Suricata |🔥| |
| CVE-2022-0543| Snort |🔥| |
