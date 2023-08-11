# VulnCheck Signature Intelligence

The following table describes overlapping signatures that VulnCheck and Emerging Threats have. The goal of this document is to exactly which VulnCheck exploits that Emerging Threats can detect.

Status emojis:

* ✔️ = Successfully detects IA pcap
* 💔 = Rule is broken or only catches a specific exploit variant (e.g. hardcoded payload or something)
* 🤷 = VulnCheck partial bypass
* 🔥 = VulnCheck full bypass

*Caveat: I skipped Log4Shell.

|CVE|Engine|Status|Note|
|---|---|---|---|
|CVE-2017-7577|Suricata|✔️|Only detects Account1|
|CVE-2017-7577|Snort|✔️|Only detects Account1|
|CVE-2018-14867|Suricata|💔|Hard-coded length|
|CVE-2018-14867|Snort|💔|Hard-coded length|
|CVE-2019-1652|Suricata|💔|Mistake reading pcap|
|CVE-2019-1652|Snort|💔|Mistake reading pcap|
|CVE-2019-1653|Suricata|✔️||
|CVE-2019-1653|Snort|✔️||
|CVE-2019-3929|Suricata|🔥||
|CVE-2019-3929|Snort|🔥||
|CVE-2019-15107|Suricata|🔥||
|CVE-2019-15107|Snort|🔥||
|CVE-2020-7961|Suricata|🔥||
|CVE-2020-7961|Snort|🔥||
|CVE-2020-22253|Suricata|💔|Only catches challenge/response variant|
|CVE-2020-22253|Snort|💔|Only catches challenge/response variant|
|CVE-2021-1497|Suricata|💔|No URI payload support. Bad encoding assumptions.|
|CVE-2021-1497|Snort|💔|No URI payload support. Bad encoding assumptions.|
|CVE-2021-1498|Suricata|💔|No GET support. Only detects when ` is used.|
|CVE-2021-1498|Snort|💔|No GET support. Only detects when ` is used.|
|CVE-2021-22205|Suricata|💔|Mistake with URI|
|CVE-2021-22205|Snort|💔|Mistake with URI|
|CVE-2021-36260|Suricata|🔥|Space in xml|
|CVE-2021-36260|Snort|🔥|Space in xml|
|CVE-2021-39144|Suricata|✔️|Bypass TODO: Hardcoded space between method and URI|
|CVE-2021-39144|Snort|✔️|Bypass TODO: Hardcoded space between method and URI|
|CVE-2021-41773|Suricata|🔥|Gap in rule coverage|
|CVE-2021-41773|Snort|🔥|Gap in rule coverage|
|CVE-2021-43798|Suricata|🔥|Overly restrictive search size|
|CVE-2021-43798|Snort|🔥|Overly restrictive search size|
|CVE-2021-44077|Suricata|🔥|Requires quotes|
|CVE-2021-44077|Snort|🔥|Requires quotes|
|CVE-2021-44515|Suricata|💔|Assumes payload is in URI|
|CVE-2021-44515|Snort|💔|Assumes payload is in URI|
|CVE-2022-0543|Suricata|🔥||
|CVE-2022-0543|Snort|🔥||
|CVE-2022-1040|Suricata|💔|Does not detect actual exploitation|
|CVE-2022-1040|Snort|💔||
|CVE-2022-1388|Suricata|🔥|Bad !|
|CVE-2022-1388|Snort|🔥|Bad !|
|CVE-2022-22947|Suricata|🔥||
|CVE-2022-22947|Snort|🔥||
|CVE-2022-22954|Suricata|🔥|Added a space, lol|
|CVE-2022-22954|Snort|🔥|Added a space, lol|
|CVE-2022-22963|Suricata|✔️||
|CVE-2022-22963|Snort|✔️||
|CVE-2022-22965|Suricata|✔️||
|CVE-2022-22965|Snort|✔️||
|CVE-2022-24112|Suricata|🔥||
|CVE-2022-24112|Snort|🔥||
|CVE-2022-24706|Suricata|💔|Hard-coded challenge response?|
|CVE-2022-24706|Snort|💔|Hard-coded challenge response?|
|CVE-2022-26259|Suricata|💔|Bad value in Cseq. Not sure this can use http either?|
|CVE-2022-26259|Snort|💔|Bad value in Cseq|
|CVE-2022-26352|Suricata|🔥||
|CVE-2022-26352|Snort|🔥||
|CVE-2022-27925|Suricata|💔|Wrong URI|
|CVE-2022-27925|Snort|💔|Wrong URI|
|CVE-2022-29464|Suricata|🔥|Strict file upload path|
|CVE-2022-29464|Snort|🔥|Strict file upload path|
|CVE-2022-30525|Suricata|🔥|Double mtu|
|CVE-2022-30525|Snort|🔥|Double mtu|
|CVE-2022-35405|Suricata|🔥|Tab instead of a space|
|CVE-2022-44877|Suricata|🔥||
|CVE-2022-44877|Snort|🔥||
|CVE-2022-46169|Suricata|🔥||
|CVE-2022-46169|Snort|🔥||
|CVE-2022-47966|Suricata|💔||
|CVE-2022-47966|Snort|💔||
|CVE-2023-34362|Suricata|🤷|Mixed-case strings|
|CVE-2023-34362|Snort|🤷|Mixed-case strings|
|CVE-2023-34960|Suricata|💔|Hard-coded requirement for `.ppt|
|CVE-2023-34960|Snort|💔|Hard-coded requirement for `.ppt|
|CVE-2023-38646|Suricata|🔥|Spacing in payload|
|CVE-2023-38646|Snort|🔥|Spacing in payload|
