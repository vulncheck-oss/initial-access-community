# Signature Testing

One of VulnCheck's stated claims is that to write truly good detections, the engineer needs to deeply understand the vulnerability and how it's exploited. Otherwise, the detection risks being low quality and brittle. This testing sets to prove out that theory by comparing VulnCheck Suricata rules against Emerging Threats Free Suricata rules. Emerging Threats has the largest source of free rules that we are aware of (and are therefore an important competitor), but it's been our observation that these rules are of very low quality.

## Creating Rule Sets

To compare apples to apples, we first need to pull the relevant rules out of Emerging threats. We extract that rules that cover CVE that we have created PCAP for like so:

```sh
$ make
$ ./signature_testing --bearer_token VULNCHECK-TOKEN
```

This will generate a file called `emerging.suricata.rules`. At the time of writing this contained 322 rules:

```sh
$ wc -l ./emerging.suricata.rules 
322 ./emerging.suricata.rules
```

Next we need to compile the VulnCheck ruleset. That is done using the `./flatten-suricata-rules.sh` script in `feed/`. At the time of writing, we have 276 rules:

```sh
albinolobster@mournland:~/initial-access/feed$ ./flatten-suricata-rules.sh 
albinolobster@mournland:~/initial-access/feed$ wc -l vulncheck.suricata.rules 
276 vulncheck.suricata.rules
```

## Gather PCAPS

VulnCheck has captured hundreds of PCAPs that demonstrate exploitation of initial access vulnerabilities. Suricata needs them all in one subdirectory. Simply use the `gather_pcap.sh` script to combine them into one directory, `./pcaps/`:

```sh
albinolobster@mournland:~/initial-access/docs/signature_testing$ ./gather_pcap.sh 
albinolobster@mournland:~/initial-access/docs/signature_testing$ ls -l ./pcaps/ | wc -l
278
```

## Testing Rules

For testing, we'll run Suricata like:

```sh
$ suricata -k none --runmode=single -vv -r ./pcaps/ -S ../../feed/vulncheck.suricata.rules --set HOME_NET=any --set EXTERNAL_NET=any
```

There are a few things I'd like to note on this:

* -k none is no checksums
* --runmode=single makes Suricata single threaded (in packet processing). I noticed some... odd... behavior associated with flowbit setting when multi-threading.
* HOME_NET is set to any because the PCAPs don't use any one subnet and it doesn't really hurt to just do any.
* EXTERNAL same for HOME_NET

### Testing Emerging Threats

Run the test like so:

```sh
$ cat emerging.suricata.rules | grep -oEi "cve,[0-9]+\-[0-9]+" | sort | uniq | wc -l
93
$ rm fast.log
$ suricata -k none --runmode=single -vv -r ./pcaps/ -S emerging.suricata.rules --set HOME_NET=any --set EXTERNAL_NET=any
[201598] Info: detect: 1 rule files processed. 322 rules successfully loaded, 0 rules failed, 0
[201598] Info: threshold-config: Threshold config parsed: 0 rule(s) found
[201598] Info: detect: 322 signatures processed. 0 are IP-only rules, 104 are inspecting packet payload, 218 inspect application layer, 0 are decoder event only
[201598] Notice: suricata: Signal Received.  Stopping engine.
[201598] Info: suricata: time elapsed 0.782s
[201601] Perf: flow-manager: 584 flows processed
[201599] Notice: pcap: read 277 files, 104254 packets, 70252589 bytes
[201598] Info: counters: Alerts: 193
[201598] Perf: ippair: ippair memory usage: 422144 bytes, maximum: 16777216
[201598] Perf: host: host memory usage: 406144 bytes, maximum: 33554432
$ cat fast.log | grep -oEi "CVE-[0-9]+-[0-9]+" | grep -oEi "[0-9]+-[0-9]+" | sort | uniq | wc -l
33
```

### Testing VulnCheck

```sh
$ cat ../../feed/vulncheck.suricata.rules | grep -oEi "cve,CVE-[0-9]+\-[0-9]+" | sort | uniq | wc -l
184
$ rm fast.log
$ suricata -k none --runmode=single -vv -r ./pcaps/ -S ../../feed/vulncheck.suricata.rules --set HOME_NET=any --set EXTERNAL_NET=any
[208771] Info: detect: 1 rule files processed. 276 rules successfully loaded, 0 rules failed, 0
[208771] Info: threshold-config: Threshold config parsed: 0 rule(s) found
[208771] Info: detect: 276 signatures processed. 0 are IP-only rules, 21 are inspecting packet payload, 254 inspect application layer, 0 are decoder event only
[208771] Notice: suricata: Signal Received.  Stopping engine.
[208771] Info: suricata: time elapsed 0.752s
[208774] Perf: flow-manager: 585 flows processed
[208772] Notice: pcap: read 277 files, 104254 packets, 70252589 bytes
[208771] Info: counters: Alerts: 455
[208771] Perf: ippair: ippair memory usage: 422144 bytes, maximum: 16777216
[208771] Perf: host: host memory usage: 406144 bytes, maximum: 33554432=
$ cat fast.log | grep -oEi "CVE-[0-9]+-[0-9]+" | grep -oEi "[0-9]+-[0-9]+" | sort | uniq | wc -l
182
```
