---
ready: false
id: {{.UUID}}
cve: {{.CVE}}
artifacts:
  - vendor: {{.Vendor}}
    product:
      - {{.Product}}
      - {{.Product2}}
    dateAdded: "{{.DateNow}}"
    artifactName: {{.Description}}
    exploit: false
    versionScanner: false
    pcap: false
    suricataRule: false
    snortRule: false
    yara: false
    nmapScript: false
    zeroday: false
    targetService: HTTP
    targetDocker: false
    shodanQueries:
      - {{.ShodanURLs}}
    censysQueries:
      - {{.CensysURLs}}
    greynoiseQueries:
      - {{.GreynoiseURLs}}
---
# {{.CVE}}: {{.Description}}

## Example: 
