---
ready: true
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
    targetEncryptedComms: {yes|no|either|}
    targetDocker: false
    mitreAttackTechniques:
      - {{.MITREAttackTechniques}}
    shodanQueries:
      - {{.ShodanURLs}}
    censysQueries:
      - {{.CensysURLs}}
    fofaQueries:
      - {{.fofaURLs}}
    zoomEyeQueries:
      - {{.zoomEyeURLs}}
    googleQueries:
      - {{.GoogleURLs}}
    baiduQueries:
      - {{.BaiduURLS}}
    greynoiseQueries:
      - {{.GreynoiseURLs}}
---
# {{.CVE}}: {{.Description}}

## Example: 
