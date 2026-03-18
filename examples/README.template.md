---
id: {{.UUID}}
cve: {{.CVE}}
artifacts:
  - vendor: {{.Vendor}}
    product:
      - {{.Product}}
      - {{.Product2}}
    dateAdded: "{{.DateNow}}"
    related: []
    chain: []
    artifactName: {{.Description}}
    exploit: false
    versionScanner: false
    pcap: false
    sigmaRule: false
    suricataRule: false
    snortRule: false
    yara: false
    nmapScript: false
    targetService: HTTP
    targetEncryptedComms: {yes|no|either|}
    targetDocker: false
    mitreAttackTechniques:
      - {{.MITREAttackTechniques}}
    shodanQueries:
      - {{.ShodanURLs}}
    censysQueries:
      - {{.CensysURLs}}
    censysLegacyQueries:
      - {{.CensysLegacyURLs}}
    fofaQueries:
      - {{.fofaURLs}}
    zoomEyeQueries:
      - {{.zoomEyeURLs}}
    driftnetQueries:
      - {{.driftnetQueries}}
    googleQueries:
      - {{.GoogleURLs}}
    baiduQueries:
      - {{.BaiduURLS}}
    greynoiseQueries:
      - {{.GreynoiseURLs}}
---
# {{.CVE}}: {{.Description}}

## Example: 
