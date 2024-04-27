import requests
import argparse
import json

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='VulnCheck CVE Lookup')
    parser.add_argument('--token', action="store", dest="token", required=True, help="VulnCheck access token")
    parser.add_argument('--cves', action="store", dest="cves", required=True, help="CVEs to look up")
    args = parser.parse_args()

    kev = 0
    vcKEV = 0
    attackersDict = dict()

    with open(args.cves, 'r') as file:
        for line in file:
            cve = line.strip()
            if len(cve) == 0:
                continue
            cve = "CVE-"+cve

            url = "https://api.vulncheck.com/v3/index/exploits"
            headers = {
                "accept": "application/json",
                "authorization": "Bearer " + args.token
            }
            params = {
                "cve": cve
            }

            response = requests.get(url, headers=headers, params=params)
            exploit_json = response.json()
            if len(exploit_json["data"]) == 0:
                continue
            exploit_json = exploit_json["data"][0]

            if exploit_json["inVCKEV"]:
                vcKEV += 1
            if exploit_json["inKEV"]:
                kev += 1
            if "reported_exploitation" not in exploit_json:
                continue

            attackerSet = set()
            for report in exploit_json["reported_exploitation"]:
                if report["refsource"].find("vulncheck") != -1:
                    attackerSet.add(report["name"])
            
            for attacker in attackerSet:
                if attacker not in attackersDict:
                    attackersDict[attacker] = 0
                attackersDict[attacker] += 1
    
    print("KEV: %d" % (kev))
    print("VC KEV: %d" % (vcKEV))
    print("=== Attackers ===")
    sorted_dict = dict(sorted(attackersDict.items(), key=lambda item: item[1], reverse=True))
    for key, value in sorted_dict.items():
        print(key, ':', value)