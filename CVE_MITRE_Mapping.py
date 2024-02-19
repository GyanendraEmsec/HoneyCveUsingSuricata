from pyattck import Attck
import requests

def fetch_cve_data():
    url = 'https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=20&startIndex=20'
    response = requests.get(url)
    print(f"fetching CVE data...")
    return response


def get_cve_data(response):
    cve_data = response.json()
    vulnerabilities = cve_data.get('vulnerabilities')
    cve_list = []
    if vulnerabilities:
        for vulnerability in vulnerabilities:
            cve_info = vulnerability.get('cve', {})
            # cve_id = cve_info.get('id')
            if cve_info:
                cve_list.append(cve_info)
    print(f"fetching CVE list...")
    return cve_list


def map_cve_to_attck(cve_id):
    print(f"mapping CVE: {cve_id} ")
    attack = Attck()
    for technique in attack.enterprise.techniques:
        for mitigation in technique.mitigations:
            for cve_reference in mitigation.external_references:
                if cve_reference.external_id == cve_id:
                    print(f"CVE {cve_id} maps to technique: {technique.name} ({technique.id})")

cve_data = fetch_cve_data()
cve_data_list = get_cve_data(cve_data)

for cve_entry in cve_data_list:
    cve_id = cve_entry.get('id')
    map_cve_to_attck(cve_id)

# def main():
#     cve_data = fetch_cve_data()
#     cve_data_list = get_cve_data(cve_data)

#     for cve_entry in cve_data_list:
#         cve_id = cve_entry.get('id')
#         map_cve_to_attck(cve_id)

# if __name__ == "_main_":
#     main()