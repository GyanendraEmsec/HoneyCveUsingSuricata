import requests
from nvd_api import NvdApiClient
from pymongo import MongoClient
import pandas as pd
import logging
from bson.objectid import ObjectId

client = MongoClient('mongodb://localhost:27017/')
db = client['honeypot']
collection = db['honeypot_cve']

allCveData = list(collection.find())
cvesList = []
nvdClient = NvdApiClient(wait_time=1 * 1000, api_key='c738e47b-edaf-4f80-866b-f03257d92480')
weaknessesList = {}
username = "XXXXXXXXXXXXXXXX"
password = "XXXXXXXXXXXXXXXX"
def get_cve_info(cve):
    response = nvdClient.get_cves(
        cve_id=cve
    )
    return response
def getCwesInfo(cve):
    cve_info = get_cve_info(cve)
    print(f"Getting CWEs for {cve}: ")
    tempArr = []
    for vun in cve_info['vulnerabilities']:
        for wk in vun['cve']['weaknesses']:
            for eachwk in wk['description']:
                url = f"https://www.opencve.io/api/cwe/{eachwk['value']}"
                response = requests.get(url, auth=(username, password))
                if response.status_code == 200:
                    print("Request successful!")
                    tempArr.append(response.json())
                    print(response.json())
                else:
                    print(f"Request failed with status code {response.status_code}")
                    print(response.text)
                # tempArr.append(eachwk['value'])
                print(eachwk['value'])
    weaknessesList[f"{cve}"] = list(tempArr)
    return weaknessesList

for eachdata in allCveData:
    for i in eachdata['data']['_source']['suricata']['eve']['alert']['metadata']['cve']:
        s = i.replace('_','-')
    #   if not s in cvesList:
        cvesList.append(s)
        wkInfo = getCwesInfo(s)
        collection.update_one({'_id': ObjectId(f"{eachdata['_id']}")},  {'$set': {"cveWeaknesses": wkInfo}})
print(cvesList)


# weaknessesList = {}
# username = "gyanendrashukla"
# password = "Gyanendra@123"
# for cve in cvesList:
#     cve_info = get_cve_info(cve)
#     print(f"Getting CWEs for {cve}: ")
#     tempArr = []
#     for vun in cve_info['vulnerabilities']:
#         for wk in vun['cve']['weaknesses']:
#             for eachwk in wk['description']:
#                 url = f"https://www.opencve.io/api/cwe/{eachwk['value']}"
#                 response = requests.get(url, auth=(username, password))
#                 if response.status_code == 200:
#                     print("Request successful!")
#                     tempArr.append(response.json())
#                     print(response.json())  # Print the response data
#                 else:
#                     print(f"Request failed with status code {response.status_code}")
#                     print(response.text)
#                 # tempArr.append(eachwk['value'])
#                 print(eachwk['value'])
#     weaknessesList[f"{cve}"] = list(tempArr)
# print(weaknessesList)