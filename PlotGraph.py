from pymongo import MongoClient
import pandas as pd
import logging

client = MongoClient('mongodb://localhost:27017/')
db = client['honeypot']
collection = db['honeypot_cve']

allCveData = list(collection.find())
cvesList = []

for eachdata in allCveData:
    for i in eachdata['data']['_source']['suricata']['eve']['alert']['metadata']['cve']:
      s = i.replace('_','-')
      if not s in cvesList:
        cvesList.append(s)
print(cvesList)

logging.basicConfig(
    level=logging.INFO # allow DEBUG level messages to pass through the logger
    )

DAY_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"

def load_data(day_url = DAY_URL):
  try:
    logging.info('Downloading day feed')
    epss_df = pd.read_csv(DAY_URL,compression='gzip',sep=',')
    if len(epss_df) > 0 :
      logging.info('Done with total rows = %d' % len(epss_df))
      header = epss_df.iloc[0]
      if len(header)==2:
        version = header.index[0].split(':')[1]
        score_date = ''.join(header.index[1].split(':')[1:])
        epss_df.columns = epss_df.iloc[0]
        num_df = epss_df.iloc[1:].copy()
        del epss_df
        num_df['epss']=num_df['epss'].astype('float')
        num_df['percentile']=num_df['percentile'].astype('float')
        return (version,score_date,num_df)
      else:
        raise Exception('EPSS format is malformed')
  except Exception as ep:
    logging.error(ep)

(version,score_date,epss_df) = load_data()
logging.info(f'Date = {score_date} Version = {version}')
logging.info(f'Total entries {len(epss_df)}')
logging.info(f"Total CVE {epss_df.index.nunique()}")
assert len(epss_df) == epss_df.index.nunique()

def getCveByEpss(filterType,scoreToFilter):
  match filterType:
    case "gt":
      rslt_df = epss_df[epss_df['epss'] > scoreToFilter]
    case "lt":
      rslt_df = epss_df[epss_df['epss'] < scoreToFilter]
    case "gteq":
      rslt_df = epss_df[epss_df['epss'] >= scoreToFilter]
    case "lteq":
      rslt_df = epss_df[epss_df['epss'] <= scoreToFilter]
    case _:
      rslt_df = epss_df[epss_df['epss'] > scoreToFilter]
  rslt_df = rslt_df.sort_values('epss')
  rslt_df.to_csv(f'CVEs_epss_{filterType}_{scoreToFilter}.csv')


def filterDfWithHoneypotCves(epss_df,honeypot_cves):
  rslt_df = epss_df[epss_df.index.isin(honeypot_cves)]
  return rslt_df

import matplotlib
import numpy as np
import matplotlib.pyplot as plt
# %matplotlib inline

epss_df.hist(column='epss', alpha=0.8,figsize=(10,4))
plt.title(f'Histogram of EPSS scores of all CVEs')
plt.show()

rslt_df = filterDfWithHoneypotCves(epss_df,cvesList)
rslt_df.hist(column='epss', alpha=0.8,figsize=(10,4))
plt.title(f'Histogram of EPSS scores of {len(rslt_df)} CVEs from honeypots')
plt.show()