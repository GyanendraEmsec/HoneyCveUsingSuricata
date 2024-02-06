import elasticsearch
from elasticsearch import Elasticsearch
from elasticsearch import helpers
from datetime import datetime, timedelta
from pymongo import MongoClient
import schedule
import time
import logging
logging.basicConfig(filename='scheduler.log', level=logging.INFO, format='%(asctime)s - %(levelname)s: %(message)s')

def job():
    logging.info("Running job at: %s", datetime.now())
    print("Running job at:", datetime.now())
    
    now = datetime.utcnow()
    twenty_four_hours_ago = now - timedelta(hours=24)
    formatted_twenty_four_hours_ago = twenty_four_hours_ago.strftime('%Y-%m-%dT%H:%M:%S.000Z')

    es5 = Elasticsearch(
        cloud_id="mt_cli1:YXNpYS1zb3V0aDEuZ2NwLmVsYXN0aWMtY2xvdWQuY29tOjQ0MyQ3YjExZWQ4MzUwYWU0NjhiOTA2MmViMmMxZDZlNWRhZiQ2MmVlMzNhN2ZiOTM0ZDNkYThhYmFlOTI5MzBlM2Q4MQ==",
        basic_auth=("elastic", "o28leqtlh4LTSO8UMUzw8zPU"),request_timeout=600
    )


    index_name="honeypot_ip_test"

    search_query = {
        "query": {
            "match": {
                "data._source.suricata.eve.alert.metadata.cve": "CVE_2023_1389"
            }
        }
    }

    query2 = {
        "size":1000,
        "query": {
            "bool": {
                "must": {
                    "exists": {
                        "field": "data._source.suricata.eve.alert.metadata.cve"
                    }
                }
            }
        }
    }

    query3 = {
        "size":1000,
        "query": {
            "bool": {
                "must": [
                    {
                        "exists": {
                            "field": "data._source.suricata.eve.alert.metadata.cve"
                        }
                    },
                    {
                        "range": {
                            "data._source.@timestamp": {
                                "gte": formatted_twenty_four_hours_ago,
                                "lte": now.strftime('%Y-%m-%dT%H:%M:%S.000Z')
                            }
                        }
                    }
                ]
            }
        }
    }


    result = es5.search(index = index_name,body = query3)

    cveContainingData = []
    for hit in result['hits']['hits']:
        cveContainingData.append(hit['_source'])
    
    logging.info("Fetched %s records",len(cveContainingData))
    print(f"Fetched {len(cveContainingData)} records.")
    client = MongoClient('mongodb://localhost:27017/')
    db = client['honeypot']
    collection = db['honeypot_cve']
    insert_result = collection.insert_many(cveContainingData)

    logging.info("Inserted %s records",len(insert_result.inserted_ids))
    logging.info("Job completed at: %s", datetime.now())
    print(f"Inserted {len(insert_result.inserted_ids)} records.")
    print("Job completed at:", datetime.now())

# run every day at 1 AM
schedule.every().day.at("01:00").do(job)

while True:
    schedule.run_pending()
    time.sleep(1)
